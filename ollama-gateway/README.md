# Ollama Gateway — login page and IAM module for Ollama

CS411 Project 1, part 4. A Python (FastAPI) gateway that puts identity and access
management in front of an Ollama server **without changing Ollama**. People sign up with
their email (confirmed by a 6-digit code) and sign in with a password and an optional
authenticator-app code. Every request to Ollama's API is checked against the user's role
and model allowlist and written to an audit log.

```
browser ──► Ollama Gateway (:8000) ──► Ollama (:11434, bound to localhost)
                  sign-up · login · roles · audit
```

## Run it

Requires Python 3.10+.

```bash
pip install -r requirements.txt

# Terminal 1 — either real Ollama ...
ollama serve                      # listens on 127.0.0.1:11434
# ... or the bundled stand-in if Ollama isn't installed:
python mock_ollama.py

# Terminal 2 — set the mail settings (see below), then:
python run_gateway.py             # http://127.0.0.1:8000
```

Open http://127.0.0.1:8000 and sign in with a demo account, or click **Create an account**:

| Username   | Password         | Role           | Model access                            |
|------------|------------------|----------------|-----------------------------------------|
| admin      | ChangeMe!2026    | Administrator  | all                                     |
| ayse.op    | Operator!2026    | Model operator | all                                     |
| deniz.dev  | Developer!2026   | Developer      | `llama3.2*, qwen3*, nomic-embed-text*`  |
| mert.view  | Viewer!2026x     | Viewer         | all (list only)                         |

Delete the `data/` folder to reset everything.

## Sign-up and email

Anyone can sign up. The gateway emails a 6-digit code; the account is created only after
the code is entered (10-minute expiry, 5 wrong tries, one resend per minute). The email
domain decides the starting role: addresses at `GATEWAY_DEVELOPER_DOMAINS` (default
`bilkent.edu.tr`, subdomains included, so `ug.bilkent.edu.tr` counts) start as
**Developer**; everyone else starts as **Viewer** until an admin upgrades them.

Codes are sent through any SMTP server. Without SMTP settings the sign-up page explains that
sign-up is off, and admins can still add users.

**Gmail** (needs 2-step verification on the Google account, then an
[app password](https://myaccount.google.com/apppasswords)):

```bash
export SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_SECURITY=starttls
export SMTP_USER=yourteam@gmail.com SMTP_PASSWORD='abcd efgh ijkl mnop'
```

**Outlook / Office 365:** `SMTP_HOST=smtp.office365.com SMTP_PORT=587 SMTP_SECURITY=starttls`
plus your address and password (your account must allow SMTP AUTH).

**Testing without a real account** — run a local SMTP server that saves messages to a folder:

```bash
pip install aiosmtpd
mkdir -p maildir/{tmp,new,cur}
python -m aiosmtpd -n -l 127.0.0.1:1025 -c aiosmtpd.handlers.Mailbox ./maildir
export SMTP_HOST=127.0.0.1 SMTP_PORT=1025 SMTP_SECURITY=none SMTP_FROM=gateway@example.edu
```

The codes then appear as files in `maildir/new/`.

## What you can do after signing in

- **Models** lists the models your role and allowlist let you use, shows your permissions, and
  has a prompt box that calls Ollama *through* the gateway. Asking for a model outside your
  allowlist, or running a model as a Viewer, returns 403 right there.
- **Account** sets up the authenticator app and changes your password.
- **Users** (admins): add users, change roles and model access, disable or unlock accounts.
- **Audit log** (admins, operators): every sign-in, sign-up and allowed/denied request.

Errors keep Ollama's `{"error": "..."}` shape: 401 (not signed in), 403 (role or model not
allowed), 502 (Ollama unreachable).

## Tests

```bash
python -m pytest -q
```

19 tests cover password hashing, the RFC 6238 TOTP test vector and replay protection,
the policy matrix, login + lockout + CSRF, the full MFA flow, enforcement through the gateway
(viewer can't run models, developer allowlist and listing filter, OpenAI-compatible route,
disabled users), auditing, and sign-up (domain-based roles, wrong-code limit, duplicates,
resend cooldown). Tests use a fake
mailer, so no email is sent.

## Project structure

```
app/
  main.py        application factory; wires everything together, security headers
  config.py      settings from environment variables
  db.py          SQLite schema and thin repository wrapper
  security.py    scrypt password hashing, TOTP (RFC 6238), random tokens
  policy.py      permissions, roles, Ollama route table, Policy Decision Point
  iam.py         IAM service: users, login, lockout, sessions, MFA
  signup.py      sign-up service: pending sign-ups, e-mailed codes, domain → role
  mailer.py      SMTP mailer and the confirmation e-mail
  proxy.py       Policy Enforcement Point: authenticated streaming reverse proxy to Ollama
  audit.py       append-only audit log
  web.py         sign-up, login, MFA, account, user admin and audit pages
  templates/     Jinja2 templates
  static/        stylesheet
mock_ollama.py   stand-in for Ollama's API (same JSON shapes, canned answers)
run_gateway.py   starts the gateway with uvicorn
tests/           pytest suite
docs/screens/    screenshots used in the report
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Where Ollama listens. Keep Ollama bound to localhost so the gateway is the only way in. |
| `GATEWAY_HOST` / `GATEWAY_PORT` | `127.0.0.1` / `8000` | Gateway bind address |
| `GATEWAY_DATA_DIR` | `./data` | SQLite database and secret |
| `GATEWAY_ADMIN_PASSWORD` | `ChangeMe!2026` | Password of the first admin, created on first start |
| `GATEWAY_SEED_DEMO` | `1` | Create the demo users |
| `GATEWAY_DEVELOPER_DOMAINS` | `bilkent.edu.tr` | Comma-separated email domains whose sign-ups start as Developer |
| `GATEWAY_SIGNUP_CODE_MINUTES` | `10` | Lifetime of a confirmation code |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | Mail server for confirmation codes |
| `SMTP_USER` / `SMTP_PASSWORD` | — | Mail account (leave empty for servers without login) |
| `SMTP_FROM` | `SMTP_USER` | Sender address |
| `SMTP_SECURITY` | `starttls` | `starttls`, `ssl` (port 465) or `none` |
| `GATEWAY_SECURE_COOKIES` | `0` | Set to `1` behind HTTPS |
| `GATEWAY_SESSION_MINUTES` | `480` | Session lifetime |
| `GATEWAY_LOCKOUT_THRESHOLD` / `_MINUTES` | `5` / `15` | Failed logins before lockout, and its length |

## Security notes

- Passwords: scrypt (N=2^14, r=8, p=1) with per-user salt; unknown users cost the same time as wrong passwords.
- Sign-up: nothing is added to `users` until the e-mailed code is confirmed; codes are stored hashed, expire, allow 5 tries and one resend per minute.
- Sessions: 256-bit random IDs stored server-side, HttpOnly + SameSite=Lax cookies, rotated after MFA.
- CSRF: per-session token on every form, a separate token on the login and sign-up forms, and an `X-CSRF-Token` header for browser API calls.
- MFA: TOTP with ±1 step tolerance and replay protection (a used code can't be reused).
- Default deny: Ollama routes that aren't in the policy table return 404 from the gateway.
- Scope: the gateway protects access through its own pages. Access for scripts and SDKs (e.g. API keys) is left as future work.
- Not production-hardened: single process and SQLite. See the report for the scaling path.
