"""IAM service: identities, credentials and sessions.

This is the application-service layer of the IAM module. The web layer
(web.py) and the gateway (proxy.py) only talk to this class, never to the
database directly.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import security
from .audit import AuditLog
from .config import Settings
from .db import Database
from .policy import ROLES, Perm, Principal


class IAMError(Exception):
    """Raised with a message that is safe to show to the user."""


@dataclass
class LoginResult:
    ok: bool
    message: str = ""
    session_id: str | None = None
    needs_mfa: bool = False


GENERIC_LOGIN_ERROR = "That username or email and password don't match. Check both and try again."


class IAMService:
    def __init__(self, db: Database, audit: AuditLog, settings: Settings) -> None:
        self.db, self.audit, self.settings = db, audit, settings

    # ------------------------------------------------------------------ users
    def create_user(self, username: str, display_name: str, password: str, roles: list[str],
                    email: str | None = None, model_allow: str = "*", auth_source: str = "admin",
                    actor: str = "system") -> int:
        username = username.strip()
        if not username or not username.replace(".", "").replace("-", "").replace("_", "").isalnum():
            raise IAMError("Usernames can contain letters, digits, dots, dashes and underscores.")
        problems = security.password_problems(password or "", username)
        if problems:
            raise IAMError(" ".join(problems))
        return self._insert_user(username, display_name, email, security.hash_password(password), roles,
                                 model_allow, auth_source, actor)

    def _insert_user(self, username: str, display_name: str, email: str | None, pw_hash: str,
                     roles: list[str], model_allow: str, auth_source: str, actor: str) -> int:
        if self.db.one("SELECT 1 FROM users WHERE username = ? OR (email IS NOT NULL AND email = ?)",
                       (username, email or "")):
            raise IAMError(f"An account for {email or username} already exists. Sign in instead.")
        unknown = [r for r in roles if r not in ROLES]
        if unknown:
            raise IAMError(f"Unknown role: {unknown[0]}.")
        with self.db.tx() as c:
            uid = c.execute(
                "INSERT INTO users (username, display_name, email, password_hash, auth_source, model_allow, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (username, display_name or username, email, pw_hash, auth_source, model_allow or "*", time.time()),
            ).lastrowid
            c.executemany("INSERT INTO user_roles (user_id, role) VALUES (?,?)", [(uid, r) for r in set(roles)])
        self.audit.record("user.create", actor=actor, resource=f"user:{username}",
                          detail={"roles": sorted(set(roles)), "source": auth_source})
        return uid

    def get_user(self, user_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not row:
            return None
        user = dict(row)
        user["roles"] = [r["role"] for r in self.db.all("SELECT role FROM user_roles WHERE user_id = ? ORDER BY role", (user_id,))]
        return user

    def find_user(self, username: str) -> dict | None:
        """Look a user up by username or by e-mail address."""
        name = username.strip()
        row = self.db.one("SELECT id FROM users WHERE username = ? OR email = ?", (name, name))
        return self.get_user(row["id"]) if row else None

    def list_users(self) -> list[dict]:
        return [self.get_user(r["id"]) for r in self.db.all("SELECT id FROM users ORDER BY username")]

    def update_user(self, user_id: int, *, roles: list[str] | None = None, model_allow: str | None = None,
                    is_active: bool | None = None, actor: str = "system") -> None:
        user = self.get_user(user_id)
        if not user:
            raise IAMError("User not found.")
        if roles is not None:
            if any(r not in ROLES for r in roles):
                raise IAMError("Unknown role.")
            if "admin" in user["roles"] and "admin" not in roles and self._admin_count() <= 1:
                raise IAMError("Keep at least one administrator.")
        if is_active is False and "admin" in user["roles"] and self._admin_count() <= 1:
            raise IAMError("You can't disable the last administrator.")
        with self.db.tx() as c:
            if roles is not None:
                c.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
                c.executemany("INSERT INTO user_roles (user_id, role) VALUES (?,?)", [(user_id, r) for r in set(roles)])
            if model_allow is not None:
                c.execute("UPDATE users SET model_allow = ? WHERE id = ?", (model_allow.strip() or "*", user_id))
            if is_active is not None:
                c.execute("UPDATE users SET is_active = ? WHERE id = ?", (int(is_active), user_id))
                if not is_active:
                    c.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))
        self.audit.record("user.update", actor=actor, resource=f"user:{user['username']}",
                          detail={k: v for k, v in {"roles": roles, "model_allow": model_allow,
                                                    "is_active": is_active}.items() if v is not None})

    def unlock_user(self, user_id: int, actor: str) -> None:
        self.db.run("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (user_id,))
        self.audit.record("user.unlock", actor=actor, resource=f"user:{user_id}")

    def _admin_count(self) -> int:
        return self.db.one("SELECT COUNT(*) n FROM user_roles ur JOIN users u ON u.id = ur.user_id"
                           " WHERE ur.role = 'admin' AND u.is_active = 1")["n"]

    def change_password(self, user_id: int, current: str, new: str) -> None:
        user = self.get_user(user_id)
        if user["password_hash"] and not security.verify_password(current, user["password_hash"]):
            raise IAMError("Your current password is incorrect.")
        problems = security.password_problems(new, user["username"])
        if problems:
            raise IAMError(" ".join(problems))
        self.db.run("UPDATE users SET password_hash = ? WHERE id = ?", (security.hash_password(new), user_id))
        self.audit.record("user.password_change", actor=user["username"], actor_type="session",
                          resource=f"user:{user['username']}")

    # ------------------------------------------------------------------ authentication
    def authenticate(self, username: str, password: str, ip: str | None, user_agent: str | None) -> LoginResult:
        user = self.find_user(username)
        now = time.time()
        if user and user["locked_until"] > now:
            minutes = max(1, int((user["locked_until"] - now) // 60) + 1)
            self.audit.record("login.locked", "deny", actor=username, actor_type="anonymous", ip=ip)
            return LoginResult(False, f"Too many failed attempts. Try again in {minutes} minute"
                                      f"{'s' if minutes != 1 else ''}, or ask an administrator to unlock your account.")
        ok = security.verify_password(password, user["password_hash"] if user else None)
        if not user or not ok or not user["is_active"]:
            if user:
                failures = user["failed_logins"] + 1
                locked = now + self.settings.lockout_minutes * 60 if failures >= self.settings.lockout_threshold else 0
                self.db.run("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                            (0 if locked else failures, locked, user["id"]))
                if locked:
                    self.audit.record("account.locked", "deny", actor=username, actor_type="anonymous", ip=ip)
            self.audit.record("login.failure", "deny", actor=username, actor_type="anonymous", ip=ip)
            return LoginResult(False, GENERIC_LOGIN_ERROR)

        self.db.run("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        needs_mfa = bool(user["mfa_enabled"])
        sid = self._create_session(user["id"], ip, user_agent, mfa_pending=needs_mfa, method="password")
        if not needs_mfa:
            self._mark_login(user, ip, "password")
        return LoginResult(True, session_id=sid, needs_mfa=needs_mfa)

    def complete_mfa(self, session_id: str, code: str, ip: str | None) -> str | None:
        """Verify the TOTP code; on success return the *new* (rotated) session id."""
        row = self.db.one("SELECT * FROM sessions WHERE id = ? AND revoked = 0 AND mfa_pending = 1", (session_id,))
        if not row or row["expires_at"] < time.time():
            return None
        user = self.get_user(row["user_id"])
        step = security.verify_totp(user["mfa_secret"], code, user["mfa_last_step"])
        if step is None:
            self.audit.record("mfa.failure", "deny", actor=user["username"], actor_type="anonymous", ip=ip)
            return None
        self.db.run("UPDATE users SET mfa_last_step = ? WHERE id = ?", (step, user["id"]))
        # Rotate the session id at privilege change to defeat session fixation.
        new_sid = security.random_token()
        self.db.run("UPDATE sessions SET id = ?, mfa_pending = 0, auth_method = 'password+totp' WHERE id = ?",
                    (new_sid, session_id))
        self._mark_login(user, ip, "password+totp")
        return new_sid

    def login_after_signup(self, user_id: int, ip: str | None, user_agent: str | None) -> str:
        """The person just proved both their password and their e-mail; sign them in."""
        sid = self._create_session(user_id, ip, user_agent, mfa_pending=False, method="signup")
        self._mark_login(self.get_user(user_id), ip, "signup")
        return sid

    def _mark_login(self, user: dict, ip: str | None, method: str) -> None:
        self.db.run("UPDATE users SET last_login_at = ? WHERE id = ?", (time.time(), user["id"]))
        self.audit.record("login.success", "allow", actor=user["username"], actor_type="session",
                          ip=ip, detail={"method": method})

    # ------------------------------------------------------------------ sessions
    def _create_session(self, user_id: int, ip: str | None, ua: str | None, *, mfa_pending: bool, method: str) -> str:
        sid = security.random_token()
        now = time.time()
        ttl = 5 * 60 if mfa_pending else self.settings.session_minutes * 60
        self.db.run("INSERT INTO sessions (id, user_id, created_at, expires_at, mfa_pending, csrf, ip, user_agent, auth_method)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (sid, user_id, now, now + ttl, int(mfa_pending), security.random_token(16), ip, (ua or "")[:200], method))
        return sid

    def session_principal(self, session_id: str | None, allow_pending: bool = False) -> Principal | None:
        if not session_id:
            return None
        row = self.db.one("SELECT * FROM sessions WHERE id = ? AND revoked = 0", (session_id,))
        if not row or row["expires_at"] < time.time():
            return None
        if row["mfa_pending"] and not allow_pending:
            return None
        user = self.get_user(row["user_id"])
        if not user or not user["is_active"]:
            return None
        return Principal(user["id"], user["username"], user["display_name"], user["roles"],
                         _split(user["model_allow"]), kind="session", session_id=session_id, csrf=row["csrf"])

    def session_row(self, session_id: str) -> dict | None:
        row = self.db.one("SELECT * FROM sessions WHERE id = ?", (session_id,))
        return dict(row) if row else None

    def logout(self, session_id: str, actor: str | None) -> None:
        self.db.run("UPDATE sessions SET revoked = 1 WHERE id = ?", (session_id,))
        self.audit.record("logout", actor=actor, actor_type="session", resource=f"session:{session_id[:6]}")

    # ------------------------------------------------------------------ MFA enrolment
    def begin_mfa_enrolment(self, user_id: int) -> str:
        secret = security.new_totp_secret()
        self.db.run("UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?", (secret, user_id))
        return secret

    def confirm_mfa_enrolment(self, user_id: int, code: str) -> bool:
        user = self.get_user(user_id)
        if not user["mfa_secret"]:
            return False
        step = security.verify_totp(user["mfa_secret"], code, user["mfa_last_step"])
        if step is None:
            return False
        self.db.run("UPDATE users SET mfa_enabled = 1, mfa_last_step = ? WHERE id = ?", (step, user_id))
        self.audit.record("mfa.enabled", actor=user["username"], actor_type="session", resource=f"user:{user['username']}")
        return True

    def disable_mfa(self, user_id: int, actor: str) -> None:
        self.db.run("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?", (user_id,))
        self.audit.record("mfa.disabled", actor=actor, resource=f"user:{user_id}")

    # ------------------------------------------------------------------ bootstrap
    def bootstrap(self) -> None:
        if self.db.one("SELECT COUNT(*) n FROM users")["n"]:
            return
        self.create_user("admin", "Gateway Administrator", self.settings.bootstrap_admin_password, ["admin"])
        if self.settings.seed_demo_users:
            self.create_user("ayse.op", "Ayşe Operator", "Operator!2026", ["operator"])
            self.create_user("deniz.dev", "Deniz Developer", "Developer!2026", ["developer"],
                             model_allow="llama3.2*, qwen3*, nomic-embed-text*")
            self.create_user("mert.view", "Mert Viewer", "Viewer!2026x", ["viewer"])


def _split(csv: str) -> list[str]:
    return [p.strip() for p in (csv or "").split(",") if p.strip()]
