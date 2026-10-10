"""Self sign-up with e-mail confirmation codes.

Flow: the visitor submits e-mail, name and password -> a pending sign-up is
stored and a 6-digit code is e-mailed -> the visitor enters the code -> the
account is created and they are signed in. Anyone may sign up; the e-mail
domain decides the starting role (developer domains vs. everyone else).
"""
from __future__ import annotations

import re
import secrets
import time

from . import security
from .audit import AuditLog
from .config import Settings
from .db import Database
from .iam import IAMError, IAMService
from .mailer import MailError, Mailer, code_email

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
MAX_ATTEMPTS = 5          # wrong codes before the pending sign-up is discarded
RESEND_COOLDOWN = 60      # seconds between e-mails
MAX_SENDS = 5             # e-mails per pending sign-up


def _code_hash(signup_id: str, code: str) -> str:
    return security.sha256_hex(f"{signup_id}:{code}")


class SignupService:
    def __init__(self, db: Database, iam: IAMService, audit: AuditLog, mailer: Mailer, settings: Settings) -> None:
        self.db, self.iam, self.audit, self.mailer, self.settings = db, iam, audit, mailer, settings

    # ------------------------------------------------------------------ policy
    def role_for(self, email: str) -> str:
        domain = email.rsplit("@", 1)[-1].lower()
        for d in self.settings.developer_domains:
            if domain == d or domain.endswith("." + d):
                return "developer"
        return "viewer"

    # ------------------------------------------------------------------ steps
    def start(self, email: str, display_name: str, password: str, ip: str | None) -> str:
        """Validate, store a pending sign-up, e-mail a code. Returns the pending sign-up id."""
        email = email.strip().lower()
        display_name = display_name.strip()
        if not EMAIL_RE.match(email):
            raise IAMError("Enter a valid e-mail address, like name@bilkent.edu.tr.")
        if not display_name:
            raise IAMError("Enter your name as you'd like other people to see it.")
        if self.iam.find_user(email):
            raise IAMError("An account with this e-mail already exists. Sign in instead.")
        problems = security.password_problems(password, email.split("@")[0])
        if problems:
            raise IAMError(" ".join(problems))

        self.db.run("DELETE FROM signups WHERE email = ?", (email,))   # a new attempt replaces an old one
        signup_id = security.random_token()
        code = f"{secrets.randbelow(10**6):06d}"
        now = time.time()
        role = self.role_for(email)
        self.db.run(
            "INSERT INTO signups (id, email, display_name, password_hash, role, code_hash, last_sent_at, expires_at, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (signup_id, email, display_name, security.hash_password(password), role, _code_hash(signup_id, code),
             now, now + self.settings.signup_code_minutes * 60, now))
        try:
            self._send(email, code)
        except MailError:
            self.db.run("DELETE FROM signups WHERE id = ?", (signup_id,))
            self.audit.record("signup.mail_failed", "deny", actor=email, actor_type="anonymous", ip=ip)
            raise IAMError("We couldn't send the confirmation e-mail. Check the address, or try again in a minute.")
        self.audit.record("signup.code_sent", actor=email, actor_type="anonymous", ip=ip, detail={"role": role})
        return signup_id

    def pending(self, signup_id: str | None) -> dict | None:
        if not signup_id:
            return None
        row = self.db.one("SELECT * FROM signups WHERE id = ?", (signup_id,))
        if not row or row["expires_at"] < time.time():
            return None
        return dict(row)

    def resend(self, signup_id: str, ip: str | None) -> None:
        row = self.pending(signup_id)
        if not row:
            raise IAMError("This sign-up expired. Start again.")
        wait = int(row["last_sent_at"] + RESEND_COOLDOWN - time.time())
        if wait > 0:
            raise IAMError(f"Wait {wait} seconds before asking for another code.")
        if row["sends"] >= MAX_SENDS:
            raise IAMError("Too many codes requested. Start the sign-up again later.")
        code = f"{secrets.randbelow(10**6):06d}"
        now = time.time()
        self.db.run("UPDATE signups SET code_hash = ?, attempts = 0, sends = sends + 1, last_sent_at = ?, expires_at = ?"
                    " WHERE id = ?", (_code_hash(signup_id, code), now,
                                       now + self.settings.signup_code_minutes * 60, signup_id))
        try:
            self._send(row["email"], code)
        except MailError:
            raise IAMError("We couldn't send the e-mail. Try again in a minute.")
        self.audit.record("signup.code_resent", actor=row["email"], actor_type="anonymous", ip=ip)

    def confirm(self, signup_id: str, code: str, ip: str | None) -> int:
        """Check the code; on success create the account and return its user id."""
        row = self.pending(signup_id)
        if not row:
            raise IAMError("This sign-up expired. Start again.")
        code = "".join(ch for ch in code if ch.isdigit())
        if not security.constant_eq(_code_hash(signup_id, code), row["code_hash"]):
            attempts = row["attempts"] + 1
            self.audit.record("signup.code_wrong", "deny", actor=row["email"], actor_type="anonymous", ip=ip)
            if attempts >= MAX_ATTEMPTS:
                self.db.run("DELETE FROM signups WHERE id = ?", (signup_id,))
                raise IAMError("Too many wrong codes. Start the sign-up again.")
            self.db.run("UPDATE signups SET attempts = ? WHERE id = ?", (attempts, signup_id))
            left = MAX_ATTEMPTS - attempts
            raise IAMError(f"That code doesn't match. {left} attempt{'s' if left != 1 else ''} left.")
        uid = self.iam._insert_user(row["email"], row["display_name"], row["email"], row["password_hash"],
                                    [row["role"]], "*", "signup", actor=row["email"])
        self.db.run("DELETE FROM signups WHERE id = ?", (signup_id,))
        self.audit.record("signup.confirmed", "allow", actor=row["email"], actor_type="anonymous", ip=ip,
                          detail={"role": row["role"]})
        return uid

    def _send(self, email: str, code: str) -> None:
        subject, text, html = code_email(code, self.settings.signup_code_minutes)
        self.mailer.send(email, subject, text, html)
