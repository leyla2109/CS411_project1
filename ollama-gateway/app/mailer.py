"""Outgoing e-mail for sign-up confirmation codes.

`Mailer` is the interface the IAM service depends on; `SMTPMailer` sends
through any SMTP server. Tests pass in a fake that records messages instead.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

from .config import Settings


class MailError(Exception):
    """The message could not be handed to the mail server."""


class Mailer(Protocol):
    def send(self, to: str, subject: str, text: str, html: str | None = None) -> None: ...


class SMTPMailer:
    def __init__(self, settings: Settings) -> None:
        self.s = settings

    def send(self, to: str, subject: str, text: str, html: str | None = None) -> None:
        msg = EmailMessage()
        msg["From"] = f"Ollama Gateway <{self.s.smtp_from}>"
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        try:
            if self.s.smtp_security == "ssl":
                server = smtplib.SMTP_SSL(self.s.smtp_host, self.s.smtp_port, timeout=15,
                                          context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=15)
            with server:
                if self.s.smtp_security == "starttls":
                    server.starttls(context=ssl.create_default_context())
                if self.s.smtp_user:
                    server.login(self.s.smtp_user, self.s.smtp_password)
                server.send_message(msg)
        except (OSError, smtplib.SMTPException) as exc:
            raise MailError(str(exc)) from exc


def code_email(code: str, minutes: int) -> tuple[str, str, str]:
    """Return (subject, text, html) for a confirmation code e-mail."""
    subject = f"{code} is your Ollama Gateway code"
    text = (f"Your confirmation code is {code}\n\n"
            f"Enter it on the sign-up page to finish creating your account. "
            f"It expires in {minutes} minutes.\n\n"
            f"If you didn't try to sign up, ignore this e-mail; no account is created without the code.")
    html = (f'<div style="font:15px/1.5 system-ui,sans-serif;color:#15191e">'
            f'<p>Your Ollama Gateway confirmation code is</p>'
            f'<p style="font:600 28px/1 monospace;letter-spacing:6px;margin:18px 0">{code}</p>'
            f'<p>Enter it on the sign-up page to finish creating your account. It expires in {minutes} minutes.</p>'
            f'<p style="color:#59616a">If you didn\'t try to sign up, ignore this e-mail; '
            f'no account is created without the code.</p></div>')
    return subject, text, html
