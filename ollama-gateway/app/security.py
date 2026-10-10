"""Cryptographic primitives used by the IAM module.

Only the Python standard library is used here, so every algorithm is visible
and testable: scrypt for passwords, RFC 6238 TOTP for the second factor, and
SHA-256 digests for confirmation codes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

# --------------------------------------------------------------------------- passwords
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        # Still burn CPU so that "unknown user" and "wrong password" take the same time.
        hashlib.scrypt(password.encode(), salt=b"0" * 16, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        return False
    try:
        _, n, r, p, salt_b64, digest_b64 = stored.split("$")
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def password_problems(password: str, username: str = "") -> list[str]:
    """Return human-readable reasons a password is rejected (empty list = OK)."""
    problems = []
    if len(password) < 10:
        problems.append("Use at least 10 characters.")
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if classes < 3:
        problems.append("Mix at least three of: lowercase, uppercase, digits, symbols.")
    if username and len(username) >= 3 and username.lower() in password.lower():
        problems.append("Don't include your username in the password.")
    return problems


# --------------------------------------------------------------------------- TOTP (RFC 6238)
TOTP_PERIOD = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // TOTP_PERIOD))


def verify_totp(secret_b32: str, code: str, last_step: int = 0, at: float | None = None,
                window: int = 1) -> int | None:
    """Return the matched time step, or None.

    A step is only accepted if it is newer than ``last_step`` so that a code
    observed by an attacker cannot be replayed within its 30-second life.
    """
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now_step = int((at or time.time()) // TOTP_PERIOD)
    for step in range(now_step - window, now_step + window + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


def totp_uri(secret_b32: str, account: str, issuer: str = "Ollama Gateway") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&period={TOTP_PERIOD}&digits={TOTP_DIGITS}")


# --------------------------------------------------------------------------- tokens
def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
