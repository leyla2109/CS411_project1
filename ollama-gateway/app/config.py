"""Runtime configuration, read once from environment variables.

Every setting has a safe default so the gateway runs with zero configuration
for the demo, while production deployments override them through the
environment (12-factor style, the same way Ollama itself is configured
through OLLAMA_* variables).
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_list(name: str, default: str) -> list[str]:
    return [p.strip().lower().lstrip("@") for p in os.environ.get(name, default).split(",") if p.strip()]


def _load_or_create_secret(path: Path) -> str:
    """Keep the session-signing secret stable across restarts."""
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(48)
    path.write_text(value)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("GATEWAY_DATA_DIR", "./data")))
    ollama_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    public_url: str = field(default_factory=lambda: os.environ.get("GATEWAY_PUBLIC_URL", "http://127.0.0.1:8000"))
    session_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_SESSION_MINUTES", 480))
    lockout_threshold: int = field(default_factory=lambda: _env_int("GATEWAY_LOCKOUT_THRESHOLD", 5))
    lockout_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_LOCKOUT_MINUTES", 15))
    secure_cookies: bool = field(default_factory=lambda: os.environ.get("GATEWAY_SECURE_COOKIES", "0") == "1")
    # Self sign-up. Anyone may register; addresses in these domains (or their
    # subdomains) start as Developers, everyone else as Viewers.
    developer_domains: list[str] = field(default_factory=lambda: _env_list("GATEWAY_DEVELOPER_DOMAINS", "bilkent.edu.tr"))
    signup_code_minutes: int = field(default_factory=lambda: _env_int("GATEWAY_SIGNUP_CODE_MINUTES", 10))
    # Outgoing e-mail for confirmation codes (any SMTP server: Gmail, Outlook, university relay...).
    smtp_host: str = field(default_factory=lambda: os.environ.get("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.environ.get("SMTP_FROM", "") or os.environ.get("SMTP_USER", ""))
    smtp_security: str = field(default_factory=lambda: os.environ.get("SMTP_SECURITY", "starttls"))  # starttls | ssl | none
    bootstrap_admin_password: str = field(default_factory=lambda: os.environ.get("GATEWAY_ADMIN_PASSWORD", "ChangeMe!2026"))
    seed_demo_users: bool = field(default_factory=lambda: os.environ.get("GATEWAY_SEED_DEMO", "1") == "1")
    secret_key: str = ""

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.secret_key:
            self.secret_key = os.environ.get("GATEWAY_SECRET_KEY") or _load_or_create_secret(
                self.data_dir / "secret.key"
            )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "iam.sqlite3"

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)
