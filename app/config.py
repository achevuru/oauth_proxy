"""Configuration handling for the OAuth proxy service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass
class Settings:
    """Runtime settings loaded from the environment."""

    tenant_id: str
    client_id: str
    redirect_uri: str
    session_secret: str
    federated_token_file: str
    session_idle_timeout_seconds: int = 30 * 60
    session_absolute_timeout_seconds: int = 8 * 60 * 60
    session_cookie_name: str = "proxy_session"
    cookie_secure: bool = True
    cookie_samesite: str = "lax"
    oidc_scopes: list[str] = field(
        default_factory=lambda: ["openid", "profile", "offline_access"]
    )
    aks_scope: str = "6dae42f8-4368-4678-94ff-3960e28e3630/.default"

    @property
    def authority(self) -> str:
        """Microsoft Entra authority URL for the configured tenant."""

        return f"https://login.microsoftonline.com/{self.tenant_id}"


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable '{name}' must be set")
    return value


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    return value if value else None


@lru_cache
def get_settings() -> Settings:
    """Load settings from environment variables (cached)."""

    tenant_id = _required_env("TENANT_ID")
    client_id = _required_env("CLIENT_ID")
    redirect_uri = _required_env("REDIRECT_URI")
    session_secret = _required_env("SESSION_SECRET")
    federated_token_file = _required_env("AZURE_FEDERATED_TOKEN_FILE")

    idle_timeout = _parse_int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS"), 30 * 60)
    absolute_timeout = _parse_int(
        os.getenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS"), 8 * 60 * 60
    )

    cookie_secure = _parse_bool(os.getenv("SESSION_COOKIE_SECURE"), True)
    cookie_samesite = _optional_env("SESSION_COOKIE_SAMESITE") or "lax"

    return Settings(
        tenant_id=tenant_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        session_secret=session_secret,
        federated_token_file=federated_token_file,
        session_idle_timeout_seconds=idle_timeout,
        session_absolute_timeout_seconds=absolute_timeout,
        session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "proxy_session"),
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite,
    )

