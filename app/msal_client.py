"""Helpers for creating MSAL clients and handling token caches."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import msal

from .config import get_settings

logger = logging.getLogger(__name__)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def build_cache_from_session(session: Dict[str, Any]) -> msal.SerializableTokenCache:
    """Create a SerializableTokenCache initialised from the session blob."""

    cache = msal.SerializableTokenCache()
    cache_blob = session.get("token_cache")
    if cache_blob:
        try:
            cache.deserialize(cache_blob)
        except ValueError:
            logger.warning("Failed to deserialize MSAL cache; starting fresh")
    return cache


def persist_cache_to_session(cache: msal.SerializableTokenCache, session: Dict[str, Any]) -> None:
    """Persist the cache back into the session when it has changed."""

    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def build_confidential_client(
    cache: Optional[msal.SerializableTokenCache] = None,
) -> msal.ConfidentialClientApplication:
    """Construct a ConfidentialClientApplication using workload identity."""

    settings = get_settings()
    client_assertion = _load_client_assertion(settings.federated_token_file)
    client_credential = {
        "client_assertion": client_assertion,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
    }

    return msal.ConfidentialClientApplication(
        client_id=settings.client_id,
        authority=settings.authority,
        client_credential=client_credential,
        token_cache=cache,
    )


def get_account_for_session(
    app: msal.ConfidentialClientApplication, session: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Return the cached account corresponding to the current session."""

    user_info = session.get("user")
    if not user_info:
        return None

    home_account_id = user_info.get("home_account_id")
    if not home_account_id:
        return None

    accounts = app.get_accounts(home_account_id=home_account_id)
    if accounts:
        return accounts[0]
    return None


def _load_client_assertion(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError as exc:  # pragma: no cover - configuration error
        raise RuntimeError(
            "AZURE_FEDERATED_TOKEN_FILE is not accessible at the configured path"
        ) from exc

