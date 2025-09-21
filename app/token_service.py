"""Token acquisition helpers for the OAuth proxy."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import msal

from .config import get_settings

logger = logging.getLogger(__name__)

TOKEN_EXPIRY_BUFFER_SECONDS = 60


class TokenAcquisitionError(Exception):
    """Raised when an access token cannot be retrieved silently."""


def needs_refresh(token_entry: Optional[Dict[str, Any]]) -> bool:
    if not token_entry:
        return True
    try:
        expires_on = int(token_entry.get("expires_on", 0))
    except (TypeError, ValueError):
        return True
    return expires_on - TOKEN_EXPIRY_BUFFER_SECONDS <= int(time.time())


def build_token_entry(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "access_token": result["access_token"],
        "expires_on": int(result["expires_on"]),
        "scope": result.get("scope"),
        "token_type": result.get("token_type", "Bearer"),
        "acquired_at": int(time.time()),
    }


def acquire_aks_token(
    app: msal.ConfidentialClientApplication, account: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Try to fetch the AKS user token silently.

    Returns a tuple of ``(token_entry, interaction_error)`` where ``token_entry`` is
    ``None`` when no access token could be retrieved silently. ``interaction_error`` is
    populated with the MSAL error code requiring user interaction.
    """

    settings = get_settings()
    result = app.acquire_token_silent([settings.aks_scope], account=account)
    if not result:
        return None, "interaction_required"

    error = result.get("error")
    if error:
        logger.info("Silent token request failed: %s", error)
        return None, error

    if "access_token" not in result:
        logger.warning("Silent token acquisition returned no access token")
        return None, "unknown_error"

    return build_token_entry(result), None

