"""Helpers for generating PKCE code verifier and challenge pairs."""

from __future__ import annotations

import base64
import hashlib
import secrets


def create_pkce_pair() -> tuple[str, str]:
    """Return a ``(verifier, challenge)`` tuple suitable for PKCE."""

    verifier_bytes = secrets.token_bytes(64)
    verifier = base64.urlsafe_b64encode(verifier_bytes).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge

