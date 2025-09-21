"""Miscellaneous helpers for the OAuth proxy."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict


def decode_jwt_without_verification(token: str) -> Dict[str, Any]:
    """Decode the payload of a JWT without validating the signature."""

    try:
        _, payload, _ = token.split(".")
    except ValueError as exc:  # pragma: no cover - malformed token
        raise ValueError("Token is not a valid JWT") from exc

    padded_payload = payload + "=" * (-len(payload) % 4)
    decoded_bytes = base64.urlsafe_b64decode(padded_payload.encode("ascii"))
    return json.loads(decoded_bytes.decode("utf-8"))

