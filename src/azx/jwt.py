"""Unsigned JWT claim decoding for access tokens."""

from __future__ import annotations

import base64
import json
from typing import Any

from .errors import TokenError


def strip_bearer(value: str) -> str:
    text = value.strip()
    if text.lower().startswith("bearer "):
        return text[7:].strip()
    return text


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode the payload of a JWT without verifying its signature.

    AZX stores tokens for authorized engagements and never relies on these
    claims for authorization decisions. Signature validation is therefore
    intentionally out of scope.
    """
    text = strip_bearer(token)
    parts = text.split(".")
    if len(parts) != 3:
        raise TokenError(
            "Access token is not a JWT. Opaque access tokens are not supported "
            "because AZX cannot derive the principal, audience, and permissions."
        )
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenError("Access token JWT payload could not be decoded.") from exc
    if not isinstance(claims, dict):
        raise TokenError("Access token JWT payload is not a JSON object.")
    return claims
