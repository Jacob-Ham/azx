"""Token claim interpretation and record construction."""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from .aliases import (
    client_short_name,
    is_arm_audience,
    is_graph_audience,
)
from .errors import TokenError, UsageError
from .jwt import decode_jwt, strip_bearer
from .util import (
    audience_slug,
    expiry_from_epoch,
    format_expiry,
    is_guid,
    parse_expiry,
    short_id,
    slugify,
    utc_now_iso,
)


def detect_token_type(claims: Mapping[str, Any]) -> str:
    idtyp = claims.get("idtyp")
    if isinstance(idtyp, str):
        if idtyp.lower() == "app":
            return "app"
        if idtyp.lower() == "user":
            return "user"

    has_scp = bool(claims.get("scp"))
    has_upn = bool(claims.get("upn") or claims.get("preferred_username"))
    if has_scp or has_upn:
        return "user"
    if claims.get("roles"):
        return "app"
    return "user"


def token_audience(claims: Mapping[str, Any]) -> str | None:
    audience = claims.get("aud")
    if isinstance(audience, list):
        audience = next((item for item in audience if item), None)
    if isinstance(audience, str) and audience.strip():
        return audience.strip()
    return None


def token_client(claims: Mapping[str, Any]) -> str | None:
    value = claims.get("appid") or claims.get("azp")
    return str(value) if value else None


def token_principal(claims: Mapping[str, Any]) -> str | None:
    value = claims.get("oid") or claims.get("sub")
    return str(value) if value else None


def token_tenant(claims: Mapping[str, Any]) -> str | None:
    value = claims.get("tid")
    return str(value) if value else None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item for item in value.split() if item]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def token_scopes(claims: Mapping[str, Any]) -> list[str]:
    return _as_list(claims.get("scp"))


def token_roles(claims: Mapping[str, Any]) -> list[str]:
    return _as_list(claims.get("roles"))


def token_cloud(claims: Mapping[str, Any]) -> str | None:
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        return None
    host = (urlparse(issuer).hostname or "").lower()
    if host in {"login.microsoftonline.com", "sts.windows.net"}:
        return "public"
    if host.endswith(".microsoftonline.us"):
        return "usgovernment"
    if host.endswith(".chinacloudapi.cn"):
        return "china"
    return "unknown"


def default_token_name(claims: Mapping[str, Any], token_type: str) -> str:
    audience = token_audience(claims)
    target = audience_slug(audience)
    if token_type == "app":
        app_id = token_client(claims)
        if not app_id:
            raise UsageError(
                "Cannot generate an app token name without an app ID; pass -n."
            )
        client_name = client_short_name(app_id)
        client_slug = slugify(client_name) if client_name else None
        parts = ["app", short_id(app_id)]
        if client_slug and client_slug != target:
            parts.append(client_slug)
        parts.append(target)
        return "-".join(parts)

    upn = claims.get("upn") or claims.get("preferred_username")
    if not upn:
        raise UsageError("Cannot generate a token name without a UPN; pass -n.")
    local_part = str(upn).split("@", 1)[0]
    client_id = token_client(claims)
    client_name = client_short_name(client_id)
    if client_name:
        client_slug = slugify(client_name)
    else:
        # Unknown clients need disambiguation so two Graph tokens do not collide.
        client_slug = short_id(client_id, 4).lower() if client_id else None
    parts = [slugify(local_part, fallback="user")]
    if client_slug and client_slug != target:
        parts.append(client_slug)
    parts.append(target)
    return "-".join(parts)


def _record_type(record: Mapping[str, Any], hint: str | None) -> str:
    value = record.get("_type")
    if value in {"user", "app"}:
        return value
    if hint in {"user", "app"}:
        return hint
    return "user"


def build_record(
    *,
    base: Mapping[str, Any] | None = None,
    access_token: str | None = None,
    refresh_token: str | None = None,
    id_token: str | None = None,
    client: str | None = None,
    tenant: str | None = None,
    source: str,
    name: str,
    type_hint: str | None = None,
) -> dict[str, Any]:
    """Build a roadtools-compatible token record with AZX metadata."""
    record: dict[str, Any] = dict(base or {})

    if access_token is not None:
        cleaned_access = strip_bearer(access_token)
        if cleaned_access:
            record["accessToken"] = cleaned_access
        else:
            record.pop("accessToken", None)
    else:
        existing_access = record.get("accessToken")
        if isinstance(existing_access, str):
            cleaned_access = strip_bearer(existing_access)
            if cleaned_access:
                record["accessToken"] = cleaned_access
            else:
                record.pop("accessToken", None)
        else:
            record.pop("accessToken", None)

    if refresh_token is not None:
        cleaned_refresh = refresh_token.strip()
        if cleaned_refresh:
            record["refreshToken"] = cleaned_refresh
        else:
            record.pop("refreshToken", None)
    else:
        existing_refresh = record.get("refreshToken")
        if isinstance(existing_refresh, str):
            cleaned_refresh = existing_refresh.strip()
            if cleaned_refresh:
                record["refreshToken"] = cleaned_refresh
            else:
                record.pop("refreshToken", None)
        else:
            record.pop("refreshToken", None)

    if id_token is not None:
        cleaned_id = id_token.strip()
        if cleaned_id:
            record["idToken"] = cleaned_id
        else:
            record.pop("idToken", None)
    else:
        existing_id = record.get("idToken")
        if isinstance(existing_id, str):
            cleaned_id = existing_id.strip()
            if cleaned_id:
                record["idToken"] = cleaned_id
            else:
                record.pop("idToken", None)
        else:
            record.pop("idToken", None)

    access = record.get("accessToken")
    claims: dict[str, Any] = {}
    if isinstance(access, str) and access.strip():
        claims = decode_jwt(access)
        record["accessToken"] = access

    token_type = (
        detect_token_type(claims) if claims else _record_type(record, type_hint)
    )

    if claims:
        if not record.get("tokenType"):
            record["tokenType"] = "Bearer"
        expires_at = expiry_from_epoch(claims.get("exp"))
        if not record.get("expiresOn") and expires_at is not None:
            record["expiresOn"] = format_expiry(expires_at)
        if not record.get("expiresIn") and expires_at is not None:
            record["expiresIn"] = max(0, int(expires_at.timestamp() - time.time()))

    client_value = token_client(claims) or client or record.get("_clientId")
    tenant_value = token_tenant(claims) or tenant or record.get("tenantId")
    if client_value:
        record["_clientId"] = client_value
    if tenant_value:
        record["tenantId"] = tenant_value

    app_id = token_client(claims) or client or record.get("_appId")
    if app_id:
        record["_appId"] = app_id

    if claims:
        principal_id = token_principal(claims)
        if principal_id:
            record["_principalId"] = principal_id
        else:
            record.pop("_principalId", None)

        audience = token_audience(claims)
        if audience:
            record["_audience"] = audience
        else:
            record.pop("_audience", None)

        record["_scopes"] = token_scopes(claims)
        record["_roles"] = token_roles(claims)

        cloud = token_cloud(claims)
        if cloud:
            record["_cloud"] = cloud

        if token_type == "app":
            service_principal_id = token_principal(claims)
            if service_principal_id:
                record["_servicePrincipalObjectId"] = service_principal_id
            else:
                record.pop("_servicePrincipalObjectId", None)
        else:
            record.pop("_servicePrincipalObjectId", None)
    else:
        if "tenantId" not in record and tenant:
            record["tenantId"] = tenant
        if app_id:
            record["_appId"] = app_id
        record.setdefault("_scopes", [])
        record.setdefault("_roles", [])

    record["_name"] = name
    record["_type"] = token_type
    record["_source"] = source
    record["_importedAt"] = utc_now_iso()
    return record


def _both_guids(left: str | None, right: str | None) -> bool:
    return bool(left and right and is_guid(left) and is_guid(right))


def validate_import_consistency(
    claims: Mapping[str, Any],
    *,
    client: str | None = None,
    tenant: str | None = None,
    existing: Mapping[str, Any] | None = None,
) -> None:
    """Reject conflicting client/tenant metadata when comparison is reliable."""
    existing = existing or {}
    claim_client = token_client(claims)
    existing_client = existing.get("_clientId")
    if _both_guids(client, claim_client) and client.lower() != claim_client.lower():
        raise UsageError("Client ID does not match the access token's appid/azp claim.")
    if (
        _both_guids(existing_client, claim_client)
        and str(existing_client).lower() != claim_client.lower()
    ):
        raise UsageError(
            "Imported _clientId does not match the access token's appid/azp claim."
        )
    if (
        _both_guids(client, existing_client)
        and client.lower() != str(existing_client).lower()
    ):
        raise UsageError("Client ID does not match the token file's _clientId.")

    claim_tenant = token_tenant(claims)
    existing_tenant = existing.get("tenantId")
    if _both_guids(tenant, claim_tenant) and tenant.lower() != claim_tenant.lower():
        raise UsageError("Tenant does not match the access token's tid claim.")
    if (
        _both_guids(existing_tenant, claim_tenant)
        and str(existing_tenant).lower() != claim_tenant.lower()
    ):
        raise UsageError(
            "Imported tenantId does not match the access token's tid claim."
        )
    if (
        _both_guids(tenant, existing_tenant)
        and tenant.lower() != str(existing_tenant).lower()
    ):
        raise UsageError("Tenant does not match the token file's tenantId.")


def audience_matches(audience: str | None, kind: str) -> bool:
    if kind == "graph":
        return is_graph_audience(audience)
    if kind == "arm":
        return is_arm_audience(audience)
    return False


def record_expiry(record: Mapping[str, Any]) -> datetime | None:
    parsed = parse_expiry(record.get("expiresOn"))
    if parsed is not None:
        return parsed
    access = record.get("accessToken")
    if isinstance(access, str) and access.strip():
        try:
            claims = decode_jwt(access)
        except TokenError:
            return None
        return expiry_from_epoch(claims.get("exp"))
    return None
