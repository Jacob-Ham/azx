"""Client-credentials application authentication."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from ..aliases import resolve_client, resolve_resource
from ..context import Context
from ..errors import ApiError, AuthError, UsageError
from ..jwt import decode_jwt
from ..model import TokenRecord
from ..tokenmeta import build_record, default_token_name
from ..util import format_expiry, validate_token_name

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def _expires_in_seconds(value: Any) -> int | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def handle_auth_app(ctx: Context, args: Any) -> None:
    client = resolve_client(args.client)
    resource, scope = resolve_resource(args.resource)
    tenant = (args.tenant or "").strip()
    if not tenant:
        raise UsageError("Tenant is required.")
    if args.name:
        validate_token_name(args.name)
        if ctx.store.exists(args.name) and not args.force:
            raise UsageError(
                f"Token '{args.name}' already exists. Use --force to overwrite it."
            )

    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Action", "Client-credentials app authentication")
        ctx.console.kv("Tenant", tenant)
        ctx.console.kv("Client", client)
        ctx.console.kv("Resource", resource)
        ctx.console.kv("Scope", scope)
        ctx.console.kv("Name", args.name or "generated from token claims")
        ctx.console.heading("Payload:")
        ctx.console.data(
            {
                "grant_type": "client_credentials",
                "client_id": client,
                "client_secret": "<redacted>",
                "scope": scope,
            }
        )
        ctx.console.kv(
            "Expected change",
            "Acquire an app-only access token and save it as a token file.",
        )
        ctx.console.kv(
            "Required permissions",
            "A confidential client with a valid app secret.",
        )
        return

    form = {
        "client_id": client,
        "client_secret": args.password,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    url = TOKEN_URL.format(tenant=quote(tenant, safe=""))
    try:
        response = ctx.http.request("POST", url, data=form, idempotent=True)
    except ApiError as exc:
        raise AuthError(f"Authentication failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError(
            "Authentication failed: the token endpoint returned invalid JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise AuthError(
            "Authentication failed: the token endpoint returned an unexpected response."
        )

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AuthError("Authentication failed: no access token was returned.")
    claims = decode_jwt(access_token)
    token_client = claims.get("appid") or claims.get("azp")
    if token_client and str(token_client).lower() != client.lower():
        raise AuthError(
            "Authentication failed: the returned token's appid/azp claim "
            "does not match the requested client."
        )
    if args.name:
        name = args.name
    else:
        name = default_token_name(claims, "app")
        validate_token_name(name)
    if ctx.store.exists(name) and not args.force:
        raise UsageError(f"Token '{name}' already exists. Use --force to overwrite it.")

    record = build_record(
        access_token=access_token,
        refresh_token=payload.get("refresh_token"),
        id_token=payload.get("id_token"),
        client=client,
        tenant=tenant,
        source="app-auth",
        name=name,
        type_hint="app",
    )
    record["_type"] = "app"
    record["_source"] = "app-auth"
    if claims.get("oid"):
        record["_principalId"] = str(claims["oid"])
        record["_servicePrincipalObjectId"] = str(claims["oid"])
    token_type = payload.get("token_type")
    if isinstance(token_type, str) and token_type:
        record["tokenType"] = token_type
    seconds = _expires_in_seconds(payload.get("expires_in"))
    if not record.get("expiresOn") and seconds is not None:
        expires_at = datetime.now() + timedelta(seconds=seconds)
        record["expiresOn"] = format_expiry(expires_at)
        record["expiresIn"] = seconds

    path = ctx.store.save(record, name, force=args.force)
    ctx.store.set_active(name)
    updated = TokenRecord(raw=record, name=name, path=path)
    ctx.console.line(f"Authenticated: {name}", style="bold green")
    display = str(updated.claims.get("app_displayname") or "").strip()
    client_id = updated.client_id or client
    client_value = (
        f"{display} ({client_id})" if display and display != client_id else client_id
    )
    ctx.console.kv("Client", client_value)
    ctx.console.kv(
        "Service principal object ID",
        updated.service_principal_id or "-",
    )
    ctx.console.kv("Audience", updated.audience_text)
    ctx.console.kv("Expires", updated.expires_display)
    ctx.console.kv("File", updated.path or "-")
