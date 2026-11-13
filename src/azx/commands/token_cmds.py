"""token subcommands."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..aliases import resolve_client
from ..context import Context
from ..errors import ApiError, AuthError, TokenError, UsageError
from ..jwt import decode_jwt
from ..model import TokenRecord
from ..render import render_value
from ..tokenmeta import (
    build_record,
    default_token_name,
    detect_token_type,
    token_cloud,
    validate_import_consistency,
)
from ..util import (
    deep_redact,
    format_expiry,
    format_list,
    is_sensitive_key,
    validate_token_name,
)

_LOGIN_BASES = {
    "public": "https://login.microsoftonline.com",
    "usgovernment": "https://login.microsoftonline.us",
    "china": "https://login.chinacloudapi.cn",
}
_KNOWN_RESOURCES = {
    "00000003-0000-0000-c000-000000000000": "https://graph.microsoft.com",
    "00000002-0000-0000-c000-000000000000": "https://graph.windows.net",
}

_DISPLAYED_FIELDS = {
    "accessToken",
    "refreshToken",
    "idToken",
    "tokenType",
    "expiresOn",
    "expiresIn",
    "tenantId",
    "_clientId",
    "_name",
    "_type",
    "_source",
    "_importedAt",
    "_principalId",
    "_appId",
    "_servicePrincipalObjectId",
    "_applicationObjectId",
    "_audience",
    "_scopes",
    "_roles",
    "_cloud",
}


def _read_token_file(value: str) -> tuple[Path, dict[str, Any]]:
    path = Path(value).expanduser()
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        raise UsageError(
            f"Cannot read token file {path}: {exc.strerror or exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise UsageError(f"Token file {path} is not valid UTF-8 text.") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"Token file {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise UsageError(f"Token file {path} must contain a JSON object.")
    return path, raw


def _normalize_token_fields(raw: dict[str, Any], source: Path) -> dict[str, Any]:
    normalized = dict(raw)
    for field in ("accessToken", "refreshToken", "idToken"):
        if field not in normalized:
            continue
        value = normalized[field]
        if value is None:
            normalized.pop(field)
            continue
        if not isinstance(value, str):
            raise UsageError(f"Token file {source} has a non-string {field}.")
        text = value.strip()
        if text:
            normalized[field] = text
        else:
            normalized.pop(field)
    return normalized


def _provided_values(
    args: Any,
) -> tuple[str | None, str | None]:
    client = resolve_client(args.client) if args.client else None
    tenant = args.tenant.strip() if args.tenant else None
    if args.tenant is not None and not tenant:
        raise UsageError("Tenant must not be empty.")
    return client, tenant


def _print_summary(ctx: Context, record: TokenRecord, path: Path) -> None:
    ctx.console.line(f"Imported token: {record.name}")
    ctx.console.kv("Principal", record.principal_display)
    ctx.console.kv("Client", record.client_display)
    ctx.console.kv("Audience", record.audience_text)
    if record.refresh_only:
        ctx.console.kv("Access token", "none (refresh token only)")
    elif not record.has_access_token:
        ctx.console.kv("Access token", "none")
    ctx.console.kv("File", path)


def _name_for_file(
    raw: dict[str, Any],
    claims: dict[str, Any],
    token_type: str,
    explicit_name: str | None,
) -> str:
    if explicit_name:
        validate_token_name(explicit_name)
        return explicit_name
    if claims:
        name = default_token_name(claims, token_type)
        validate_token_name(name)
        return name
    existing = raw.get("_name")
    if isinstance(existing, str):
        try:
            validate_token_name(existing)
            return existing
        except UsageError:
            pass
    raise UsageError(
        "A name is required for a token file without an access token; pass -n <name>."
    )


def handle_import(ctx: Context, args: Any) -> None:
    files = list(args.files or [])
    files.extend(args.tokenfile or [])
    has_raw = bool(args.access_token or args.refresh_token)
    if files and has_raw:
        raise UsageError("Import either token files or raw token values, not both.")
    if not files and not has_raw:
        raise UsageError(
            "No token input supplied. Pass a token file, --access-token, "
            "or --refresh-token."
        )
    if len(files) > 1 and args.name:
        raise UsageError("-n can only be used when importing one token.")

    client, tenant = _provided_values(args)
    pending: list[tuple[str, dict[str, Any]]] = []

    if files:
        for value in files:
            source, raw = _read_token_file(value)
            raw = _normalize_token_fields(raw, source)
            access = raw.get("accessToken")
            refresh = raw.get("refreshToken")
            id_token = raw.get("idToken")
            if not access and not refresh and not id_token:
                raise UsageError(
                    f"Token file {source} contains no access, refresh, or ID token."
                )
            claims: dict[str, Any] = {}
            if access:
                claims = decode_jwt(access)
                validate_import_consistency(
                    claims,
                    client=client,
                    tenant=tenant,
                    existing=raw,
                )
            elif refresh and (
                not (client or raw.get("_clientId"))
                or not (tenant or raw.get("tenantId"))
            ):
                raise UsageError(
                    "A refresh-only token requires -c <client> and "
                    "-t <tenant>, or _clientId and tenantId in the file."
                )
            if claims:
                token_type = detect_token_type(claims)
            elif raw.get("_type") in {"user", "app"}:
                token_type = str(raw["_type"])
            else:
                token_type = "user"
            name = _name_for_file(raw, claims, token_type, args.name)
            record = build_record(
                base=raw,
                client=client,
                tenant=tenant,
                source="import",
                name=name,
                type_hint=token_type,
            )
            pending.append((name, record))
    else:
        access = args.access_token.strip() if args.access_token is not None else None
        refresh = args.refresh_token.strip() if args.refresh_token is not None else None
        if args.access_token is not None and not access:
            raise UsageError("--access-token must not be empty.")
        if args.refresh_token is not None and not refresh:
            raise UsageError("--refresh-token must not be empty.")
        if refresh and not access and (not client or not tenant):
            raise UsageError(
                "A refresh-only token requires -c <client> and -t <tenant>."
            )
        claims: dict[str, Any] = {}
        if access:
            claims = decode_jwt(access)
            validate_import_consistency(claims, client=client, tenant=tenant)
        token_type = detect_token_type(claims) if claims else "user"
        if args.name:
            validate_token_name(args.name)
            name = args.name
        elif claims:
            name = default_token_name(claims, token_type)
            validate_token_name(name)
        else:
            raise UsageError(
                "A name is required for a refresh-only token; pass -n <name>."
            )
        record = build_record(
            access_token=access,
            refresh_token=refresh,
            client=client,
            tenant=tenant,
            source="import",
            name=name,
            type_hint=token_type,
        )
        pending.append((name, record))

    seen: set[str] = set()
    for name, _ in pending:
        if name in seen:
            raise UsageError(f"Multiple imported tokens would use the name '{name}'.")
        seen.add(name)
        if ctx.store.exists(name) and not args.force:
            raise UsageError(
                f"Token '{name}' already exists. Use --force to overwrite it."
            )

    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        for index, (name, raw) in enumerate(pending):
            if index:
                ctx.console.blank()
            record = TokenRecord(raw=raw, name=name, path=ctx.store.path_for(name))
            ctx.console.kv("Action", f"Import token '{name}'")
            ctx.console.kv("Principal", record.principal_display)
            ctx.console.kv("Audience", record.audience_text)
            if record.refresh_only:
                ctx.console.kv("Access token", "none (refresh token only)")
            elif not record.has_access_token:
                ctx.console.kv("Access token", "none")
            ctx.console.kv("File", record.path)
        return

    for index, (name, raw) in enumerate(pending):
        path = ctx.store.save(raw, name, force=args.force)
        if index:
            ctx.console.blank()
        _print_summary(ctx, TokenRecord(raw=raw, name=name, path=path), path)


def _refresh_version(record: TokenRecord) -> str:
    version = str(record.claims.get("ver") or "")
    if version == "2.0":
        return "v2"
    if not version:
        issuer = str(record.claims.get("iss") or "").lower()
        if "login.microsoftonline.com" in issuer:
            return "v2"
    return "v1"


def _refresh_login_base(record: TokenRecord) -> str:
    cloud = record.cloud or token_cloud(record.claims) or "public"
    return _LOGIN_BASES.get(cloud, _LOGIN_BASES["public"])


def _refresh_form(
    record: TokenRecord,
    version: str,
) -> tuple[dict[str, str], str, str]:
    client_id = record.client_id
    refresh_token = record.refresh_token
    if not client_id:
        raise TokenError(f"Token '{record.name}' has no client ID; cannot refresh it.")
    if not refresh_token:
        raise TokenError(
            f"Token '{record.name}' has no refresh token; re-import or "
            "authenticate again."
        )
    form = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    audience = record.audience
    if version == "v2":
        scopes = [scope for scope in record.scopes if not scope.startswith("_")]
        if not scopes and audience:
            resource = _KNOWN_RESOURCES.get(audience.lower(), audience)
            if "://" in resource:
                scopes = [resource.rstrip("/") + "/.default"]
        if not scopes:
            raise TokenError(
                f"Token '{record.name}' has no refresh scope; cannot refresh it."
            )
        if "offline_access" not in {scope.casefold() for scope in scopes}:
            scopes.append("offline_access")
        scope = " ".join(scopes)
        form["scope"] = scope
        return form, "Scope", scope

    if not audience:
        raise TokenError(f"Token '{record.name}' has no audience; cannot refresh it.")
    resource = _KNOWN_RESOURCES.get(audience.lower(), audience)
    form["resource"] = resource
    return form, "Resource", resource


def _refresh_expires_seconds(value: Any) -> int | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def handle_refresh(ctx: Context, args: Any) -> None:
    name = args.name or ctx.settings.token_name or ctx.store.active_name()
    if not name:
        raise TokenError("No active token. Pass a token name or use --token.")
    record = ctx.store.get(name)
    tenant = record.tenant_id
    if not tenant:
        raise TokenError(f"Token '{name}' has no tenant ID; cannot refresh it.")

    version = _refresh_version(record)
    form, parameter, value = _refresh_form(record, version)
    base = _refresh_login_base(record)
    endpoint = "oauth2/v2.0/token" if version == "v2" else "oauth2/token"
    url = f"{base}/{quote(tenant, safe='')}/{endpoint}"

    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Action", f"Refresh token '{name}'")
        ctx.console.kv("Endpoint", url)
        ctx.console.kv(parameter, value)
        display = dict(form)
        display["refresh_token"] = "<redacted>"
        ctx.console.heading("Payload:")
        ctx.console.data(display)
        ctx.console.kv(
            "Expected change",
            "A new access token is saved in the existing token record.",
        )
        ctx.console.kv(
            "Required permissions",
            "A valid refresh token for the client.",
        )
        return

    try:
        response = ctx.http.request("POST", url, data=form, idempotent=False)
    except ApiError as exc:
        raise AuthError(f"Token refresh failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError(
            "Token refresh failed: the token endpoint returned invalid JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise AuthError(
            "Token refresh failed: the token endpoint returned an unexpected response."
        )

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AuthError("Token refresh failed: no access token was returned.")
    try:
        claims = decode_jwt(access_token)
    except TokenError as exc:
        raise AuthError(f"Token refresh failed: {exc}") from exc
    validate_import_consistency(
        claims,
        client=record.client_id,
        tenant=tenant,
        existing=record.raw,
    )

    base_record = dict(record.raw)
    for field in ("expiresOn", "expiresIn", "tokenType"):
        base_record.pop(field, None)
    new_refresh = payload.get("refresh_token")
    new_id_token = payload.get("id_token")
    refreshed = build_record(
        base=base_record,
        access_token=access_token,
        refresh_token=(
            new_refresh
            if isinstance(new_refresh, str) and new_refresh.strip()
            else None
        ),
        id_token=(
            new_id_token
            if isinstance(new_id_token, str) and new_id_token.strip()
            else None
        ),
        client=record.client_id,
        tenant=tenant,
        source="refresh",
        name=name,
        type_hint=record.type,
    )
    seconds = _refresh_expires_seconds(payload.get("expires_in"))
    if not refreshed.get("expiresOn") and seconds is not None:
        expires_at = datetime.now(UTC) + timedelta(seconds=seconds)
        refreshed["expiresOn"] = format_expiry(expires_at)
        refreshed["expiresIn"] = seconds
    token_type = payload.get("token_type")
    if isinstance(token_type, str) and token_type:
        refreshed["tokenType"] = token_type

    path = ctx.store.save(refreshed, name, force=True)
    updated = TokenRecord(raw=refreshed, name=name, path=path)
    ctx.console.line(f"Refreshed token: {name}")
    ctx.console.kv("Principal", updated.principal_display)
    ctx.console.kv("Audience", updated.audience_text)
    expires = updated.expires_at
    ctx.console.kv(
        "Expires",
        expires.strftime("%Y-%m-%d %H:%M:%S") if expires else "-",
    )
    ctx.console.kv("File", path)


def handle_list(ctx: Context, args: Any) -> None:
    records = ctx.store.scan()
    if not records:
        ctx.console.line("No tokens found.")
        return
    ctx.console.table(
        [
            "NAME",
            "PRINCIPAL",
            "CLIENT",
            "AUDIENCE",
            "COLLECTED",
            "EXPIRES",
        ],
        [record.summary_row for record in records],
    )


def _claims_rows(claims: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, value in claims.items():
        if is_sensitive_key(key):
            rows.append((key, "<redacted>"))
        elif isinstance(value, list):
            rows.append((key, ", ".join(str(item) for item in value) or "-"))
        elif isinstance(value, dict):
            rows.append(
                (
                    key,
                    "; ".join(
                        f"{item_key}: {item_value}"
                        for item_key, item_value in value.items()
                    ),
                )
            )
        else:
            rows.append((key, str(value)))
    return rows


def handle_show(ctx: Context, args: Any) -> None:
    record = ctx.store.get(args.name)
    ctx.console.kv("Token", record.name)
    ctx.console.kv("Type", record.type)
    ctx.console.kv("Source", record.source or "-")
    ctx.console.kv("Token type", record.raw.get("tokenType") or "-")
    ctx.console.kv("Principal", record.principal_display)
    ctx.console.kv("Principal ID", record.principal_id or "-")
    ctx.console.kv("App ID", record.app_id or "-")
    ctx.console.kv("Service principal object ID", record.service_principal_id or "-")
    ctx.console.kv("Application object ID", record.application_object_id or "-")
    ctx.console.kv("Tenant", record.tenant_display)
    ctx.console.kv("Client", record.client_display)
    ctx.console.kv("Audience", record.audience_text)
    ctx.console.kv("Scopes", format_list(record.scopes))
    ctx.console.kv("Roles", format_list(record.roles))
    ctx.console.kv("Cloud", record.cloud or "-")
    ctx.console.kv("Refresh token", "present" if record.has_refresh_token else "none")
    ctx.console.kv(
        "ID token",
        "present" if record.raw.get("idToken") else "none",
    )
    ctx.console.kv("Imported at", record.imported_at or "-")
    ctx.console.kv("Expires in", record.raw.get("expiresIn", "-"))
    expires = record.expires_at
    if expires is None:
        ctx.console.kv("Expires", "-")
    else:
        suffix = " (expired)" if record.expired else ""
        ctx.console.kv("Expires", expires.strftime("%Y-%m-%d %H:%M:%S") + suffix)
    ctx.console.kv("File", record.path or "-")
    extra = {
        key: value
        for key, value in record.raw.items()
        if key not in _DISPLAYED_FIELDS and not is_sensitive_key(key)
    }
    if extra:
        ctx.console.blank()
        ctx.console.heading("Additional metadata:")
        for key, value in extra.items():
            ctx.console.kv(key, render_value(deep_redact(value)))
    if not record.has_access_token:
        if record.refresh_only:
            ctx.console.kv("Access token", "none (refresh token only)")
        else:
            ctx.console.kv("Access token", "none")
        return
    claims = deep_redact(record.claims)
    if not claims:
        ctx.console.kv("Claims", "none decoded")
        return
    ctx.console.blank()
    ctx.console.heading("Claims:")
    for key, value in _claims_rows(claims):
        ctx.console.kv(key, value)


def handle_select(ctx: Context, args: Any) -> None:
    selected = ctx.select_token(all_tokens=True, activate=not ctx.dry_run)
    if selected is None:
        raise TokenError("No token selected.")
    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Would activate token", selected.name)
        return
    ctx.console.token_line(selected.name)


def handle_current(ctx: Context, args: Any) -> None:
    active = ctx.store.active_name()
    if not active:
        raise TokenError("No active token.")
    ctx.console.line(active)


def handle_delete(ctx: Context, args: Any) -> None:
    record = ctx.store.get(args.name)
    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Action", "Delete token")
        ctx.console.kv("Target", record.name)
        ctx.console.kv("File", record.path or "-")
        return
    cleared = ctx.store.delete(args.name)
    ctx.console.line(f"Deleted token: {args.name}")
    if cleared:
        ctx.console.line("Active token cleared.")


def handle_export(ctx: Context, args: Any) -> None:
    record = ctx.store.get(args.name)
    target = Path(args.tokenfile).expanduser()
    if (
        ctx.settings.output is not None
        and target.resolve() == ctx.settings.output.resolve()
    ):
        raise UsageError("--output and --tokenfile must be different files.")
    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Action", "Export token")
        ctx.console.kv("Target", record.name)
        ctx.console.kv("File", target)
        return
    exported = ctx.store.export(record, target)
    ctx.console.line(f"Exported token: {record.name} -> {exported}")
