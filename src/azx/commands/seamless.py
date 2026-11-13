"""Seamless SSO authentication using Kerberos tickets."""

from __future__ import annotations

import base64
import logging
import types
import warnings
from typing import Any

from ..aliases import resolve_client, resolve_resource
from ..context import Context
from ..errors import AuthError, TokenError, UsageError
from ..jwt import decode_jwt
from ..model import TokenRecord
from ..tokenmeta import build_record, default_token_name, detect_token_type
from ..util import validate_token_name


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _log_detail(messages: list[str]) -> str:
    useful = [message for message in messages if message][-5:]
    return f" ({'; '.join(useful)})" if useful else ""


def _validate_flow(args: Any) -> None:
    if not args.tenant:
        raise UsageError("--tenant is required.")
    if args.tgt or args.tgs:
        if args.tgt and not args.tgs and not (args.dc_host and args.domain):
            raise UsageError("--tgt requires --dc and --domain.")
        return
    if args.adssoacc_ntlm or args.adssoacc_aes:
        if not ((args.domain_sid and args.user_rid is not None) or args.user_sid):
            raise UsageError(
                "Forged TGS requires --user-sid or --domain-sid with --user-rid."
            )
        return
    if not (args.dc_host and args.domain and args.username):
        raise UsageError(
            "Provide --tgt/--tgs, AZUREADSSOACC credentials, or "
            "--dc, --domain, and --username."
        )
    if not (args.password or args.ntlm or args.aes_key):
        raise UsageError(
            "Provide --password, --ntlm, or --aes-key for domain authentication."
        )


def _flow_description(args: Any) -> str:
    if args.tgs:
        return "Provided TGS"
    if args.tgt:
        return "Provided TGT + domain controller"
    if args.adssoacc_ntlm or args.adssoacc_aes:
        return "Forged TGS using AZUREADSSOACC credentials"
    methods = []
    if args.password:
        methods.append("password")
    if args.ntlm:
        methods.append("NTLM hash")
    if args.aes_key:
        methods.append("AES key")
    return "Domain authentication using " + ", ".join(methods)


def handle_auth_seamless(ctx: Context, args: Any) -> None:
    _validate_flow(args)
    tenant = args.tenant.strip()
    client = resolve_client(args.client)
    resource, _ = resolve_resource(args.resource)
    if args.name:
        validate_token_name(args.name)
        if ctx.store.exists(args.name) and not args.force:
            raise UsageError(
                f"Token '{args.name}' already exists. Use --force to overwrite it."
            )

    if ctx.dry_run:
        ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
        ctx.console.kv("Action", "Seamless SSO authentication")
        ctx.console.kv("Tenant", tenant)
        ctx.console.kv("Resource", resource)
        ctx.console.kv("Client", client)
        ctx.console.kv("Authentication", _flow_description(args))
        ctx.console.kv(
            "SSO check",
            "skipped" if args.ignore_sso_check else "required",
        )
        ctx.console.kv("Name", args.name or "generated from token claims")
        if ctx.settings.proxy:
            ctx.console.kv("Proxy", ctx.settings.proxy)
        ctx.console.kv(
            "Expected change",
            "Acquire a token through Seamless SSO and import it automatically.",
        )
        return

    try:
        from seamlesspass.utils.exceptions import UsageError as SeamlessUsageError
        from seamlesspass.utils.kerberos import KerberosHelper
        from seamlesspass.utils.microsoft365 import Microsoft365Helper
    except ImportError as exc:
        raise AuthError(
            "Seamless SSO support requires the 'seamlesspass' package. "
            "Install it with `pip install -r requirements.txt`."
        ) from exc

    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    capture = _LogCapture()
    logger = logging.getLogger("SeamlessPass")
    logger.handlers.clear()
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    domain = args.domain
    username = args.username
    if (args.adssoacc_ntlm or args.adssoacc_aes) and not args.tgt and not args.tgs:
        domain = domain or "dummy.lab"
        username = username or "dummy_user"
    options = types.SimpleNamespace(
        tenant=tenant,
        resource=resource,
        client_id=client,
        proxies=(
            {"http": ctx.settings.proxy, "https": ctx.settings.proxy}
            if ctx.settings.proxy
            else None
        ),
        user_agent=getattr(args, "user_agent", None),
        ignore_sso_check=args.ignore_sso_check,
        domain=domain,
        dc_host=args.dc_host,
        username=username,
        password=args.password,
        ntlm=args.ntlm,
        aes_key=args.aes_key,
        tgt=args.tgt,
        tgs=args.tgs,
        spn=args.spn,
        domain_sid=args.domain_sid,
        user_rid=args.user_rid,
        user_sid=args.user_sid,
        adssoacc_ntlm=args.adssoacc_ntlm,
        adssoacc_aes=args.adssoacc_aes,
    )

    m365 = Microsoft365Helper.from_options(options)
    if not args.ignore_sso_check and not m365.check_seamless_sso():
        raise AuthError(
            "Seamless SSO is not enabled for this tenant. "
            "Use --ignore-sso-check to proceed anyway."
        )

    try:
        kerberos = KerberosHelper.from_options(options)
        tgs = kerberos.get_TGS()
    except SeamlessUsageError as exc:
        raise UsageError(str(exc)) from exc
    except Exception as exc:
        raise AuthError(
            f"Kerberos ticket acquisition failed: {exc}{_log_detail(capture.messages)}"
        ) from exc
    if not tgs:
        raise AuthError(
            f"Could not acquire a service ticket.{_log_detail(capture.messages)}"
        )

    try:
        spnego = KerberosHelper.tgs_to_spnego(tgs)
        kerberos_ticket = base64.b64encode(spnego).decode()
        token = m365.get_access_token_with_kerberos_ticket(kerberos_ticket)
    except Exception as exc:
        raise AuthError(
            f"Seamless SSO token exchange failed: {exc}{_log_detail(capture.messages)}"
        ) from exc
    if not isinstance(token, dict):
        raise AuthError(
            f"Seamless SSO did not return a token.{_log_detail(capture.messages)}"
        )
    access_token = token.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise AuthError(
            "Seamless SSO did not return an access token."
            f"{_log_detail(capture.messages)}"
        )

    try:
        claims = decode_jwt(access_token)
    except TokenError as exc:
        raise AuthError(
            f"Seamless SSO returned an invalid access token: {exc}"
        ) from exc
    token_type = detect_token_type(claims)
    if args.name:
        name = args.name
    else:
        name = default_token_name(claims, token_type)
        validate_token_name(name)
    if ctx.store.exists(name) and not args.force:
        raise UsageError(f"Token '{name}' already exists. Use --force to overwrite it.")

    refresh_token = token.get("refresh_token")
    id_token = token.get("id_token")
    record = build_record(
        access_token=access_token,
        refresh_token=(
            refresh_token
            if isinstance(refresh_token, str) and refresh_token.strip()
            else None
        ),
        id_token=(id_token if isinstance(id_token, str) and id_token.strip() else None),
        client=client,
        tenant=tenant,
        source="seamless",
        name=name,
        type_hint=token_type,
    )
    path = ctx.store.save(record, name, force=args.force)
    ctx.store.set_active(name)
    updated = TokenRecord(raw=record, name=name, path=path)
    ctx.console.token_line(name)
    ctx.console.kv("Principal", updated.principal_display)
    ctx.console.kv("Client", updated.client_display)
    ctx.console.kv("Audience", updated.audience_text)
    ctx.console.kv("Refresh token", "present" if updated.has_refresh_token else "none")
    ctx.console.kv("File", path)
