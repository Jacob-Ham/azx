"""Certificate-based authentication (CBA) for delegated tokens.

This implements the cloud CBA login flow: authorization request, credential
discovery, certificate authentication, login, and code exchange. The user
certificate must be trusted by the tenant and map to the user (SAN/UPN by
default, or certificateUserIds for high-affinity bindings). Federated CBA
(AD FS) is not handled here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ..aliases import resolve_client, resolve_resource
from ..config import Settings
from ..context import Context
from ..errors import AuthError, UsageError
from ..jwt import decode_jwt
from ..model import TokenRecord
from ..tokenmeta import (
    build_record,
    default_token_name,
    detect_token_type,
    validate_import_consistency,
)
from ..util import is_guid, validate_token_name

LOGIN_BASE = "https://login.microsoftonline.com"
CERTAUTH_BASE = "https://certauth.login.microsoftonline.com"
DEFAULT_REDIRECT_URI = "http://localhost"
_FOLLOW_LIMIT = 6
_AADSTS_RE = re.compile(r"AADSTS\d+")
_UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.action: str | None = None
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "form" and self.action is None:
            self.action = values.get("action") or ""
        elif tag == "input":
            name = values.get("name")
            if name:
                self.inputs[name] = values.get("value", "")


def _parse_html(html: str) -> _FormParser:
    parser = _FormParser()
    parser.feed(html)
    return parser


def _extract_config(html: str) -> dict[str, Any]:
    marker = "$Config="
    start = html.find(marker)
    if start < 0:
        return {}
    index = start + len(marker)
    depth = 0
    in_string = False
    escaped = False
    for position in range(index, len(html)):
        char = html[position]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(html[index : position + 1])
                except ValueError:
                    return {}
                return value if isinstance(value, dict) else {}
    return {}


def _form_inputs(payload: Any, html: str = "") -> dict[str, str]:
    if isinstance(payload, dict):
        try:
            block = payload["html"]["body"]["form"]
            items = block["input"] if isinstance(block, dict) else block
            if isinstance(items, dict):
                items = [items]
            if isinstance(items, list):
                return {
                    str(item["name"]): str(item.get("value", ""))
                    for item in items
                    if isinstance(item, dict) and item.get("name")
                }
        except (KeyError, TypeError):
            pass
    return _parse_html(html).inputs


def _code_value(response: httpx.Response) -> str | None:
    location = response.headers.get("location")
    if location:
        code = parse_qs(urlsplit(location).query).get("code")
        if code:
            return code[0]
    content_type = response.headers.get("content-type", "")
    payload: Any = None
    if "json" in content_type:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("code"), str):
            return payload["code"]
    inputs = _form_inputs(payload, response.text)
    if inputs.get("code"):
        return inputs["code"]
    match = re.search(r"[?&]code=([A-Za-z0-9._~-]+)", response.text)
    return match.group(1) if match else None


def _login_error(html: str) -> str | None:
    config = _extract_config(html)
    message = (
        config.get("strServiceExceptionMessage")
        or config.get("strMainMessage")
        or config.get("sErrorDescription")
    )
    if isinstance(message, str) and message.strip():
        return message.strip()
    match = _AADSTS_RE.search(html)
    if match:
        line = next(
            (line for line in html.splitlines() if match.group(0) in line),
            match.group(0),
        )
        return line.strip()[:400]
    return None


def _debug(
    settings: Settings,
    console: Any,
    method: str,
    url: str,
    data: Any = None,
    headers: Any = None,
) -> None:
    if not settings.debug_http:
        return
    console.debug(f"> {method} {url}")
    for key, value in (headers or {}).items():
        console.debug(f"> {key}: {value}")
    if data:
        console.debug(f"> {data}")
    console.debug(">")


def _debug_response(settings: Settings, console: Any, response: httpx.Response) -> None:
    if not settings.debug_http:
        return
    console.debug(f"< {response.status_code} {response.reason_phrase}")
    for key, value in response.headers.items():
        console.debug(f"< {key}: {value}")
    text = response.text[:2000]
    if text:
        console.debug("< " + text)
    console.debug("<")


def _new_client(
    settings: Settings, *, cert: tuple[str, str] | None = None
) -> httpx.Client:
    try:
        return httpx.Client(
            proxy=settings.proxy,
            timeout=httpx.Timeout(settings.timeout),
            verify=not bool(settings.proxy),
            follow_redirects=False,
            headers={
                "User-Agent": settings.user_agent,
                "Accept": "*/*",
                **settings.headers,
            },
            cert=cert,
        )
    except (ValueError, TypeError) as exc:
        raise UsageError(f"Invalid HTTP configuration: {exc}") from exc


def _request(
    client: httpx.Client,
    settings: Settings,
    console: Any,
    method: str,
    url: str,
    *,
    data: Any = None,
    json_body: Any = None,
    headers: Any = None,
) -> httpx.Response:
    _debug(
        settings,
        console,
        method,
        url,
        data if data is not None else json_body,
        headers,
    )
    try:
        response = client.request(
            method, url, data=data, json=json_body, headers=headers
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise AuthError(f"CBA request failed: {exc}") from exc
    _debug_response(settings, console, response)
    return response


def _extract_upn(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for name in san:
            if isinstance(name, x509.RFC822Name) and "@" in name.value:
                return name.value
            if isinstance(name, x509.OtherName) and name.type_id == _UPN_OID:
                value = name.value
                if value and value[0] == 0x0C and len(value) > 2:
                    try:
                        return value[2 : 2 + value[1]].decode("utf-8")
                    except (UnicodeDecodeError, IndexError):
                        pass
    except x509.ExtensionNotFound:
        pass
    for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = str(attribute.value)
        if "@" in value:
            return value
    raise UsageError(
        "Certificate does not contain a UPN in the SAN or common name; "
        "cannot determine the user or tenant."
    )


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _load_pfx(path: Path, password: str | None) -> tuple[str, str, x509.Certificate]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"Cannot read PFX file {path}: {exc}") from exc
    try:
        key, cert, chain = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8") if password else None
        )
    except ValueError as exc:
        raise UsageError(
            f"Cannot open PFX file {path}: {exc}. Check that it is a PKCS#12 "
            "file and that the password is correct."
        ) from exc
    if key is None or cert is None:
        raise UsageError(
            f"PFX file {path} does not contain a private key and certificate."
        )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    for extra in chain or []:
        cert_pem += extra.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_file = tempfile.mkstemp(prefix="azx-cba-cert-", suffix=".pem")
    key_file = tempfile.mkstemp(prefix="azx-cba-key-", suffix=".pem")
    os.close(cert_file[0])
    os.close(key_file[0])
    try:
        _write_private(Path(cert_file[1]), cert_pem)
        _write_private(Path(key_file[1]), key_pem)
    except OSError as exc:
        Path(cert_file[1]).unlink(missing_ok=True)
        Path(key_file[1]).unlink(missing_ok=True)
        raise UsageError(f"Cannot prepare certificate files: {exc}") from exc
    return cert_file[1], key_file[1], cert


def _load_pem(cert_path: Path, key_path: Path) -> x509.Certificate:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise UsageError(f"Cannot read certificate {cert_path}: {exc}") from exc
    try:
        key_path.read_bytes()
    except OSError as exc:
        raise UsageError(f"Cannot read private key {key_path}: {exc}") from exc
    return cert


def _tenant_id(
    client: httpx.Client,
    settings: Settings,
    console: Any,
    upn: str,
    explicit: str | None,
) -> str:
    if explicit:
        text = explicit.strip()
        if is_guid(text):
            return text
        domain = text
    else:
        domain = upn.split("@", 1)[-1]
    url = f"{LOGIN_BASE}/{quote(domain, safe='')}/v2.0/.well-known/openid-configuration"
    response = _request(client, settings, console, "GET", url)
    if response.status_code != 200:
        raise AuthError(
            f"Cannot resolve tenant for {domain}: HTTP {response.status_code}."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError("Tenant discovery returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise AuthError("Tenant discovery returned an unexpected response.")
    issuer = str(payload.get("issuer") or "")
    parts = [part for part in issuer.split("/") if part]
    if len(parts) < 2:
        raise AuthError(f"Cannot determine tenant from issuer {issuer!r}.")
    return parts[-2]


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _authorize_url(
    tenant: str,
    client_id: str,
    resource: str,
    redirect_uri: str,
    upn: str,
    code_challenge: str,
) -> str:
    return (
        f"{LOGIN_BASE}/{quote(tenant, safe='')}/oauth2/authorize"
        f"?client_id={quote(client_id, safe='')}"
        f"&response_type=code"
        f"&response_mode=query"
        f"&redirect_uri={quote(redirect_uri, safe='')}"
        f"&resource={quote(resource, safe='')}"
        f"&login_hint={quote(upn, safe='@')}"
        f"&amr_values=rsa"
        f"&code_challenge={quote(code_challenge, safe='')}"
        f"&code_challenge_method=S256"
    )


def _credential_type(
    session: httpx.Client,
    settings: Settings,
    console: Any,
    upn: str,
    flow_token: str,
    referer: str,
) -> dict[str, Any]:
    url = f"{LOGIN_BASE}/common/GetCredentialType?mkt=en-US"
    response = _request(
        session,
        settings,
        console,
        "POST",
        url,
        json_body={"username": upn, "flowtoken": flow_token},
        headers={"Referer": referer, "Origin": LOGIN_BASE},
    )
    if response.status_code >= 400:
        raise AuthError(
            f"Credential discovery failed: HTTP {response.status_code} "
            f"{_login_error(response.text) or response.reason_phrase}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError("Credential discovery returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise AuthError("Credential discovery returned an unexpected response.")
    error = _login_error(response.text)
    if error:
        raise AuthError(f"Credential discovery failed: {error}")
    return payload


def _cert_auth_url(payload: dict[str, Any], tenant: str) -> str:
    credentials = payload.get("Credentials")
    if isinstance(credentials, dict):
        params = credentials.get("CertAuthParams")
        if isinstance(params, dict):
            candidate = params.get("CertAuthUrl")
            if isinstance(candidate, str) and candidate.strip():
                parsed = urlsplit(candidate)
                host = (parsed.hostname or "").lower()
                if parsed.scheme == "https" and (
                    host == "certauth.login.microsoftonline.com"
                    or host.endswith(".certauth.login.microsoftonline.com")
                ):
                    return candidate
    return f"{CERTAUTH_BASE}/{quote(tenant, safe='')}/certauth"


def _acquire_code(
    settings: Settings,
    console: Any,
    session: httpx.Client,
    cert_client: httpx.Client,
    tenant: str,
    client_id: str,
    resource: str,
    redirect_uri: str,
    upn: str,
    code_challenge: str,
) -> str:
    authorize = _authorize_url(
        tenant, client_id, resource, redirect_uri, upn, code_challenge
    )
    _debug(settings, console, "GET", authorize)
    try:
        response = session.get(authorize)
        for _ in range(_FOLLOW_LIMIT):
            code = _code_value(response)
            if code:
                return code
            if not response.is_redirect:
                break
            location_header = response.headers.get("location")
            if not location_header:
                break
            location = urljoin(str(response.url), location_header)
            redirect_code = parse_qs(urlsplit(location).query).get("code")
            if redirect_code:
                return redirect_code[0]
            response = session.get(location)
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise AuthError(f"CBA authorization request failed: {exc}") from exc
    _debug_response(settings, console, response)
    if response.status_code >= 400:
        raise AuthError(
            f"Authorization request failed: HTTP {response.status_code} "
            f"{_login_error(response.text) or response.reason_phrase}"
        )
    code = _code_value(response)
    if code:
        return code
    host = urlsplit(str(response.url)).hostname or ""
    if host and host not in {"login.microsoftonline.com", "login.microsoft.com"}:
        raise AuthError(
            f"Login was redirected to {host}; federated or third-party sign-in "
            "is not supported by the CBA flow."
        )
    config = _extract_config(response.text)
    if not config.get("sCtx") or not config.get("sFT"):
        raise AuthError(
            "Could not parse the login configuration. The sign-in page may have "
            "changed or CBA may not be enabled for this user."
        )
    # The flow token from the login page is not accepted by certauth directly.
    # Credential discovery returns the token certauth expects and advertises
    # the tenant-specific certauth endpoint.
    credential = _credential_type(
        session, settings, console, upn, config["sFT"], str(response.url)
    )
    credentials = credential.get("Credentials")
    if isinstance(credentials, dict) and credentials.get("HasCertAuth") is False:
        raise AuthError(
            "Certificate-based authentication is not enabled for this user or tenant."
        )
    new_flow_token = credential.get("FlowToken") or credential.get("flowToken")
    cert_body = {
        "ctx": config["sCtx"],
        "flowToken": (
            new_flow_token
            if isinstance(new_flow_token, str) and new_flow_token.strip()
            else config["sFT"]
        ),
    }
    certauth_url = _cert_auth_url(credential, tenant)
    response = _request(
        cert_client, settings, console, "POST", certauth_url, data=cert_body
    )
    if response.status_code >= 400:
        raise AuthError(
            "Certificate authentication failed: "
            f"HTTP {response.status_code} "
            f"{_login_error(response.text) or response.reason_phrase}"
        )
    cert_error = _login_error(response.text)
    if cert_error:
        raise AuthError(f"Certificate authentication failed: {cert_error}")
    try:
        payload: Any = response.json()
    except ValueError:
        payload = None
    fields = _form_inputs(payload, response.text)
    if not fields:
        raise AuthError("Certificate authentication did not return a login form.")

    login_fields = dict(fields)
    if not login_fields.get("login"):
        login_fields["login"] = upn
    response = _request(
        session,
        settings,
        console,
        "POST",
        f"{LOGIN_BASE}/common/login",
        data=login_fields,
        headers={
            "Referer": f"{CERTAUTH_BASE}/",
            "Origin": CERTAUTH_BASE,
        },
    )
    if response.status_code >= 400:
        raise AuthError(
            f"Login failed: HTTP {response.status_code} "
            f"{_login_error(response.text) or response.reason_phrase}"
        )
    if response.is_redirect:
        location_header = response.headers.get("location")
        if not location_header:
            raise AuthError("Login redirect did not include a location.")
        location = urljoin(str(response.url), location_header)
        redirect_code = parse_qs(urlsplit(location).query).get("code")
        if redirect_code:
            return redirect_code[0]
        try:
            response = session.get(location)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise AuthError(f"CBA login redirect failed: {exc}") from exc
        _debug_response(settings, console, response)
    code = _code_value(response)
    if code:
        return code
    config = _extract_config(response.text)
    error = _login_error(response.text)
    if error:
        raise AuthError(f"Login failed: {error}")
    if not config.get("sCtx") or not config.get("sFT"):
        raise AuthError(
            "The login flow did not return a usable session. The sign-in page "
            "may have changed or the client may not allow this redirect URI."
        )

    kmsi = {
        "LoginOptions": "3",
        "type": "28",
        "ctx": config.get("sCtx", ""),
        "hpgrequestid": config.get("sessionId", ""),
        "flowToken": config.get("sFT", ""),
        "canary": config.get("canary", ""),
        "i19": "2326",
    }
    response = _request(
        session, settings, console, "POST", f"{LOGIN_BASE}/kmsi", data=kmsi
    )
    if response.status_code >= 400:
        raise AuthError(
            f"Login completion failed: HTTP {response.status_code} "
            f"{_login_error(response.text) or response.reason_phrase}"
        )
    code = _code_value(response)
    if code:
        return code
    if response.is_redirect:
        location = urljoin(str(response.url), response.headers["location"])
        code = parse_qs(urlsplit(location).query).get("code")
        if code:
            return code[0]
    error = _login_error(response.text)
    if error:
        raise AuthError(f"Login failed: {error}")
    raise AuthError(
        "The login flow completed without returning an authorization code. "
        "The client or redirect URI may not be usable for interactive sign-in."
    )


def _exchange_code(
    settings: Settings,
    console: Any,
    tenant: str,
    client_id: str,
    resource: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    url = f"{LOGIN_BASE}/{quote(tenant, safe='')}/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "code_verifier": code_verifier,
    }
    with _new_client(settings) as client:
        response = _request(client, settings, console, "POST", url, data=data)
    if response.status_code != 200:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        description = (
            payload.get("error_description")
            or payload.get("error")
            or response.text[:500]
        )
        raise AuthError(f"Authorization code exchange failed: {description}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthError("Token endpoint returned invalid JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(
        payload.get("access_token"), str
    ):
        raise AuthError("Token endpoint did not return an access token.")
    return payload


def handle_auth_cba(ctx: Context, args: Any) -> None:
    client_id = resolve_client(args.client)
    resource, _ = resolve_resource(args.resource)
    tenant = (args.tenant or "").strip() or None
    redirect_uri = (args.redirect_uri or DEFAULT_REDIRECT_URI).strip()
    if args.pfx and (args.cert or args.key):
        raise UsageError("Use either --pfx or --cert/--key, not both.")
    if bool(args.cert) != bool(args.key):
        raise UsageError("--cert and --key must be provided together.")
    if not args.pfx and not args.cert:
        raise UsageError("Provide --pfx, or --cert with --key.")
    if args.name:
        validate_token_name(args.name)
        if ctx.store.exists(args.name) and not args.force:
            raise UsageError(
                f"Token '{args.name}' already exists. Use --force to overwrite it."
            )

    cert_file: str | None = None
    key_file: str | None = None
    cleanup: list[str] = []
    try:
        if args.pfx:
            cert_file, key_file, certificate = _load_pfx(
                Path(args.pfx).expanduser(), args.pfx_password
            )
            cleanup = [cert_file, key_file]
        else:
            certificate = _load_pem(
                Path(args.cert).expanduser(), Path(args.key).expanduser()
            )
            cert_file, key_file = (
                str(Path(args.cert).expanduser()),
                str(Path(args.key).expanduser()),
            )
        upn = _extract_upn(certificate)
        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()

        if ctx.dry_run:
            ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
            ctx.console.kv("Action", "Certificate-based authentication")
            ctx.console.kv("Certificate subject", subject)
            ctx.console.kv("Certificate issuer", issuer)
            ctx.console.kv("User", upn)
            ctx.console.kv("Tenant", tenant or "resolved from user domain")
            ctx.console.kv("Client", client_id)
            ctx.console.kv("Resource", resource)
            ctx.console.kv("Redirect URI", redirect_uri)
            ctx.console.kv(
                "Expected change",
                "A delegated access token is acquired and stored.",
            )
            return

        code_verifier, code_challenge = _pkce_pair()
        with _new_client(ctx.settings) as session:
            tenant = _tenant_id(session, ctx.settings, ctx.console, upn, tenant)
            assert cert_file is not None and key_file is not None
            with _new_client(ctx.settings, cert=(cert_file, key_file)) as cert_client:
                code = _acquire_code(
                    ctx.settings,
                    ctx.console,
                    session,
                    cert_client,
                    tenant,
                    client_id,
                    resource,
                    redirect_uri,
                    upn,
                    code_challenge,
                )
    finally:
        for path in cleanup:
            Path(path).unlink(missing_ok=True)

    payload = _exchange_code(
        ctx.settings,
        ctx.console,
        tenant,
        client_id,
        resource,
        redirect_uri,
        code,
        code_verifier,
    )
    access_token = payload["access_token"]
    try:
        claims = decode_jwt(access_token)
    except Exception as exc:
        raise AuthError(f"CBA returned an invalid access token: {exc}") from exc
    validate_import_consistency(claims, client=client_id, tenant=tenant)

    token_type = detect_token_type(claims)
    if args.name:
        validate_token_name(args.name)
        name = args.name
    else:
        name = default_token_name(claims, token_type)
        validate_token_name(name)
    if ctx.store.exists(name) and not args.force:
        raise UsageError(f"Token '{name}' already exists. Use --force to overwrite it.")

    refresh_token = payload.get("refresh_token")
    id_token = payload.get("id_token")
    record = build_record(
        access_token=access_token,
        refresh_token=(
            refresh_token
            if isinstance(refresh_token, str) and refresh_token.strip()
            else None
        ),
        id_token=(id_token if isinstance(id_token, str) and id_token.strip() else None),
        client=client_id,
        tenant=tenant,
        source="cba",
        name=name,
        type_hint=token_type,
    )
    record["_type"] = token_type
    path = ctx.store.save(record, name, force=args.force)
    ctx.store.set_active(name)
    updated = TokenRecord(raw=record, name=name, path=path)
    ctx.console.line(f"Authenticated: {name}", style="bold green")
    ctx.console.kv("Principal", updated.principal_display)
    ctx.console.kv("Client", updated.client_display)
    ctx.console.kv("Audience", updated.audience_text)
    ctx.console.kv("AMR", updated.amr_display)
    ctx.console.kv("Refresh token", "present" if updated.has_refresh_token else "none")
    ctx.console.kv("Expires", updated.expires_display)
    ctx.console.kv("File", path)
