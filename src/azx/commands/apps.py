"""Application registration commands."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from ..api import GraphClient
from ..context import Context
from ..errors import ApiError, AzxError, UsageError
from ..util import format_api_datetime, format_list, is_guid, yes_no
from .common import dry_run, odata_type

APP_SELECT = (
    "id,appId,displayName,description,signInAudience,publisherDomain,"
    "createdDateTime,identifierUris,tags,passwordCredentials,"
    "servicePrincipalLockConfiguration"
)
SP_SELECT = (
    "id,appId,displayName,appDisplayName,servicePrincipalType,accountEnabled,"
    "appRoleAssignmentRequired,signInAudience,publisherName,homepage,"
    "logoutUrl,loginUrl,preferredSingleSignOnMode,servicePrincipalNames,tags,"
    "appOwnerOrganizationId"
)
SP_SECRET_SELECT = "id,appId,displayName,passwordCredentials"


def _require_client_id(reference: str) -> str:
    text = (reference or "").strip()
    if not is_guid(text):
        raise UsageError("Client ID must be a GUID (the application appId).")
    return text


def _app_path(client_id: str, suffix: str = "") -> str:
    return f"/applications(appId='{quote(client_id)}'){suffix}"


def _sp_path(client_id: str, suffix: str = "") -> str:
    return f"/servicePrincipals(appId='{quote(client_id)}'){suffix}"


def resolve_service_principal(
    graph: GraphClient,
    client_id: str,
    *,
    select: str = SP_SELECT,
) -> dict[str, Any]:
    text = _require_client_id(client_id)
    try:
        return graph.get(_sp_path(text), params={"$select": select})
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(
            f"Service principal not found for client ID {text}. Use the appId "
            "(not the object ID)."
        ) from exc


def resolve_application(graph: GraphClient, client_id: str) -> dict[str, Any]:
    text = _require_client_id(client_id)
    try:
        return graph.get(_app_path(text), params={"$select": APP_SELECT})
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(
            f"Application not found for client ID {text}. Use the appId "
            "(not the object ID)."
        ) from exc


def handle_create(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    name = (args.name or "").strip()
    if not name:
        raise UsageError("Application name is required.")
    application_payload = {"displayName": name}
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Create application registration",
            target=name,
            payload={
                "requests": [
                    {
                        "method": "POST",
                        "path": "/applications",
                        "body": application_payload,
                    },
                    {
                        "method": "POST",
                        "path": "/servicePrincipals",
                        "body": {"appId": "<created-app-id>"},
                    },
                ]
            },
            expected=(
                "The application registration and its service principal are created."
            ),
            permissions=(
                "Application.ReadWrite.All; Directory.ReadWrite.All may be "
                "required to create the service principal."
            ),
        )
        return

    application = graph.post("/applications", json_body=application_payload)
    object_id = application.get("id")
    app_id = application.get("appId")
    if not object_id or not app_id:
        raise AzxError(
            "Application was created but the response did not include its "
            "object ID and app ID."
        )
    service_principal_id: str | None = None
    service_principal_error: str | None = None
    try:
        service_principal = graph.post(
            "/servicePrincipals", json_body={"appId": app_id}
        )
        service_principal_id = service_principal.get("id")
    except AzxError as exc:
        service_principal_error = str(exc)

    ctx.console.kv("Created application", name)
    ctx.console.kv("Client ID", app_id)
    ctx.console.kv("Object ID", object_id)
    if service_principal_id:
        ctx.console.kv("Service principal ID", service_principal_id)
    if service_principal_error:
        raise AzxError(
            "The application was created, but creating its service principal "
            f"failed: {service_principal_error}"
        )


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    applications = graph.get_all(
        "/applications",
        params={
            "$select": "id,appId,displayName,createdDateTime,signInAudience",
            "$top": "999",
        },
    )
    if not applications:
        ctx.console.line("No applications found.")
        return
    ctx.console.table(
        ["NAME", "CLIENT ID", "OBJECT ID", "CREATED"],
        [
            [
                application.get("displayName", "-"),
                application.get("appId", "-"),
                application.get("id", "-"),
                format_api_datetime(application.get("createdDateTime")),
            ]
            for application in applications
        ],
    )


def handle_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    application = resolve_application(graph, args.client_id)
    ctx.console.kv("Client ID", application.get("appId", "-"))
    ctx.console.kv("Object ID", application.get("id", "-"))
    ctx.console.kv("Display name", application.get("displayName", "-"))
    ctx.console.kv("Description", application.get("description") or "-")
    ctx.console.kv("Sign-in audience", application.get("signInAudience") or "-")
    ctx.console.kv("Publisher domain", application.get("publisherDomain") or "-")
    ctx.console.kv("Created", format_api_datetime(application.get("createdDateTime")))
    ctx.console.kv("Identifier URIs", format_list(application.get("identifierUris")))
    ctx.console.kv("Tags", format_list(application.get("tags")))
    lock = application.get("servicePrincipalLockConfiguration")
    if isinstance(lock, dict):
        ctx.console.kv(
            "Property lock", "enabled" if lock.get("isEnabled") else "disabled"
        )
        if lock.get("isEnabled"):
            ctx.console.kv("Locked properties", format_list(_lock_labels(lock)))
    else:
        ctx.console.kv("Property lock", "not configured")


def _lock_labels(lock: dict[str, Any]) -> list[str]:
    if lock.get("allProperties"):
        return ["all sensitive properties"]
    labels: list[str] = []
    if lock.get("credentialsWithUsageVerify"):
        labels.append("verification credentials")
    if lock.get("credentialsWithUsageSign"):
        labels.append("signing credentials")
    if lock.get("tokenEncryptionKeyId"):
        labels.append("token encryption key")
    return labels


def handle_lock(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    if args.all and (args.verify or args.sign or args.token_key):
        raise UsageError(
            "--all cannot be combined with --verify, --sign, or --token-key."
        )
    all_properties = args.all or not (args.verify or args.sign or args.token_key)
    config = {
        "isEnabled": True,
        "allProperties": all_properties,
        "credentialsWithUsageVerify": bool(args.verify) and not all_properties,
        "credentialsWithUsageSign": bool(args.sign) and not all_properties,
        "tokenEncryptionKeyId": bool(args.token_key) and not all_properties,
    }
    payload = {"servicePrincipalLockConfiguration": config}
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Lock service principal properties",
            target=client_id,
            payload=payload,
            expected=(
                "The selected sensitive service principal properties are locked."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    graph.patch(_app_path(client_id), json_body=payload)
    ctx.console.kv("Application client ID", client_id)
    ctx.console.kv("Property lock", "enabled")
    ctx.console.kv("Locked properties", format_list(_lock_labels(config)))


def handle_unlock(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    config = {
        "isEnabled": False,
        "allProperties": False,
        "credentialsWithUsageVerify": False,
        "credentialsWithUsageSign": False,
        "tokenEncryptionKeyId": False,
    }
    payload = {"servicePrincipalLockConfiguration": config}
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Unlock service principal properties",
            target=client_id,
            payload=payload,
            expected=("The sensitive service principal properties are unlocked."),
            permissions="Application.ReadWrite.All",
        )
        return
    graph.patch(_app_path(client_id), json_body=payload)
    ctx.console.kv("Application client ID", client_id)
    ctx.console.kv("Property lock", "disabled")


def _secret_end_date(days: int) -> str:
    if days < 1 or days > 730:
        raise UsageError("--lifetime must be between 1 and 730 days.")
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def handle_delete(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Delete application registration",
            target=client_id,
            payload={"method": "DELETE", "path": _app_path(client_id)},
            expected=(
                "The application registration is deleted; its service "
                "principal is not removed."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    try:
        graph.delete(_app_path(client_id))
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(
            f"Application not found for client ID {client_id}. Use the appId "
            "(not the object ID)."
        ) from exc
    ctx.console.line(f"Deleted application: {client_id}")


def handle_secret_add(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    days = args.lifetime if args.lifetime is not None else 365
    end_date = _secret_end_date(days)
    secret_name = (args.secret_name or "").strip()
    if not secret_name:
        raise UsageError("Secret name is required.")
    payload = {
        "passwordCredential": {
            "displayName": secret_name,
            "endDateTime": end_date,
        }
    }
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Add application client secret",
            target=client_id,
            payload=payload,
            expected=(
                "A new client secret is created and its secret text is displayed once."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    result = graph.post(_app_path(client_id, "/addPassword"), json_body=payload)
    secret = result.get("secretText")
    if not secret:
        raise AzxError("The client secret was created but no secret text was returned.")
    ctx.console.kv("Application client ID", client_id)
    ctx.console.kv("Secret", secret)
    ctx.console.kv("Key ID", result.get("keyId", "-"))
    ctx.console.kv("Display name", result.get("displayName") or secret_name)
    ctx.console.kv("Starts", format_api_datetime(result.get("startDateTime")))
    ctx.console.kv("Expires", format_api_datetime(result.get("endDateTime")))


def handle_secret_remove(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    key_id = args.key_id.strip()
    if not is_guid(key_id):
        raise UsageError("Key ID must be a GUID.")
    payload = {"keyId": key_id}
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove application client secret",
            target=client_id,
            payload=payload,
            expected="The client secret is removed from the application.",
            permissions="Application.ReadWrite.All",
        )
        return
    graph.post(_app_path(client_id, "/removePassword"), json_body=payload)
    ctx.console.line(f"Removed client secret {key_id} from {client_id}")


def _print_secrets(
    ctx: Context,
    credentials: list[dict[str, Any]],
    *,
    empty_message: str = "No client secrets found.",
) -> None:
    if not credentials:
        ctx.console.line(empty_message)
        return
    ctx.console.table(
        ["KEY ID", "DISPLAY NAME", "START", "END", "HINT"],
        [
            [
                credential.get("keyId", "-"),
                credential.get("displayName", "-"),
                format_api_datetime(credential.get("startDateTime")),
                format_api_datetime(credential.get("endDateTime")),
                credential.get("hint", "-"),
            ]
            for credential in credentials
        ],
    )


def handle_secret_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    application = resolve_application(graph, args.client_id)
    _print_secrets(ctx, application.get("passwordCredentials") or [])


def _print_owners(ctx: Context, owners: list[dict[str, Any]]) -> None:
    if not owners:
        ctx.console.line("No owners found.")
        return
    ctx.console.table(
        ["TYPE", "NAME", "PRINCIPAL", "ID"],
        [
            [
                odata_type(owner.get("@odata.type")),
                owner.get("displayName") or "-",
                owner.get("userPrincipalName") or owner.get("appId") or "-",
                owner.get("id", "-"),
            ]
            for owner in owners
        ],
    )


def handle_owner_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    _print_owners(ctx, graph.get_all(_app_path(client_id, "/owners")))


def _principal_path(reference: str, principal_type: str | None) -> tuple[str, str]:
    ref = (reference or "").strip()
    if not ref:
        raise UsageError("Principal is required.")
    if "@" in ref:
        if principal_type == "service-principal":
            raise UsageError(
                "A UPN identifies a user; --type service-principal requires "
                "an object ID."
            )
        return "users", quote(ref, safe="@")
    if not is_guid(ref):
        raise UsageError(
            "Principal must be a user UPN, a user object ID, or a service "
            "principal object ID (GUID)."
        )
    if principal_type is None:
        raise UsageError(
            "--type is required with an object ID: user or service-principal."
        )
    collection = "users" if principal_type == "user" else "servicePrincipals"
    return collection, quote(ref)


def handle_owned_by(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    collection, principal_id = _principal_path(args.principal, args.principal_type)
    applications = graph.get_all(
        f"/{collection}/{principal_id}/ownedObjects/microsoft.graph.application",
        params={"$select": "id,appId,displayName", "$top": "999"},
    )
    if not applications:
        ctx.console.line("No owned applications found.")
        return
    ctx.console.table(
        ["NAME", "CLIENT ID", "OBJECT ID"],
        [
            [
                application.get("displayName", "-"),
                application.get("appId", "-"),
                application.get("id", "-"),
            ]
            for application in applications
        ],
    )


def handle_sp_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    service_principals = graph.get_all(
        "/servicePrincipals",
        params={
            "$select": (
                "id,appId,displayName,servicePrincipalType,accountEnabled,"
                "appOwnerOrganizationId"
            ),
            "$top": "999",
        },
    )
    if not service_principals:
        ctx.console.line("No service principals found.")
        return
    ctx.console.table(
        ["NAME", "TYPE", "CLIENT ID", "OBJECT ID", "ENABLED"],
        [
            [
                service_principal.get("displayName", "-"),
                service_principal.get("servicePrincipalType") or "-",
                service_principal.get("appId", "-"),
                service_principal.get("id", "-"),
                yes_no(service_principal.get("accountEnabled")),
            ]
            for service_principal in service_principals
        ],
    )


def handle_sp_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    service_principal = resolve_service_principal(graph, args.client_id)
    ctx.console.kv("Object ID", service_principal.get("id", "-"))
    ctx.console.kv("Client ID", service_principal.get("appId", "-"))
    ctx.console.kv("Display name", service_principal.get("displayName") or "-")
    ctx.console.kv("App display name", service_principal.get("appDisplayName") or "-")
    ctx.console.kv("Type", service_principal.get("servicePrincipalType") or "-")
    ctx.console.kv("Enabled", yes_no(service_principal.get("accountEnabled")))
    ctx.console.kv(
        "App role assignment required",
        yes_no(service_principal.get("appRoleAssignmentRequired")),
    )
    ctx.console.kv("Sign-in audience", service_principal.get("signInAudience") or "-")
    ctx.console.kv("Publisher", service_principal.get("publisherName") or "-")
    ctx.console.kv("Homepage", service_principal.get("homepage") or "-")
    ctx.console.kv("Login URL", service_principal.get("loginUrl") or "-")
    ctx.console.kv("Logout URL", service_principal.get("logoutUrl") or "-")
    ctx.console.kv(
        "SSO mode", service_principal.get("preferredSingleSignOnMode") or "-"
    )
    ctx.console.kv(
        "App owner tenant",
        service_principal.get("appOwnerOrganizationId") or "-",
    )
    ctx.console.kv(
        "Service principal names",
        format_list(service_principal.get("servicePrincipalNames")),
    )
    ctx.console.kv("Tags", format_list(service_principal.get("tags")))


def handle_sp_create(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    display_name = (args.display_name or "").strip()
    payload: dict[str, Any] = {"appId": client_id}
    if display_name:
        payload["displayName"] = display_name
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Create service principal",
            target=display_name or client_id,
            payload=payload,
            expected=(
                "A service principal is created from the application registration."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    service_principal = graph.post("/servicePrincipals", json_body=payload)
    ctx.console.kv(
        "Created service principal",
        service_principal.get("displayName") or display_name or client_id,
    )
    ctx.console.kv("Client ID", service_principal.get("appId") or client_id)
    ctx.console.kv("Object ID", service_principal.get("id", "-"))


def handle_sp_delete(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Delete service principal",
            target=client_id,
            payload={"method": "DELETE", "path": _sp_path(client_id)},
            expected=(
                "The service principal is deleted; the application "
                "registration is not removed."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    try:
        graph.delete(_sp_path(client_id))
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(
            f"Service principal not found for client ID {client_id}. Use the "
            "appId (not the object ID)."
        ) from exc
    ctx.console.line(f"Deleted service principal: {client_id}")


def handle_sp_owner_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    _print_owners(ctx, graph.get_all(_sp_path(client_id, "/owners")))


def handle_sp_owned_by(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    collection, principal_id = _principal_path(args.principal, args.principal_type)
    service_principals = graph.get_all(
        f"/{collection}/{principal_id}/ownedObjects/microsoft.graph.servicePrincipal",
        params={
            "$select": "id,appId,displayName,servicePrincipalType",
            "$top": "999",
        },
    )
    if not service_principals:
        ctx.console.line("No owned service principals found.")
        return
    ctx.console.table(
        ["NAME", "TYPE", "CLIENT ID", "OBJECT ID"],
        [
            [
                service_principal.get("displayName", "-"),
                service_principal.get("servicePrincipalType") or "-",
                service_principal.get("appId", "-"),
                service_principal.get("id", "-"),
            ]
            for service_principal in service_principals
        ],
    )


def handle_sp_secret_add(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    days = args.lifetime if args.lifetime is not None else 365
    end_date = _secret_end_date(days)
    secret_name = (args.secret_name or "").strip()
    if not secret_name:
        raise UsageError("Secret name is required.")
    payload = {
        "passwordCredential": {
            "displayName": secret_name,
            "endDateTime": end_date,
        }
    }
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Add service principal secret",
            target=client_id,
            payload=payload,
            expected=(
                "A new secret is created on the service principal and its "
                "secret text is displayed once."
            ),
            permissions="Application.ReadWrite.All",
        )
        return
    result = graph.post(_sp_path(client_id, "/addPassword"), json_body=payload)
    secret = result.get("secretText")
    if not secret:
        raise AzxError(
            "The service principal secret was created but no secret text was returned."
        )
    ctx.console.kv("Service principal client ID", client_id)
    ctx.console.kv("Secret", secret)
    ctx.console.kv("Key ID", result.get("keyId", "-"))
    ctx.console.kv("Display name", result.get("displayName") or secret_name)
    ctx.console.kv("Starts", format_api_datetime(result.get("startDateTime")))
    ctx.console.kv("Expires", format_api_datetime(result.get("endDateTime")))


def handle_sp_secret_remove(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    client_id = _require_client_id(args.client_id)
    key_id = args.key_id.strip()
    if not is_guid(key_id):
        raise UsageError("Key ID must be a GUID.")
    payload = {"keyId": key_id}
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove service principal secret",
            target=client_id,
            payload=payload,
            expected="The secret is removed from the service principal.",
            permissions="Application.ReadWrite.All",
        )
        return
    graph.post(_sp_path(client_id, "/removePassword"), json_body=payload)
    ctx.console.line(f"Removed service principal secret {key_id} from {client_id}")


def handle_sp_secret_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    service_principal = resolve_service_principal(
        graph, args.client_id, select=SP_SECRET_SELECT
    )
    _print_secrets(
        ctx,
        service_principal.get("passwordCredentials") or [],
        empty_message="No service principal secrets found.",
    )
