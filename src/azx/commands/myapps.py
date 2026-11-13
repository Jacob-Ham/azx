"""MyApps app-role assignment commands."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..api import GraphClient
from ..context import Context
from ..errors import ApiError, UsageError
from ..util import is_guid
from .common import dry_run, require_guid

DEFAULT_APP_ROLE = "00000000-0000-0000-0000-000000000000"
SP_SELECT = "id,appId,displayName,appRoles"


def _user_role(role: dict[str, Any]) -> bool:
    if role.get("isEnabled") is False:
        return False
    allowed = role.get("allowedMemberTypes")
    if allowed is None:
        return True
    return "User" in allowed


def _resolve_app_sp(graph: GraphClient, reference: str) -> dict[str, Any]:
    text = (reference or "").strip()
    if not is_guid(text):
        raise UsageError(
            "Enterprise application must be an appId or service principal "
            "object ID (GUID)."
        )
    try:
        return graph.get(
            f"/servicePrincipals(appId='{quote(text)}')",
            params={"$select": SP_SELECT},
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
    try:
        return graph.get(
            f"/servicePrincipals/{quote(text)}",
            params={"$select": SP_SELECT},
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(
            f"Enterprise application not found for appId or service "
            f"principal object ID {text}."
        ) from exc


def _role_id(service_principal: dict[str, Any], reference: str | None) -> str:
    roles = service_principal.get("appRoles") or []
    user_roles = [role for role in roles if _user_role(role)]
    if not reference:
        if user_roles:
            names = ", ".join(
                str(role.get("displayName") or role.get("value")) for role in user_roles
            )
            raise UsageError(
                f"{service_principal.get('displayName') or 'Application'} "
                f"exposes roles; specify --role ({names})."
            )
        return DEFAULT_APP_ROLE
    folded = reference.casefold()
    matches = [
        role
        for role in roles
        if str(role.get("id", "")).casefold() == folded
        or str(role.get("displayName", "")).casefold() == folded
        or str(role.get("value", "")).casefold() == folded
    ]
    if not matches:
        raise UsageError(
            f"App role not found on "
            f"{service_principal.get('displayName') or 'application'}: "
            f"{reference}"
        )
    assignable = [role for role in matches if _user_role(role)]
    if not assignable:
        raise UsageError(f"App role is not assignable to users: {reference}")
    if len(assignable) > 1:
        identifiers = ", ".join(
            str(role.get("id") or role.get("displayName")) for role in assignable
        )
        raise UsageError(f"Multiple app roles match {reference!r}: {identifiers}.")
    role = assignable[0]
    role_id = role.get("id")
    if not role_id:
        raise UsageError(f"App role has no ID: {reference}")
    return str(role_id)


def _role_name(service_principal: dict[str, Any], app_role_id: str) -> str:
    if app_role_id == DEFAULT_APP_ROLE:
        return "Default access"
    for role in service_principal.get("appRoles") or []:
        if str(role.get("id", "")).casefold() == app_role_id.casefold():
            return str(role.get("displayName") or role.get("value") or app_role_id)
    return app_role_id


def _print_assignments(
    ctx: Context,
    assignments: list[dict[str, Any]],
) -> None:
    rows = [
        [
            assignment.get("resourceDisplayName")
            or assignment.get("resourceId")
            or "-",
            assignment.get("resourceId") or "-",
            assignment.get("appRoleId") or DEFAULT_APP_ROLE,
            assignment.get("id") or "-",
        ]
        for assignment in assignments
    ]
    ctx.console.table(
        ["APPLICATION", "RESOURCE ID", "ROLE ID", "ASSIGNMENT ID"],
        rows,
    )


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    if args.user:
        user_id = require_guid(args.user, "User")
        principal_path = quote(user_id)
        collection = "users"
    else:
        token = ctx.current_token
        if token is None or not token.has_access_token:
            raise UsageError("No active token is available.")
        principal_id = token.principal_id or ""
        if not principal_id:
            raise UsageError("The active token has no principal object ID.")
        collection = "servicePrincipals" if token.is_app else "users"
        principal_path = quote(principal_id)
    assignments = graph.get_all(
        f"/{collection}/{principal_path}/appRoleAssignments",
        params={"$top": "999"},
    )
    if not assignments:
        ctx.console.line("No app role assignments found.")
        return
    _print_assignments(ctx, assignments)


def handle_assign(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_id = require_guid(args.user, "User")
    service_principal = _resolve_app_sp(graph, args.client_id)
    app_role_id = _role_id(service_principal, args.role)
    payload = {
        "principalId": user_id,
        "resourceId": service_principal["id"],
        "appRoleId": app_role_id,
    }
    target = f"{user_id} -> {service_principal.get('displayName') or args.client_id}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Assign user to application",
            target=target,
            payload=payload,
            expected="The user receives the application role assignment.",
            permissions="AppRoleAssignment.ReadWrite.All",
        )
        return
    assignment = graph.post(
        f"/users/{quote(user_id)}/appRoleAssignments", json_body=payload
    )
    ctx.console.kv(
        "Assigned application",
        service_principal.get("displayName", args.client_id),
    )
    ctx.console.kv("User", user_id)
    ctx.console.kv(
        "Role",
        _role_name(service_principal, app_role_id),
    )
    ctx.console.kv("Assignment ID", assignment.get("id", "-"))


def handle_unassign(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_id = require_guid(args.user, "User")
    service_principal = _resolve_app_sp(graph, args.client_id)
    assignments = graph.get_all(
        f"/users/{quote(user_id)}/appRoleAssignments",
        params={"$top": "999"},
    )
    matches = [
        assignment
        for assignment in assignments
        if str(assignment.get("resourceId", "")).casefold()
        == str(service_principal["id"]).casefold()
    ]
    if args.role:
        app_role_id = _role_id(service_principal, args.role)
        matches = [
            assignment
            for assignment in matches
            if str(assignment.get("appRoleId", "")).casefold() == app_role_id.casefold()
        ]
    if not matches:
        raise UsageError("No matching app role assignment found.")
    if len(matches) > 1:
        identifiers = ", ".join(
            str(assignment.get("id", "-")) for assignment in matches
        )
        raise UsageError(
            "Multiple matching app role assignments found: "
            f"{identifiers}. Specify --role to disambiguate."
        )
    assignment = matches[0]
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Unassign user from application",
            target=(
                f"{user_id} <- {service_principal.get('displayName') or args.client_id}"
            ),
            payload={
                "method": "DELETE",
                "path": (
                    f"/users/{quote(user_id)}/appRoleAssignments/{assignment.get('id')}"
                ),
            },
            expected="The user's application role assignment is removed.",
            permissions="AppRoleAssignment.ReadWrite.All",
        )
        return
    graph.delete(f"/users/{quote(user_id)}/appRoleAssignments/{assignment['id']}")
    ctx.console.line(
        f"Unassigned user from application: "
        f"{service_principal.get('displayName') or args.client_id}"
    )
