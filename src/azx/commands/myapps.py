"""MyApps app-role assignment commands."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..api import GraphClient
from ..context import Context
from ..errors import ApiError, UsageError
from ..util import is_guid, yes_no
from .common import dry_run, require_guid

DEFAULT_APP_ROLE = "00000000-0000-0000-0000-000000000000"
SP_SELECT = "id,appId,displayName,appRoles,appRoleAssignmentRequired"


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
        data = graph.get(
            "/servicePrincipals",
            params={
                "$filter": f"id eq '{text}' or appId eq '{text}'",
                "$select": SP_SELECT,
            },
        )
    except ApiError as exc:
        if exc.status_code in {400, 404}:
            raise UsageError(
                f"Enterprise application not found for appId or service "
                f"principal object ID {text}."
            ) from exc
        raise
    items = data.get("value")
    if not isinstance(items, list):
        items = []
    matches = [
        item
        for item in items
        if isinstance(item, dict)
        and (
            str(item.get("id", "")).casefold() == text.casefold()
            or str(item.get("appId", "")).casefold() == text.casefold()
        )
    ]
    if not matches:
        raise UsageError(
            f"Enterprise application not found for appId or service principal "
            f"object ID {text}."
        )
    if len(matches) > 1:
        raise UsageError(
            f"Enterprise application identifier {text} matched multiple "
            "service principals."
        )
    return matches[0]


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


def _print_app_roles(
    ctx: Context,
    service_principals: list[dict[str, Any]],
) -> None:
    rows = []
    for service_principal in service_principals:
        roles = [
            role for role in service_principal.get("appRoles") or [] if _user_role(role)
        ]
        if not roles:
            continue
        labels = ", ".join(
            str(role.get("displayName") or role.get("value") or role.get("id") or "-")
            for role in roles
        )
        rows.append(
            [
                service_principal.get("displayName") or "-",
                service_principal.get("appId") or "-",
                service_principal.get("id") or "-",
                labels,
            ]
        )
    if not rows:
        ctx.console.line("No enterprise applications expose user-assignable roles.")
        return
    rows.sort(key=lambda row: str(row[0]).casefold())
    ctx.console.table(
        ["APPLICATION", "APP ID", "OBJECT ID", "ASSIGNABLE ROLES"],
        rows,
    )


def handle_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    service_principal = _resolve_app_sp(graph, args.app)
    ctx.console.kv("Application", service_principal.get("displayName") or "-")
    ctx.console.kv("App ID", service_principal.get("appId") or "-")
    ctx.console.kv("Object ID", service_principal.get("id") or "-")
    ctx.console.kv(
        "App role assignment required",
        yes_no(service_principal.get("appRoleAssignmentRequired")),
    )
    roles = [
        role for role in service_principal.get("appRoles") or [] if _user_role(role)
    ]
    if not roles:
        ctx.console.line("No user-assignable roles (default access only).")
        return
    ctx.console.heading("Assignable roles")
    ctx.console.table(
        ["ROLE", "ROLE ID", "VALUE"],
        [
            [
                role.get("displayName") or role.get("value") or "-",
                role.get("id") or "-",
                role.get("value") or "-",
            ]
            for role in roles
        ],
    )


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    service_principals = graph.get_all(
        "/servicePrincipals",
        params={
            "$select": "id,appId,displayName,appRoles",
            "$top": "999",
        },
    )
    _print_app_roles(ctx, service_principals)


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
