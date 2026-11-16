"""Entra directory role commands."""

from __future__ import annotations

from typing import Any

from ..api import GraphClient
from ..context import Context
from ..directory_roles import ROLE_ALIASES, ROLE_TEMPLATES
from ..errors import ApiError, UsageError
from ..util import is_guid
from .common import dry_run, odata_type, require_guid

ROLE_SELECT = "id,displayName,roleTemplateId"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_DISPLAY_NAME = "Microsoft Graph"

_ROLE_TEMPLATES_BY_NAME = {
    name.casefold(): template_id for name, template_id in ROLE_TEMPLATES.items()
}
for _alias, _canonical in ROLE_ALIASES.items():
    _template_id = ROLE_TEMPLATES.get(_canonical)
    if _template_id:
        _ROLE_TEMPLATES_BY_NAME[_alias.casefold()] = _template_id

_ROLE_NAMES_BY_TEMPLATE = {
    template_id.casefold(): name for name, template_id in ROLE_TEMPLATES.items()
}


def _fold(value: Any) -> str:
    return str(value or "").strip().casefold()


def _template_id_for(reference: str) -> str | None:
    text = reference.strip()
    if is_guid(text):
        return text.lower()
    return _ROLE_TEMPLATES_BY_NAME.get(_fold(text))


def _template_name(template_id: str | None) -> str | None:
    if not template_id:
        return None
    return _ROLE_NAMES_BY_TEMPLATE.get(template_id.casefold())


def _find_active(roles: list[dict[str, Any]], reference: str) -> dict[str, Any] | None:
    folded = _fold(reference)
    template_id = _template_id_for(reference)
    folded_template = template_id.casefold() if template_id else None
    for role in roles:
        if _fold(role.get("id")) == folded:
            return role
        if folded_template and _fold(role.get("roleTemplateId")) == folded_template:
            return role
        if _fold(role.get("displayName")) == folded:
            return role
    return None


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    active_roles = graph.get_all("/directoryRoles", params={"$select": ROLE_SELECT})
    if not active_roles:
        ctx.console.line("No active directory roles found.")
        return
    rows = [
        [
            role.get("displayName", "-"),
            role.get("roleTemplateId") or "-",
            role.get("id", "-"),
        ]
        for role in active_roles
    ]
    ctx.console.table(["NAME", "TEMPLATE ID", "ROLE ID"], rows)


def handle_list_members(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    roles = graph.get_all("/directoryRoles", params={"$select": ROLE_SELECT})
    role = _find_active(roles, args.role)
    if role is None:
        raise UsageError(f"Directory role is not active or was not found: {args.role}")
    members = graph.get_all(f"/directoryRoles/{role['id']}/members")
    if not members:
        ctx.console.line(
            f"No members found for role: {role.get('displayName') or args.role}"
        )
        return
    ctx.console.table(
        ["NAME", "TYPE", "PRINCIPAL", "ID"],
        [
            [
                member.get("displayName")
                or member.get("userPrincipalName")
                or member.get("id", "-"),
                odata_type(member.get("@odata.type")),
                member.get("userPrincipalName")
                or member.get("mail")
                or member.get("appId")
                or "-",
                member.get("id", "-"),
            ]
            for member in members
        ],
    )


def _service_principal_by_app_id(
    service_principals: list[dict[str, Any]],
    app_id: str,
) -> dict[str, Any] | None:
    folded = app_id.casefold()
    for service_principal in service_principals:
        if str(service_principal.get("appId", "")).casefold() == folded:
            return service_principal
    return None


def _service_principal_by_id(
    service_principals: list[dict[str, Any]],
    object_id: str,
) -> dict[str, Any] | None:
    folded = object_id.casefold()
    for service_principal in service_principals:
        if str(service_principal.get("id", "")).casefold() == folded:
            return service_principal
    return None


def _resolve_principal_reference(
    graph: GraphClient,
    reference: str,
) -> tuple[str, str | None]:
    """Return the directory object ID and client ID when the reference is an SP."""
    try:
        service_principals = graph.get_all(
            "/servicePrincipals",
            params={
                "$filter": f"id eq '{reference}' or appId eq '{reference}'",
                "$select": "id,appId,displayName",
                "$top": "2",
            },
        )
    except ApiError as exc:
        if exc.status_code == 403:
            return reference, None
        raise
    for service_principal in service_principals:
        object_id = str(service_principal.get("id") or "")
        if object_id.casefold() == reference.casefold():
            app_id = str(service_principal.get("appId") or "")
            return object_id, app_id or None
    for service_principal in service_principals:
        app_id = str(service_principal.get("appId") or "")
        if app_id.casefold() == reference.casefold():
            object_id = str(service_principal.get("id") or "")
            if object_id:
                return object_id, app_id
    return reference, None


def _application_permission_role(
    service_principal: dict[str, Any],
    permission: str,
) -> dict[str, Any]:
    folded = permission.casefold()
    matches = []
    for role in service_principal.get("appRoles") or []:
        if role.get("isEnabled") is False:
            continue
        allowed = role.get("allowedMemberTypes") or []
        if "Application" not in allowed:
            continue
        identifiers = {
            str(role.get("value") or "").casefold(),
            str(role.get("displayName") or "").casefold(),
            str(role.get("id") or "").casefold(),
        }
        if folded in identifiers:
            matches.append(role)
    if not matches:
        raise UsageError(
            f"Application permission not found on "
            f"{service_principal.get('displayName') or GRAPH_DISPLAY_NAME}: "
            f"{permission}. Use the permission value, display name, or app role ID."
        )
    if len(matches) > 1:
        identifiers = ", ".join(
            str(role.get("value") or role.get("displayName") or role.get("id"))
            for role in matches
        )
        raise UsageError(
            f"Multiple application permissions match {permission!r}: {identifiers}."
        )
    return matches[0]


def _is_duplicate_assignment(exc: ApiError) -> bool:
    text = f"{exc.code or ''} {exc.message or ''} {exc.body or ''}".casefold()
    return (
        exc.status_code == 409 or "already exists" in text or "already assigned" in text
    )


def _resolve_api_permission(
    graph: GraphClient,
    principal_reference: str,
    permission: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    service_principals = graph.get_all(
        "/servicePrincipals",
        params={
            "$filter": (
                f"id eq '{principal_reference}' or "
                f"appId eq '{principal_reference}' or "
                f"appId eq '{GRAPH_APP_ID}'"
            ),
            "$select": "id,appId,displayName,appRoles",
            "$top": "999",
        },
    )
    target = _service_principal_by_id(
        service_principals, principal_reference
    ) or _service_principal_by_app_id(service_principals, principal_reference)
    if target is None:
        raise UsageError(
            "API permission assignments are only supported for service "
            f"principals. No service principal found for object ID or client ID "
            f"{principal_reference}."
        )
    if str(target.get("appId", "")).casefold() == GRAPH_APP_ID.casefold():
        raise UsageError("The target application must not be Microsoft Graph itself.")
    resource = _service_principal_by_app_id(service_principals, GRAPH_APP_ID)
    if resource is None:
        raise UsageError(
            "Microsoft Graph service principal is not present in this tenant."
        )
    role = _application_permission_role(resource, permission)
    return target, resource, role


def _assign_api_permission(
    ctx: Context,
    graph: GraphClient,
    principal_id: str,
    permission: str,
) -> None:
    target, resource, role = _resolve_api_permission(graph, principal_id, permission)
    resource_id = str(resource.get("id") or "")
    target_id = str(target.get("id") or "")
    if not resource_id or not target_id:
        raise UsageError("Service principal responses did not include object IDs.")

    role_id = str(role.get("id") or "")
    if not role_id:
        raise UsageError(f"Application permission has no ID: {permission}")
    permission_name = str(role.get("value") or role.get("displayName") or role_id)
    target_name = str(target.get("displayName") or principal_id)
    target_app_id = str(target.get("appId") or "")
    path = f"/servicePrincipals/{resource_id}/appRoleAssignedTo"
    payload = {
        "principalId": target_id,
        "resourceId": resource_id,
        "appRoleId": role_id,
    }
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Assign application permission",
            target=f"{target_name} -> Microsoft Graph / {permission_name}",
            payload={"method": "POST", "path": path, "body": payload},
            expected="The application receives the permission.",
            permissions="AppRoleAssignment.ReadWrite.All",
        )
        return

    try:
        assignment = graph.post(path, json_body=payload)
    except ApiError as exc:
        if _is_duplicate_assignment(exc):
            ctx.console.line(
                f"Application permission already assigned: {permission_name}"
            )
            return
        raise

    application = f"{target_name} ({target_app_id})" if target_app_id else target_name
    ctx.console.line("Assigned application permission", style="bold green")
    ctx.console.kv("Application", application)
    ctx.console.kv("Service principal object ID", target_id)
    ctx.console.kv("API", resource.get("displayName") or GRAPH_DISPLAY_NAME)
    ctx.console.kv("Permission", permission_name)
    ctx.console.kv("App role ID", role_id)
    ctx.console.kv("Assignment ID", assignment.get("id") or "-")


def _unassign_api_permission(
    ctx: Context,
    graph: GraphClient,
    principal_id: str,
    permission: str,
) -> None:
    target, resource, role = _resolve_api_permission(graph, principal_id, permission)
    target_id = str(target.get("id") or "")
    resource_id = str(resource.get("id") or "")
    role_id = str(role.get("id") or "")
    if not target_id or not resource_id or not role_id:
        raise UsageError("Service principal or app role response did not include IDs.")

    assignments = graph.get_all(
        f"/servicePrincipals/{target_id}/appRoleAssignments",
        params={
            "$select": "id,resourceId,resourceDisplayName,appRoleId",
            "$top": "999",
        },
    )
    matches = [
        assignment
        for assignment in assignments
        if str(assignment.get("resourceId", "")).casefold() == resource_id.casefold()
        and str(assignment.get("appRoleId", "")).casefold() == role_id.casefold()
    ]
    if not matches:
        permission_name = str(role.get("value") or role.get("displayName") or role_id)
        raise UsageError(f"Application permission is not assigned: {permission_name}")
    if len(matches) > 1:
        identifiers = ", ".join(
            str(assignment.get("id") or "-") for assignment in matches
        )
        raise UsageError(
            f"Multiple matching application permission assignments found: "
            f"{identifiers}."
        )
    assignment = matches[0]
    assignment_id = str(assignment.get("id") or "")
    if not assignment_id:
        raise UsageError("The matching application permission assignment has no ID.")

    permission_name = str(role.get("value") or role.get("displayName") or role_id)
    target_name = str(target.get("displayName") or principal_id)
    target_app_id = str(target.get("appId") or "")
    path = f"/servicePrincipals/{resource_id}/appRoleAssignedTo/{assignment_id}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Unassign application permission",
            target=f"{target_name} <- Microsoft Graph / {permission_name}",
            payload={"method": "DELETE", "path": path},
            expected="The application loses the permission.",
            permissions="AppRoleAssignment.ReadWrite.All",
        )
        return

    graph.delete(path)
    application = f"{target_name} ({target_app_id})" if target_app_id else target_name
    ctx.console.line("Unassigned application permission", style="bold green")
    ctx.console.kv("Application", application)
    ctx.console.kv("Service principal object ID", target_id)
    ctx.console.kv("API", resource.get("displayName") or GRAPH_DISPLAY_NAME)
    ctx.console.kv("Permission", permission_name)
    ctx.console.kv("App role ID", role_id)
    ctx.console.kv("Assignment ID", assignment_id)


def handle_assign(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    principal_reference = require_guid(args.principal, "Principal")
    if args.api_permission:
        _assign_api_permission(ctx, graph, principal_reference, args.api_permission)
        return
    if not args.role:
        raise UsageError("Provide --role or --api-permission.")
    template_id = (args.role or "").strip()
    if not is_guid(template_id):
        raise UsageError(
            "--role must be a directory role template/definition ID (GUID)."
        )
    principal_id, principal_client_id = _resolve_principal_reference(
        graph, principal_reference
    )
    display_name = _template_name(template_id) or template_id
    payload = {
        "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
        "principalId": principal_id,
        "roleDefinitionId": template_id,
        "directoryScopeId": "/",
    }
    target = f"{principal_id} -> {display_name}"
    if principal_client_id:
        target = f"{principal_id} ({principal_client_id}) -> {display_name}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Assign directory role",
            target=target,
            payload={
                "method": "POST",
                "path": "/roleManagement/directory/roleAssignments",
                "body": payload,
            },
            expected="The principal is permanently assigned to the directory role.",
            permissions="RoleManagement.ReadWrite.Directory",
        )
        return

    def print_principal() -> None:
        ctx.console.kv("Principal", principal_id)
        if principal_client_id:
            ctx.console.kv("Client ID", principal_client_id)

    try:
        assignment = graph.post(
            "/roleManagement/directory/roleAssignments",
            json_body=payload,
        )
    except ApiError as exc:
        if _is_duplicate_assignment(exc):
            ctx.console.line(
                f"Directory role already assigned: {display_name}",
                style="bold yellow",
            )
            print_principal()
            return
        raise
    ctx.console.line("Assigned directory role", style="bold green")
    ctx.console.kv("Role", display_name)
    print_principal()
    ctx.console.kv("Role definition ID", template_id)
    ctx.console.kv("Assignment ID", assignment.get("id") or "-")


def handle_unassign(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    principal_reference = require_guid(args.principal, "Principal")
    if args.api_permission:
        _unassign_api_permission(ctx, graph, principal_reference, args.api_permission)
        return
    if not args.role:
        raise UsageError("Provide --role or --api-permission.")
    template_id = (args.role or "").strip()
    if not is_guid(template_id):
        raise UsageError(
            "--role must be a directory role template/definition ID (GUID)."
        )
    principal_id, principal_client_id = _resolve_principal_reference(
        graph, principal_reference
    )
    assignments = graph.get_all(
        "/roleManagement/directory/roleAssignments",
        params={
            "$filter": f"principalId eq '{principal_id}'",
            "$top": "999",
        },
    )
    matches = [
        assignment
        for assignment in assignments
        if str(assignment.get("roleDefinitionId", "")).casefold()
        == template_id.casefold()
    ]
    if not matches:
        raise UsageError(
            f"Directory role assignment not found for principal "
            f"{principal_id}: {args.role}"
        )
    if len(matches) > 1:
        identifiers = ", ".join(
            f"{assignment.get('id')} ({assignment.get('directoryScopeId') or '/'})"
            for assignment in matches
        )
        raise UsageError(
            f"Multiple directory role assignments match {args.role!r}: {identifiers}."
        )
    assignment = matches[0]
    assignment_id = str(assignment.get("id") or "")
    if not assignment_id:
        raise UsageError("The matching directory role assignment has no ID.")
    display_name = _template_name(template_id) or args.role
    path = f"/roleManagement/directory/roleAssignments/{assignment_id}"
    target = f"{principal_id} <- {display_name}"
    if principal_client_id:
        target = f"{principal_id} ({principal_client_id}) <- {display_name}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Unassign directory role",
            target=target,
            payload={"method": "DELETE", "path": path},
            expected="The principal is unassigned from the directory role.",
            permissions="RoleManagement.ReadWrite.Directory",
        )
        return
    graph.delete(path)
    ctx.console.line("Unassigned directory role", style="bold green")
    ctx.console.kv("Role", display_name)
    ctx.console.kv("Principal", principal_id)
    if principal_client_id:
        ctx.console.kv("Client ID", principal_client_id)
    ctx.console.kv("Role definition ID", template_id)
    ctx.console.kv("Assignment ID", assignment_id)
