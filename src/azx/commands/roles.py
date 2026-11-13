"""Entra directory role commands."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..directory_roles import ROLE_ALIASES, ROLE_TEMPLATES
from ..errors import UsageError
from ..util import is_guid
from .common import dry_run, odata_type, require_guid

ROLE_SELECT = "id,displayName,roleTemplateId"

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


def _member_reference(user_id: str) -> dict[str, str]:
    return {
        "@odata.id": (f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}")
    }


def handle_assign(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_id = require_guid(args.user, "User")
    roles = graph.get_all("/directoryRoles", params={"$select": ROLE_SELECT})
    active = _find_active(roles, args.role)
    template_id = _template_id_for(args.role)
    if active is None and template_id is None:
        raise UsageError(
            f"Unknown built-in directory role: {args.role}. "
            "For a custom role, pass its role template ID (GUID)."
        )

    display_name = (
        (active.get("displayName") if active is not None else None)
        or _template_name(template_id)
        or args.role
    )
    target = f"{user_id} -> {display_name}"

    if ctx.dry_run:
        requests: list[dict[str, Any]] = []
        if active is None:
            requests.append(
                {
                    "method": "POST",
                    "path": "/directoryRoles",
                    "body": {"roleTemplateId": template_id},
                }
            )
        requests.append(
            {
                "method": "POST",
                "path": (
                    f"/directoryRoles/"
                    f"{active['id'] if active is not None else '<activated-role-id>'}"
                    "/members/$ref"
                ),
                "body": _member_reference(user_id),
            }
        )
        dry_run(
            ctx,
            action="Assign directory role",
            target=target,
            payload={"requests": requests},
            expected=(
                "The directory role is activated if necessary and the user "
                "is assigned permanently."
            ),
            permissions="RoleManagement.ReadWrite.Directory",
        )
        return

    role = active
    if role is None:
        role = graph.post(
            "/directoryRoles",
            json_body={"roleTemplateId": template_id},
        )
    if not role or not role.get("id"):
        raise UsageError("The directory role could not be resolved after activation.")
    graph.post(
        f"/directoryRoles/{role['id']}/members/$ref",
        json_body=_member_reference(user_id),
    )
    ctx.console.kv("Assigned role", role.get("displayName") or display_name)
    ctx.console.kv("User", user_id)
    ctx.console.kv("Role ID", role.get("id", "-"))


def handle_remove(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_id = require_guid(args.user, "User")
    roles = graph.get_all("/directoryRoles", params={"$select": ROLE_SELECT})
    role = _find_active(roles, args.role)
    if role is None:
        raise UsageError(f"Directory role is not active or was not found: {args.role}")
    path = f"/directoryRoles/{role['id']}/members/{user_id}/$ref"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove directory role assignment",
            target=f"{user_id} <- {role.get('displayName')}",
            payload={"method": "DELETE", "path": path},
            expected="The user is removed from the directory role.",
            permissions="RoleManagement.ReadWrite.Directory",
        )
        return
    graph.delete(path)
    ctx.console.kv("Removed role", role.get("displayName", args.role))
    ctx.console.kv("User", user_id)
