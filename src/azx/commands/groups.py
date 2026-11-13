"""Group commands."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..errors import ApiError, UsageError
from ..util import (
    format_api_datetime,
    format_list,
    slugify,
    yes_no,
)
from .common import dry_run, odata_type, require_guid, resolve_group


def _group_type(group: dict[str, Any]) -> str:
    group_types = group.get("groupTypes") or []
    if "Unified" in group_types:
        return "Microsoft 365"
    if group.get("securityEnabled"):
        return "Security"
    if group.get("mailEnabled"):
        return "Distribution"
    return "Group"


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    groups = graph.get_all(
        "/groups",
        params={
            "$select": (
                "id,displayName,mail,description,securityEnabled,mailEnabled,groupTypes"
            ),
            "$top": "999",
        },
    )
    if not groups:
        ctx.console.line("No groups found.")
        return
    ctx.console.table(
        ["NAME", "TYPE", "MAIL", "ID"],
        [
            [
                group.get("displayName", "-"),
                _group_type(group),
                group.get("mail") or "-",
                group.get("id", "-"),
            ]
            for group in groups
        ],
    )


def handle_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    group = resolve_group(graph, args.group)
    ctx.console.kv("ID", group.get("id", "-"))
    ctx.console.kv("Display name", group.get("displayName", "-"))
    ctx.console.kv("Description", group.get("description") or "-")
    ctx.console.kv("Mail", group.get("mail") or "-")
    ctx.console.kv("Mail nickname", group.get("mailNickname") or "-")
    ctx.console.kv("Type", _group_type(group))
    ctx.console.kv("Security enabled", yes_no(group.get("securityEnabled")))
    ctx.console.kv("Mail enabled", yes_no(group.get("mailEnabled")))
    ctx.console.kv("Group types", format_list(group.get("groupTypes")))
    ctx.console.kv("Created", format_api_datetime(group.get("createdDateTime")))


def handle_members(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    group_id = require_guid(args.group, "Group")
    members = graph.get_all(
        f"/groups/{group_id}/members",
        params={"$top": "999"},
    )
    if not members:
        ctx.console.line("No group members found.")
        return
    ctx.console.table(
        ["NAME", "TYPE", "PRINCIPAL", "ID"],
        [
            [
                member.get("displayName")
                or member.get("userPrincipalName")
                or member.get("id", "-"),
                odata_type(member.get("@odata.type")),
                member.get("userPrincipalName") or member.get("mail") or "-",
                member.get("id", "-"),
            ]
            for member in members
        ],
    )


def _member_reference(member_id: str) -> dict[str, str]:
    return {
        "@odata.id": (f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}")
    }


def handle_add_member(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    group_id = require_guid(args.group, "Group")
    member_id = require_guid(args.member, "Member")
    payload = _member_reference(member_id)
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Add group member",
            target=f"{member_id} -> {group_id}",
            payload=payload,
            expected="The directory object becomes a member of the group.",
            permissions="Group.ReadWrite.All",
        )
        return
    graph.post(f"/groups/{group_id}/members/$ref", json_body=payload)
    ctx.console.line(f"Added member {member_id} to group {group_id}")


def handle_remove_member(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    group_id = require_guid(args.group, "Group")
    member_id = require_guid(args.member, "Member")
    path = f"/groups/{group_id}/members/{member_id}/$ref"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove group member",
            target=f"{member_id} <- {group_id}",
            payload={"method": "DELETE", "path": path},
            expected="The directory object is removed from the group.",
            permissions="Group.ReadWrite.All",
        )
        return
    graph.delete(path)
    ctx.console.line(f"Removed member {member_id} from group {group_id}")


def handle_delete(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    group_id = require_guid(args.group, "Group")
    path = f"/groups/{group_id}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Delete group",
            target=group_id,
            payload={"method": "DELETE", "path": path},
            expected=("The group is soft-deleted and can be restored for 30 days."),
            permissions="Group.ReadWrite.All",
        )
        return
    try:
        graph.delete(path)
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(f"Group not found: {group_id}") from exc
    ctx.console.line(f"Deleted group: {group_id}")


def handle_create(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    name = (args.name or "").strip()
    if not name:
        raise UsageError("Group name is required.")
    mail_nickname = args.mail_nickname or slugify(name, fallback="group")[:64]
    payload: dict[str, Any] = {
        "displayName": name,
        "mailEnabled": False,
        "mailNickname": mail_nickname,
        "securityEnabled": True,
        "groupTypes": [],
    }
    if args.description:
        payload["description"] = args.description
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Create security group",
            target=name,
            payload=payload,
            expected="A new security group is created.",
            permissions="Group.ReadWrite.All",
        )
        return
    group = graph.post("/groups", json_body=payload)
    ctx.console.kv("Created group", group.get("displayName", name))
    ctx.console.kv("ID", group.get("id", "-"))
    ctx.console.kv("Mail nickname", group.get("mailNickname", mail_nickname))
