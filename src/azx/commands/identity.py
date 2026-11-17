"""Identity commands: whoami and user queries."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..errors import TokenError
from ..util import format_api_datetime, format_list, yes_no
from .common import odata_type, resolve_user, user_path_segment


def handle_whoami(ctx: Context, args: Any) -> None:
    token = ctx.resolve_token()
    if not token.has_access_token:
        raise TokenError(f"Token '{token.name}' has no access token.")
    claims = token.claims
    ctx.console.kv("Token", token.name)
    ctx.console.kv("Type", token.type)
    ctx.console.kv("Principal", token.principal_display)
    ctx.console.kv("Principal ID", token.principal_id or "-")
    ctx.console.kv("Tenant", token.tenant_display)
    ctx.console.kv("Client", token.client_display)
    ctx.console.kv("App ID", token.app_id or "-")
    ctx.console.kv("Service principal object ID", token.service_principal_id or "-")
    ctx.console.kv("Audience", token.audience_text)
    ctx.console.kv("Scopes", format_list(token.scopes))
    ctx.console.kv("Roles", format_list(token.roles))
    expires = token.expires_at
    if expires is None:
        ctx.console.kv("Expires", "-")
    else:
        suffix = " (expired)" if token.expired else ""
        ctx.console.kv("Expires", expires.strftime("%Y-%m-%d %H:%M:%S") + suffix)
    ctx.console.kv("Source", token.source or "-")
    ctx.console.kv("File", token.path or "-")
    if claims.get("iss"):
        ctx.console.kv("Issuer", claims["iss"])


def handle_user_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user = resolve_user(graph, args.user)
    ctx.console.kv("ID", user.get("id", "-"))
    ctx.console.kv("Display name", user.get("displayName", "-"))
    ctx.console.kv("User principal name", user.get("userPrincipalName", "-"))
    ctx.console.kv("Mail", user.get("mail") or "-")
    ctx.console.kv("Account enabled", yes_no(user.get("accountEnabled")))
    ctx.console.kv("User type", user.get("userType") or "-")
    ctx.console.kv("Created", format_api_datetime(user.get("createdDateTime")))
    ctx.console.kv("Job title", user.get("jobTitle") or "-")
    ctx.console.kv("Department", user.get("department") or "-")
    ctx.console.kv("Office", user.get("officeLocation") or "-")
    ctx.console.kv("Mobile phone", user.get("mobilePhone") or "-")
    ctx.console.kv("Business phones", format_list(user.get("businessPhones")))
    ctx.console.kv(
        "On-premises sync enabled",
        yes_no(user.get("onPremisesSyncEnabled")),
    )


def handle_user_groups(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, _ = user_path_segment(args.user)
    groups = graph.get_all(
        f"/users/{user_segment}/memberOf/microsoft.graph.group",
        params={
            "$select": "id,displayName,mail,description,securityEnabled",
            "$top": "999",
        },
    )
    if not groups:
        ctx.console.line("No groups found.")
        return
    ctx.console.table(
        ["NAME", "MAIL", "SECURITY", "ID"],
        [
            [
                group.get("displayName", "-"),
                group.get("mail") or "-",
                yes_no(group.get("securityEnabled")),
                group.get("id", "-"),
            ]
            for group in groups
        ],
    )


def handle_user_roles(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, _ = user_path_segment(args.user)
    roles = graph.get_all(
        f"/users/{user_segment}/memberOf/microsoft.graph.directoryRole",
        params={
            "$select": "id,displayName,description,roleTemplateId",
            "$top": "999",
        },
    )
    if not roles:
        ctx.console.line("No directory roles found.")
        return
    ctx.console.table(
        ["NAME", "TEMPLATE ID", "DESCRIPTION", "ID"],
        [
            [
                role.get("displayName", "-"),
                role.get("roleTemplateId") or "-",
                role.get("description") or "-",
                role.get("id", "-"),
            ]
            for role in roles
        ],
    )


def handle_user_owned(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, _ = user_path_segment(args.user)
    objects = graph.get_all(
        f"/users/{user_segment}/ownedObjects",
        params={"$top": "999"},
    )
    if not objects:
        ctx.console.line("No owned objects found.")
        return
    ctx.console.table(
        ["NAME", "TYPE", "APP ID", "OBJECT ID"],
        [
            [
                item.get("displayName") or item.get("appId") or item.get("id", "-"),
                odata_type(item.get("@odata.type")),
                item.get("appId") or "-",
                item.get("id", "-"),
            ]
            for item in objects
        ],
        fold_columns={2, 3},
    )
