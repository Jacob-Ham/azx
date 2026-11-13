"""AZX command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .commands.apps import (
    handle_create as app_create,
    handle_delete as app_delete,
    handle_get as app_get,
    handle_list as app_list,
    handle_lock as app_lock,
    handle_owned_by as app_owned_by,
    handle_owner_list as app_owner_list,
    handle_secret_add as app_secret_add,
    handle_secret_list as app_secret_list,
    handle_secret_remove as app_secret_remove,
    handle_sp_create as app_sp_create,
    handle_sp_delete as app_sp_delete,
    handle_sp_get as app_sp_get,
    handle_sp_list as app_sp_list,
    handle_sp_owned_by as app_sp_owned_by,
    handle_sp_owner_list as app_sp_owner_list,
    handle_sp_secret_add as app_sp_secret_add,
    handle_sp_secret_list as app_sp_secret_list,
    handle_sp_secret_remove as app_sp_secret_remove,
    handle_unlock as app_unlock,
)
from .commands.auth_cmd import handle_auth_app
from .commands.azure import (
    handle_elevate,
    handle_role_assign as azure_role_assign,
    handle_role_list as azure_role_list,
    handle_role_remove as azure_role_remove,
    handle_subscriptions,
)
from .commands.groups import (
    handle_add_member,
    handle_create as group_create,
    handle_delete as group_delete,
    handle_get as group_get,
    handle_list as group_list,
    handle_members,
    handle_remove_member,
)
from .commands.identity import (
    handle_user_get,
    handle_user_groups,
    handle_user_owned,
    handle_user_roles,
    handle_whoami,
)
from .commands.intune import (
    handle_apps as intune_apps,
    handle_devices as intune_devices,
)
from .commands.methods import (
    handle_add as method_add,
    handle_list as method_list,
    handle_remove as method_remove,
)
from .commands.myapps import (
    handle_assign as myapps_assign,
    handle_list as myapps_list,
    handle_unassign as myapps_unassign,
)
from .commands.raw import handle_arm_get, handle_graph_get
from .commands.roles import (
    handle_assign as role_assign,
    handle_list as role_list,
    handle_list_members as role_list_members,
    handle_remove as role_remove,
)
from .commands.seamless import handle_auth_seamless
from .commands.taps import (
    handle_create as tap_create,
    handle_delete as tap_delete,
    handle_list as tap_list,
    handle_policy as tap_policy,
)
from .commands.token_cmds import (
    handle_current,
    handle_delete as token_delete,
    handle_export,
    handle_import,
    handle_list as token_list,
    handle_refresh as token_refresh,
    handle_select,
    handle_show,
)
from .config import Settings, resolve_tokens_dir
from .console import Output
from .context import Context
from .errors import AzxError
from .http import HttpClient
from .storage import TOKEN_SUFFIX, TokenStore

GLOBAL_USAGE_DESTS = {
    "token_name",
    "output",
    "proxy",
    "user_agent",
    "headers",
    "timeout",
    "debug_http",
    "dry_run",
}


def _is_global_action(action: argparse.Action) -> bool:
    return action.dest in GLOBAL_USAGE_DESTS


class AzxHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_usage(
        self,
        usage: str | None,
        actions: list[argparse.Action],
        groups: list[Any],
        prefix: str | None,
    ) -> str:
        filtered_actions = [
            action for action in actions if not _is_global_action(action)
        ]
        filtered_groups = [
            group
            for group in groups
            if not any(
                _is_global_action(action)
                for action in getattr(group, "_group_actions", [])
            )
        ]
        return super()._format_usage(usage, filtered_actions, filtered_groups, prefix)


class AzxArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", AzxHelpFormatter)
        super().__init__(*args, **kwargs)

    def format_usage(self) -> str:
        return "\n" + super().format_usage()

    def format_help(self) -> str:
        text = super().format_help()
        for header in ("positional arguments:", "options:", "global options:"):
            text = text.replace(f"\n{header}\n", f"\n\n{header}\n")
        return "\n" + text

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"\n{self.prog}: error: {message}\n")


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_argument_group("global options")
    group.add_argument(
        "--token",
        dest="token_name",
        metavar="NAME",
        default=argparse.SUPPRESS,
        help="Use a specific token for this command.",
    )
    group.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=argparse.SUPPRESS,
        help="Save exactly what is displayed to FILE.",
    )
    group.add_argument(
        "--proxy",
        metavar="URL",
        default=argparse.SUPPRESS,
        help="HTTP or SOCKS proxy URL; disables TLS certificate verification.",
    )
    group.add_argument(
        "-ua",
        "--user-agent",
        dest="user_agent",
        metavar="STRING",
        default=argparse.SUPPRESS,
        help="Custom HTTP User-Agent.",
    )
    group.add_argument(
        "-H",
        "--headers",
        dest="headers",
        action="append",
        metavar="HEADER",
        default=argparse.SUPPRESS,
        help='Additional request header as "Name: Value"; repeatable.',
    )
    group.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        default=argparse.SUPPRESS,
        help="HTTP request timeout in seconds.",
    )
    group.add_argument(
        "--debug",
        dest="debug_http",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print redacted HTTP requests and responses.",
    )
    group.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Resolve and display mutations without applying them.",
    )
    return parser


COMMON = _common_parser()

USER_HELP = "User object ID (GUID) or UPN."
USER_ID_HELP = "User object ID (GUID)."
GROUP_HELP = "Group object ID (GUID)."
MEMBER_HELP = "Directory object ID (GUID) of the user, group, or service principal."
CLIENT_ID_HELP = "Application client ID (appId GUID; object IDs are not accepted)."
SP_CLIENT_ID_HELP = (
    "Application client ID (appId GUID) associated with the service principal."
)
TOKEN_NAME_HELP = "Token name."
MYAPPS_USER_HELP = "User object ID (GUID)."


def _command(
    subparsers: Any, name: str, help_text: str, **kwargs: Any
) -> argparse.ArgumentParser:
    return subparsers.add_parser(name, parents=[COMMON], help=help_text, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = AzxArgumentParser(
        prog="azx",
        parents=[COMMON],
        description=(
            "Token vault and focused operator CLI for authorized Entra ID "
            "and Azure engagements."
        ),
        epilog=(
            "Argument convention:\n"
            "  The primary target is positional (USER, GROUP, CLIENT_ID, "
            "NAME,\n"
            "  ASSIGNMENT_ID, PRINCIPAL, PATH).\n"
            "  Secondary identifiers are flags (--member, --role, "
            "--tap-id, --method-id,\n"
            "  --key-id, --app, --type).\n"
            "  Object IDs are GUIDs. UPNs are accepted only where Graph "
            "accepts them\n"
            "  directly; display names are not resolved."
        ),
    )
    parser.add_argument("--version", action="version", version=f"azx {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="command")

    token = _command(subparsers, "token", "Manage stored tokens.")
    token_sub = token.add_subparsers(
        dest="token_command", required=True, metavar="command"
    )
    token_import = _command(
        token_sub, "import", "Import tokens from files or raw values."
    )
    token_import.add_argument(
        "files", nargs="*", metavar="FILE", help="Roadtools auth file(s)."
    )
    token_import.add_argument(
        "--tokenfile",
        action="append",
        metavar="PATH",
        help="Roadtools auth file to import.",
    )
    token_import.add_argument(
        "--access-token", metavar="TOKEN", help="Raw access token value."
    )
    token_import.add_argument(
        "--refresh-token", metavar="TOKEN", help="Raw refresh token value."
    )
    token_import.add_argument(
        "-n",
        "--name",
        metavar="NAME",
        help="Token name; generated when omitted.",
    )
    token_import.add_argument(
        "-c",
        "--client",
        metavar="CLIENT",
        help="Client alias or client ID.",
    )
    token_import.add_argument(
        "-t",
        "--tenant",
        metavar="TENANT",
        help="Tenant ID or domain.",
    )
    token_import.add_argument(
        "--force", action="store_true", help="Overwrite an existing token."
    )
    token_import.set_defaults(func=handle_import)

    token_list_parser = _command(token_sub, "list", "Show the token table.")
    token_list_parser.set_defaults(func=token_list)

    token_show_parser = _command(
        token_sub, "show", "Show token metadata and decoded claims."
    )
    token_show_parser.add_argument("name", metavar="NAME", help=TOKEN_NAME_HELP)
    token_show_parser.set_defaults(func=handle_show)

    token_select_parser = _command(token_sub, "select", "Select and activate a token.")
    token_select_parser.set_defaults(func=handle_select)

    token_current_parser = _command(
        token_sub, "current", "Print the active token name."
    )
    token_current_parser.set_defaults(func=handle_current)

    token_refresh_parser = _command(
        token_sub, "refresh", "Refresh a token using its stored refresh token."
    )
    token_refresh_parser.add_argument(
        "name",
        nargs="?",
        metavar="NAME",
        help="Token name; defaults to the active token.",
    )
    token_refresh_parser.set_defaults(func=token_refresh)

    token_delete_parser = _command(token_sub, "delete", "Delete a token file.")
    token_delete_parser.add_argument("name", metavar="NAME", help=TOKEN_NAME_HELP)
    token_delete_parser.set_defaults(func=token_delete)

    token_export_parser = _command(
        token_sub, "export", "Write a roadtools-compatible copy."
    )
    token_export_parser.add_argument("name", metavar="NAME", help=TOKEN_NAME_HELP)
    token_export_parser.add_argument(
        "--tokenfile",
        required=True,
        metavar="PATH",
        help="Destination file path.",
    )
    token_export_parser.set_defaults(func=handle_export)

    auth = _command(subparsers, "auth", "Authentication commands.")
    auth_sub = auth.add_subparsers(
        dest="auth_command", required=True, metavar="command"
    )
    auth_app = _command(
        auth_sub, "app", "Client-credentials authentication with a secret."
    )
    auth_app.add_argument(
        "-c",
        "--client",
        required=True,
        metavar="CLIENT",
        help="Client alias or application/client ID.",
    )
    auth_app.add_argument(
        "-p",
        "--password",
        required=True,
        metavar="SECRET",
        help="Client secret value.",
    )
    auth_app.add_argument(
        "-t",
        "--tenant",
        required=True,
        metavar="TENANT",
        help="Tenant ID or domain.",
    )
    auth_app.add_argument(
        "-r",
        "--resource",
        required=True,
        metavar="RESOURCE",
        help="Resource alias or resource URL.",
    )
    auth_app.add_argument(
        "-n",
        "--name",
        metavar="NAME",
        help="Token name; generated when omitted.",
    )
    auth_app.add_argument(
        "--force", action="store_true", help="Overwrite an existing token."
    )
    auth_app.set_defaults(func=handle_auth_app)

    auth_seamless = _command(
        auth_sub,
        "seamless",
        "Seamless SSO authentication using Kerberos tickets.",
    )
    auth_seamless.add_argument(
        "-t",
        "--tenant",
        required=True,
        metavar="DOMAIN",
        help="Tenant domain.",
    )
    auth_seamless.add_argument(
        "-r",
        "--resource",
        default="msgraph",
        metavar="RESOURCE",
        help="Resource alias or URL (default: msgraph).",
    )
    auth_seamless.add_argument(
        "-c",
        "--client",
        default="aadps",
        metavar="CLIENT",
        help="Client alias or client ID (default: aadps).",
    )
    auth_seamless.add_argument(
        "--ignore-sso-check",
        action="store_true",
        help="Proceed even if Seamless SSO is not detected.",
    )
    auth_seamless.add_argument(
        "-d",
        "--domain",
        metavar="DOMAIN",
        help="On-premises Active Directory domain.",
    )
    auth_seamless.add_argument(
        "--dc",
        "--dc-host",
        dest="dc_host",
        metavar="HOST",
        help="Domain controller hostname or IP address.",
    )
    auth_seamless.add_argument(
        "-u",
        "--username",
        metavar="USER",
        help="On-premises username.",
    )
    auth_seamless.add_argument(
        "-p",
        "--password",
        metavar="PASSWORD",
        help="On-premises password.",
    )
    auth_seamless.add_argument(
        "--ntlm",
        metavar="[LMHASH:]NTHASH",
        help="User NTLM hash.",
    )
    auth_seamless.add_argument(
        "--aes-key",
        "--aes",
        dest="aes_key",
        metavar="KEY",
        help="User AES 128/256 key.",
    )
    auth_seamless.add_argument(
        "--tgt",
        metavar="TGT",
        help="Base64 TGT or path to a kirbi/ccache file.",
    )
    auth_seamless.add_argument(
        "--tgs",
        metavar="TGS",
        help="Base64 TGS or path to a kirbi/ccache file.",
    )
    auth_seamless.add_argument(
        "--spn",
        metavar="SPN",
        help="Target SPN (default: HTTP/autologon.microsoftazuread-sso.com).",
    )
    auth_seamless.add_argument(
        "--domain-sid",
        metavar="SID",
        help="Domain SID for forged TGS.",
    )
    auth_seamless.add_argument(
        "--user-rid",
        metavar="RID",
        help="User RID for forged TGS.",
    )
    auth_seamless.add_argument(
        "--user-sid",
        metavar="SID",
        help="User SID for forged TGS.",
    )
    auth_seamless.add_argument(
        "--adssoacc-ntlm",
        metavar="[LMHASH:]NTHASH",
        help="AZUREADSSOACC account NTLM hash.",
    )
    auth_seamless.add_argument(
        "--adssoacc-aes",
        metavar="KEY",
        help="AZUREADSSOACC account AES 128/256 key.",
    )
    auth_seamless.add_argument(
        "-n",
        "--name",
        metavar="NAME",
        help="Token name; generated when omitted.",
    )
    auth_seamless.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing token.",
    )
    auth_seamless.set_defaults(func=handle_auth_seamless)

    whoami = _command(subparsers, "whoami", "Show the active token identity.")
    whoami.set_defaults(func=handle_whoami)

    user = _command(subparsers, "user", "User queries.")
    user_sub = user.add_subparsers(
        dest="user_command", required=True, metavar="command"
    )
    user_get = _command(user_sub, "get", "Get a user.")
    user_get.add_argument("user", metavar="USER", help=USER_HELP)
    user_get.set_defaults(func=handle_user_get)
    user_groups = _command(user_sub, "groups", "List a user's groups.")
    user_groups.add_argument("user", metavar="USER", help=USER_HELP)
    user_groups.set_defaults(func=handle_user_groups)
    user_roles = _command(user_sub, "roles", "List a user's directory roles.")
    user_roles.add_argument("user", metavar="USER", help=USER_HELP)
    user_roles.set_defaults(func=handle_user_roles)
    user_owned = _command(user_sub, "owned", "List a user's owned objects.")
    user_owned.add_argument("user", metavar="USER", help=USER_HELP)
    user_owned.set_defaults(func=handle_user_owned)

    group = _command(subparsers, "group", "Group commands.")
    group_sub = group.add_subparsers(
        dest="group_command", required=True, metavar="command"
    )
    group_list_parser = _command(group_sub, "list", "List groups.")
    group_list_parser.set_defaults(func=group_list)
    group_get_parser = _command(group_sub, "get", "Get a group.")
    group_get_parser.add_argument("group", metavar="GROUP", help=GROUP_HELP)
    group_get_parser.set_defaults(func=group_get)
    group_delete_parser = _command(group_sub, "delete", "Delete a group by object ID.")
    group_delete_parser.add_argument("group", metavar="GROUP", help=GROUP_HELP)
    group_delete_parser.set_defaults(func=group_delete)
    group_members_parser = _command(group_sub, "members", "List a group's members.")
    group_members_parser.add_argument("group", metavar="GROUP", help=GROUP_HELP)
    group_members_parser.set_defaults(func=handle_members)
    group_add_parser = _command(group_sub, "add-member", "Add a member to a group.")
    group_add_parser.add_argument("group", metavar="GROUP", help=GROUP_HELP)
    group_add_parser.add_argument(
        "--member",
        required=True,
        metavar="MEMBER",
        help=MEMBER_HELP,
    )
    group_add_parser.set_defaults(func=handle_add_member)
    group_remove_parser = _command(
        group_sub, "remove-member", "Remove a member from a group."
    )
    group_remove_parser.add_argument("group", metavar="GROUP", help=GROUP_HELP)
    group_remove_parser.add_argument(
        "--member",
        required=True,
        metavar="MEMBER",
        help=MEMBER_HELP,
    )
    group_remove_parser.set_defaults(func=handle_remove_member)
    group_create_parser = _command(group_sub, "create", "Create a security group.")
    group_create_parser.add_argument("name", metavar="NAME", help="Group display name.")
    group_create_parser.add_argument(
        "-d",
        "--description",
        metavar="TEXT",
        help="Optional group description.",
    )
    group_create_parser.add_argument(
        "--mail-nickname",
        metavar="NAME",
        help="Optional mail nickname; generated from the name by default.",
    )
    group_create_parser.set_defaults(func=group_create)

    tap = _command(subparsers, "tap", "Temporary Access Pass commands.")
    tap_sub = tap.add_subparsers(dest="tap_command", required=True, metavar="command")
    tap_create_parser = _command(tap_sub, "create", "Create a TAP.")
    tap_create_parser.add_argument("user", metavar="USER", help=USER_HELP)
    tap_create_parser.add_argument(
        "--lifetime",
        type=int,
        default=60,
        metavar="MINUTES",
        help=(
            "TAP lifetime in minutes (default: 60; tenant policy may "
            "narrow the valid range)."
        ),
    )
    tap_usage = tap_create_parser.add_mutually_exclusive_group()
    tap_usage.add_argument(
        "--one-time",
        dest="one_time",
        action="store_true",
        default=True,
        help="Create a one-time pass (default).",
    )
    tap_usage.add_argument(
        "--multi-use",
        dest="one_time",
        action="store_false",
        help="Create a reusable multi-use pass.",
    )
    tap_create_parser.add_argument(
        "--start", metavar="DATETIME", help="Optional UTC start time."
    )
    tap_create_parser.set_defaults(func=tap_create)
    tap_list_parser = _command(tap_sub, "list", "List a user's TAPs.")
    tap_list_parser.add_argument("user", metavar="USER", help=USER_HELP)
    tap_list_parser.set_defaults(func=tap_list)
    tap_delete_parser = _command(tap_sub, "delete", "Delete a TAP.")
    tap_delete_parser.add_argument("user", metavar="USER", help=USER_HELP)
    tap_delete_parser.add_argument(
        "--tap-id",
        dest="tap_id",
        required=True,
        metavar="TAP_ID",
        help="Temporary Access Pass method ID (GUID).",
    )
    tap_delete_parser.set_defaults(func=tap_delete)
    tap_policy_parser = _command(
        tap_sub, "policy", "Show the TAP policy configuration."
    )
    tap_policy_parser.set_defaults(func=tap_policy)

    method = _command(subparsers, "authmethod", "Authentication method commands.")
    method_sub = method.add_subparsers(
        dest="method_command", required=True, metavar="command"
    )
    method_list_parser = _command(
        method_sub, "list", "List a user's authentication methods."
    )
    method_list_parser.add_argument("user", metavar="USER", help=USER_HELP)
    method_list_parser.set_defaults(func=method_list)
    method_add_parser = _command(method_sub, "add", "Add an authentication method.")
    method_add_parser.add_argument("user", metavar="USER", help=USER_HELP)
    method_add_parser.add_argument(
        "--type",
        required=True,
        choices=["phone", "email", "authenticator"],
        help="Authentication method type.",
    )
    method_add_parser.add_argument(
        "--phone-number",
        metavar="NUMBER",
        help="Phone number; required with --type phone.",
    )
    method_add_parser.add_argument(
        "--phone-type",
        choices=["mobile", "office", "alternateMobile"],
        help="Phone type; defaults to mobile.",
    )
    method_add_parser.add_argument(
        "--email",
        metavar="ADDRESS",
        help="Email address; required with --type email.",
    )
    method_add_parser.set_defaults(func=method_add)
    method_remove_parser = _command(
        method_sub, "remove", "Remove an authentication method."
    )
    method_remove_parser.add_argument("user", metavar="USER", help=USER_HELP)
    method_remove_parser.add_argument(
        "--method-id",
        dest="method_id",
        required=True,
        metavar="METHOD_ID",
        help="Authentication method ID (GUID).",
    )
    method_remove_parser.set_defaults(func=method_remove)

    role = _command(subparsers, "role", "Entra directory role commands.")
    role_sub = role.add_subparsers(
        dest="role_command", required=True, metavar="command"
    )
    role_list_parser = _command(role_sub, "list", "List active directory roles.")
    role_list_parser.set_defaults(func=role_list)
    role_list_members_parser = _command(
        role_sub, "list-members", "List members of a directory role."
    )
    role_list_members_parser.add_argument(
        "role",
        metavar="ROLE",
        help="Built-in directory role name, template ID, or active role ID.",
    )
    role_list_members_parser.set_defaults(func=role_list_members)
    role_assign_parser = _command(
        role_sub, "assign", "Assign a permanent directory role."
    )
    role_assign_parser.add_argument("user", metavar="USER", help=USER_ID_HELP)
    role_assign_parser.add_argument(
        "--role",
        required=True,
        metavar="ROLE",
        help="Built-in directory role name or role template ID.",
    )
    role_assign_parser.set_defaults(func=role_assign)
    role_remove_parser = _command(
        role_sub, "remove", "Remove a directory role assignment."
    )
    role_remove_parser.add_argument("user", metavar="USER", help=USER_ID_HELP)
    role_remove_parser.add_argument(
        "--role",
        required=True,
        metavar="ROLE",
        help="Built-in directory role name or role template ID.",
    )
    role_remove_parser.set_defaults(func=role_remove)

    azure = _command(subparsers, "azure", "Azure Resource Manager commands.")
    azure_sub = azure.add_subparsers(
        dest="azure_command", required=True, metavar="command"
    )
    azure_elevate_parser = _command(azure_sub, "elevate", "Elevate tenant root access.")
    azure_elevate_parser.set_defaults(func=handle_elevate)
    azure_subscriptions_parser = _command(
        azure_sub, "subscriptions", "List Azure subscriptions."
    )
    azure_subscriptions_parser.set_defaults(func=handle_subscriptions)
    azure_role = _command(azure_sub, "role", "Azure RBAC commands.")
    azure_role_sub = azure_role.add_subparsers(
        dest="azure_role_command", required=True, metavar="command"
    )
    azure_role_list_parser = _command(
        azure_role_sub, "list", "List Azure RBAC assignments and role definition IDs."
    )
    azure_role_list_parser.add_argument(
        "--scope", default="/", metavar="SCOPE", help="ARM scope; defaults to /."
    )
    azure_role_list_parser.set_defaults(func=azure_role_list)
    azure_role_assign_parser = _command(
        azure_role_sub, "assign", "Assign an Azure RBAC role."
    )
    azure_role_assign_parser.add_argument(
        "principal",
        metavar="PRINCIPAL_ID",
        help=("Directory object ID (GUID) of the user, group, or service principal."),
    )
    azure_role_assign_parser.add_argument(
        "--role",
        required=True,
        metavar="ROLE",
        help=(
            "Azure role definition ID (GUID or full resource ID; the full "
            "ID avoids a lookup)."
        ),
    )
    azure_role_assign_parser.add_argument(
        "--scope", default="/", metavar="SCOPE", help="ARM scope; defaults to /."
    )
    azure_role_assign_parser.add_argument(
        "--principal-type",
        choices=["User", "Group", "ServicePrincipal", "ForeignGroup", "Device"],
        help="Optional ARM principal type.",
    )
    azure_role_assign_parser.set_defaults(func=azure_role_assign)
    azure_role_remove_parser = _command(
        azure_role_sub, "remove", "Remove an Azure RBAC assignment."
    )
    azure_role_remove_parser.add_argument(
        "assignment_id",
        metavar="ASSIGNMENT_ID",
        help="Full assignment ID, or a GUID together with --scope.",
    )
    azure_role_remove_parser.add_argument(
        "--scope", default="/", metavar="SCOPE", help="ARM scope; defaults to /."
    )
    azure_role_remove_parser.set_defaults(func=azure_role_remove)

    app = _command(subparsers, "app", "Application registration commands.")
    app_sub = app.add_subparsers(dest="app_command", required=True, metavar="command")
    app_create_parser = _command(
        app_sub, "create", "Create an application registration (prints its client ID)."
    )
    app_create_parser.add_argument(
        "name", metavar="NAME", help="Application display name."
    )
    app_create_parser.set_defaults(func=app_create)
    app_list_parser = _command(
        app_sub, "list", "List applications and their client/object IDs."
    )
    app_list_parser.set_defaults(func=app_list)
    app_get_parser = _command(app_sub, "get", "Get an application by client ID.")
    app_get_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_get_parser.set_defaults(func=app_get)
    app_delete_parser = _command(
        app_sub,
        "delete",
        "Delete an application registration by client ID.",
    )
    app_delete_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_delete_parser.set_defaults(func=app_delete)
    app_lock_parser = _command(
        app_sub, "lock", "Lock sensitive service principal properties."
    )
    app_lock_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_lock_parser.add_argument(
        "--all",
        action="store_true",
        help="Lock all sensitive properties (default).",
    )
    app_lock_parser.add_argument(
        "--verify",
        action="store_true",
        help="Lock credentials used for verification (OIDC client credentials).",
    )
    app_lock_parser.add_argument(
        "--sign",
        action="store_true",
        help="Lock credentials used for token signing (SAML).",
    )
    app_lock_parser.add_argument(
        "--token-key",
        dest="token_key",
        action="store_true",
        help="Lock the token encryption key ID.",
    )
    app_lock_parser.set_defaults(func=app_lock)
    app_unlock_parser = _command(
        app_sub, "unlock", "Unlock sensitive service principal properties."
    )
    app_unlock_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_unlock_parser.set_defaults(func=app_unlock)
    app_secret = _command(app_sub, "secret", "Application client secrets.")
    app_secret_sub = app_secret.add_subparsers(
        dest="app_secret_command", required=True, metavar="command"
    )
    app_secret_add_parser = _command(
        app_secret_sub, "add", "Add a client secret by application client ID."
    )
    app_secret_add_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_secret_add_parser.add_argument(
        "--secret-name",
        required=True,
        metavar="NAME",
        help="Secret display name.",
    )
    app_secret_add_parser.add_argument(
        "--lifetime",
        type=int,
        default=365,
        metavar="DAYS",
        help="Secret lifetime in days (default: 365).",
    )
    app_secret_add_parser.set_defaults(func=app_secret_add)
    app_secret_remove_parser = _command(
        app_secret_sub, "remove", "Remove a client secret by application client ID."
    )
    app_secret_remove_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_secret_remove_parser.add_argument(
        "--key-id",
        dest="key_id",
        required=True,
        metavar="KEY_ID",
        help="Client secret key ID (GUID).",
    )
    app_secret_remove_parser.set_defaults(func=app_secret_remove)
    app_secret_list_parser = _command(
        app_secret_sub, "list", "List client secrets by application client ID."
    )
    app_secret_list_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_secret_list_parser.set_defaults(func=app_secret_list)
    app_owner = _command(app_sub, "owner", "Application owners.")
    app_owner_sub = app_owner.add_subparsers(
        dest="app_owner_command", required=True, metavar="command"
    )
    app_owner_list_parser = _command(
        app_owner_sub, "list", "List application owners by client ID."
    )
    app_owner_list_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=CLIENT_ID_HELP,
    )
    app_owner_list_parser.set_defaults(func=app_owner_list)
    app_owned_by_parser = _command(
        app_sub, "owned-by", "List applications owned by a principal."
    )
    app_owned_by_parser.add_argument(
        "principal",
        metavar="PRINCIPAL",
        help=(
            "User UPN, user object ID, or service principal object ID; "
            "GUIDs need --type."
        ),
    )
    app_owned_by_parser.add_argument(
        "--type",
        dest="principal_type",
        choices=["user", "service-principal"],
        help="Principal kind; required with a GUID, unnecessary with a UPN.",
    )
    app_owned_by_parser.set_defaults(func=app_owned_by)

    app_sp = _command(app_sub, "sp", "Service principal commands.")
    app_sp_sub = app_sp.add_subparsers(
        dest="app_sp_command", required=True, metavar="command"
    )
    app_sp_list_parser = _command(app_sp_sub, "list", "List service principals.")
    app_sp_list_parser.set_defaults(func=app_sp_list)
    app_sp_get_parser = _command(
        app_sp_sub, "get", "Get a service principal by client ID."
    )
    app_sp_get_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_get_parser.set_defaults(func=app_sp_get)
    app_sp_create_parser = _command(
        app_sp_sub,
        "create",
        "Create a service principal from an application registration.",
    )
    app_sp_create_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_create_parser.add_argument(
        "--display-name",
        metavar="NAME",
        help="Optional service principal display name.",
    )
    app_sp_create_parser.set_defaults(func=app_sp_create)
    app_sp_delete_parser = _command(
        app_sp_sub, "delete", "Delete a service principal by client ID."
    )
    app_sp_delete_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_delete_parser.set_defaults(func=app_sp_delete)
    app_sp_secret = _command(app_sp_sub, "secret", "Service principal secrets.")
    app_sp_secret_sub = app_sp_secret.add_subparsers(
        dest="app_sp_secret_command", required=True, metavar="command"
    )
    app_sp_secret_add_parser = _command(
        app_sp_secret_sub,
        "add",
        "Add a secret to a service principal by client ID.",
    )
    app_sp_secret_add_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_secret_add_parser.add_argument(
        "--secret-name",
        required=True,
        metavar="NAME",
        help="Secret display name.",
    )
    app_sp_secret_add_parser.add_argument(
        "--lifetime",
        type=int,
        default=365,
        metavar="DAYS",
        help="Secret lifetime in days (default: 365).",
    )
    app_sp_secret_add_parser.set_defaults(func=app_sp_secret_add)
    app_sp_secret_remove_parser = _command(
        app_sp_secret_sub,
        "remove",
        "Remove a secret from a service principal by client ID.",
    )
    app_sp_secret_remove_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_secret_remove_parser.add_argument(
        "--key-id",
        dest="key_id",
        required=True,
        metavar="KEY_ID",
        help="Secret key ID (GUID).",
    )
    app_sp_secret_remove_parser.set_defaults(func=app_sp_secret_remove)
    app_sp_secret_list_parser = _command(
        app_sp_secret_sub,
        "list",
        "List secrets on a service principal by client ID.",
    )
    app_sp_secret_list_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_secret_list_parser.set_defaults(func=app_sp_secret_list)
    app_sp_owner = _command(app_sp_sub, "owner", "Service principal owners.")
    app_sp_owner_sub = app_sp_owner.add_subparsers(
        dest="app_sp_owner_command", required=True, metavar="command"
    )
    app_sp_owner_list_parser = _command(
        app_sp_owner_sub, "list", "List service principal owners by client ID."
    )
    app_sp_owner_list_parser.add_argument(
        "client_id",
        metavar="CLIENT_ID",
        help=SP_CLIENT_ID_HELP,
    )
    app_sp_owner_list_parser.set_defaults(func=app_sp_owner_list)
    app_sp_owned_by_parser = _command(
        app_sp_sub, "owned-by", "List service principals owned by a principal."
    )
    app_sp_owned_by_parser.add_argument(
        "principal",
        metavar="PRINCIPAL",
        help=(
            "User UPN, user object ID, or service principal object ID; "
            "GUIDs need --type."
        ),
    )
    app_sp_owned_by_parser.add_argument(
        "--type",
        dest="principal_type",
        choices=["user", "service-principal"],
        help="Principal kind; required with a GUID, unnecessary with a UPN.",
    )
    app_sp_owned_by_parser.set_defaults(func=app_sp_owned_by)

    myapps = _command(
        subparsers,
        "myapps",
        "Enterprise application role assignments.",
    )
    myapps_sub = myapps.add_subparsers(
        dest="myapps_command", required=True, metavar="command"
    )
    myapps_list_parser = _command(
        myapps_sub, "list", "List enterprise application assignments."
    )
    myapps_list_parser.add_argument(
        "user",
        nargs="?",
        metavar="USER",
        help="Optional user object ID (GUID); defaults to the active token.",
    )
    myapps_list_parser.set_defaults(func=myapps_list)
    myapps_assign_parser = _command(
        myapps_sub, "assign", "Assign a user to an enterprise application."
    )
    myapps_assign_parser.add_argument("user", metavar="USER", help=MYAPPS_USER_HELP)
    myapps_assign_parser.add_argument(
        "--app",
        dest="client_id",
        required=True,
        metavar="APP",
        help=("Enterprise application appId or service principal object ID (GUID)."),
    )
    myapps_assign_parser.add_argument(
        "--role",
        metavar="ROLE",
        help=(
            "App role display name, value, or ID; required when the "
            "enterprise application exposes user roles."
        ),
    )
    myapps_assign_parser.set_defaults(func=myapps_assign)
    myapps_unassign_parser = _command(
        myapps_sub, "unassign", "Unassign a user from an enterprise application."
    )
    myapps_unassign_parser.add_argument("user", metavar="USER", help=MYAPPS_USER_HELP)
    myapps_unassign_parser.add_argument(
        "--app",
        dest="client_id",
        required=True,
        metavar="APP",
        help=("Enterprise application appId or service principal object ID (GUID)."),
    )
    myapps_unassign_parser.add_argument(
        "--role",
        metavar="ROLE",
        help="App role display name, value, or ID.",
    )
    myapps_unassign_parser.set_defaults(func=myapps_unassign)

    intune = _command(subparsers, "intune", "Intune inventory commands.")
    intune_sub = intune.add_subparsers(
        dest="intune_command", required=True, metavar="command"
    )
    intune_devices_parser = _command(intune_sub, "devices", "List managed devices.")
    intune_devices_parser.set_defaults(func=intune_devices)
    intune_apps_parser = _command(intune_sub, "apps", "List Intune apps.")
    intune_apps_parser.set_defaults(func=intune_apps)

    graph = _command(subparsers, "graph", "Raw Graph commands.")
    graph_sub = graph.add_subparsers(
        dest="graph_command", required=True, metavar="command"
    )
    graph_get_parser = _command(graph_sub, "get", "Run a Graph GET request.")
    graph_get_parser.add_argument(
        "path", metavar="PATH", help="Graph path or full Graph URL."
    )
    graph_get_parser.set_defaults(func=handle_graph_get)

    arm = _command(subparsers, "arm", "Raw ARM commands.")
    arm_sub = arm.add_subparsers(dest="arm_command", required=True, metavar="command")
    arm_get_parser = _command(arm_sub, "get", "Run an ARM GET request.")
    arm_get_parser.add_argument(
        "path", metavar="PATH", help="ARM path or full ARM URL."
    )
    arm_get_parser.set_defaults(func=handle_arm_get)

    return parser


def _output_conflicts(args: Any, output: Path) -> str | None:
    candidates: list[str] = []
    files = getattr(args, "files", None)
    if isinstance(files, list):
        candidates.extend(str(value) for value in files)
    tokenfile = getattr(args, "tokenfile", None)
    if isinstance(tokenfile, str):
        candidates.append(tokenfile)
    elif isinstance(tokenfile, list):
        candidates.extend(str(value) for value in tokenfile)
    output_resolved = output.expanduser().resolve()
    for candidate in candidates:
        if Path(candidate).expanduser().resolve() == output_resolved:
            return f"--output {output} conflicts with token file {candidate}."
    return None


def _output_path(args: Any) -> Path | None:
    value = getattr(args, "output", None)
    return Path(value).expanduser() if value else None


def _is_protected_output(path: Path, tokens_dir: Path) -> bool:
    try:
        target = path.resolve()
        directory = tokens_dir.resolve()
    except (OSError, RuntimeError):
        return False
    if target.parent != directory:
        return False
    return target.name == "active" or target.name.endswith(TOKEN_SUFFIX)


def _plain_error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        raw_output = _output_path(args)
        if raw_output is not None:
            if _is_protected_output(raw_output, resolve_tokens_dir()):
                _plain_error(
                    "Refusing to write the output transcript over the token "
                    f"store file {raw_output}."
                )
                return 1
            conflict = _output_conflicts(args, raw_output)
            if conflict:
                _plain_error(conflict)
                return 1
    except (OSError, RuntimeError) as exc:
        _plain_error(f"Cannot resolve output path: {exc}")
        return 1

    console: Output | None = None
    http: HttpClient | None = None
    try:
        console = Output(raw_output)
        settings = Settings.from_args(args)
        store = TokenStore(settings)
        store.ensure()
        http = HttpClient(settings, console)
        ctx = Context(settings, console, store, http)
        console.blank()
        args.func(ctx, args)
        console.ensure_trailing_blank()
        return 0
    except AzxError as exc:
        if console is not None:
            console.error(str(exc))
        else:
            _plain_error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        if console is not None:
            console.error("Cancelled.")
        else:
            _plain_error("Cancelled.")
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:  # pragma: no cover - defensive fallback
        if os.environ.get("AZX_DEBUG"):
            raise
        message = f"Unexpected error: {exc}"
        if console is not None:
            console.error(message)
        else:
            _plain_error(message)
        return 1
    finally:
        if http is not None:
            http.close()
        if console is not None:
            console.close()
