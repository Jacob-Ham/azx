"""Helpers shared by command modules."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..api import GraphClient
from ..context import Context
from ..errors import UsageError
from ..util import humanize_odata_type, is_guid

USER_SELECT = (
    "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,"
    "jobTitle,department,officeLocation,mobilePhone,businessPhones,userType,"
    "onPremisesSyncEnabled"
)
GROUP_SELECT = (
    "id,displayName,mail,mailNickname,description,securityEnabled,"
    "mailEnabled,groupTypes,createdDateTime"
)


def require_user_reference(reference: str) -> str:
    """Return a user object ID or UPN accepted directly by Graph.

    Display names are rejected because resolving them needs an extra read.
    """
    ref = (reference or "").strip()
    if not ref:
        raise UsageError("User is required.")
    if not (is_guid(ref) or "@" in ref):
        raise UsageError(
            "User must be an object ID (GUID) or UPN; display names are not resolved."
        )
    return ref


def resolve_user(
    graph: GraphClient,
    reference: str,
    *,
    select: str = USER_SELECT,
) -> dict[str, Any]:
    ref = require_user_reference(reference)
    return graph.get(
        f"/users/{quote(ref, safe='@')}",
        params={"$select": select},
    )


def user_path_segment(reference: str) -> tuple[str, str]:
    """Return a user path segment and label without resolving anything."""
    ref = require_user_reference(reference)
    return quote(ref, safe="@"), ref


def resolve_group(graph: GraphClient, reference: str) -> dict[str, Any]:
    ref = (reference or "").strip()
    if not ref:
        raise UsageError("Group is required.")
    if not is_guid(ref):
        raise UsageError("Group must be an object ID (GUID).")
    return graph.get(f"/groups/{quote(ref)}", params={"$select": GROUP_SELECT})


def require_guid(reference: str, label: str) -> str:
    ref = (reference or "").strip()
    if not is_guid(ref):
        raise UsageError(f"{label} must be an object ID (GUID).")
    return ref


def odata_type(value: Any) -> str:
    return humanize_odata_type(value)


def dry_run(
    ctx: Context,
    *,
    action: str,
    target: str,
    expected: str,
    permissions: str,
    scope: str | None = None,
    payload: Any = None,
) -> None:
    ctx.console.line("Dry run: no changes will be made.", style="bold yellow")
    ctx.console.kv("Action", action)
    ctx.console.kv("Target", target)
    if scope is not None:
        ctx.console.kv("Scope", scope)
    if payload is not None:
        ctx.console.heading("Payload:")
        ctx.console.data(payload)
    ctx.console.kv("Expected change", expected)
    ctx.console.kv("Required permissions", permissions)
