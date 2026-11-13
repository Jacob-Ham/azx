"""Azure Resource Manager commands."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from ..api import ARM_BASE, ArmClient
from ..context import Context
from ..errors import ApiError, UsageError
from ..util import is_guid
from .common import dry_run

ROLE_API = "2022-04-01"
SUBSCRIPTIONS_API = "2022-12-01"
ELEVATE_API = "2015-07-01"


def _normalize_scope(value: str) -> str:
    text = (value or "/").strip()
    if text.lower().startswith(ARM_BASE):
        text = text[len(ARM_BASE) :] or "/"
    elif text.lower().startswith(("http://", "https://")):
        raise UsageError(f"Invalid ARM scope: {value!r}.")
    if text.lower().startswith("subscriptions/"):
        text = "/" + text
    if not text.startswith("/"):
        if is_guid(text):
            text = f"/subscriptions/{text}"
        else:
            text = "/" + text
    return text.rstrip("/") or "/"


def _scope_path(scope: str, suffix: str) -> str:
    return f"{scope.rstrip('/')}{suffix}"


def _find_role_definition(arm: ArmClient, scope: str, reference: str) -> dict[str, Any]:
    ref = (reference or "").strip()
    if not ref:
        raise UsageError("Role definition is required.")
    if ref.lower().startswith(ARM_BASE):
        ref = ref[len(ARM_BASE) :] or "/"
    if ref.startswith("/"):
        ref = ref.rstrip("/")
        if "/providers/microsoft.authorization/roledefinitions/" not in ref.lower():
            raise UsageError("The role must be a role definition ID.")
        return {"id": ref, "properties": {"roleName": ref.rsplit("/", 1)[-1]}}
    if not is_guid(ref):
        raise UsageError(
            "Azure role definition must be a GUID or full role definition ID."
        )
    try:
        return arm.get(
            _scope_path(
                scope,
                f"/providers/Microsoft.Authorization/roleDefinitions/{ref}",
            ),
            params={"api-version": ROLE_API},
        )
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        raise UsageError(f"Azure role definition not found: {reference}") from exc


def _role_name(definition: dict[str, Any]) -> str:
    properties = definition.get("properties", {})
    if isinstance(properties, dict) and properties.get("roleName"):
        return str(properties["roleName"])
    return str(definition.get("name") or definition.get("id") or "-")


def handle_subscriptions(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    subscriptions = arm.get_all(
        "/subscriptions", params={"api-version": SUBSCRIPTIONS_API}
    )
    if not subscriptions:
        ctx.console.line("No subscriptions found.")
        return
    ctx.console.table(
        ["NAME", "SUBSCRIPTION ID", "STATE", "TENANT"],
        [
            [
                subscription.get("displayName", "-"),
                subscription.get("subscriptionId", "-"),
                subscription.get("state", "-"),
                subscription.get("tenantId", "-"),
            ]
            for subscription in subscriptions
        ],
    )


def handle_elevate(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Elevate tenant root access",
            target="Tenant root",
            payload={
                "method": "POST",
                "path": "/providers/Microsoft.Authorization/elevateAccess",
                "api-version": ELEVATE_API,
            },
            expected=(
                "The calling principal receives User Access Administrator "
                "at the tenant root scope."
            ),
            permissions="Microsoft.Authorization/elevateAccess/action",
        )
        return
    arm.post(
        "/providers/Microsoft.Authorization/elevateAccess",
        params={"api-version": ELEVATE_API},
    )
    ctx.console.line(
        "Elevated tenant root access: User Access Administrator granted "
        "to the calling principal."
    )


def handle_role_list(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    scope = _normalize_scope(args.scope)
    assignments = arm.get_all(
        _scope_path(scope, "/providers/Microsoft.Authorization/roleAssignments"),
        params={"api-version": ROLE_API},
    )
    if not assignments:
        ctx.console.line("No Azure role assignments found.")
        return
    rows = []
    for assignment in assignments:
        properties = assignment.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        role_id = str(properties.get("roleDefinitionId", ""))
        rows.append(
            [
                role_id.rsplit("/", 1)[-1] or "-",
                properties.get("principalId", "-"),
                properties.get("principalType", "-"),
                properties.get("scope", scope),
                assignment.get("id") or assignment.get("name", "-"),
            ]
        )
    ctx.console.table(
        ["ROLE DEFINITION ID", "PRINCIPAL", "TYPE", "SCOPE", "ASSIGNMENT ID"],
        rows,
    )


def handle_role_assign(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    scope = _normalize_scope(args.scope)
    principal = args.principal.strip()
    if not is_guid(principal):
        raise UsageError("Azure RBAC principals must be directory object IDs (GUIDs).")
    definition = _find_role_definition(arm, scope, args.role)
    role_definition_id = definition.get("id")
    if not role_definition_id:
        raise UsageError("The Azure role definition has no ID.")
    properties: dict[str, Any] = {
        "roleDefinitionId": role_definition_id,
        "principalId": principal,
    }
    if args.principal_type:
        properties["principalType"] = args.principal_type
    payload = {"properties": properties}
    assignment_id = str(uuid4())
    path = _scope_path(
        scope,
        f"/providers/Microsoft.Authorization/roleAssignments/{assignment_id}",
    )
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Assign Azure RBAC role",
            target=f"{principal} -> {_role_name(definition)}",
            scope=scope,
            payload={
                "method": "PUT",
                "path": path,
                "api-version": ROLE_API,
                "body": payload,
            },
            expected="The principal receives the role at the requested scope.",
            permissions="Microsoft.Authorization/roleAssignments/write",
        )
        return
    assignment = arm.put(
        path,
        params={"api-version": ROLE_API},
        json_body=payload,
    )
    ctx.console.kv("Assigned role", _role_name(definition))
    ctx.console.kv("Principal", principal)
    ctx.console.kv("Scope", scope)
    ctx.console.kv(
        "Assignment ID",
        assignment.get("id") or assignment.get("name") or assignment_id,
    )


def handle_role_remove(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    value = args.assignment_id.strip()
    if value.lower().startswith(ARM_BASE):
        value = value[len(ARM_BASE) :] or "/"
    elif value.lower().startswith(("http://", "https://")):
        raise UsageError(f"Invalid role assignment ID: {args.assignment_id!r}.")
    if value.startswith("/"):
        path = value.split("?", 1)[0]
        if "/providers/microsoft.authorization/roleassignments/" not in (path.lower()):
            raise UsageError("The assignment ID must reference a role assignment.")
    elif is_guid(value):
        scope = _normalize_scope(args.scope)
        path = _scope_path(
            scope,
            f"/providers/Microsoft.Authorization/roleAssignments/{value}",
        )
    else:
        raise UsageError("Pass a role assignment ID, or a GUID with --scope.")
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove Azure RBAC role assignment",
            target=path,
            payload={
                "method": "DELETE",
                "path": path,
                "api-version": ROLE_API,
            },
            expected="The role assignment is removed.",
            permissions="Microsoft.Authorization/roleAssignments/delete",
        )
        return
    arm.delete(path, params={"api-version": ROLE_API})
    ctx.console.line(f"Removed role assignment: {path.rsplit('/', 1)[-1]}")
