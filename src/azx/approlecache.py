"""Local cache of app role IDs to permission names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .api import GraphClient
from .errors import AzxError
from .util import secure_path

CACHE_VERSION = 1
_FETCH_CHUNK = 20


def _empty_cache() -> dict[str, Any]:
    return {"version": CACHE_VERSION, "tenants": {}}


def _load_cache(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty_cache()
    if not isinstance(value, dict) or value.get("version") != CACHE_VERSION:
        return _empty_cache()
    if not isinstance(value.get("tenants"), dict):
        return _empty_cache()
    return value


def _tenant_resources(
    cache: dict[str, Any],
    tenant_id: str | None,
) -> dict[str, dict[str, str]]:
    tenants = cache.setdefault("tenants", {})
    tenant = tenants.setdefault(tenant_id or "unknown", {})
    resources = tenant.setdefault("resources", {})
    if not isinstance(resources, dict):
        resources = {}
        tenant["resources"] = resources
    return resources


def _role_name(role: dict[str, Any]) -> str:
    return str(
        role.get("value") or role.get("displayName") or role.get("id") or ""
    ).strip()


def _fetch_resource_roles(
    graph: GraphClient,
    resource_ids: set[str],
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    ids = sorted(resource_ids)
    for index in range(0, len(ids), _FETCH_CHUNK):
        chunk = ids[index : index + _FETCH_CHUNK]
        filter_expression = " or ".join(
            f"id eq '{resource_id}'" for resource_id in chunk
        )
        try:
            service_principals = graph.get_all(
                "/servicePrincipals",
                params={
                    "$filter": filter_expression,
                    "$select": "id,appId,displayName,appRoles",
                    "$top": "999",
                },
            )
        except AzxError:
            continue
        for service_principal in service_principals:
            resource_id = str(service_principal.get("id") or "")
            if not resource_id:
                continue
            roles: dict[str, str] = {}
            for role in service_principal.get("appRoles") or []:
                if not isinstance(role, dict):
                    continue
                role_id = str(role.get("id") or "")
                name = _role_name(role)
                if role_id and name:
                    roles[role_id] = name
            result[resource_id] = roles
    return result


def resolve_permission_names(
    graph: GraphClient,
    cache_path: Path,
    tenant_id: str | None,
    permissions: list[dict[str, Any]],
) -> dict[tuple[str, str], str]:
    """Return {(resource object ID, app role ID): permission name}."""
    if not permissions:
        return {}
    cache = _load_cache(cache_path)
    resources = _tenant_resources(cache, tenant_id)

    pending: set[str] = set()
    for permission in permissions:
        resource_id = str(permission.get("resourceId") or "")
        role_id = str(permission.get("appRoleId") or "")
        if not resource_id or not role_id:
            continue
        roles = resources.get(resource_id)
        if not isinstance(roles, dict) or role_id not in roles:
            pending.add(resource_id)

    if pending:
        fetched = _fetch_resource_roles(graph, pending)
        for resource_id in pending:
            resources[resource_id] = fetched.get(resource_id, {})
        try:
            cache_path.write_text(
                json.dumps(cache, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            secure_path(cache_path)
        except OSError:
            pass

    names: dict[tuple[str, str], str] = {}
    for permission in permissions:
        resource_id = str(permission.get("resourceId") or "")
        role_id = str(permission.get("appRoleId") or "")
        if not resource_id or not role_id:
            continue
        roles = resources.get(resource_id)
        if isinstance(roles, dict):
            name = roles.get(role_id)
            if isinstance(name, str) and name:
                names[(resource_id, role_id)] = name
    return names
