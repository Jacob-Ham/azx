"""Temporary Access Pass commands."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..context import Context
from ..errors import ApiError, UsageError
from ..util import (
    format_api_datetime,
    is_guid,
    normalize_datetime_arg,
    parse_expiry,
    yes_no,
)
from .common import dry_run, user_path_segment

_POLICY_CONFIG_PATH = (
    "/policies/authenticationMethodsPolicy/"
    "authenticationMethodConfigurations/temporaryAccessPass"
)
_POLICY_PATH = "/policies/authenticationMethodsPolicy"
_MIN_LIFETIME = 10
_MAX_LIFETIME = 43200


def _tap_path(user_id: str) -> str:
    return f"/users/{user_id}/authentication/temporaryAccessPassMethods"


def _status(method: dict[str, Any]) -> str:
    reason = method.get("methodUsabilityReason")
    if reason:
        return str(reason)
    start = parse_expiry(method.get("startDateTime"))
    end = parse_expiry(method.get("endDateTime"))
    now = datetime.now()
    if end is not None and end < now:
        return "expired"
    if start is not None and start > now:
        return "not started"
    return "usable"


def handle_create(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, user_label = user_path_segment(args.user)
    lifetime = args.lifetime
    if not isinstance(lifetime, int):
        raise UsageError("--lifetime must be an integer number of minutes.")
    if lifetime < _MIN_LIFETIME or lifetime > _MAX_LIFETIME:
        raise UsageError(
            "TAP lifetime must be between 10 and 43200 minutes (30 days); "
            "tenant policy may be narrower."
        )
    payload: dict[str, Any] = {
        "lifetimeInMinutes": lifetime,
        "isUsableOnce": bool(args.one_time),
    }
    if args.start:
        payload["startDateTime"] = normalize_datetime_arg(args.start)
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Create temporary access pass",
            target=user_label,
            payload=payload,
            expected="A temporary access pass is created and displayed once.",
            permissions="UserAuthenticationMethod.ReadWrite.All",
        )
        return
    method = graph.post(_tap_path(user_segment), json_body=payload)
    ctx.console.kv("Temporary access pass", method.get("temporaryAccessPass", "-"))
    ctx.console.kv("User", user_label)
    ctx.console.kv("Start", format_api_datetime(method.get("startDateTime")))
    ctx.console.kv("End", format_api_datetime(method.get("endDateTime")))
    ctx.console.kv(
        "Lifetime (minutes)",
        method.get("lifetimeInMinutes", lifetime),
    )
    ctx.console.kv("One-time", yes_no(method.get("isUsableOnce", args.one_time)))
    ctx.console.kv("Method ID", method.get("id", "-"))


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, _ = user_path_segment(args.user)
    methods = graph.get_all(_tap_path(user_segment))
    if not methods:
        ctx.console.line("No temporary access passes found.")
        return
    ctx.console.table(
        ["ID", "START", "END", "LIFETIME", "ONE-TIME", "STATUS"],
        [
            [
                method.get("id", "-"),
                format_api_datetime(method.get("startDateTime")),
                format_api_datetime(method.get("endDateTime")),
                method.get("lifetimeInMinutes", "-"),
                yes_no(method.get("isUsableOnce")),
                _status(method),
            ]
            for method in methods
        ],
    )


def handle_delete(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, user_label = user_path_segment(args.user)
    tap_id = args.tap_id.strip()
    if not is_guid(tap_id):
        raise UsageError("TAP ID must be a GUID.")
    path = f"{_tap_path(user_segment)}/{tap_id}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Delete temporary access pass",
            target=f"{tap_id} for {user_label}",
            payload={"method": "DELETE", "path": path},
            expected="The temporary access pass method is deleted.",
            permissions="UserAuthenticationMethod.ReadWrite.All",
        )
        return
    graph.delete(path)
    ctx.console.line(f"Deleted temporary access pass: {tap_id}")


def _try_get(graph: Any, path: str, version: str) -> dict[str, Any] | None:
    try:
        return graph.get(path, version=version)
    except ApiError as exc:
        if exc.status_code != 404:
            raise
        return None


def _policy_configuration(graph: Any) -> dict[str, Any]:
    for version in ("v1.0", "beta"):
        configuration = _try_get(graph, _POLICY_CONFIG_PATH, version)
        if configuration is not None:
            return configuration
    for version in ("v1.0", "beta"):
        policy = _try_get(graph, _POLICY_PATH, version)
        if policy is None:
            continue
        configurations = policy.get("authenticationMethodConfigurations", [])
        if isinstance(configurations, list):
            for item in configurations:
                if not isinstance(item, dict):
                    continue
                identifier = str(item.get("id", "")).lower()
                odata = str(item.get("@odata.type", "")).lower()
                if "temporaryaccesspass" in identifier or (
                    "temporaryaccesspass" in odata
                ):
                    return item
    raise UsageError("Temporary Access Pass policy configuration was not found.")


def handle_policy(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    configuration = _policy_configuration(graph)
    ctx.console.kv("State", configuration.get("state", "-"))
    ctx.console.kv(
        "Default lifetime (minutes)",
        configuration.get("defaultLifetimeInMinutes", "-"),
    )
    ctx.console.kv(
        "Minimum lifetime (minutes)",
        configuration.get("minimumLifetimeInMinutes", "-"),
    )
    ctx.console.kv(
        "Maximum lifetime (minutes)",
        configuration.get("maximumLifetimeInMinutes", "-"),
    )
    ctx.console.kv("Default length", configuration.get("defaultLength", "-"))
    ctx.console.kv(
        "One-time by default",
        yes_no(configuration.get("isUsableOnce")),
    )
