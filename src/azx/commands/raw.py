"""Read-only raw Graph and ARM GET commands."""

from __future__ import annotations

from typing import Any

from ..context import Context


def _graph_path(value: str) -> tuple[str, str]:
    path = value.strip()
    if path.lower().startswith("https://"):
        return path, "v1.0"
    if path.lower() in {"/beta", "beta"}:
        return "/", "beta"
    if path.lower().startswith("/beta/"):
        return path[len("/beta") :], "beta"
    if path.lower().startswith("beta/"):
        return "/" + path[len("beta/") :], "beta"
    if path.lower() in {"/v1.0", "v1.0"}:
        return "/", "v1.0"
    if path.lower().startswith("/v1.0/"):
        return path[len("/v1.0") :], "v1.0"
    if path.lower().startswith("v1.0/"):
        return "/" + path[len("v1.0/") :], "v1.0"
    if not path.startswith("/"):
        path = "/" + path
    return path, "v1.0"


def handle_graph_get(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    path, version = _graph_path(args.path)
    if path.lower().startswith("https://"):
        data = graph.get_absolute(path)
    else:
        data = graph.get(path, version=version)
    ctx.console.data(data)


def handle_arm_get(ctx: Context, args: Any) -> None:
    arm = ctx.arm()
    path = args.path.strip()
    if not path.lower().startswith("https://") and not path.startswith("/"):
        path = "/" + path
    data = arm.get(path)
    ctx.console.data(data)
