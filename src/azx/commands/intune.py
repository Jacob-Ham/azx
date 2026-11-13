"""Intune inventory commands."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..util import format_api_datetime
from .common import odata_type


def handle_devices(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    devices = graph.get_all(
        "/deviceManagement/managedDevices",
        params={
            "$select": (
                "id,deviceName,userPrincipalName,operatingSystem,"
                "complianceState,lastSyncDateTime,managedDeviceOwnerType"
            ),
            "$top": "999",
        },
    )
    if not devices:
        ctx.console.line("No managed devices found.")
        return
    ctx.console.table(
        ["NAME", "USER", "OS", "COMPLIANCE", "LAST SYNC", "ID"],
        [
            [
                device.get("deviceName", "-"),
                device.get("userPrincipalName") or "-",
                device.get("operatingSystem") or "-",
                device.get("complianceState") or "-",
                format_api_datetime(device.get("lastSyncDateTime")),
                device.get("id", "-"),
            ]
            for device in devices
        ],
    )


def handle_apps(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    applications = graph.get_all(
        "/deviceManagement/mobileApps",
        params={"$top": "999"},
    )
    if not applications:
        ctx.console.line("No Intune applications found.")
        return
    ctx.console.table(
        ["NAME", "PUBLISHER", "TYPE", "ID"],
        [
            [
                application.get("displayName", "-"),
                application.get("publisher") or "-",
                odata_type(application.get("@odata.type")),
                application.get("id", "-"),
            ]
            for application in applications
        ],
    )
