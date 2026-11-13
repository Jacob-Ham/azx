"""Authentication method commands."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..errors import UsageError
from ..util import format_api_datetime, humanize_odata_type, is_guid
from .common import dry_run, user_path_segment

_METHOD_PATHS = {
    "#microsoft.graph.phoneauthenticationmethod": "phoneMethods",
    "#microsoft.graph.microsoftauthenticatorauthenticationmethod": (
        "microsoftAuthenticatorMethods"
    ),
    "#microsoft.graph.softwareoathauthenticationmethod": "softwareOathMethods",
    "#microsoft.graph.fido2authenticationmethod": "fido2Methods",
    "#microsoft.graph.windowshelloforbusinessauthenticationmethod": (
        "windowsHelloForBusinessMethods"
    ),
    "#microsoft.graph.temporaryaccesspassauthenticationmethod": (
        "temporaryAccessPassMethods"
    ),
    "#microsoft.graph.emailauthenticationmethod": "emailMethods",
}


def _detail(method: dict[str, Any]) -> str:
    odata = str(method.get("@odata.type", "")).lower()
    if odata.endswith("phoneauthenticationmethod"):
        number = method.get("phoneNumber", "-")
        phone_type = method.get("phoneType", "-")
        sms = method.get("smsSignInState")
        detail = f"{number} ({phone_type})"
        if sms:
            detail += f", SMS sign-in: {sms}"
        return detail
    if odata.endswith("emailauthenticationmethod"):
        return str(method.get("emailAddress", "-"))
    if odata.endswith("microsoftauthenticatorauthenticationmethod"):
        detail = str(method.get("displayName") or "Microsoft Authenticator")
        if method.get("deviceTag"):
            detail += f" ({method['deviceTag']})"
        return detail
    if odata.endswith("temporaryaccesspassauthenticationmethod"):
        return (
            f"{format_api_datetime(method.get('startDateTime'))} - "
            f"{format_api_datetime(method.get('endDateTime'))}"
        )
    if odata.endswith("softwareoathauthenticationmethod"):
        return "Software OATH token"
    return str(method.get("displayName") or "-")


def handle_list(ctx: Context, args: Any) -> None:
    graph = ctx.graph()
    user_segment, _ = user_path_segment(args.user)
    methods = graph.get_all(f"/users/{user_segment}/authentication/methods")
    if not methods:
        ctx.console.line("No authentication methods found.")
        return
    ctx.console.table(
        ["TYPE", "DETAIL", "ID"],
        [
            [
                humanize_odata_type(method.get("@odata.type")),
                _detail(method),
                method.get("id", "-"),
            ]
            for method in methods
        ],
    )


def handle_add(ctx: Context, args: Any) -> None:
    if args.type == "authenticator":
        raise UsageError(
            "Microsoft Authenticator methods cannot be created through "
            "Microsoft Graph. Register the Authenticator app on the user's "
            "device, then verify it with `azx authmethod list`."
        )
    graph = ctx.graph()
    user_segment, target = user_path_segment(args.user)

    if args.type == "phone":
        if not args.phone_number:
            raise UsageError("--phone-number is required for --type phone.")
        phone_type = args.phone_type or "mobile"
        payload = {
            "phoneNumber": args.phone_number,
            "phoneType": phone_type,
        }
        path = f"/users/{user_segment}/authentication/phoneMethods"
        if ctx.dry_run:
            dry_run(
                ctx,
                action="Add phone authentication method",
                target=target,
                payload=payload,
                expected="The phone method is registered for the user.",
                permissions="UserAuthenticationMethod.ReadWrite.All",
            )
            return
        method = graph.post(path, json_body=payload)
        ctx.console.kv("Added phone method", args.phone_number)
        ctx.console.kv("Phone type", phone_type)
        ctx.console.kv("Method ID", method.get("id", "-"))
        return

    if args.type == "email":
        if not args.email:
            raise UsageError("--email is required for --type email.")
        payload = {"emailAddress": args.email}
        path = f"/users/{user_segment}/authentication/emailMethods"
        if ctx.dry_run:
            dry_run(
                ctx,
                action="Add email authentication method",
                target=target,
                payload=payload,
                expected="The email method is registered for the user.",
                permissions="UserAuthenticationMethod.ReadWrite.All",
            )
            return
        method = graph.post(path, json_body=payload, version="beta")
        ctx.console.kv("Added email method", args.email)
        ctx.console.kv("Method ID", method.get("id", "-"))
        return

    raise UsageError(f"Unsupported authentication method type: {args.type}")


def handle_remove(ctx: Context, args: Any) -> None:
    method_id = args.method_id.strip()
    if not is_guid(method_id):
        raise UsageError("METHOD_ID must be a GUID.")
    graph = ctx.graph()
    user_segment, user_label = user_path_segment(args.user)
    method = next(
        (
            item
            for item in graph.get_all(f"/users/{user_segment}/authentication/methods")
            if item.get("id") == method_id
        ),
        None,
    )
    if method is None:
        method = next(
            (
                item
                for item in graph.get_all(
                    f"/users/{user_segment}/authentication/methods",
                    version="beta",
                )
                if item.get("id") == method_id
            ),
            None,
        )
    if method is None:
        raise UsageError(f"Authentication method not found: {method_id}")
    raw_odata = str(method.get("@odata.type", ""))
    odata = raw_odata.lower()
    method_type = humanize_odata_type(raw_odata)
    if odata.endswith("passwordauthenticationmethod"):
        raise UsageError("The password authentication method cannot be removed.")
    segment = _METHOD_PATHS.get(odata)
    version = "beta" if segment == "emailMethods" else None
    if segment:
        path = f"/users/{user_segment}/authentication/{segment}/{method_id}"
    else:
        path = f"/users/{user_segment}/authentication/methods/{method_id}"
    if ctx.dry_run:
        dry_run(
            ctx,
            action="Remove authentication method",
            target=f"{method_type} {method_id} for {user_label}",
            payload={
                "method": "DELETE",
                "path": path,
                "version": version or "v1.0",
            },
            expected="The authentication method is removed from the user.",
            permissions="UserAuthenticationMethod.ReadWrite.All",
        )
        return
    graph.delete(path, version=version)
    ctx.console.line(f"Removed {method_type.lower()} method: {method_id}")
