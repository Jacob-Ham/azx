"""Human-readable rendering of API objects."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .util import humanize_odata_type

if TYPE_CHECKING:
    from .console import Output

_LABELS = {
    "@odata.type": "Type",
    "@odata.count": "Count",
    "id": "ID",
    "appId": "App ID",
    "objectId": "Object ID",
    "roleTemplateId": "Role template ID",
    "roleDefinitionId": "Role definition ID",
    "principalId": "Principal ID",
    "resourceId": "Resource ID",
    "appRoleId": "App role ID",
    "displayName": "Display name",
    "userPrincipalName": "User principal name",
    "givenName": "Given name",
    "surname": "Surname",
    "mail": "Mail",
    "mailNickname": "Mail nickname",
    "accountEnabled": "Account enabled",
    "securityEnabled": "Security enabled",
    "mailEnabled": "Mail enabled",
    "groupTypes": "Group types",
    "createdDateTime": "Created",
    "lastModifiedDateTime": "Last modified",
    "lastSyncDateTime": "Last sync",
    "signInAudience": "Sign-in audience",
    "publisherDomain": "Publisher domain",
    "identifierUris": "Identifier URIs",
    "passwordCredentials": "Password credentials",
    "keyCredentials": "Key credentials",
    "appRoles": "App roles",
    "servicePrincipalId": "Service principal ID",
    "servicePrincipalObjectId": "Service principal object ID",
    "temporaryAccessPass": "Temporary access pass",
    "temporaryAccessPassMethods": "Temporary access pass methods",
    "phoneNumber": "Phone number",
    "phoneType": "Phone type",
    "emailAddress": "Email address",
    "smsSignInState": "SMS sign-in state",
    "deviceTag": "Device tag",
    "phoneAppVersion": "Phone app version",
    "startDateTime": "Start",
    "endDateTime": "End",
    "lifetimeInMinutes": "Lifetime (minutes)",
    "isUsableOnce": "One-time",
    "methodUsabilityReason": "Status",
    "complianceState": "Compliance",
    "operatingSystem": "Operating system",
    "managedDeviceOwnerType": "Owner type",
    "deviceName": "Device name",
    "publisher": "Publisher",
    "appRoleAssignments": "App role assignments",
    "roleName": "Role name",
    "roleType": "Role type",
    "description": "Description",
    "state": "State",
    "tenantId": "Tenant ID",
    "subscriptionId": "Subscription ID",
    "subscription": "Subscription",
    "scope": "Scope",
    "principalType": "Principal type",
    "createdOn": "Created",
    "createdBy": "Created by",
    "modifiedBy": "Modified by",
    "tags": "Tags",
    "notes": "Notes",
    "defaultLifetimeInMinutes": "Default lifetime (minutes)",
    "minimumLifetimeInMinutes": "Minimum lifetime (minutes)",
    "maximumLifetimeInMinutes": "Maximum lifetime (minutes)",
    "defaultLength": "Default length",
    "authenticationMethodConfigurations": "Authentication method configurations",
}

_SKIP_KEYS = {"@odata.context", "@odata.nextLink", "@odata.etag"}


def human_label(key: str) -> str:
    if key in _LABELS:
        return _LABELS[key]
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    text = text.replace("_", " ").strip()
    if not text:
        return key
    return text[:1].upper() + text[1:]


def render_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, set)):
        rendered = [render_value(item) for item in value]
        return ", ".join(item for item in rendered if item != "-") or "-"
    if isinstance(value, dict):
        pieces = []
        for key, item in value.items():
            if key in _SKIP_KEYS:
                continue
            pieces.append(f"{human_label(key)}: {render_value(item)}")
        return "; ".join(pieces) or "-"
    return str(value)


def _table_columns(items: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    for item in items:
        for key in item:
            if key in _SKIP_KEYS:
                continue
            if key not in columns:
                columns.append(key)
    return columns


def _render_list(console: Output, items: list[Any]) -> None:
    if not items:
        console.line("-")
        return
    if all(isinstance(item, dict) for item in items):
        dictionaries = [item for item in items if isinstance(item, dict)]
        columns = _table_columns(dictionaries)
        if len(columns) <= 8:
            headers = [human_label(column) for column in columns]
            rows = [
                [
                    _render_type(item.get(column))
                    if column == "@odata.type"
                    else render_value(item.get(column))
                    for column in columns
                ]
                for item in dictionaries
            ]
            console.table(headers, rows)
            return
    for index, item in enumerate(items):
        if index:
            console.blank()
        if isinstance(item, dict):
            _render_dict(console, item)
        elif isinstance(item, list):
            _render_list(console, item)
        else:
            console.line(render_value(item))


def _render_type(value: Any) -> str:
    return humanize_odata_type(value)


def _render_dict(console: Output, data: dict[str, Any]) -> None:
    if not data:
        console.line("-")
        return
    for key, value in data.items():
        if key in _SKIP_KEYS:
            continue
        label = human_label(key)
        if key == "@odata.type":
            console.kv(label, _render_type(value))
        elif key == "value" and isinstance(value, list):
            _render_list(console, value)
        elif (
            isinstance(value, list)
            and value
            and all(isinstance(item, dict) for item in value)
        ):
            console.heading(f"{label}:")
            _render_list(console, value)
        elif isinstance(value, dict):
            console.heading(f"{label}:")
            _render_dict(console, value)
        else:
            console.kv(label, render_value(value))


def render_data(console: Output, value: Any) -> None:
    if isinstance(value, dict):
        _render_dict(console, value)
    elif isinstance(value, list):
        _render_list(console, value)
    else:
        console.line(render_value(value))
