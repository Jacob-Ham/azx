"""Roadtools-compatible resource and client aliases."""

from __future__ import annotations

from urllib.parse import urlparse

from .errors import UsageError
from .util import is_guid, short_id

RESOURCE_ALIASES: dict[str, str] = {
    "msgraph": "https://graph.microsoft.com/",
    "aadgraph": "https://graph.windows.net/",
    "azrm": "https://management.core.windows.net/",
    "azurerm": "https://management.core.windows.net/",
    "outlook": "https://outlook.office.com/",
    "sharepoint": "00000003-0000-0ff1-ce00-000000000000",
    "devicereg": "urn:ms-drs:enterpriseregistration.windows.net",
    "drs": "urn:ms-drs:enterpriseregistration.windows.net",
    "enrollment": "https://enrollment.manage.microsoft.com",
    "ig": "https://elm.iga.azure.com",
    "iga": "https://elm.iga.azure.com",
    "elm": "https://elm.iga.azure.com",
    "pim": "https://api.azrbac.mspim.azure.com",
    "mspim": "https://api.azrbac.mspim.azure.com",
    "aadtx": "api://AzureADTokenExchange",
}

CLIENT_ALIASES: dict[str, str] = {
    "aadps": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "azcli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "msteams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "azps": "1950a258-227b-4e31-a9cf-717495945fc2",
    "msedge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "edge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "msbroker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "companyportal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "azureportal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
}

CLIENT_NAMES: dict[str, str] = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "AAD Graph",
    "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Graph PowerShell",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "AAD PowerShell",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Teams",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Edge",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Broker",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Company Portal",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
}

CLIENT_SHORT_NAMES: dict[str, str] = {
    "00000003-0000-0000-c000-000000000000": "Graph",
    "00000002-0000-0000-c000-000000000000": "AAD Graph",
    "00000002-0000-0ff1-ce00-000000000000": "Exchange",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Graph PS",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "AAD PS",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Teams",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PS",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Edge",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Broker",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Company Portal",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
}

_AUDIENCE_LABELS: dict[str, str] = {
    "https://graph.microsoft.com": "Graph",
    "https://graph.windows.net": "AAD Graph",
    "00000003-0000-0000-c000-000000000000": "Graph",
    "00000002-0000-0000-c000-000000000000": "AAD Graph",
    "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
    "https://management.core.windows.net": "ARM",
    "https://management.azure.com": "ARM",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": "ARM",
    "https://outlook.office.com": "Outlook",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint",
    "urn:ms-drs:enterpriseregistration.windows.net": "Device Registration",
    "https://enrollment.manage.microsoft.com": "Enrollment",
    "https://elm.iga.azure.com": "IGA",
    "https://api.azrbac.mspim.azure.com": "PIM",
    "api://azureadtokenexchange": "Token Exchange",
}


def _normalize_audience(audience: str) -> str:
    return audience.strip().rstrip("/").lower()


def resolve_client(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise UsageError("Client ID is required.")
    alias = CLIENT_ALIASES.get(text.lower())
    if alias:
        return alias
    if is_guid(text):
        return text.lower()
    raise UsageError(
        f"Unknown client alias or invalid client ID: {value!r}. "
        "Pass a known roadtools alias or a client ID GUID."
    )


def _normalize_resource(text: str) -> str:
    value = text.strip()
    if value.lower().endswith("/.default"):
        value = value[: -len("/.default")]
    value = value.rstrip("/")
    if not value:
        raise UsageError("Resource is required.")
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        if not parsed.netloc:
            raise UsageError(f"Invalid resource URL: {text!r}.")
        return value
    if parsed.scheme == "api" and value.lower().startswith("api://"):
        if not value[6:]:
            raise UsageError(f"Invalid resource URL: {text!r}.")
        return value
    if value.lower().startswith("urn:") and len(value) > 4:
        return value
    if is_guid(value):
        return value
    raise UsageError(
        f"Unknown resource alias or invalid resource URL: {text!r}. "
        "Pass a known roadtools alias, a resource URL, a URN, or a GUID."
    )


def resolve_resource(value: str) -> tuple[str, str]:
    """Return the normalized resource and its client-credentials scope."""
    text = (value or "").strip()
    if not text:
        raise UsageError("Resource is required.")
    lookup = text
    if lookup.lower().endswith("/.default"):
        lookup = lookup[: -len("/.default")]
    lookup = lookup.rstrip("/")
    target = RESOURCE_ALIASES.get(lookup.lower())
    if target is None:
        target = _normalize_resource(text)
    else:
        target = _normalize_resource(target)
    return target, f"{target}/.default"


def audience_label(audience: str | None) -> str:
    if not audience:
        return "-"
    normalized = _normalize_audience(audience)
    label = _AUDIENCE_LABELS.get(normalized)
    if label:
        return label
    parsed = urlparse(audience)
    if parsed.hostname:
        return parsed.hostname
    return audience


def client_short_name(client_id: str | None) -> str | None:
    if not client_id:
        return None
    return CLIENT_SHORT_NAMES.get(client_id.lower())


def client_display(client_id: str | None, *, app_token: bool = False) -> str:
    if not client_id:
        return "-"
    known = CLIENT_NAMES.get(client_id.lower())
    if known:
        return known
    if app_token:
        return f"app:{short_id(client_id)}"
    return client_id


def client_short_display(client_id: str | None, *, app_token: bool = False) -> str:
    if not client_id:
        return "-"
    known = CLIENT_SHORT_NAMES.get(client_id.lower())
    if known:
        return known
    if app_token:
        return f"app:{short_id(client_id)}"
    return client_id
