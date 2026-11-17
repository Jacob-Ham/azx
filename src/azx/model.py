"""Token record model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .aliases import audience_label, client_display, client_short_display
from .errors import TokenError
from .jwt import decode_jwt
from .tokenmeta import (
    detect_token_type,
    record_expiry,
    token_audience,
    token_client,
    token_principal,
    token_roles,
    token_scopes,
    token_tenant,
)
from .util import expiry_display, format_list, parse_expiry


def _first_audience(value: Any) -> str | None:
    if isinstance(value, list):
        value = next((item for item in value if item), None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item for item in value.split() if item]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


@dataclass
class TokenRecord:
    raw: dict[str, Any]
    name: str
    path: Path | None = None
    _claims: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _claims_loaded: bool = field(default=False, init=False, repr=False)

    @property
    def has_access_token(self) -> bool:
        value = self.raw.get("accessToken")
        return isinstance(value, str) and bool(value.strip())

    @property
    def has_refresh_token(self) -> bool:
        value = self.raw.get("refreshToken")
        return isinstance(value, str) and bool(value.strip())

    @property
    def access_token(self) -> str | None:
        value = self.raw.get("accessToken")
        return value if isinstance(value, str) and value.strip() else None

    @property
    def refresh_token(self) -> str | None:
        value = self.raw.get("refreshToken")
        return value if isinstance(value, str) and value.strip() else None

    @property
    def claims(self) -> dict[str, Any]:
        if not self._claims_loaded:
            self._claims_loaded = True
            token = self.access_token
            if token:
                try:
                    self._claims = decode_jwt(token)
                except TokenError:
                    self._claims = {}
            else:
                self._claims = {}
        return self._claims or {}

    @property
    def type(self) -> str:
        value = self.raw.get("_type")
        if value in {"user", "app"}:
            return value
        return detect_token_type(self.claims)

    @property
    def is_app(self) -> bool:
        return self.type == "app"

    @property
    def principal_id(self) -> str | None:
        value = self.raw.get("_principalId") or token_principal(self.claims)
        return str(value) if value else None

    @property
    def app_id(self) -> str | None:
        value = self.raw.get("_appId") or token_client(self.claims)
        return str(value) if value else None

    @property
    def service_principal_id(self) -> str | None:
        value = self.raw.get("_servicePrincipalObjectId")
        if value:
            return str(value)
        if self.is_app:
            return self.principal_id
        return None

    @property
    def application_object_id(self) -> str | None:
        value = self.raw.get("_applicationObjectId")
        return str(value) if value else None

    @property
    def tenant_id(self) -> str | None:
        value = self.raw.get("tenantId") or token_tenant(self.claims)
        return str(value) if value else None

    @property
    def client_id(self) -> str | None:
        value = self.raw.get("_clientId") or token_client(self.claims)
        return str(value) if value else None

    @property
    def audience(self) -> str | None:
        value = _first_audience(self.raw.get("_audience"))
        if value:
            return value
        return token_audience(self.claims)

    @property
    def scopes(self) -> list[str]:
        if "_scopes" in self.raw:
            return _as_list(self.raw.get("_scopes"))
        return token_scopes(self.claims)

    @property
    def roles(self) -> list[str]:
        if "_roles" in self.raw:
            return _as_list(self.raw.get("_roles"))
        return token_roles(self.claims)

    @property
    def cloud(self) -> str | None:
        value = self.raw.get("_cloud")
        return str(value) if value else None

    @property
    def source(self) -> str | None:
        value = self.raw.get("_source")
        return str(value) if value else None

    @property
    def imported_at(self) -> str | None:
        value = self.raw.get("_importedAt")
        return str(value) if value else None

    @property
    def collected_display(self) -> str:
        value = self.imported_at
        if not value:
            return "-"
        parsed = parse_expiry(value)
        if parsed is None:
            return value
        return parsed.strftime("%Y-%m-%d")

    @property
    def expires_at(self) -> datetime | None:
        return record_expiry(self.raw)

    @property
    def expired(self) -> bool:
        expires_at = self.expires_at
        return expires_at is not None and expires_at < datetime.now()

    @property
    def expires_display(self) -> str:
        if not self.has_access_token:
            return "no access"
        if self.expired:
            return "expired"
        return expiry_display(self.expires_at)

    @property
    def principal_display(self) -> str:
        if not self.has_access_token:
            return "unknown"
        if self.is_app:
            identifier = self.app_id or self.principal_id
            return f"app:{identifier}" if identifier else "app:unknown"
        upn = (
            self.claims.get("upn")
            or self.claims.get("preferred_username")
            or self.claims.get("unique_name")
            or self.claims.get("email")
        )
        return str(upn) if upn else (self.principal_id or "unknown")

    @property
    def client_display(self) -> str:
        return client_display(self.client_id, app_token=self.is_app)

    @property
    def client_table_display(self) -> str:
        if self.is_app:
            return self.client_id or "-"
        return client_short_display(self.client_id)

    @property
    def amr_display(self) -> str:
        return format_list(_as_list(self.claims.get("amr")))

    @property
    def refresh_display(self) -> str:
        return "yes" if self.has_refresh_token else "no"

    @property
    def audience_display(self) -> str:
        return audience_label(self.audience)

    @property
    def audience_text(self) -> str:
        if not self.audience:
            return "-"
        if self.audience_display == self.audience:
            return self.audience
        return f"{self.audience_display} ({self.audience})"

    @property
    def tenant_display(self) -> str:
        return self.tenant_id or "-"

    @property
    def details(self) -> str:
        parts = [f"Tenant: {self.tenant_display}"]
        if self.is_app and self.client_id:
            parts.append(f"Client ID: {self.client_id}")
        if self.imported_at:
            collected = parse_expiry(self.imported_at)
            if collected is not None:
                parts.append(f"Collected: {collected.strftime('%Y-%m-%d %H:%M')}")
        if not self.has_access_token:
            parts.append("Access token: none")
        if self.scopes:
            parts.append(f"Scopes: {format_list(self.scopes)}")
        if self.roles:
            parts.append(f"Roles: {format_list(self.roles)}")
        parts.append(f"File: {self.path}")
        return " | ".join(parts)

    @property
    def summary_row(self) -> list[str]:
        return [
            self.name,
            self.principal_display,
            self.client_table_display,
            self.audience_display,
            self.collected_display,
            self.expires_display,
        ]

    @property
    def selector_row(self) -> list[str]:
        return [
            self.name,
            self.principal_display,
            self.client_table_display,
            self.amr_display,
            self.refresh_display,
            self.audience_display,
            self.collected_display,
            self.expires_display,
        ]
