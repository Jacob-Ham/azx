"""Thin Graph and ARM clients."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from .errors import AzxError
from .http import HttpClient

GRAPH_BASE = "https://graph.microsoft.com"
ARM_BASE = "https://management.azure.com"


def _json_or_empty(response: Any) -> dict[str, Any]:
    if response.status_code == 204 or not response.content:
        return {}
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {"value": value}


class GraphClient:
    def __init__(self, http: HttpClient, token: str, *, version: str = "v1.0") -> None:
        self.http = http
        self.token = token
        self.version = version

    def _url(self, path: str, version: str | None = None) -> str:
        if path.lower().startswith("https://"):
            parsed = urlparse(path)
            if parsed.hostname != "graph.microsoft.com":
                raise AzxError("Refusing to send a Graph token to a non-Graph host.")
            return path
        if not path.startswith("/"):
            path = "/" + path
        selected = version or self.version
        return f"{GRAPH_BASE}/{selected}{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        version: str | None = None,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        idempotent: bool | None = None,
    ) -> Any:
        response = self.http.request(
            method,
            self._url(path, version),
            token=self.token,
            params=params,
            json_body=json_body,
            idempotent=idempotent,
        )
        return _json_or_empty(response)

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "GET", path, params=params, version=version, idempotent=True
        )

    def get_absolute(self, url: str) -> dict[str, Any]:
        return _json_or_empty(
            self.http.request("GET", self._url(url), token=self.token)
        )

    def get_all(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        data = self.get(path, params=params, version=version)
        items = data.get("value", [])
        if not isinstance(items, list):
            return []
        result = [item for item in items if isinstance(item, dict)]
        next_link = data.get("@odata.nextLink")
        while isinstance(next_link, str) and next_link:
            data = self.get_absolute(next_link)
            page = data.get("value", [])
            if isinstance(page, list):
                result.extend(item for item in page if isinstance(item, dict))
            next_link = data.get("@odata.nextLink")
        return result

    def post(
        self,
        path: str,
        *,
        json_body: Any = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            path,
            version=version,
            json_body=json_body,
            idempotent=False,
        )

    def patch(
        self,
        path: str,
        *,
        json_body: Any = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "PATCH",
            path,
            version=version,
            json_body=json_body,
            idempotent=True,
        )

    def delete(self, path: str, *, version: str | None = None) -> dict[str, Any]:
        return self.request("DELETE", path, version=version, idempotent=True)


class ArmClient:
    def __init__(self, http: HttpClient, token: str) -> None:
        self.http = http
        self.token = token

    def _url(self, path: str) -> str:
        if path.lower().startswith("https://"):
            parsed = urlparse(path)
            if parsed.hostname != "management.azure.com":
                raise AzxError("Refusing to send an ARM token to a non-ARM host.")
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{ARM_BASE}{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        idempotent: bool | None = None,
    ) -> Any:
        response = self.http.request(
            method,
            self._url(path),
            token=self.token,
            params=params,
            json_body=json_body,
            idempotent=idempotent,
        )
        return _json_or_empty(response)

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request("GET", path, params=params, idempotent=True)

    def get_all(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        data = self.get(path, params=params)
        items = data.get("value", [])
        if not isinstance(items, list):
            return []
        result = [item for item in items if isinstance(item, dict)]
        next_link = data.get("nextLink")
        while isinstance(next_link, str) and next_link:
            data = self.get(next_link)
            page = data.get("value", [])
            if isinstance(page, list):
                result.extend(item for item in page if isinstance(item, dict))
            next_link = data.get("nextLink")
        return result

    def post(
        self,
        path: str,
        *,
        json_body: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            path,
            params=params,
            json_body=json_body,
            idempotent=False,
        )

    def put(
        self,
        path: str,
        *,
        json_body: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "PUT",
            path,
            params=params,
            json_body=json_body,
            idempotent=True,
        )

    def delete(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request("DELETE", path, params=params, idempotent=True)
