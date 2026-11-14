"""HTTP transport with retries, debugging, and API errors."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from .config import Settings
from .console import Output
from .errors import ApiError, AzxError, UsageError

_MAX_ATTEMPTS = 4
_RETRY_STATUSES = {429, 500, 502, 503, 504}


def _format_debug_data(data: Any) -> str:
    if isinstance(data, Mapping):
        return urlencode(data, doseq=True)
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


def _response_body_for_debug(response: httpx.Response) -> str:
    content_type = response.headers.get("content-type", "")
    if "json" in content_type:
        try:
            value = response.json()
            return json.dumps(value, indent=2, ensure_ascii=False)
        except (ValueError, json.JSONDecodeError):
            pass
    text = response.text
    if len(text) > 2000:
        text = text[:2000] + "\n... (truncated)"
    return text


def _retry_delay(response: httpx.Response | None, attempt: int) -> float:
    if response is not None:
        value = response.headers.get("retry-after")
        if value:
            try:
                delay = float(value)
            except ValueError:
                try:
                    when = parsedate_to_datetime(value)
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=UTC)
                    delta = (when - datetime.now(UTC)).total_seconds()
                    return max(0.0, min(delta, 30.0))
                except (TypeError, ValueError):
                    pass
            else:
                if math.isfinite(delay):
                    return max(0.0, min(delay, 30.0))
    return min(1.0 * (2**attempt), 30.0)


def _api_error(response: httpx.Response) -> ApiError:
    request_id = (
        response.headers.get("request-id")
        or response.headers.get("x-ms-request-id")
        or response.headers.get("x-ms-client-request-id")
    )
    code: str | None = None
    message: str | None = None
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        body = None

    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            code_value = error.get("code")
            message_value = error.get("message")
            code = str(code_value) if code_value else None
            message = str(message_value) if message_value else None
        elif isinstance(error, str):
            code = error
        if not message:
            description = body.get("error_description")
            if isinstance(description, str):
                message = description
        if not message:
            detail = body.get("message")
            if isinstance(detail, str):
                message = detail
    if not message:
        text = response.text.strip()
        if text:
            message = text[:1000]
    raw_body = response.text
    return ApiError(
        response.status_code,
        response.reason_phrase,
        message or response.reason_phrase,
        code=code,
        request_id=request_id,
        body=raw_body if raw_body.strip() else None,
    )


class HttpClient:
    def __init__(self, settings: Settings, console: Output) -> None:
        self.settings = settings
        self.console = console
        try:
            self._client = httpx.Client(
                proxy=settings.proxy,
                timeout=httpx.Timeout(settings.timeout),
                verify=not bool(settings.proxy),
                follow_redirects=False,
                headers={
                    "User-Agent": settings.user_agent,
                    "Accept": "application/json",
                },
            )
        except (ValueError, TypeError) as exc:
            raise UsageError(f"Invalid HTTP configuration: {exc}") from exc

    def close(self) -> None:
        self._client.close()

    def _headers(
        self,
        *,
        token: str | None,
        headers: Mapping[str, str] | None,
    ) -> dict[str, str]:
        merged = dict(self.settings.headers)
        if headers:
            merged.update(headers)
        if token:
            merged["Authorization"] = f"Bearer {token}"
        return merged

    def _debug_request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        data: Any,
        json_body: Any,
    ) -> None:
        if not self.settings.debug_http:
            return
        self.console.debug(f"> {method} {url}")
        for key, value in headers.items():
            self.console.debug(f"> {key}: {value}")
        if data is not None:
            self.console.debug("> " + _format_debug_data(data))
        elif json_body is not None:
            self.console.debug(
                "> " + json.dumps(json_body, indent=2, ensure_ascii=False)
            )
        self.console.debug(">")

    def _debug_response(self, response: httpx.Response) -> None:
        if not self.settings.debug_http:
            return
        self.console.debug(f"< {response.status_code} {response.reason_phrase}")
        for key, value in response.headers.items():
            self.console.debug(f"< {key}: {value}")
        body = _response_body_for_debug(response)
        if body:
            self.console.debug("< " + body)
        self.console.debug("<")

    def request(
        self,
        method: str,
        url: str,
        *,
        token: str | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        data: Any = None,
        json_body: Any = None,
        idempotent: bool | None = None,
    ) -> httpx.Response:
        method = method.upper()
        if idempotent is None:
            idempotent = method in {"GET", "HEAD", "DELETE", "OPTIONS"}
        request_headers = self._headers(token=token, headers=headers)
        debug_url = str(httpx.URL(url, params=params)) if params else url
        self._debug_request(method, debug_url, request_headers, data, json_body)

        last_network_error: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = self._client.request(
                    method,
                    url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json_body,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_network_error = exc
                if idempotent and attempt < _MAX_ATTEMPTS - 1:
                    time.sleep(_retry_delay(None, attempt))
                    continue
                raise AzxError(self._network_error_message(exc)) from exc

            self._debug_response(response)
            if response.status_code in _RETRY_STATUSES:
                # Retry only idempotent requests so a mutation is never
                # duplicated by the retry loop.
                retry_429 = response.status_code == 429 and idempotent
                retry_5xx = 500 <= response.status_code < 600 and idempotent
                if (retry_429 or retry_5xx) and attempt < _MAX_ATTEMPTS - 1:
                    delay = _retry_delay(response, attempt)
                    if self.settings.debug_http:
                        self.console.debug(f"... retrying after {delay:.1f}s")
                    time.sleep(delay)
                    continue

            if not response.is_success:
                raise _api_error(response)
            return response

        if last_network_error is not None:
            raise AzxError(self._network_error_message(last_network_error))
        raise AzxError("Request failed after retries.")

    def _network_error_message(self, exc: Exception) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return f"Request timed out after {self.settings.timeout:g} seconds."
        if isinstance(exc, httpx.ProxyError):
            return f"Proxy request failed: {exc}"
        return f"Network request failed: {exc}"
