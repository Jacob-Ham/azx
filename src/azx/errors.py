"""User-facing error types."""

from __future__ import annotations


class AzxError(Exception):
    """An expected failure that should be shown without a traceback."""

    exit_code = 1


class UsageError(AzxError):
    """Invalid command usage or input."""


class TokenError(AzxError):
    """A token could not be read or used."""


class AuthError(AzxError):
    """Authentication against Entra ID failed."""


class ApiError(AzxError):
    """A Graph or ARM request failed."""

    def __init__(
        self,
        status_code: int,
        reason: str,
        message: str,
        *,
        code: str | None = None,
        request_id: str | None = None,
        body: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.reason = reason
        self.message = message
        self.code = code
        self.request_id = request_id
        self.body = body
        super().__init__(self._format())

    def _format(self) -> str:
        text = f"HTTP {self.status_code} {self.reason}"
        if self.body:
            text += f"\n{self.body}"
        else:
            detail = self.message.strip() or self.reason
            if self.code:
                detail = f"{self.code}: {detail}"
            text += f": {detail}"
        if self.request_id:
            text += f"\nRequest ID: {self.request_id}"
        return text
