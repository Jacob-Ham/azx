"""Runtime settings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .errors import UsageError

DEFAULT_TOKENS_DIR = "~/.azxtokens"
DEFAULT_TIMEOUT = 30.0


def resolve_tokens_dir() -> Path:
    value = os.environ.get("AZX_TOKENS_DIR") or DEFAULT_TOKENS_DIR
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    return path


@dataclass(slots=True)
class Settings:
    tokens_dir: Path
    timeout: float = DEFAULT_TIMEOUT
    proxy: str | None = None
    user_agent: str = f"azx/{__version__}"
    headers: dict[str, str] = field(default_factory=dict)
    debug_http: bool = False
    output: Path | None = None
    dry_run: bool = False
    token_name: str | None = None

    @classmethod
    def from_args(cls, args: Any) -> Settings:
        tokens_dir = resolve_tokens_dir()

        timeout = getattr(args, "timeout", None)
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        if timeout <= 0:
            raise UsageError("--timeout must be greater than zero.")

        raw_headers = getattr(args, "headers", None) or []
        headers: dict[str, str] = {}
        for item in raw_headers:
            name, separator, value = item.partition(":")
            name = name.strip()
            value = value.strip()
            if not separator or not name:
                raise UsageError('--headers values must use "Name: Value" format.')
            if any(char.isspace() for char in name) or any(
                char in name or char in value for char in "\r\n"
            ):
                raise UsageError(f"Invalid HTTP header: {item!r}.")
            headers[name] = value

        output = getattr(args, "output", None)
        output_path = Path(output).expanduser() if output else None

        return cls(
            tokens_dir=tokens_dir,
            timeout=float(timeout),
            proxy=getattr(args, "proxy", None) or None,
            user_agent=getattr(args, "user_agent", None) or f"azx/{__version__}",
            headers=headers,
            debug_http=bool(getattr(args, "debug_http", False)),
            output=output_path,
            dry_run=bool(getattr(args, "dry_run", False)),
            token_name=getattr(args, "token_name", None) or None,
        )
