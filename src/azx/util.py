"""Small shared helpers."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import UsageError

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_TOKEN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_AUDIENCE_SLUGS = {
    "https://graph.microsoft.com": "graph",
    "https://graph.windows.net": "aadgraph",
    "00000003-0000-0000-c000-000000000000": "graph",
    "00000002-0000-0000-c000-000000000000": "aadgraph",
    "00000002-0000-0ff1-ce00-000000000000": "exchange",
    "https://management.core.windows.net": "arm",
    "https://management.azure.com": "arm",
    "https://outlook.office.com": "outlook",
    "00000003-0000-0ff1-ce00-000000000000": "sharepoint",
    "urn:ms-drs:enterpriseregistration.windows.net": "devicereg",
    "https://enrollment.manage.microsoft.com": "enrollment",
    "https://elm.iga.azure.com": "iga",
    "https://api.azrbac.mspim.azure.com": "pim",
    "api://azureadtokenexchange": "aadtx",
}


def chmod_private_fd(descriptor: int) -> None:
    """Apply owner-only permissions to regular files, ignoring devices/FIFOs."""
    if os.name != "posix":
        return
    if stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.fchmod(descriptor, 0o600)


def secure_path(path: Path, *, directory: bool = False) -> None:
    """Apply owner-only permissions using POSIX modes or a Windows ACL."""
    if os.name == "posix":
        mode = os.stat(path).st_mode
        if directory and stat.S_ISDIR(mode):
            os.chmod(path, 0o700)
        elif not directory and stat.S_ISREG(mode):
            os.chmod(path, 0o600)
        return
    if os.name != "nt":
        return
    user = os.environ.get("USERNAME")
    if not user:
        return
    grant = f"{user}:(OI)(CI)F" if directory else f"{user}:F"
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return


def is_guid(value: str) -> bool:
    return bool(_GUID_RE.fullmatch(value.strip()))


def validate_token_name(name: str) -> None:
    if not name or not _TOKEN_NAME_RE.fullmatch(name):
        raise UsageError(f"Token names must match [A-Za-z0-9._-]+ (got {name!r}).")


def slugify(value: str, fallback: str = "token") -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    text = text.strip("-._")
    return text or fallback


def short_id(value: str, length: int = 6) -> str:
    return value[:length]


def normalize_datetime_arg(value: str) -> str:
    """Normalize an operator-supplied timestamp to UTC ISO 8601."""
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise UsageError(
            f"Invalid date/time {value!r}; use ISO 8601, for example "
            "2026-01-31T18:00:00Z."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_expiry(value: Any) -> datetime | None:
    """Parse a roadtools expiry or ISO timestamp into a displayable naive time."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value))
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        # Year 1 and 9999 are API sentinels; local conversion can overflow.
        if parsed.year in (1, 9999):
            return parsed.replace(tzinfo=None)
        try:
            parsed = parsed.astimezone().replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            parsed = parsed.replace(tzinfo=None)
    return parsed


def format_expiry(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def expiry_from_epoch(epoch: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(epoch))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def expiry_display(value: datetime | None) -> str:
    if value is None:
        return "-"
    now = datetime.now()
    if value.date() == now.date():
        return value.strftime("%H:%M")
    return value.strftime("%Y-%m-%d %H:%M")


def format_api_datetime(value: Any) -> Any:
    if value is None:
        return "-"
    if not isinstance(value, str):
        return value
    parsed = parse_expiry(value)
    if parsed is None:
        return value
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_now_iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def audience_slug(audience: Any) -> str:
    if isinstance(audience, list):
        audience = next((item for item in audience if item), None)
    if not audience:
        return "token"
    text = str(audience).strip().rstrip("/")
    known = _AUDIENCE_SLUGS.get(text.lower())
    if known:
        return known
    parsed = urlparse(text)
    if parsed.hostname:
        candidate = parsed.hostname.split(".")[0]
    elif parsed.scheme:
        candidate = parsed.path.rsplit("/", 1)[-1] or parsed.scheme
    else:
        candidate = text.rsplit(":", 1)[-1] or text
    return slugify(candidate)


def format_list(values: Any) -> str:
    if not values:
        return "-"
    if isinstance(values, str):
        return values
    return ", ".join(str(value) for value in values)


def yes_no(value: Any) -> Any:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return value if value is not None else "-"


def humanize_odata_type(value: Any) -> str:
    if not value:
        return "-"
    text = str(value)
    if text.startswith("#"):
        text = text.rsplit(".", 1)[-1]
    text = re.sub(r"AuthenticationMethod$", "", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = text.strip()
    return text[:1].upper() + text[1:] if text else "-"


_SENSITIVE_KEYS = {
    "access_token",
    "accesstoken",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "clientsecret",
    "cookie",
    "id_token",
    "idtoken",
    "passcode",
    "password",
    "proxy_authorization",
    "refresh_token",
    "refreshtoken",
    "secret",
    "secretkey",
    "secrettext",
    "set_cookie",
    "temporaryaccesspass",
    "token",
    "x_api_key",
    "x_apikey",
}


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_").lstrip("_")
    return normalized in _SENSITIVE_KEYS


def deep_redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if is_sensitive_key(str(key)) else deep_redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [deep_redact(item) for item in value]
    return value


def is_interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False
