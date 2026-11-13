"""Roadtools-compatible token store."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import TokenError, UsageError
from .model import TokenRecord
from .util import chmod_private_fd, secure_path, validate_token_name

TOKEN_SUFFIX = ".roadtools_auth"


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".azx-", dir=str(path.parent))
    temporary_path = Path(temporary)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        secure_path(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


class TokenStore:
    def __init__(self, settings: Settings) -> None:
        self.directory = settings.tokens_dir

    def ensure(self) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            secure_path(self.directory, directory=True)
        except OSError as exc:
            raise UsageError(
                f"Cannot prepare token directory {self.directory}: "
                f"{exc.strerror or exc}"
            ) from exc
        if not self.directory.is_dir():
            raise UsageError(f"Token path {self.directory} is not a directory.")

    def path_for(self, name: str) -> Path:
        validate_token_name(name)
        return self.directory / f"{name}{TOKEN_SUFFIX}"

    def _load(self, path: Path, name: str) -> TokenRecord | None:
        try:
            with path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict):
            return None
        return TokenRecord(raw=raw, name=name, path=path)

    def scan(self) -> list[TokenRecord]:
        if not self.directory.is_dir():
            return []
        records: list[TokenRecord] = []
        for path in sorted(self.directory.glob(f"*{TOKEN_SUFFIX}")):
            stem = path.name[: -len(TOKEN_SUFFIX)]
            try:
                validate_token_name(stem)
                name = stem
            except UsageError:
                raw_name = None
                try:
                    with path.open("r", encoding="utf-8") as handle:
                        candidate = json.load(handle)
                    if isinstance(candidate, dict):
                        raw_name = candidate.get("_name")
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
                if not isinstance(raw_name, str):
                    continue
                try:
                    validate_token_name(raw_name)
                except UsageError:
                    continue
                name = raw_name
            record = self._load(path, name)
            if record is not None:
                records.append(record)
        return records

    def _find_scanned(self, name: str) -> TokenRecord | None:
        for record in self.scan():
            if record.name == name:
                return record
        return None

    def get(self, name: str, *, required: bool = True) -> TokenRecord | None:
        path = self.path_for(name)
        record = self._load(path, name)
        if record is None:
            record = self._find_scanned(name)
        if record is None and required:
            raise TokenError(f"Token not found: {name}")
        return record

    def exists(self, name: str) -> bool:
        if self.path_for(name).is_file():
            return True
        return self._find_scanned(name) is not None

    def save(self, raw: dict[str, Any], name: str, *, force: bool = False) -> Path:
        self.ensure()
        path = self.path_for(name)
        if self.exists(name) and not force:
            raise UsageError(
                f"Token '{name}' already exists. Use --force to overwrite it."
            )
        _atomic_write(path, json.dumps(raw, indent=2, ensure_ascii=False) + "\n")
        return path

    def delete(self, name: str) -> bool:
        record = self.get(name, required=False)
        if record is None or record.path is None:
            raise TokenError(f"Token not found: {name}")
        path = record.path
        try:
            path.unlink()
        except OSError as exc:
            raise TokenError(
                f"Cannot delete token {name}: {exc.strerror or exc}"
            ) from exc
        cleared = False
        if self.active_name() == name:
            self.clear_active()
            cleared = True
        return cleared

    def active_name(self) -> str | None:
        path = self.directory / "active"
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return None
        if not value:
            return None
        try:
            validate_token_name(value)
        except UsageError:
            return None
        return value

    def set_active(self, name: str) -> None:
        self.ensure()
        if not self.exists(name):
            raise TokenError(f"Token not found: {name}")
        _atomic_write(self.directory / "active", name + "\n")

    def clear_active(self) -> None:
        try:
            (self.directory / "active").unlink(missing_ok=True)
        except OSError as exc:
            raise TokenError(
                f"Cannot clear the active token: {exc.strerror or exc}"
            ) from exc

    def export(self, record: TokenRecord, path: Path) -> Path:
        target = path.expanduser()
        protected = {(self.directory / "active").resolve()}
        if target.resolve() in protected:
            raise UsageError(
                "Refusing to overwrite token store metadata with a token export."
            )
        if target.parent and not target.parent.is_dir():
            raise UsageError(
                f"Cannot write token export: directory {target.parent} does not exist."
            )
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            chmod_private_fd(descriptor)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(record.raw, indent=2, ensure_ascii=False) + "\n"
                )
            secure_path(target)
        except OSError as exc:
            raise UsageError(
                f"Cannot write token export {target}: {exc.strerror or exc}"
            ) from exc
        return target
