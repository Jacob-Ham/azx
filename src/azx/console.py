"""Terminal output and the optional command transcript."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, TextIO

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from .errors import AzxError
from .util import chmod_private_fd, secure_path


class OutputError(AzxError):
    """The requested output transcript could not be opened."""


class Transcript:
    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            chmod_private_fd(descriptor)
            self._file: TextIO = os.fdopen(
                descriptor, "w", encoding="utf-8", buffering=1
            )
            secure_path(path)
        except OSError as exc:
            raise OutputError(
                f"Cannot open output file {path}: {exc.strerror or exc}"
            ) from exc

    def write(self, text: str) -> int:
        self._file.write(text)
        self._file.flush()
        return len(text)

    def close(self) -> None:
        self._file.close()


class AzxConsole(Console):
    """Rich console that lets the CLI handle broken pipes cleanly."""

    def on_broken_pipe(self) -> None:
        self.quiet = True
        try:
            target = self.file.fileno()
        except (AttributeError, OSError, ValueError):
            target = sys.stdout.fileno()
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, target)
        finally:
            raise BrokenPipeError


class Tee:
    """Write to the terminal stream and, when present, the transcript."""

    def __init__(self, primary: TextIO, transcript: Transcript | None) -> None:
        self._primary = primary
        self._transcript = transcript

    def write(self, text: str) -> int:
        self._primary.write(text)
        self._primary.flush()
        if self._transcript is not None:
            self._transcript.write(text)
        return len(text)

    def flush(self) -> None:
        self._primary.flush()

    def isatty(self) -> bool:
        try:
            return self._primary.isatty()
        except (AttributeError, ValueError):
            return False

    def fileno(self) -> int:
        return self._primary.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._primary, "encoding", "utf-8")

    @property
    def errors(self) -> str:
        return getattr(self._primary, "errors", "strict")


class IndentedTee(Tee):
    """Tee that adds a small prefix to the start of every output line."""

    def __init__(
        self,
        primary: TextIO,
        transcript: Transcript | None,
        indent: str = " ",
    ) -> None:
        super().__init__(primary, transcript)
        self._indent = indent
        self._at_line_start = True

    def write(self, text: str) -> int:
        if not text:
            return 0
        chunks: list[str] = []
        for char in text:
            if self._at_line_start and char != "\n":
                chunks.append(self._indent)
            chunks.append(char)
            self._at_line_start = char == "\n"
        return super().write("".join(chunks))


def _console_width() -> int:
    columns = shutil.get_terminal_size((100, 24)).columns
    return max(80, min(columns, 160))


class Output:
    def __init__(self, output_path: Path | None) -> None:
        self.transcript = Transcript(output_path) if output_path else None
        plain = self.transcript is not None
        width = _console_width() if plain else None

        common: dict[str, Any] = {
            "highlight": False,
            "emoji": False,
            "soft_wrap": False,
            "width": width,
        }
        if plain:
            common.update(
                {
                    "no_color": True,
                    "color_system": None,
                    "force_terminal": False,
                }
            )

        self.out = AzxConsole(file=IndentedTee(sys.stdout, self.transcript), **common)
        self.err = AzxConsole(file=IndentedTee(sys.stderr, self.transcript), **common)
        self.plain = plain
        self.closed = False
        self._last_was_blank = True

    def line(self, text: Any = "", *, style: str | None = None) -> None:
        self.out.print(text, style=style, markup=False, highlight=False)
        self._last_was_blank = not str(text).strip()

    def blank(self) -> None:
        self.line()

    def ensure_trailing_blank(self) -> None:
        if not self._last_was_blank:
            self.blank()

    def token_line(self, name: str) -> None:
        self.line(f"Using token: {name}")
        self.blank()

    def kv(self, label: str, value: Any) -> None:
        text = Text(" ")
        text.append(f"{label}: ", style="bold")
        text.append(str(value))
        self.out.print(text, markup=False, highlight=False)
        self._last_was_blank = False

    def heading(self, text: str) -> None:
        self.out.print(Text(text, style="bold cyan"), markup=False, highlight=False)
        self._last_was_blank = False

    def error(self, message: str) -> None:
        self.err.print(
            f"Error: {message}",
            style="bold red",
            markup=False,
            highlight=False,
            soft_wrap=True,
        )

    def debug(self, message: str) -> None:
        self.err.print(message, style="dim", markup=False, highlight=False)

    def table(
        self,
        headers: list[str],
        rows: list[list[Any]],
        *,
        title: str | None = None,
    ) -> None:
        table = Table(
            title=title,
            box=box.SIMPLE_HEAD,
            show_edge=False,
            pad_edge=False,
            header_style=None if self.plain else "bold cyan",
            border_style=None if self.plain else "bright_black",
            padding=(0, 1),
        )
        for header in headers:
            table.add_column(Text(header))
        for row in rows:
            table.add_row(*(Text(_cell(value)) for value in row))
        self.out.print(
            Padding(table, (0, 0, 0, 1), expand=False),
            markup=False,
            highlight=False,
        )
        self._last_was_blank = False

    def data(self, value: Any) -> None:
        from .render import render_data

        render_data(self, value)

    def flush(self) -> None:
        self.out.file.flush()
        self.err.file.flush()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.flush()
        except (BrokenPipeError, OSError):
            pass
        if self.transcript is not None:
            try:
                self.transcript.close()
            except OSError:
                pass


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)
