"""Interactive mini TUI for selecting the active token."""

from __future__ import annotations

import shutil
import sys
import textwrap
from collections.abc import Callable
from typing import Any

from prompt_toolkit import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl

from .errors import TokenError
from .model import TokenRecord

_HEADERS = [
    "NAME",
    "PRINCIPAL",
    "CLIENT",
    "AMR",
    "REFRESH",
    "AUDIENCE",
    "COLLECTED",
    "EXPIRES",
]
_MIN_WIDTHS = [4, 8, 6, 3, 3, 6, 10, 7]

_HELP_LINES = [
    "AZX token selector",
    "",
    "Up / Down      Move",
    "/              Filter",
    "Tab            Toggle details",
    "d              Delete current token",
    "Enter          Select and activate",
    "Esc            Cancel",
    "?              Help",
    "q              Quit",
    "",
    "Press ? or Esc to close help.",
]


def _fit(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return text[:1]
    return text[: width - 1] + "…"


class _Selector:
    def __init__(
        self,
        tokens: list[TokenRecord],
        *,
        on_delete: Callable[[str], bool] | None = None,
    ) -> None:
        self.tokens = tokens
        self.filtered = list(tokens)
        self.on_delete = on_delete
        self.cursor = 0
        self.scroll = 0
        self.filter_text = ""
        self.filtering = False
        self.show_detail = False
        self.help = False
        self.pending_delete: str | None = None
        self.status: str | None = None
        self.result: str | None = None

    def _current(self) -> TokenRecord | None:
        if not self.filtered:
            return None
        return self.filtered[self.cursor]

    def _request_delete(self) -> None:
        token = self._current()
        if token is None:
            return
        self.pending_delete = token.name
        self.status = None

    def _delete_current(self) -> None:
        name = self.pending_delete
        if name is None:
            return
        if self.on_delete is None:
            self.pending_delete = None
            self.status = "Token deletion is not available."
            return
        try:
            self.on_delete(name)
        except TokenError as exc:
            self.pending_delete = None
            self.status = str(exc)
            return
        index = self.cursor
        self.pending_delete = None
        self.status = f"Deleted token: {name}"
        self.tokens = [token for token in self.tokens if token.name != name]
        self._recompute()
        if self.filtered:
            self.cursor = min(index, len(self.filtered) - 1)
            self._ensure_visible()

    def _recompute(self) -> None:
        query = self.filter_text.casefold().strip()
        if query:
            self.filtered = [
                token
                for token in self.tokens
                if query
                in (
                    f"{token.name} {token.principal_display} "
                    f"{token.client_display} {token.amr_display} "
                    f"{token.refresh_display} {token.audience_display} "
                    f"{token.tenant_display}"
                ).casefold()
            ]
        else:
            self.filtered = list(self.tokens)
        self.cursor = 0
        self.scroll = 0

    def _move(self, delta: int) -> None:
        if self.pending_delete or not self.filtered:
            return
        self.status = None
        self.cursor = max(0, min(len(self.filtered) - 1, self.cursor + delta))

    def _visible_rows(self) -> int:
        height = shutil.get_terminal_size((100, 24)).lines
        reserved = 5
        if self.show_detail:
            reserved += 2
        if self.filtering or self.filter_text:
            reserved += 1
        if self.pending_delete or self.status:
            reserved += 1
        return max(1, height - reserved)

    def _ensure_visible(self) -> None:
        visible = self._visible_rows()
        if self.cursor < self.scroll:
            self.scroll = self.cursor
        elif self.cursor >= self.scroll + visible:
            self.scroll = self.cursor - visible + 1
        maximum = max(0, len(self.filtered) - visible)
        self.scroll = max(0, min(self.scroll, maximum))

    def _widths(self) -> list[int]:
        columns = shutil.get_terminal_size((100, 24)).columns
        available = max(20, columns - 2 * (len(_HEADERS) - 1))
        widths = []
        for index, header in enumerate(_HEADERS):
            values = [header]
            values.extend(token.selector_row[index] for token in self.tokens)
            widths.append(max(len(value) for value in values))
        while sum(widths) > available:
            candidates = [
                index
                for index, width in enumerate(widths)
                if width > _MIN_WIDTHS[index]
            ]
            if not candidates:
                break
            widest = max(candidates, key=lambda index: widths[index])
            widths[widest] -= 1
        return widths

    def _row_text(self, token: TokenRecord, widths: list[int]) -> str:
        cells = [
            _fit(value, widths[index]) for index, value in enumerate(token.selector_row)
        ]
        return "  ".join(
            cell.ljust(widths[index]) for index, cell in enumerate(cells)
        ).rstrip()

    def _render(self) -> FormattedText:
        if self.help:
            return self._render_help()

        columns = shutil.get_terminal_size((100, 24)).columns
        widths = self._widths()
        fragments: list[tuple[str, str]] = []

        header = "  ".join(
            _fit(header, widths[index]).ljust(widths[index])
            for index, header in enumerate(_HEADERS)
        )
        fragments.append(("bold", header.rstrip() + "\n"))

        self._ensure_visible()
        visible = self._visible_rows()
        start = self.scroll
        end = start + visible
        page = self.filtered[start:end]

        if not page:
            fragments.append(("fg:ansibrightblack", "No tokens match.\n"))
        for offset, token in enumerate(page):
            index = start + offset
            selected = index == self.cursor
            style = "reverse"
            if token.expired:
                style += " fg:ansired"
            fragments.append(
                (style if selected else "", self._row_text(token, widths) + "\n")
            )

        if self.show_detail:
            fragments.append(("", "\n"))
            token = self._current()
            detail = token.details if token else "No token selected."
            wrapped = textwrap.wrap(
                detail,
                width=max(20, columns),
                subsequent_indent="  ",
                break_long_words=False,
                break_on_hyphens=False,
            ) or [detail]
            for line in wrapped:
                fragments.append(("fg:ansicyan", line + "\n"))

        if self.pending_delete:
            fragments.append(
                (
                    "fg:ansired",
                    f"Delete token '{self.pending_delete}'? y/N\n",
                )
            )
        elif self.status:
            fragments.append(("fg:ansiyellow", self.status + "\n"))

        if self.filtering or self.filter_text:
            fragments.append(
                (
                    "fg:ansiyellow",
                    f"Filter: {self.filter_text}"
                    + ("_" if self.filtering else "")
                    + "\n",
                )
            )

        fragments.append(
            (
                "fg:ansibrightblack",
                (
                    "Up/Down move  / filter  Tab details  d delete  "
                    "Enter select  Esc cancel  ? help  q quit"
                ),
            )
        )
        return FormattedText(fragments)

    def _render_help(self) -> FormattedText:
        fragments: list[tuple[str, str]] = []
        for index, line in enumerate(_HELP_LINES):
            style = "bold" if index == 0 else ""
            fragments.append((style, line + "\n"))
        fragments.append(("fg:ansibrightblack", "Press ? or Esc to close help."))
        return FormattedText(fragments)

    def _bindings(self) -> KeyBindings:
        bindings = KeyBindings()

        def close_help() -> None:
            self.help = False

        @bindings.add("up")
        def _up(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.help:
                close_help()
            else:
                self._move(-1)
            event.app.invalidate()

        @bindings.add("down")
        def _down(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.help:
                close_help()
            else:
                self._move(1)
            event.app.invalidate()

        @bindings.add("pageup")
        def _page_up(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if not self.help:
                self._move(-10)
            event.app.invalidate()

        @bindings.add("pagedown")
        def _page_down(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if not self.help:
                self._move(10)
            event.app.invalidate()

        @bindings.add("home")
        def _home(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if not self.help:
                self.status = None
                self.cursor = 0
            event.app.invalidate()

        @bindings.add("end")
        def _end(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if not self.help and self.filtered:
                self.status = None
                self.cursor = len(self.filtered) - 1
            event.app.invalidate()

        @bindings.add("tab")
        def _tab(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.help:
                close_help()
            else:
                self.show_detail = not self.show_detail
            event.app.invalidate()

        @bindings.add("/")
        def _filter(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.help:
                close_help()
            elif self.filtering:
                self.filter_text += "/"
                self._recompute()
            else:
                self.filtering = True
                self.filter_text = ""
                self.status = None
                self._recompute()
            event.app.invalidate()

        @bindings.add("backspace")
        def _backspace(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.filtering:
                self.filter_text = self.filter_text[:-1]
                self._recompute()
                event.app.invalidate()

        @bindings.add("enter")
        def _enter(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.help:
                close_help()
            else:
                self.filtering = False
                token = self._current()
                if token is not None:
                    self.result = token.name
                    event.app.exit()
            event.app.invalidate()

        @bindings.add("escape")
        def _escape(event: Any) -> None:
            if self.pending_delete:
                self.pending_delete = None
                self.status = "Delete cancelled."
            elif self.help:
                close_help()
            elif self.filtering:
                self.filtering = False
                self.filter_text = ""
                self._recompute()
            else:
                event.app.exit()
            event.app.invalidate()

        @bindings.add("d")
        def _delete(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.filtering:
                self.filter_text += "d"
                self._recompute()
            elif not self.help:
                self._request_delete()
            event.app.invalidate()

        @bindings.add("y")
        @bindings.add("Y")
        def _yes(event: Any) -> None:
            if self.pending_delete:
                self._delete_current()
            elif self.filtering and not self.help:
                self.filter_text += event.data
                self._recompute()
            event.app.invalidate()

        @bindings.add("n")
        @bindings.add("N")
        def _no(event: Any) -> None:
            if self.pending_delete:
                self.pending_delete = None
                self.status = "Delete cancelled."
            elif self.filtering and not self.help:
                self.filter_text += event.data
                self._recompute()
            event.app.invalidate()

        @bindings.add("?")
        def _help(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.filtering:
                self.filter_text += "?"
                self._recompute()
            else:
                self.help = not self.help
            event.app.invalidate()

        @bindings.add("q")
        def _quit(event: Any) -> None:
            if self.pending_delete:
                event.app.invalidate()
                return
            if self.filtering:
                self.filter_text += "q"
                self._recompute()
            else:
                event.app.exit()
            event.app.invalidate()

        @bindings.add("c-c")
        def _cancel(event: Any) -> None:
            event.app.exit()

        @bindings.add(Keys.Any)
        def _text(event: Any) -> None:
            if self.filtering and not self.help and not self.pending_delete:
                text = event.data
                if text and text.isprintable():
                    self.filter_text += text
                    self._recompute()
                    event.app.invalidate()

        return bindings

    def run(self) -> str | None:
        if not self.tokens:
            raise TokenError("No tokens available to select.")
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise TokenError(
                "Interactive token selection requires a terminal. "
                "Pass --token <name> or run in an interactive shell."
            )

        control = FormattedTextControl(self._render, focusable=True, show_cursor=False)
        window = Window(
            content=control,
            wrap_lines=False,
            always_hide_cursor=True,
        )
        app = Application(
            layout=Layout(window),
            key_bindings=self._bindings(),
            full_screen=True,
            mouse_support=False,
        )
        try:
            app.run()
        except KeyboardInterrupt:
            return None
        return self.result


def run_selector(
    tokens: list[TokenRecord],
    *,
    on_delete: Callable[[str], bool] | None = None,
) -> str | None:
    return _Selector(tokens, on_delete=on_delete).run()
