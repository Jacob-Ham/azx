"""Command context: token resolution and API clients."""

from __future__ import annotations

from .api import ArmClient, GraphClient
from .config import Settings
from .console import Output
from .errors import AzxError, TokenError
from .http import HttpClient
from .model import TokenRecord
from .storage import TokenStore
from .util import is_interactive


def _usable(token: TokenRecord) -> bool:
    return token.has_access_token and bool(token.claims)


class Context:
    def __init__(
        self,
        settings: Settings,
        console: Output,
        store: TokenStore,
        http: HttpClient,
    ) -> None:
        self.settings = settings
        self.console = console
        self.store = store
        self.http = http
        self.current_token: TokenRecord | None = None
        self._client_used = False

    @property
    def interactive(self) -> bool:
        return is_interactive()

    @property
    def dry_run(self) -> bool:
        return self.settings.dry_run

    def _validate_token(
        self,
        token: TokenRecord,
        *,
        allow_expired: bool = False,
    ) -> None:
        if not token.has_access_token:
            raise TokenError(f"Token '{token.name}' has no access token.")
        if not token.claims:
            raise TokenError(
                f"Token '{token.name}' does not contain a decodable JWT access "
                "token. Opaque access tokens are not supported."
            )
        if token.expired and not allow_expired:
            if token.has_refresh_token:
                raise TokenError(
                    f"Token '{token.name}' is expired. Run "
                    f"`azx token refresh {token.name}` to refresh it."
                )
            raise TokenError(f"Token '{token.name}' is expired.")

    def _no_token_message(self) -> str:
        return (
            "No tokens found. Import one with `azx token import` or "
            "acquire one with `azx auth app`."
        )

    def _no_active_message(self) -> str:
        if any(_usable(token) for token in self.store.scan()):
            return (
                "No active token is set. Run `azx token select` to choose "
                "one, or pass --token <name>."
            )
        return self._no_token_message()

    def _active_failure(self, token: TokenRecord | None, active: str) -> str:
        if token is None:
            return (
                f"Active token '{active}' was not found. "
                "Run `azx token select` to choose a token."
            )
        if not token.has_access_token:
            return (
                f"Active token '{active}' has no access token (refresh token "
                "only). Import a matching access token instead."
            )
        if not token.claims:
            return (
                f"Active token '{active}' does not contain a decodable JWT "
                "access token. Opaque access tokens are not supported."
            )
        if token.expired:
            if token.has_refresh_token:
                return (
                    f"Active token '{active}' is expired. Run "
                    f"`azx token refresh {active}` to refresh it, or "
                    "`azx token select` to choose another token."
                )
            return (
                f"Active token '{active}' is expired. "
                "Run `azx token select` to choose another token."
            )
        return self._no_token_message()

    def _select(
        self,
        tokens: list[TokenRecord],
        *,
        activate: bool = True,
    ) -> TokenRecord | None:
        if not tokens:
            raise TokenError(self._no_token_message())
        from .selector import run_selector

        selected = run_selector(tokens, on_delete=self.store.delete)
        if selected is None:
            return None
        token = self.store.get(selected)
        if activate:
            self.store.set_active(token.name)
        return token

    def select_token(self, *, activate: bool = True) -> TokenRecord | None:
        tokens = [token for token in self.store.scan() if _usable(token)]
        return self._select(tokens, activate=activate)

    def _select_usable(
        self,
        *,
        allow_expired: bool,
        activate: bool = True,
    ) -> TokenRecord:
        selected = self._select(
            [token for token in self.store.scan() if _usable(token)],
            activate=False,
        )
        if selected is None:
            raise TokenError("No token selected.")
        self._validate_token(selected, allow_expired=allow_expired)
        if activate:
            self.store.set_active(selected.name)
        return selected

    def resolve_token(self, *, allow_expired: bool = False) -> TokenRecord:
        explicit = self.settings.token_name
        if explicit:
            token = self.store.get(explicit)
            self._validate_token(token, allow_expired=allow_expired)
            return token

        active = self.store.active_name()
        if active:
            token = self.store.get(active, required=False)
            if token is not None:
                try:
                    self._validate_token(token, allow_expired=allow_expired)
                    return token
                except TokenError:
                    pass
            if self.interactive:
                return self._select_usable(
                    allow_expired=allow_expired,
                    activate=not self.settings.dry_run,
                )
            raise TokenError(self._active_failure(token, active))

        if self.interactive:
            return self._select_usable(
                allow_expired=allow_expired,
                activate=not self.settings.dry_run,
            )

        raise TokenError(self._no_active_message())

    def _begin_api(self) -> TokenRecord:
        if self._client_used:
            raise AzxError(
                "This command attempted to use both Graph and ARM; "
                "that is not supported."
            )
        token = self.resolve_token()
        self.console.token_line(token.name)
        self.current_token = token
        self._client_used = True
        return token

    def graph(self) -> GraphClient:
        token = self._begin_api()
        assert token.access_token is not None
        return GraphClient(self.http, token.access_token)

    def arm(self) -> ArmClient:
        token = self._begin_api()
        assert token.access_token is not None
        return ArmClient(self.http, token.access_token)
