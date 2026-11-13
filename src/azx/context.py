"""Command context: token resolution and API clients."""

from __future__ import annotations

from dataclasses import dataclass

from .api import ArmClient, GraphClient
from .config import Settings
from .console import Output
from .errors import AzxError, TokenError
from .http import HttpClient
from .model import TokenRecord
from .storage import TokenStore
from .tokenmeta import audience_matches
from .util import is_interactive


@dataclass(frozen=True)
class AudienceRequirement:
    kind: str
    label: str
    auth_hint: str

    def matches(self, token: TokenRecord) -> bool:
        return audience_matches(token.audience, self.kind)


GRAPH = AudienceRequirement(
    kind="graph",
    label="Graph",
    auth_hint="azx auth app -c <client-id> -p <secret> -t <tenant> -r msgraph",
)
ARM = AudienceRequirement(
    kind="arm",
    label="ARM",
    auth_hint="azx auth app -c <client-id> -p <secret> -t <tenant> -r azrm",
)


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
        requirement: AudienceRequirement | None,
        *,
        allow_expired: bool = False,
    ) -> None:
        if not token.has_access_token:
            raise TokenError(
                f"Token '{token.name}' has no access token (refresh token only)."
            )
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
        if requirement is not None and not requirement.matches(token):
            raise TokenError(
                f"Token '{token.name}' has audience "
                f"'{token.audience_display}', but {requirement.label} is "
                "required."
            )

    def _no_token_message(self, requirement: AudienceRequirement | None) -> str:
        if requirement is None:
            return (
                "No tokens found. Import one with `azx token import` or "
                "acquire one with `azx auth app`."
            )
        return (
            f"No {requirement.label} token found. Import one with "
            "`azx token import` or acquire one with:\n"
            f"  {requirement.auth_hint}"
        )

    def _no_active_message(self, requirement: AudienceRequirement | None) -> str:
        usable = [
            token
            for token in self.store.scan()
            if token.has_access_token
            and token.claims
            and (requirement is None or requirement.matches(token))
        ]
        if usable:
            return (
                "No active token is set. Run `azx token select` to choose "
                "one, or pass --token <name>."
            )
        return self._no_token_message(requirement)

    def _active_failure(
        self,
        token: TokenRecord | None,
        active: str,
        requirement: AudienceRequirement | None,
    ) -> str:
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
        if requirement is not None and not requirement.matches(token):
            return (
                f"Active token '{active}' has audience "
                f"'{token.audience_display}', but {requirement.label} is "
                "required. Run `azx token select` to choose another token."
            )
        return self._no_token_message(requirement)

    def _select(
        self,
        tokens: list[TokenRecord],
        requirement: AudienceRequirement | None,
        *,
        activate: bool = True,
    ) -> TokenRecord | None:
        if not tokens:
            raise TokenError(self._no_token_message(requirement))
        from .selector import run_selector

        selected = run_selector(tokens, on_delete=self.store.delete)
        if selected is None:
            return None
        token = self.store.get(selected)
        if activate:
            self.store.set_active(token.name)
        return token

    def select_token(
        self,
        requirement: AudienceRequirement | None = None,
        *,
        all_tokens: bool = False,
        activate: bool = True,
    ) -> TokenRecord | None:
        tokens = self.store.scan()
        if not all_tokens:
            tokens = [
                token
                for token in tokens
                if token.has_access_token
                and token.claims
                and (requirement is None or requirement.matches(token))
            ]
        return self._select(tokens, requirement, activate=activate)

    def _select_for_requirement(
        self,
        requirement: AudienceRequirement | None,
        *,
        allow_expired: bool,
        activate: bool = True,
    ) -> TokenRecord:
        selected = self._select(
            [
                item
                for item in self.store.scan()
                if item.has_access_token
                and item.claims
                and (requirement is None or requirement.matches(item))
            ],
            requirement,
            activate=False,
        )
        if selected is None:
            raise TokenError("No token selected.")
        self._validate_token(selected, requirement, allow_expired=allow_expired)
        if activate:
            self.store.set_active(selected.name)
        return selected

    def resolve_token(
        self,
        requirement: AudienceRequirement | None = None,
        *,
        allow_expired: bool = False,
    ) -> TokenRecord:
        explicit = self.settings.token_name
        if explicit:
            token = self.store.get(explicit)
            self._validate_token(token, requirement, allow_expired=allow_expired)
            return token

        active = self.store.active_name()
        if active:
            token = self.store.get(active, required=False)
            if token is not None:
                try:
                    self._validate_token(
                        token, requirement, allow_expired=allow_expired
                    )
                    return token
                except TokenError:
                    pass
            if self.interactive:
                return self._select_for_requirement(
                    requirement,
                    allow_expired=allow_expired,
                    activate=not self.settings.dry_run,
                )
            raise TokenError(self._active_failure(token, active, requirement))

        if self.interactive:
            return self._select_for_requirement(
                requirement,
                allow_expired=allow_expired,
                activate=not self.settings.dry_run,
            )

        raise TokenError(self._no_active_message(requirement))

    def _begin_api(self, requirement: AudienceRequirement) -> TokenRecord:
        if self._client_used:
            raise AzxError(
                "This command attempted to use more than one API audience; "
                "that is not supported."
            )
        token = self.resolve_token(requirement)
        self.console.token_line(token.name)
        self.current_token = token
        self._client_used = True
        return token

    def graph(self) -> GraphClient:
        token = self._begin_api(GRAPH)
        assert token.access_token is not None
        return GraphClient(self.http, token.access_token)

    def arm(self) -> ArmClient:
        token = self._begin_api(ARM)
        assert token.access_token is not None
        return ArmClient(self.http, token.access_token)
