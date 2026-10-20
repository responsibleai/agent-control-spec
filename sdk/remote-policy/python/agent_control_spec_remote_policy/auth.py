# Copyright (c) Microsoft. All rights reserved.
"""Trusted credential selection and add-only, single-request HTTP authentication."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncGenerator, Callable, Generator, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, NoReturn, Protocol, TypeAlias, cast, runtime_checkable

import httpx

from .poller import (
    CredentialOption,
    PolicyError,
    PolicySourceError,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
)

_LOG = logging.getLogger(__name__)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SINGLE_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9_-]* [\x21-\x7e]{1,16384}")
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}")
_FORBIDDEN = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "cookie",
        "set-cookie",
        "forwarded",
        "via",
        "max-forwards",
        "range",
        "x-http-method-override",
        "x-original-url",
        "x-rewrite-url",
    }
)
_FORBIDDEN_PREFIXES = ("content-", "proxy-", "x-forwarded-", "if-")
_CLEANUP_NOTE = "Credential cleanup also failed; provider details were suppressed."
_CANCELLATION_NOTE = "A prior body failure occurred; its details were suppressed."
_CORRELATION_HEADERS = (
    "x-ms-client-request-id",
    "x-request-id",
    "x-correlation-id",
    "x-ms-correlation-request-id",
)
_AuthReason: TypeAlias = Literal[
    "invalid_request",
    "provider_error",
    "provider_timeout",
    "invalid_legacy_value",
    "invalid_headers",
]
_RegistryReason: TypeAlias = Literal[
    "invalid_config",
    "provider_error",
    "provider_timeout",
    "entry_timeout",
    "entry_cancelled",
    "cleanup_error",
    "cleanup_timeout",
]


def _optional_identifier(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise PolicyValidationError("config")
    return value


def _audit_identifier(value: object) -> str | None:
    return (
        value if isinstance(value, str) and _ID.fullmatch(value) is not None else None
    )


def _exception_class(error: BaseException) -> str:
    name = type(error).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "Exception"


def _credential_event(
    event: str,
    reference: str | None,
    provider: str | None,
    stage: Literal["entry", "open", "close"],
    *,
    reason: _RegistryReason | None = None,
    error: BaseException | None = None,
    retained_tasks: int = 0,
) -> None:
    _LOG.log(
        (
            logging.ERROR
            if event == "credential_cleanup_failed"
            else logging.WARNING
            if reason is not None
            else logging.INFO
        ),
        event,
        extra={
            "event": event,
            "credential_ref": reference,
            "provider": provider,
            "stage": stage,
            "reason": reason,
            "exception_class": _exception_class(error) if error is not None else None,
            "retained_tasks": retained_tasks,
        },
    )


@runtime_checkable
class AuthorizationProvider(Protocol):
    """Host credential returning one strictly validated Authorization value."""

    async def authorization(self) -> str: ...


@dataclass(frozen=True, slots=True)
class AuthenticationRequest:
    """Read-only final pre-auth request; no live HTTPX object is exposed."""

    method: str
    url: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        raw: object = self.headers
        if (
            not isinstance(self.method, str)
            or not isinstance(self.url, str)
            or not isinstance(self.body, bytes)
            or not isinstance(raw, Mapping)
        ):
            raise PolicyValidationError("config")
        headers: dict[str, str] = {}
        for name, value in cast(Mapping[object, object], raw).items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise PolicyValidationError("config")
            headers[name] = value
        object.__setattr__(self, "headers", MappingProxyType(headers))


@runtime_checkable
class RequestAuthenticator(Protocol):
    """Re-entrant host signer; return only new authentication headers."""

    async def authenticate(
        self, request: AuthenticationRequest
    ) -> Mapping[str, str]: ...


Credential: TypeAlias = AuthorizationProvider | RequestAuthenticator
CredentialProviderFactory: TypeAlias = Callable[
    [Mapping[str, CredentialOption]], AbstractAsyncContextManager[Credential]
]


def _normalize(credential: Credential) -> Credential:
    if isinstance(credential, AuthorizationProvider) == isinstance(
        credential, RequestAuthenticator
    ):
        raise PolicyValidationError("config")
    return credential


def _authentication_headers(raw: object, existing: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise TypeError("Invalid authentication headers")
    fields = cast(Mapping[object, object], raw)
    if not 1 <= len(fields) <= 32:
        raise ValueError("Invalid authentication headers")
    reserved = {name.lower() for name in existing}
    result: dict[str, str] = {}
    total = 0
    for name, value in fields.items():
        if len(result) >= 32:
            raise ValueError("Authentication headers too numerous")
        if (
            not isinstance(name, str)
            or _HEADER_NAME.fullmatch(name) is None
            or not isinstance(value, str)
            or re.fullmatch(r"[\x20-\x7e]{1,16384}", value) is None
            or value != value.strip()
        ):
            raise ValueError("Invalid authentication headers")
        lower = name.lower()
        if (
            lower in reserved
            or lower in result
            or lower in _FORBIDDEN
            or lower.startswith(_FORBIDDEN_PREFIXES)
        ):
            raise ValueError("Reserved authentication header")
        total += len(name) + len(value)
        if total > 32768:
            raise ValueError("Authentication headers too large")
        result[lower] = value
    return result


class RequestAuthentication(httpx.Auth):
    """Async-only one-request auth; unread streams fail closed without buffering.

    Labels are host-supplied, non-secret configuration metadata, not proof of
    credential identity. Audit-only HTTPX extensions never enter signer context.
    """

    def __init__(
        self,
        credential: Credential,
        *,
        credential_ref: str | None = None,
        provider: str | None = None,
    ) -> None:
        self._credential = _normalize(credential)
        self._reference = _optional_identifier(credential_ref)
        self._provider = _optional_identifier(provider)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """Reject synchronous clients before credentials or transport are used."""
        raise TypeError("RequestAuthentication requires httpx.AsyncClient")

    def _fail(
        self,
        request: httpx.Request,
        reason: _AuthReason,
        error: Exception,
    ) -> NoReturn:
        child = next(
            (
                request.headers[name]
                for name in _CORRELATION_HEADERS
                if name in request.headers
            ),
            None,
        )
        _LOG.warning(
            "credential_authentication_failed",
            extra={
                "event": "credential_authentication_failed",
                "stage": "authenticate",
                "reason": reason,
                "exception_class": _exception_class(error),
                "credential_ref": self._reference,
                "provider": self._provider,
                "request_id": _audit_identifier(child),
                "http_request_id": _audit_identifier(child),
                "policy_request_id": _audit_identifier(
                    request.extensions.get("acs_policy_request_id")
                ),
            },
        )
        raise PolicySourceError("transient", "credential") from None

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """Apply validated add-only headers; redact all provider exception details."""
        try:
            _optional_identifier(request.extensions.get("acs_policy_request_id"))
            for name in _CORRELATION_HEADERS:
                _optional_identifier(request.headers.get(name))
            context = AuthenticationRequest(
                request.method,
                str(request.url),
                dict(request.headers.items()),
                request.content,
            )
        except Exception as error:  # noqa: BLE001 - credential security boundary.
            self._fail(request, "invalid_request", error)
        single_header = isinstance(self._credential, AuthorizationProvider)
        try:
            raw: object
            if isinstance(self._credential, AuthorizationProvider):
                raw = await self._credential.authorization()
            else:
                raw = await self._credential.authenticate(context)
        except (TimeoutError, httpx.TimeoutException) as error:
            self._fail(request, "provider_timeout", error)
        except Exception as error:  # noqa: BLE001 - credential security boundary.
            self._fail(request, "provider_error", error)
        if single_header:
            try:
                if not isinstance(raw, str) or _SINGLE_HEADER.fullmatch(raw) is None:
                    raise ValueError("Invalid single-header authorization")
            except Exception as error:  # noqa: BLE001 - credential security boundary.
                self._fail(request, "invalid_legacy_value", error)
        try:
            if single_header:
                if "authorization" in context.headers:
                    raise ValueError("Reserved authentication header")
                headers = {"authorization": cast(str, raw)}
            else:
                headers = _authentication_headers(raw, context.headers)
            request.headers.update(headers)
        except Exception as error:  # noqa: BLE001 - credential security boundary.
            self._fail(request, "invalid_headers", error)
        yield request


class CredentialCloseError(PolicyError):
    """Credential cleanup failed; retained work is explicitly not closed."""

    def __init__(self, retained_tasks: int) -> None:
        self.retained_tasks = retained_tasks
        super().__init__("Remote policy credential did not close cleanly")


def _observe_ready(ready: asyncio.Future[Credential]) -> None:
    if not ready.cancelled():
        ready.exception()


def _observe_owner(owner: asyncio.Task[None]) -> None:
    if not owner.cancelled():
        owner.exception()


class CredentialProviderRegistry:
    """Immutable factory allow-list; one bounded provider owner per source registry.

    The default allow-list is empty: a ``credential_ref`` is refused, before any
    credential is acquired, unless trusted host code registered the provider its
    YAML names. A registered factory receives the YAML's options and the YAML
    chooses the endpoint that credential is sent to, so register only factories
    whose configuration the YAML author is trusted to control.

    Factories enter/exit in one task. ContextVars set there are not an
    authentication context: providers keep shared state on their instance.
    """

    def __init__(
        self, providers: Mapping[str, CredentialProviderFactory] | None = None
    ) -> None:
        if providers is None:
            providers = MappingProxyType({})
        raw: object = providers
        if not isinstance(raw, Mapping) or len(raw) > 32:
            raise PolicyValidationError("config")
        copied: dict[str, CredentialProviderFactory] = {}
        for name, factory in cast(Mapping[object, object], raw).items():
            if (
                not isinstance(name, str)
                or _ID.fullmatch(name) is None
                or not callable(factory)
                or name in copied
                or len(copied) >= 32
            ):
                raise PolicyValidationError("config")
            copied[name] = cast(CredentialProviderFactory, factory)
        self._providers = MappingProxyType(copied)
        self._active = False
        self._failed = False
        self._owner: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def pending_task_count(self) -> int:
        """Number of retained live owners (always zero or one)."""
        return int(self._owner is not None and not self._owner.done())

    async def _own(
        self,
        factory: CredentialProviderFactory,
        options: Mapping[str, CredentialOption],
        ready: asyncio.Future[Credential],
        release: asyncio.Event,
        reference: str,
        provider: str,
    ) -> None:
        try:
            async with factory(options) as credential:
                if ready.done():
                    # A retained, cancellation-resistant entry finished after
                    # its caller left. Exit its context instead of publishing.
                    return
                ready.set_result(_normalize(credential))
                await release.wait()
        except asyncio.CancelledError:
            if not ready.done():
                ready.cancel()
            raise
        except Exception as error:
            task = asyncio.current_task()
            if ready.done() or (task is not None and task.cancelling()):
                raise
            _credential_event(
                "credential_entry_failed",
                reference,
                provider,
                "entry",
                reason=(
                    "invalid_config"
                    if isinstance(error, PolicyValidationError)
                    else "provider_timeout"
                    if isinstance(error, (TimeoutError, httpx.TimeoutException))
                    else "provider_error"
                ),
                error=error,
            )
            failure = (
                PolicyValidationError("config")
                if isinstance(error, PolicyValidationError) and error.code == "config"
                else PolicySourceError("transient", "credential")
            )
            ready.set_exception(failure)

    async def _wait_until(
        self, owner: asyncio.Task[None], deadline: float
    ) -> asyncio.CancelledError | None:
        cancellation: asyncio.CancelledError | None = None
        loop = asyncio.get_running_loop()
        while not owner.done() and (remaining := deadline - loop.time()) > 0:
            try:
                await asyncio.wait({owner}, timeout=remaining)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
        return cancellation

    async def _close(
        self, owner: asyncio.Task[None], timeout: float
    ) -> tuple[CredentialCloseError | None, asyncio.CancelledError | None]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        cancellation = await self._wait_until(owner, started + timeout / 2)
        interrupted = not owner.done()
        if not owner.done():
            owner.cancel()
            later = await self._wait_until(owner, started + timeout)
            cancellation = cancellation if cancellation is not None else later
        failed = not owner.done()
        if owner.done() and not owner.cancelled():
            failed = owner.exception() is not None
        elif owner.cancelled() and interrupted:
            failed = True
        if failed:
            self._failed = True
            return CredentialCloseError(self.pending_task_count), cancellation
        self._owner = None
        return None, cancellation

    @asynccontextmanager
    async def open(
        self, config: PollerConfig
    ) -> AsyncGenerator[Mapping[str, Credential], None]:
        """Open the selected provider with bounded, fail-closed resource ownership.

        After successful cleanup, new external cancellation supersedes a
        non-cancel body error. An already-primary cancellation retains identity.
        If cleanup fails too, preserve the exact primary error with safe notes.
        """
        loop = asyncio.get_running_loop()
        if (
            self._failed
            or self._active
            or (self._loop is not None and self._loop is not loop)
        ):
            raise PolicyUsageError("Credential registry is unavailable")
        reference = config.credential_ref
        provider: str | None = None
        factory: CredentialProviderFactory | None = None
        options: Mapping[str, CredentialOption] = MappingProxyType({})
        if reference is not None:
            definition = config.credentials.get(reference)
            if definition is None or definition.provider not in self._providers:
                _credential_event(
                    "credential_entry_failed",
                    reference,
                    definition.provider if definition is not None else None,
                    "entry",
                    reason="invalid_config",
                    error=PolicyValidationError("config"),
                )
                raise PolicyValidationError("config")
            provider = definition.provider
            factory = self._providers[definition.provider]
            options = definition.options
        # Admission check and update have no await between them.
        self._active = True
        self._loop = loop
        owner: asyncio.Task[None] | None = None
        ready: asyncio.Future[Credential] = loop.create_future()
        ready.add_done_callback(_observe_ready)
        release = asyncio.Event()
        primary: BaseException | None = None
        opened = False
        try:
            selected: dict[str, Credential] = {}
            if factory is not None and reference is not None and provider is not None:
                owner = asyncio.create_task(
                    self._own(factory, options, ready, release, reference, provider),
                    name="policy-credential-owner",
                )
                owner.add_done_callback(_observe_owner)
                self._owner = owner
                try:
                    async with asyncio.timeout(config.request_timeout_seconds):
                        selected[reference] = await asyncio.shield(ready)
                except TimeoutError as error:
                    owner.cancel()
                    _credential_event(
                        "credential_entry_failed",
                        reference,
                        provider,
                        "entry",
                        reason="entry_timeout",
                        error=error,
                    )
                    raise PolicySourceError("transient", "timeout") from None
                except asyncio.CancelledError as error:
                    owner.cancel()
                    _credential_event(
                        "credential_entry_failed",
                        reference,
                        provider,
                        "entry",
                        reason="entry_cancelled",
                        error=error,
                    )
                    raise
                opened = True
                _credential_event("credential_opened", reference, provider, "open")
            yield MappingProxyType(selected)
        except BaseException as error:
            primary = error
            raise
        finally:
            release.set()
            try:
                if owner is not None:
                    failure, cancellation = await self._close(
                        owner, config.request_timeout_seconds
                    )
                    if failure is not None:
                        close_error = (
                            owner.exception()
                            if owner.done() and not owner.cancelled()
                            else None
                        )
                        _credential_event(
                            "credential_cleanup_failed",
                            reference,
                            provider,
                            "close",
                            reason="cleanup_error"
                            if close_error is not None
                            else "cleanup_timeout",
                            error=close_error
                            if close_error is not None
                            else TimeoutError(),
                            retained_tasks=failure.retained_tasks,
                        )
                        if primary is not None:
                            primary.add_note(_CLEANUP_NOTE)
                            if cancellation is not None and not isinstance(
                                primary, asyncio.CancelledError
                            ):
                                primary.add_note(
                                    "Cancellation also arrived during credential cleanup."
                                )
                        elif cancellation is not None:
                            cancellation.add_note(_CLEANUP_NOTE)
                            raise cancellation
                        else:
                            raise failure
                    else:
                        if opened:
                            _credential_event(
                                "credential_closed", reference, provider, "close"
                            )
                        if cancellation is not None and not isinstance(
                            primary, asyncio.CancelledError
                        ):
                            if primary is not None:
                                cancellation.add_note(_CANCELLATION_NOTE)
                            raise cancellation from None
            finally:
                if not ready.done():
                    ready.cancel()
                self._active = False
