# Copyright (c) Microsoft. All rights reserved.
"""Core managed ports with no new mandatory third-party dependencies.

Native activation always runs first and its errors are raised unchanged. Default
discovery lazily imports the optional polling distribution only after native
activation reports a manifest load failure and the file is regular
``remote_policy`` configuration; trusted injected loaders supply their own backend.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import stat
import threading
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import Protocol, TypeVar, runtime_checkable

from agent_hooks import Verdict

MANAGED_ACTIVATION_API_VERSION = 1
_START_TIMEOUT = 240.0
_CLOSE_TIMEOUT = 30.0
_T = TypeVar("_T")
_LOG = logging.getLogger(__name__)
# Routing is advisory: none of these may replace the native activation error.
_CLASSIFIER_FAILURES = (ValueError, OverflowError, RecursionError, TypeError)
# A cheap hint-only filter: YAML or JSON text with a ``remote_policy`` key.
_REMOTE_ROOT = re.compile(r"""^[ \t{]*["']?remote_policy["']?[ \t]*:""", re.MULTILINE)


class ManagedPolicyUsageError(RuntimeError):
    """A managed policy was used outside its one asynchronous lifetime."""


class RemotePolicyDependencyError(ImportError):
    """Managed activation needs compatible core and optional distributions."""


@runtime_checkable
class PolicyEvaluation(Protocol):
    """One complete verdict bound to its policy snapshot and lifetime."""

    @property
    def verdict(self) -> Verdict:
        """The full native verdict, not an authorization to defer execution."""
        ...

    def assert_current(self) -> None:
        """Synchronously reject replacement, expiry, fencing, or closure."""
        ...


@runtime_checkable
class AsyncPolicyEvaluator(Protocol):
    """Trusted backend; evaluate locally without executing the protected effect."""

    async def evaluate(
        self, point: str, context: Mapping[str, object]
    ) -> PolicyEvaluation: ...


class RemotePolicyLoader(Protocol):
    """Host-injected configuration and lifetime; never a YAML executable import."""

    def is_remote_configuration(self, configuration_yaml: str) -> bool:
        """Strictly classify bounded configuration without I/O."""
        ...

    def open(
        self, configuration_yaml: str
    ) -> AbstractAsyncContextManager[AsyncPolicyEvaluator]:
        """Own bounded startup, evaluation resources, and shutdown."""
        ...


def valid_positive_integer(value: object) -> bool:
    """Validate even untyped host callers without weakening the public port."""
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _is_mapping(value: object) -> bool:
    return isinstance(value, Mapping)


def _checked_classifier(value: object) -> bool:
    if not isinstance(value, bool):
        if inspect.iscoroutine(value):
            value.close()
        raise ManagedPolicyUsageError(
            "Managed loader classifier must synchronously return bool"
        )
    return value


def _checked_backend(value: object) -> AsyncPolicyEvaluator:
    if not isinstance(value, AsyncPolicyEvaluator):
        raise ManagedPolicyUsageError("Managed loader returned no evaluator")
    return value


def _check_verdict(value: object) -> None:
    if not isinstance(value, Verdict):
        raise ManagedPolicyUsageError("PolicyEvaluation must contain a Verdict")


def checked_evaluation(value: object) -> PolicyEvaluation:
    """Reject invalid custom completions before the final synchronous gate."""
    message = (
        "Managed evaluator must return PolicyEvaluation with a Verdict "
        "and synchronous assert_current()"
    )
    try:
        if (
            not isinstance(value, PolicyEvaluation)
            or not callable(value.assert_current)
            or inspect.iscoroutinefunction(value.assert_current)
        ):
            raise ManagedPolicyUsageError(message)
        _check_verdict(value.verdict)
    except (AttributeError, TypeError):
        raise ManagedPolicyUsageError(message) from None
    return value


def assert_evaluation_current(completion: PolicyEvaluation) -> None:
    """Execute the final gate, rejecting disguised asynchronous host callbacks."""
    assertion: Callable[[], object] = completion.assert_current
    result = assertion()
    if result is not None:
        if inspect.iscoroutine(result):
            result.close()
        raise ManagedPolicyUsageError(
            "PolicyEvaluation.assert_current() must synchronously return None"
        )


def freeze_context(context: Mapping[str, object]) -> dict[str, object]:
    """Capture before scheduling, with at most 2 MiB of serialized host context."""
    captured = bytearray()
    try:
        for chunk in json.JSONEncoder(allow_nan=False).iterencode(dict(context)):
            # ensure_ascii defaults true, so character and UTF-8 byte caps agree.
            if len(captured) + len(chunk) > 2 * 1024 * 1024:
                raise ManagedPolicyUsageError("Managed context exceeds its byte limit")
            captured.extend(chunk.encode("ascii"))
        result: dict[str, object] = json.loads(captured)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ManagedPolicyUsageError("Managed context must be bounded JSON") from None


async def finish_owned(work: asyncio.Future[_T]) -> _T:
    """Drain one owned operation despite repeated cancellation; never duplicate it."""
    cancellation: asyncio.CancelledError | None = None
    while not work.done():
        try:
            await asyncio.shield(work)
        except asyncio.CancelledError as error:
            cancellation = cancellation if cancellation is not None else error
    result = work.result()
    if cancellation is not None:
        raise cancellation
    return result


def _observe(work: asyncio.Future[_T]) -> None:
    if not work.cancelled():
        work.exception()


class ManagedActivation:
    """Stable captured configuration, atomically claimable exactly once."""

    def __init__(self, source: str, loader: RemotePolicyLoader) -> None:
        self._source = source
        self._loader = loader
        self._claimed = False
        self._lock = threading.Lock()

    def claim(self) -> ManagedRuntime:
        """Consume this activation; call activate again for another lifetime."""
        with self._lock:
            if self._claimed:
                raise ManagedPolicyUsageError(
                    "Remote activation is single-owner/single-use; call activate() "
                    "again and use separate loaders/registries for concurrent lifetimes"
                )
            self._claimed = True
        return ManagedRuntime(self._source, self._loader)


class ManagedRuntime:
    """Enter and exit a loader in one task, even when callers change tasks."""

    def __init__(self, source: str, loader: RemotePolicyLoader) -> None:
        self._source = source
        self._loader = loader
        self._owner: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[AsyncPolicyEvaluator] | None = None
        self._release: asyncio.Event | None = None
        self._closing = False

    async def _own(self) -> None:
        assert self._ready is not None and self._release is not None
        try:
            async with self._loader.open(self._source) as backend:
                self._ready.set_result(_checked_backend(backend))
                await self._release.wait()
        except BaseException as error:
            if not self._ready.done():
                if isinstance(error, asyncio.CancelledError):
                    self._ready.cancel()
                else:
                    self._ready.set_exception(error)
            raise

    async def start(self) -> AsyncPolicyEvaluator:
        """Wait up to 240 seconds; the caller owns close after startup failure."""
        if self._owner is not None or self._closing:
            raise ManagedPolicyUsageError(
                "Managed runtime is single-use; call activate() again"
            )
        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        self._ready.add_done_callback(_observe)
        self._release = asyncio.Event()
        self._owner = loop.create_task(self._own(), name="acs-managed-owner")
        self._owner.add_done_callback(_observe)
        done, _ = await asyncio.wait({self._ready}, timeout=_START_TIMEOUT)
        if not done:
            raise ManagedPolicyUsageError("Managed startup exceeded its deadline")
        if self._closing and self._ready.cancelled():
            caller = asyncio.current_task()
            if caller is not None and caller.cancelling() == 0:
                raise ManagedPolicyUsageError("Remote startup was closed")
        return self._ready.result()

    async def aclose(self) -> None:
        """Wait up to 30 seconds for the same owner; replay failures on retry."""
        self.request_close()
        owner = self._owner
        if owner is None:
            return
        done, _ = await asyncio.wait({owner}, timeout=_CLOSE_TIMEOUT)
        if not done:
            raise ManagedPolicyUsageError(
                "Managed cleanup exceeded its deadline; one owner remains retained"
            )
        if not owner.cancelled():
            owner.result()

    def request_close(self) -> None:
        """Signal the same owner, also usable when retained evaluation finally exits."""
        if self._closing:
            return
        self._closing = True
        if self._owner is not None:
            assert self._ready is not None and self._release is not None
            if not self._ready.done():
                self._owner.cancel()
            else:
                self._release.set()


def _read_source(path: str, cap: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("ACS configuration must be a regular file")
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        return stream.read(cap + 1)


def _read_regular_source(path: str, cap: int) -> str | None:
    """Read a regular UTF-8 file for routing only; never open a special file.

    Native activation already read (or rejected) ``path``. A FIFO or device is
    left alone: opening one here could block or consume data. Returns ``None``
    when the file is special, unreadable, oversized or not UTF-8, so the native
    error stands.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        raw = _read_source(path, cap)
        return raw.decode("utf-8") if len(raw) <= cap else None
    except (OSError, ValueError, OverflowError):  # UnicodeError is a ValueError.
        return None


def _optional_import_note(failure: ImportError) -> str:
    if failure.name == "agent_control_spec_remote_policy":
        return (
            "If this is remote_policy YAML, install "
            "agent-control-spec-remote-policy. Native parsing error preserved."
        )
    return (
        "agent-control-spec-remote-policy is installed but could not be "
        "imported; reinstall it. Native parsing error preserved."
    )


def _add_remote_note(source: str, error: ValueError) -> None:
    """Attach a payload-free note for an established remote root; never raises."""
    try:
        from agent_control_spec_remote_policy import poller

        note = getattr(poller, "remote_configuration_note", None)
        detail: object = note(source) if callable(note) else None
    except ImportError:
        return
    except _CLASSIFIER_FAILURES as failure:
        _LOG.debug(
            "remote_configuration_note_failed error_type=%s", type(failure).__name__
        )
        return
    if isinstance(detail, str):
        error.add_note(detail)


def prepare_managed(
    path: str,
    loader: RemotePolicyLoader | None,
    limits: Mapping[str, int] | None,
    native_error: ValueError,
) -> ManagedActivation | None:
    """Route a failed native activation to managed remote mode, if it is one.

    Call only after native activation raised ``native_error`` while loading the
    manifest. Returns a single-use activation only when ``path`` is a regular
    UTF-8 file that the native grammar rejects and remote configuration
    validation accepts. Every other outcome returns ``None`` so the caller
    re-raises ``native_error`` unchanged, optionally with a hint added through
    ``add_note``. Classification problems in this module never replace the native
    error; exceptions raised by a host loader's own classifier are trusted host
    code and propagate.

    Raises:
        ManagedPolicyUsageError: a host loader's classifier is not a synchronous
            function returning ``bool``, which violates the loader contract.
        RemotePolicyDependencyError: the file is valid remote configuration but
            the installed optional distribution lacks the managed capability.
    """
    from agent_control_spec import DEFAULT_LIMITS, ManifestInvalidError, parse_manifest

    cap = DEFAULT_LIMITS["max_merged_manifest_bytes"]
    if limits is not None:
        if not _is_mapping(limits):
            return None
        requested = limits.get("max_merged_manifest_bytes", cap)
        if not valid_positive_integer(requested):
            return None  # Native activation owns invalid-limit diagnostics.
        # Remote configuration is small: routing never reads beyond the default
        # bound, even when a host raised the native manifest limit.
        cap = min(cap, requested)
    source = _read_regular_source(path, cap)
    if source is None:
        return None
    try:
        parse_manifest(source, limits=limits)
    except ManifestInvalidError:
        pass  # The native grammar rejects it: it may be remote configuration.
    except _CLASSIFIER_FAILURES:
        return None
    else:
        return None  # A valid local manifest: the native failure is not routing.
    if loader is not None:
        if _checked_classifier(loader.is_remote_configuration(source)):
            return ManagedActivation(source, loader)
        _add_remote_note(source, native_error)
        return None
    try:
        # This old-compatible low-level parser never imports managed ports.
        import agent_control_spec_remote_policy as optional
        from agent_control_spec_remote_policy.poller import (
            PolicyValidationError,
            PollerConfig,
        )
    except ImportError as failure:
        # Hint only when the file plausibly is remote configuration: a plain
        # typo in a local manifest keeps exactly the native error.
        if _REMOTE_ROOT.search(source) is not None:
            native_error.add_note(_optional_import_note(failure))
        return None
    try:
        PollerConfig.from_yaml(source)
    except PolicyValidationError:
        # Only an established root receives a payload-free diagnostic.
        _add_remote_note(source, native_error)
        return None
    except _CLASSIFIER_FAILURES as failure:
        _LOG.debug(
            "remote_policy_classification_failed error_type=%s", type(failure).__name__
        )
        return None
    if (
        getattr(optional, "MANAGED_ACTIVATION_API_VERSION", None)
        != MANAGED_ACTIVATION_API_VERSION
    ):
        raise RemotePolicyDependencyError(
            "Remote activation requires a matching "
            "agent-control-spec-remote-policy with managed activation API 1"
        ) from None
    from agent_control_spec_remote_policy.integration import RemotePolicyFileLoader

    return ManagedActivation(source, RemotePolicyFileLoader())
