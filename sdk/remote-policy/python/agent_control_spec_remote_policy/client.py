# Copyright (c) Microsoft. All rights reserved.
"""YAML-first ownership of authentication, polling, and native ACS evaluation."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
from collections.abc import AsyncGenerator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Self, TypeVar

from agent_hooks import Verdict

from .auth import Credential, CredentialProviderRegistry
from .evaluation import evaluate_policy_snapshot
from .http import HttpPolicySource
from .poller import (
    MAX_EVALUATION_BYTES,
    MAX_YAML_BYTES,
    AgentPolicy,
    Changed,
    JsonValue,
    NotModified,
    PolicyCapacityError,
    PolicyCloseError,
    PolicyPoller,
    PolicySnapshot,
    PolicySource,
    PolicySourceError,
    PolicyStatus,
    PolicyUnavailable,
    PolicyValidationError,
    PollerConfig,
    decode_json,
)
from .ports import PolicyPollerFactory, PolicyPollerProtocol, PolicySourceFactory

_LOG = logging.getLogger(__name__)
_SOURCE_CLOSE_TIMEOUT = 5.0
_T = TypeVar("_T")


def _read_config(path: str | Path) -> PollerConfig:
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise PolicyValidationError("config")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PolicyValidationError("config")
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        raw = stream.read(MAX_YAML_BYTES + 1)
    if len(raw) > MAX_YAML_BYTES:
        raise PolicyValidationError("config")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise PolicyValidationError("config") from None
    return PollerConfig.from_yaml(text)


async def _close_poller(poller: PolicyPollerProtocol) -> None:
    work = asyncio.create_task(poller.aclose(), name="acs-remote-policy-poller-close")
    work.add_done_callback(_observe)
    deadline = asyncio.get_running_loop().time() + 2 * _SOURCE_CLOSE_TIMEOUT
    cancellation: asyncio.CancelledError | None = None
    while not work.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise PolicyCloseError(1)
        try:
            await asyncio.wait({work}, timeout=remaining)
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
    if work.cancelled():
        _LOG.error("remote_policy_poller_cleanup_failed")
        raise PolicyCloseError(1)
    work.result()
    if cancellation is not None:
        raise cancellation


def _observe(work: asyncio.Future[_T]) -> None:
    if not work.cancelled():
        work.exception()


class _OwnedSource:
    """One bounded source close; credentials remain owned until all users exit."""

    def __init__(self, source: PolicySource) -> None:
        self._source = source
        self._active = 0
        self._drained = asyncio.Event()
        self._drained.set()
        self._closing: asyncio.Task[None] | None = None

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        if self._closing is not None or self._active >= 4:
            raise PolicySourceError("transient", "busy")
        self._active += 1
        self._drained.clear()
        try:
            return await self._source.fetch(selection, if_none_match)
        finally:
            self._active -= 1
            if self._active == 0:
                self._drained.set()

    async def _close(self) -> None:
        try:
            await self._source.aclose()
        finally:
            await self._drained.wait()

    async def aclose(self) -> None:
        if self._closing is None:
            self._closing = asyncio.create_task(
                self._close(), name="acs-remote-policy-source-owner"
            )
            self._closing.add_done_callback(_observe)
        done, _ = await asyncio.wait({self._closing}, timeout=_SOURCE_CLOSE_TIMEOUT)
        if not done:
            raise PolicyCloseError(1)
        if self._closing.cancelled() or self._closing.exception() is not None:
            raise PolicyCloseError(0)

    async def wait_closed(self) -> None:
        """Retain the credential owner after timeout; never create replacement work."""
        assert self._closing is not None
        while not self._closing.done():
            try:
                await asyncio.shield(self._closing)
            except asyncio.CancelledError:
                continue
        # Source users have drained even on a terminal close failure. Report
        # failure; never describe it as successful cleanup.
        if self._closing.cancelled() or self._closing.exception() is not None:
            raise PolicyCloseError(0)


@dataclass(frozen=True, slots=True)
class SnapshotEvaluation:
    """Full native verdict bound to the exact client, agent and immutable snapshot."""

    verdict: Verdict
    _client: RemotePolicyClient
    _agent_id: str
    _snapshot: PolicySnapshot

    def assert_current(self) -> None:
        """Synchronously reject closure, replacement, expiration or authorization loss."""
        self._client.assert_current(self._agent_id, self._snapshot)


class RemotePolicyClient:
    """A running poller plus isolated evaluation, scoped to one async context.

    Use open with a YAML path for the normal consumer flow. The API must serve
    the existing v1 ACS envelope; no deployment-specific parsing is needed.
    """

    def __init__(self, poller: PolicyPollerProtocol) -> None:
        self._poller = poller
        self._evaluation: asyncio.Task[Verdict] | None = None
        self._closed = False
        self._cleanup_failed = False

    @classmethod
    @asynccontextmanager
    async def open(
        cls,
        configuration: str | Path | PollerConfig,
        *,
        registry: CredentialProviderRegistry | None = None,
        credentials: Mapping[str, Credential] | None = None,
        source_factory: PolicySourceFactory | None = None,
        poller_factory: PolicyPollerFactory | None = None,
    ) -> AsyncGenerator[Self, None]:
        """Read YAML, authenticate, fetch initial policies, and start scheduling.

        Keep the context open while serving agents. It closes the poller/source
        before registry-owned credentials, including startup failure and
        cancellation. Injected credentials remain caller-owned. An explicit
        registry is a complete trusted allow-list, not executable YAML.
        """
        if registry is not None and credentials is not None:
            raise PolicyValidationError("config")
        config = (
            configuration
            if isinstance(configuration, PollerConfig)
            else _read_config(configuration)
        )
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[Self] = loop.create_future()
        closed: asyncio.Future[None] = loop.create_future()
        ready.add_done_callback(_observe)
        closed.add_done_callback(_observe)
        release = asyncio.Event()

        async def own() -> None:
            failure: BaseException | None = None
            try:
                async with AsyncExitStack() as stack:
                    selected = credentials
                    if selected is None:
                        providers = (
                            registry
                            if registry is not None
                            else CredentialProviderRegistry()
                        )
                        selected = await stack.enter_async_context(
                            providers.open(config)
                        )
                    source: _OwnedSource | None = None
                    poller: PolicyPollerProtocol | None = None
                    client: Self | None = None
                    try:
                        make_source = source_factory or HttpPolicySource.from_config
                        source = _OwnedSource(
                            make_source(config, MappingProxyType(dict(selected)))
                        )
                        make_poller = poller_factory or PolicyPoller
                        poller = make_poller(config, source)
                        if poller.config != config:
                            raise PolicyValidationError("config")
                        await poller.start()
                        client = cls(poller)
                        ready.set_result(client)
                        await release.wait()
                    finally:
                        try:
                            if client is not None:
                                await client._close_evaluation()
                        finally:
                            try:
                                if poller is not None:
                                    await _close_poller(poller)
                            finally:
                                if source is not None:
                                    try:
                                        await source.aclose()
                                    except PolicyCloseError as error:
                                        # Signal bounded failure, but keep the
                                        # provider context alive in this owner.
                                        if not ready.done():
                                            ready.set_exception(error)
                                        if not closed.done():
                                            closed.set_exception(error)
                                        await source.wait_closed()
                                        raise
            except BaseException as error:
                failure = error
                _LOG.warning(
                    "remote_policy_owner_failed",
                    extra={"exception_class": type(error).__name__},
                )
                raise
            finally:
                if not ready.done():
                    if failure is None:
                        failure = PolicyUnavailable("Remote startup did not complete")
                    ready.set_exception(failure)
                if not closed.done():
                    if failure is None or isinstance(failure, asyncio.CancelledError):
                        closed.set_result(None)
                    else:
                        closed.set_exception(failure)

        owner = loop.create_task(own(), name="acs-remote-policy-client-owner")
        owner.add_done_callback(_observe)
        primary: BaseException | None = None
        try:
            yield await asyncio.shield(ready)
        except BaseException as error:
            primary = error
            raise
        finally:
            release.set()
            if not ready.done():
                owner.cancel()
            cancellation: asyncio.CancelledError | None = None
            while not closed.done():
                try:
                    await asyncio.wait({closed})
                except asyncio.CancelledError as error:
                    cancellation = cancellation if cancellation is not None else error
            if closed.cancelled():
                raise PolicyCloseError(1)
            error = closed.exception()
            if error is not None:
                if primary is None:
                    raise error
                primary.add_note("Remote policy cleanup failed; details suppressed.")
                _LOG.error(
                    "remote_policy_cleanup_failed",
                    extra={"exception_class": type(error).__name__},
                )
            if cancellation is not None and not isinstance(
                primary, asyncio.CancelledError
            ):
                raise cancellation

    async def _close_evaluation(self) -> None:
        self._closed = True
        work = self._evaluation
        cancelled = False
        if work is not None and not work.done():
            work.cancel()
            deadline = asyncio.get_running_loop().time() + 5
            while not work.done():
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    _LOG.error("remote_policy_evaluation_cleanup_failed")
                    raise PolicyCloseError(1)
                try:
                    await asyncio.wait({work}, timeout=remaining)
                except asyncio.CancelledError:
                    cancelled = True
        if self._cleanup_failed or (
            work is not None
            and not work.cancelled()
            and isinstance(work.exception(), PolicyCloseError)
        ):
            _LOG.error("remote_policy_evaluation_cleanup_failed")
            raise PolicyCloseError(1)
        if cancelled:
            raise asyncio.CancelledError

    def _evaluation_finished(self, work: asyncio.Task[Verdict]) -> None:
        if not work.cancelled() and work.exception() is not None:
            if isinstance(work.exception(), PolicyCloseError):
                self._cleanup_failed = True
            _LOG.warning("remote_policy_evaluation_failed")

    @property
    def config(self) -> PollerConfig:
        """Return the validated immutable configuration."""
        return self._poller.config

    def get_policy(self, agent_id: str) -> PolicySnapshot:
        """Read the current validated snapshot; missing/expired/closed blocks."""
        if self._closed:
            raise PolicyUnavailable("Remote policy client is closed")
        return self._poller.get_policy(agent_id)

    def assert_current(self, agent_id: str, snapshot: PolicySnapshot) -> None:
        """Check a retained snapshot immediately before a protected action."""
        if self._closed:
            raise PolicyUnavailable("Remote policy client is closed")
        self._poller.assert_current(agent_id, snapshot)

    def status(self, agent_id: str) -> PolicyStatus:
        """Read safe scheduling and revision metadata for one registration."""
        return self._poller.status(agent_id)

    async def refresh(self, agent_id: str) -> PolicySnapshot:
        """Request one coalesced refresh without creating a second scheduler."""
        if self._closed:
            raise PolicyUnavailable("Remote policy client is closed")
        return await self._poller.refresh(agent_id)

    async def evaluate(
        self,
        agent_id: str,
        point: str,
        context: Mapping[str, JsonValue],
        *,
        timeout_seconds: float = 10,
    ) -> Verdict:
        """Return the native ACS verdict only while its policy is still current.

        Host code supplies the existing agent-hooks context and applies the
        verdict. Do not await between an allow and the protected action; if the
        host defers execution it must re-evaluate. Policy changes, expiry,
        authorization fences, cleanup, or worker failure never yield an allow.
        """
        completion = await self.evaluate_completion(
            agent_id, point, context, timeout_seconds=timeout_seconds
        )
        completion.assert_current()
        return completion.verdict

    async def evaluate_completion(
        self,
        agent_id: str,
        point: str,
        context: Mapping[str, JsonValue],
        *,
        timeout_seconds: float = 10,
    ) -> SnapshotEvaluation:
        """Return a snapshot-bound completion; caller must gate after its last await."""
        snapshot = self.get_policy(agent_id)
        if self._evaluation is not None and not self._evaluation.done():
            _LOG.warning("policy_worker_busy")
            raise PolicyCapacityError("Remote policy evaluator is busy")
        try:
            captured = decode_json(
                json.dumps(dict(context), allow_nan=False).encode("utf-8"),
                max_bytes=MAX_EVALUATION_BYTES,
            )
        except (ValueError, TypeError, UnicodeError):
            raise PolicyValidationError("json") from None
        if not isinstance(captured, dict):
            raise PolicyValidationError("json")
        work = asyncio.create_task(
            evaluate_policy_snapshot(
                snapshot, point, captured, timeout_seconds=timeout_seconds
            ),
            name="acs-remote-policy-evaluation",
        )
        self._evaluation = work
        work.add_done_callback(self._evaluation_finished)
        try:
            verdict = await work
        finally:
            if work.done() and self._evaluation is work:
                self._evaluation = None
        self.assert_current(agent_id, snapshot)
        _LOG.info(
            "remote_policy_evaluated",
            extra={
                "agent_id": agent_id,
                "revision": snapshot.revision,
                "decision": verdict.decision.value,
            },
        )
        return SnapshotEvaluation(verdict, self, agent_id, snapshot)
