# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Bounded asyncio integration over an already-activated policy."""

from __future__ import annotations

import asyncio
import contextvars
import copy
import logging
import math
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, Self

from agent_hooks import InterceptionPoint, Verdict

if TYPE_CHECKING:
    from agent_control_spec import ActivatedPolicy

_logger = logging.getLogger(__name__)


class Scope(str, Enum):
    """Whether known lifecycle points outside this control are evaluated."""

    STRICT = "strict"
    BOUND_POINTS_ONLY = "bound_points_only"


class AsyncAcsInterceptor:
    """An awaitable interceptor with a dedicated, bounded evaluation pool.

    Activate the policy outside the serving loop. The first async use binds
    this adapter to one event loop; sharing it across loops is an error.
    Custom dispatchers and telemetry sinks must support concurrent threads.

    ``on_saturation="reject"`` denies immediately when all workers are busy.
    ``"wait"`` admits at most ``max_pending`` waiters, each for at most
    ``admission_timeout`` seconds. The emitter's timeout includes admission.
    Neither mode submits an unbounded executor backlog.

    Timeout/cancellation stops waiting, not evaluation. Capacity stays
    occupied until the native call returns. Configure finite operation
    deadlines in dispatchers; this adapter cannot terminate their threads.
    Use ``async with`` or await :meth:`aclose` before closing the event loop.
    """

    def __init__(
        self,
        policy: ActivatedPolicy,
        name: str = "acs",
        *,
        scope: Scope = Scope.STRICT,
        max_concurrency: int = 8,
        on_saturation: Literal["reject", "wait"] = "reject",
        max_pending: int = 64,
        admission_timeout: float = 0.1,
    ) -> None:
        for key, value in (
            ("max_concurrency", max_concurrency),
            ("max_pending", max_pending),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{key} must be a positive integer")
        if on_saturation not in ("reject", "wait"):
            raise ValueError("on_saturation must be 'reject' or 'wait'")
        if (
            isinstance(admission_timeout, bool)
            or not isinstance(admission_timeout, (int, float))
            or not math.isfinite(admission_timeout)
            or admission_timeout <= 0
        ):
            raise ValueError("admission_timeout must be finite and positive")
        self._scope = Scope(scope)
        self._policy = policy
        self._points = frozenset(policy.intervention_points)
        self._name = name
        self._max_concurrency = max_concurrency
        self._on_saturation = on_saturation
        self._max_pending = max_pending
        self._admission_timeout = admission_timeout
        self._executor = ThreadPoolExecutor(
            max_workers=max_concurrency, thread_name_prefix="acs"
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._in_flight: set[asyncio.Future[Verdict]] = set()
        self._waiting = 0
        self._changed = asyncio.Event()
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None

    @property
    def name(self) -> str:
        """Payload-free registration name; pass it to ``emitter.register``."""
        return self._name

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise RuntimeError(
                "AsyncAcsInterceptor cannot be shared across event loops"
            )
        return loop

    async def intercept(self, context: Mapping[str, Any]) -> Verdict:
        loop = self._bind_loop()
        # Validate before the scope bypass: governs() alone accepts typos as
        # unbound, which would turn an invalid point into an allow.
        point = InterceptionPoint(context["interception_point"]).value
        if self._closed:
            return Verdict.deny(reason="acs_async_closed")
        if self._scope is Scope.BOUND_POINTS_ONLY and point not in self._points:
            return Verdict.allow()
        if len(self._in_flight) >= self._max_concurrency:
            if self._on_saturation == "reject" or self._waiting >= self._max_pending:
                return Verdict.deny(reason="acs_async_capacity_exceeded")
            self._waiting += 1
            try:
                async with asyncio.timeout(self._admission_timeout):
                    while (
                        len(self._in_flight) >= self._max_concurrency
                        and not self._closed
                    ):
                        self._changed.clear()
                        await self._changed.wait()
            except TimeoutError:
                return Verdict.deny(reason="acs_async_admission_timeout")
            finally:
                self._waiting -= 1
        if self._closed:
            return Verdict.deny(reason="acs_async_closed")
        snapshot = copy.deepcopy(context)
        work = loop.run_in_executor(
            self._executor,
            contextvars.copy_context().run,
            self._policy.evaluate,
            point,
            snapshot,
        )
        self._in_flight.add(work)
        work.add_done_callback(self._completed)
        # Only the native future's completion releases capacity. Cancelling
        # an emitter/awaiter must not cancel that future or its accounting.
        return await asyncio.shield(work)

    def _completed(self, work: asyncio.Future[Verdict]) -> None:
        self._in_flight.remove(work)
        self._changed.set()
        error = work.exception()
        if error is not None:
            # Retrieve and report even a late exception after caller timeout.
            # Do not log the context or exception message (potential payload).
            _logger.error("ACS async evaluation raised %s", type(error).__name__)

    async def aclose(self) -> None:
        """Reject new work and drain existing calls without blocking the loop.

        Idempotent. Cancelling this awaiter leaves cleanup running; await
        ``aclose()`` again before loop shutdown. A dispatcher that never
        returns can prevent draining indefinitely.
        """
        self._bind_loop()
        if self._close_task is None:
            self._closed = True
            self._changed.set()
            self._close_task = asyncio.create_task(self._drain())
        await asyncio.shield(self._close_task)

    async def _drain(self) -> None:
        while self._in_flight:
            self._changed.clear()
            await self._changed.wait()
        await asyncio.to_thread(self._executor.shutdown, wait=True)

    async def __aenter__(self) -> Self:
        self._bind_loop()
        if self._closed:
            raise RuntimeError("AsyncAcsInterceptor is closed")
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
