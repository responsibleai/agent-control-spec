# Copyright (c) Microsoft. All rights reserved.

"""Bounded asyncio integration over an already-activated policy."""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import math
import threading
from collections import OrderedDict
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from enum import Enum
from typing import TYPE_CHECKING, Any, Self

from agent_hooks import Decision, InterceptionPoint, Verdict

from agent_control_spec._evaluation import evaluate_wire
from agent_control_spec.loading import (
    AsyncPolicyEvaluator,
    ManagedPolicyUsageError,
    ManagedRuntime,
    PolicyEvaluation,
    assert_evaluation_current,
    checked_evaluation,
    finish_owned,
    freeze_context,
    valid_positive_integer,
)

if TYPE_CHECKING:
    from agent_control_spec import ActivatedPolicy

_logger = logging.getLogger(__name__)
_MANAGED_DRAIN_TIMEOUT = 30.0


def _positive_timeout(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value > 0
    )


class Scope(str, Enum):
    """Whether known lifecycle points outside this control are evaluated."""

    STRICT = "strict"
    BOUND_POINTS_ONLY = "bound_points_only"


class Saturation(str, Enum):
    """Admission policy when all evaluation workers are occupied."""

    REJECT = "reject"
    WAIT = "wait"


class AsyncAcsLoopMismatchError(RuntimeError):
    """An adapter was called from a different event loop."""


class AsyncAcsInterceptor:
    """An awaitable interceptor with a dedicated, bounded evaluation pool.

    Activate the policy outside the serving loop. The first async use binds
    this adapter to one event loop; sharing it across loops is an error.
    Custom dispatchers and telemetry sinks must support concurrent threads.

    ``Saturation.REJECT`` denies immediately when all workers are busy.
    ``Saturation.WAIT`` admits at most ``max_pending`` waiters, each for at
    most ``admission_timeout`` seconds. Its five-second default matches
    the emitter's default budget but is configured independently. The
    emitter's timeout still caps admission plus evaluation.

    Timeout/cancellation stops waiting, not evaluation. Capacity stays
    occupied until the native call returns. Configure finite operation
    deadlines in dispatchers; this adapter cannot terminate their threads.
    Use ``async with`` or await :meth:`aclose` before closing the event loop.

    A managed remote activation instead starts at async entry and evaluates in
    one process-wide isolated worker, without a queue. Local concurrency/scope
    overrides are unsupported in remote mode. The activation is single-use:
    call activate() again and use separate loaders/registries for concurrent
    lifetimes. Close-induced evaluation cancellation becomes a closed deny;
    cancellation requested by the caller still propagates.
    """

    def __init__(
        self,
        policy: ActivatedPolicy,
        name: str = "acs",
        *,
        scope: Scope | str = Scope.STRICT,
        max_concurrency: int = 8,
        on_saturation: Saturation | str = Saturation.REJECT,
        max_pending: int = 64,
        admission_timeout: float = 5.0,
    ) -> None:
        for key, value in (
            ("max_concurrency", max_concurrency),
            ("max_pending", max_pending),
        ):
            if not valid_positive_integer(value):
                raise ValueError(f"{key} must be a positive integer")
        if not _positive_timeout(admission_timeout):
            raise ValueError("admission_timeout must be finite and positive")
        self._scope = Scope(scope)
        self._policy: ActivatedPolicy | None = policy
        managed = policy._managed  # pyright: ignore[reportPrivateUsage]
        if managed is not None and (
            self._scope is not Scope.STRICT
            or max_concurrency != 8
            or Saturation(on_saturation) is not Saturation.REJECT
            or max_pending != 64
            or admission_timeout != 5.0
        ):
            raise ManagedPolicyUsageError(
                "Remote mode requires strict scope and one immediate evaluation "
                "slot/no queue; local concurrency options are unsupported"
            )
        self._points = (
            frozenset(policy.intervention_points)
            if managed is None
            else frozenset[str]()
        )
        self._name = name
        self._max_concurrency = max_concurrency
        self._on_saturation = Saturation(on_saturation)
        self._max_pending = max_pending
        self._admission_timeout = admission_timeout
        self._executor: ThreadPoolExecutor | None = (
            ThreadPoolExecutor(max_workers=max_concurrency, thread_name_prefix="acs")
            if managed is None
            else None
        )
        self._init_lifecycle()
        self._managed_runtime = managed.claim() if managed is not None else None

    def _init_lifecycle(self) -> None:
        self._backend: AsyncPolicyEvaluator | None = None
        self._managed_runtime: ManagedRuntime | None = None
        self._entered = False
        self._start_failed = False
        self._backend_work: asyncio.Task[PolicyEvaluation] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._in_flight: set[asyncio.Future[Verdict]] = set()
        self._waiters: OrderedDict[asyncio.Future[bool], float] = OrderedDict()
        self._reserved = 0
        self._drained = asyncio.Event()
        self._drained.set()
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._close_lock = threading.Lock()

    @property
    def name(self) -> str:
        """Payload-free registration name; pass it to ``emitter.register``."""
        return self._name

    @property
    def in_flight(self) -> int:
        """Submitted evaluations not yet accounted as complete on the loop."""
        return len(self._in_flight) + int(
            self._backend_work is not None and not self._backend_work.done()
        )

    @property
    def waiting(self) -> int:
        """Queued calls, excluding those already granted a worker slot."""
        return len(self._waiters)

    @property
    def closed(self) -> bool:
        """Whether closing has started; active evaluations may still be draining."""
        return self._closed

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise AsyncAcsLoopMismatchError(
                "AsyncAcsInterceptor cannot be shared across event loops"
            )
        return loop

    async def intercept(self, context: Mapping[str, Any]) -> Verdict:
        """Await a scoped decision, with bounded admission before native work.

        Closed, saturated, and admission-timeout paths return deny verdicts.
        Invalid/missing points, unserializable contexts, and cross-loop use
        raise boundary errors. The emitter records errors raised here as
        ``host_error:interceptor_failed``; envelope validation may reject
        invalid input before this method runs.
        """
        loop = self._bind_loop()
        if self._managed_runtime is not None:
            if self._start_failed:
                raise ManagedPolicyUsageError(
                    "Remote startup failed before READY; call activate() again"
                )
            if self._closed:
                return Verdict.deny(reason="runtime_error:acs_async_closed")
            if self._backend is None:
                raise ManagedPolicyUsageError(
                    "Remote policy is not READY; use async with AsyncAcsInterceptor(policy)"
                )
        # Validate before the scope bypass: governs() alone accepts typos as
        # unbound, which would turn an invalid point into an allow.
        point = InterceptionPoint(context["interception_point"]).value
        if self._closed:
            return Verdict.deny(reason="runtime_error:acs_async_closed")
        if self._managed_runtime is not None:
            if self._backend_work is not None and not self._backend_work.done():
                return Verdict.deny(reason="runtime_error:acs_async_capacity_exceeded")
            try:
                completion = checked_evaluation(
                    await self._intercept_backend(point, context)
                )
            except asyncio.CancelledError:
                caller = asyncio.current_task()
                if caller is not None and caller.cancelling():
                    raise
                if self._closed:
                    return Verdict.deny(reason="runtime_error:acs_async_closed")
                raise ManagedPolicyUsageError(
                    "Managed evaluator cancelled without caller cancellation"
                ) from None
            if self._closed:
                return Verdict.deny(reason="runtime_error:acs_async_closed")
            # FINAL gate in the outer coroutine, after the last internal await.
            assert_evaluation_current(completion)
            return completion.verdict
        if self._scope is Scope.BOUND_POINTS_ONLY and point not in self._points:
            return Verdict(decision=Decision.ALLOW, reason="acs_point_unbound")
        deadline = None
        if (
            self._waiters
            or len(self._in_flight) + self._reserved >= self._max_concurrency
        ):
            if (
                self._on_saturation is Saturation.REJECT
                or len(self._waiters) >= self._max_pending
            ):
                return Verdict.deny(reason="runtime_error:acs_async_capacity_exceeded")
            waiter: asyncio.Future[bool] = loop.create_future()
            deadline = loop.time() + self._admission_timeout
            self._waiters[waiter] = deadline
            self._wake_waiters()
            granted = False
            try:
                async with asyncio.timeout_at(deadline):
                    granted = await waiter
            except TimeoutError:
                return Verdict.deny(reason="runtime_error:acs_async_admission_timeout")
            finally:
                self._waiters.pop(waiter, None)
                # Cancellation can arrive after a slot was reserved but before
                # the awaiting task resumed. Hand that unused slot onwards.
                if (
                    not granted
                    and waiter.done()
                    and not waiter.cancelled()
                    and waiter.result()
                ):
                    self._reserved -= 1
                    self._wake_waiters()
            if not granted:
                return Verdict.deny(
                    reason="runtime_error:acs_async_closed"
                    if self._closed
                    else "runtime_error:acs_async_admission_timeout"
                )
        else:
            self._reserved += 1
        try:
            if self._closed:
                return Verdict.deny(reason="runtime_error:acs_async_closed")
            snapshot = json.dumps(context, allow_nan=False)
            # A delayed task can resume before its expired timeout callback.
            # Do not submit expired queued work, regardless of callback order.
            if deadline is not None and loop.time() >= deadline:
                return Verdict.deny(reason="runtime_error:acs_async_admission_timeout")
            assert self._executor is not None and self._policy is not None
            worker = self._executor.submit(
                contextvars.copy_context().run,
                evaluate_wire,
                # Package-internal opaque handle; serialize exactly once.
                self._policy._local_handle(),  # pyright: ignore[reportPrivateUsage]
                point,
                snapshot,
            )
            # Native completion and error reporting must survive a lost loop.
            worker.add_done_callback(self._report_worker_error)
            work = asyncio.wrap_future(worker, loop=loop)
            self._in_flight.add(work)
            self._drained.clear()
            work.add_done_callback(self._completed)
        finally:
            self._reserved -= 1
            self._wake_waiters()
        # Only the native future's completion releases capacity. Cancelling
        # an emitter/awaiter must not cancel that future or its accounting.
        return await asyncio.shield(work)

    async def _intercept_backend(
        self, point: str, context: Mapping[str, object]
    ) -> PolicyEvaluation:
        assert self._backend is not None
        # Freeze before scheduling: caller mutation at our first await cannot
        # change the host-owned identity or payload observed by the backend.
        captured = freeze_context(context)
        work = asyncio.create_task(self._backend.evaluate(point, captured))
        self._backend_work = work
        try:
            # Unlike the local thread path, cancellation must reach the remote
            # worker's existing kill/drain ownership.
            return await work
        finally:
            if work.done() and self._backend_work is work:
                self._backend_work = None

    def _completed(self, work: asyncio.Future[Verdict]) -> None:
        self._in_flight.remove(work)
        if not self._in_flight:
            self._drained.set()
        self._wake_waiters()
        if not work.cancelled():
            work.exception()

    @staticmethod
    def _report_worker_error(work: Future[Verdict]) -> None:
        if work.cancelled():
            return
        error = work.exception()
        if error is not None:
            # Also report late failures when the owner's loop is already gone.
            # Do not log the context or exception message (potential payload).
            _logger.error("ACS async evaluation raised %s", type(error).__name__)

    def _wake_waiters(self) -> None:
        if self._closed:
            return
        loop = asyncio.get_running_loop()
        while (
            self._waiters
            and len(self._in_flight) + self._reserved < self._max_concurrency
        ):
            waiter, deadline = self._waiters.popitem(last=False)
            if waiter.done():
                continue
            if loop.time() >= deadline:
                waiter.set_result(False)
                continue
            # Reserve before waking: a newcomer must not steal the slot while
            # this waiter is scheduled but has not submitted its work yet.
            self._reserved += 1
            waiter.set_result(True)

    async def aclose(self) -> None:
        """Reject new work and drain existing calls without blocking the loop.

        Cleanup ownership is reused, not duplicated. Successful close can be
        repeated; completed errors, including startup failures, are replayed
        rather than swallowed. Cancelling this awaiter leaves cleanup owned;
        await ``aclose()`` again before loop shutdown. A local dispatcher that
        never returns can prevent draining indefinitely.

        If the owning loop has closed, a new loop may call this method:
        it runs :meth:`close` in a thread instead of touching the old loop.
        """
        if self._loop is not None and self._loop.is_closed():
            if self._managed_runtime is not None:
                raise AsyncAcsLoopMismatchError(
                    "Remote ACS must be closed on its owning loop before shutdown"
                )
            await asyncio.to_thread(self.close)
            return
        self._bind_loop()
        retry = (
            self._managed_runtime is not None
            and self._close_task is not None
            and self._close_task.done()
            and not self._close_task.cancelled()
            and self._close_task.exception() is not None
            and (self._backend_work is None or self._backend_work.done())
        )
        if self._close_task is None or retry:
            self._closed = True
            while self._waiters:
                waiter, _ = self._waiters.popitem(last=False)
                if not waiter.done():
                    waiter.set_result(False)
            self._close_task = asyncio.create_task(self._drain())
        if self._managed_runtime is not None:
            await finish_owned(self._close_task)
        else:
            await asyncio.shield(self._close_task)

    def close(self) -> None:
        """Join workers after the owning loop has closed, or before first use.

        This synchronous recovery method blocks until native calls finish.
        Use ``aclose()`` on a replacement loop to wait without blocking it.
        A live owning loop must use its own ``aclose()``; stopping that loop
        temporarily does not transfer ownership. Neither method can terminate
        a stuck native callback or make calls from another loop valid.
        """
        if self._loop is not None and not self._loop.is_closed():
            raise AsyncAcsLoopMismatchError(
                "close() requires the owning event loop to be closed; "
                "use aclose() on that loop"
            )
        with self._close_lock:
            if self._managed_runtime is not None:
                raise AsyncAcsLoopMismatchError(
                    "Remote ACS requires aclose() on its owning event loop"
                )
            self._closed = True
            assert self._executor is not None
            self._executor.shutdown(wait=True, cancel_futures=True)
            # The closed loop cannot run _completed. Native shutdown has joined
            # all workers, so bookkeeping can now be discarded without freeing
            # capacity while evaluation is still running.
            for work in self._in_flight:
                if work.done() and not work.cancelled():
                    work.exception()
            self._in_flight.clear()
            self._waiters.clear()
            self._reserved = 0

    async def _drain(self) -> None:
        if self._managed_runtime is not None:
            work = self._backend_work
            if work is not None:
                work.cancel()
                done, _ = await asyncio.wait({work}, timeout=_MANAGED_DRAIN_TIMEOUT)
                if not done:
                    # Keep its loader alive while that evaluator can use it.
                    runtime = self._managed_runtime
                    work.add_done_callback(lambda _done: runtime.request_close())
                    raise ManagedPolicyUsageError(
                        "Managed evaluation cleanup failed; one task remains retained"
                    )
                if not work.cancelled():
                    work.exception()
            await self._managed_runtime.aclose()
            return
        while self._in_flight:
            await self._drained.wait()
        assert self._executor is not None
        await asyncio.to_thread(self._executor.shutdown, wait=True)

    async def __aenter__(self) -> Self:
        self._bind_loop()
        if self._closed:
            raise RuntimeError("AsyncAcsInterceptor is closed")
        if self._managed_runtime is not None:
            if self._entered:
                raise ManagedPolicyUsageError(
                    "Remote interceptor is single-use; call activate() again"
                )
            self._entered = True
            try:
                backend = await self._managed_runtime.start()
                if self._closed:
                    raise ManagedPolicyUsageError("Remote startup was closed")
                self._backend = backend
            except BaseException as error:
                self._start_failed = not self._closed and not isinstance(
                    error, asyncio.CancelledError
                )
                try:
                    await finish_owned(asyncio.create_task(self.aclose()))
                except asyncio.CancelledError:
                    if isinstance(error, asyncio.CancelledError):
                        raise error
                    raise
                raise
        return self

    async def __aexit__(self, *_exc: object) -> None:
        try:
            await self.aclose()
        except asyncio.CancelledError:
            if len(_exc) > 1 and isinstance(_exc[1], asyncio.CancelledError):
                raise _exc[1]
            raise
