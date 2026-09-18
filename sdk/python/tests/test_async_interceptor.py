# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Real emitter and native evaluation, with event-gated local dispatchers."""

import asyncio
import inspect
import json
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_control_spec import ActivatedPolicy, _evaluation
from agent_control_spec.async_interceptor import (
    AsyncAcsInterceptor,
    AsyncAcsLoopMismatchError,
    Saturation,
    Scope,
)
from agent_hooks import (
    AgentContextBuilder,
    InterceptionBlocked,
    InterceptionEmitter,
    Verdict,
)

from ._async_helpers import BUNDLES, MANIFEST, TRACE, GatedAnnotator, entered, until

TOOL_MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: test
    verdict:
      decision: deny
      reason: tool_policy_still_enforced
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy:
      id: gate
"""


def builder():
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


@asynccontextmanager
async def gated_adapter(**options):
    gate = GatedAnnotator()
    policy = ActivatedPolicy.from_memory(MANIFEST, BUNDLES, annotator_dispatcher=gate)
    adapter = AsyncAcsInterceptor(policy, **options)
    try:
        yield gate, adapter
    finally:
        gate.release_all()
        await adapter.aclose()


def test_loop_progress_and_contextvars_during_native_evaluation():
    async def run():
        async with gated_adapter() as (gate, adapter):
            emitter = InterceptionEmitter(timeout=3).register(adapter, adapter.name)
            token = TRACE.set("request-1")
            try:
                task = asyncio.create_task(
                    emitter.emit(builder().input(content="hello"))
                )
                assert await entered(gate) == (0, "request-1")
                progressed = asyncio.Event()
                asyncio.get_running_loop().call_soon(progressed.set)
                await progressed.wait()
                assert not task.done()
                assert not gate.finished
                gate.gates[0].set()
                result = await task
                assert result.record.verdict.decision.value == "allow"
            finally:
                TRACE.reset(token)

    asyncio.run(run())


@pytest.mark.parametrize("cancel", [False, True], ids=["timeout", "cancellation"])
def test_timeout_or_cancellation_does_not_release_worker_capacity(cancel):
    async def run():
        async with gated_adapter(max_concurrency=1) as (gate, adapter):
            records = []
            emitter = (
                InterceptionEmitter(timeout=None if cancel else 0.1)
                .register(adapter)
                .set_record_sink(records.append)
            )
            task = asyncio.create_task(emitter.emit(builder().input(content="first")))
            assert (await entered(gate))[0] == 0
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert len(records) == 1
                assert records[0].verdict.decision.value == "deny"
                assert records[0].verdict.reason == "host_error:interceptor_failed"
                assert records[0].verdict.message == "CancelledError"
            else:
                with pytest.raises(InterceptionBlocked) as blocked:
                    await task
                assert (
                    blocked.value.result.verdict.reason
                    == "host_error:interceptor_timeout"
                )
            assert not gate.finished
            record = await emitter.emit_unchecked(builder().input(content="second"))
            assert record.verdict.reason == "runtime_error:acs_async_capacity_exceeded"
            assert gate.calls == 1
            gate.gates[0].set()
            await until(lambda: adapter.in_flight == 0)
            gate.gates[1].set()
            assert (
                await emitter.emit(builder().input(content="third"))
            ).record.verdict.decision.value == "allow"

    asyncio.run(run())


def test_worker_and_waiter_bounds_and_completion_driven_admission():
    async def run():
        async with gated_adapter(
            max_concurrency=2,
            on_saturation="wait",
            max_pending=1,
            admission_timeout=3,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            second = asyncio.create_task(
                emitter.emit(builder().input(content="second"))
            )
            assert {(await entered(gate))[0], (await entered(gate))[0]} == {0, 1}
            waiting = asyncio.create_task(
                emitter.emit(builder().input(content="waiting"))
            )
            await until(lambda: adapter.waiting == 1)
            overflow = await emitter.emit_unchecked(builder().input(content="overflow"))
            assert (
                overflow.verdict.reason == "runtime_error:acs_async_capacity_exceeded"
            )
            assert gate.calls == 2
            assert not waiting.done()
            gate.gates[0].set()
            assert (await entered(gate))[0] == 2
            assert 0 in gate.finished
            assert 1 not in gate.finished
            gate.release_all()
            for result in await asyncio.gather(first, second, waiting):
                assert result.record.verdict.decision.value == "allow"

    asyncio.run(run())


@pytest.mark.parametrize("cancel", [False, True], ids=["deadline", "cancellation"])
def test_waiter_deadline_or_cancellation_does_not_submit_or_leak(cancel):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            max_pending=1,
            admission_timeout=3 if cancel else 0.05,
        ) as (gate, adapter):
            records = []
            emitter = (
                InterceptionEmitter(timeout=None)
                .register(adapter)
                .set_record_sink(records.append)
            )
            running = asyncio.create_task(
                emitter.emit(builder().input(content="running"))
            )
            await entered(gate)
            waiting = asyncio.create_task(
                emitter.emit_unchecked(builder().input(content="waiting"))
            )
            await until(lambda: adapter.waiting == 1)
            if cancel:
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting
                assert len(records) == 1
                assert records[0].verdict.decision.value == "deny"
                assert records[0].verdict.reason == "host_error:interceptor_failed"
                assert records[0].verdict.message == "CancelledError"
            else:
                assert (
                    await waiting
                ).verdict.reason == "runtime_error:acs_async_admission_timeout"
            assert adapter.waiting == 0
            assert gate.calls == 1
            replacement = asyncio.create_task(
                emitter.emit(builder().input(content="replacement"))
            )
            await until(lambda: adapter.waiting == 1)
            gate.release_all()
            await asyncio.gather(running, replacement)
            assert gate.calls == 2

    asyncio.run(run())


def test_close_rejects_pending_and_new_work_and_drains_after_cancellation():
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=3,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            running = asyncio.create_task(
                emitter.emit(builder().input(content="running"))
            )
            await entered(gate)
            waiting = asyncio.create_task(
                emitter.emit_unchecked(builder().input(content="waiting"))
            )
            await until(lambda: adapter.waiting == 1)
            closing = asyncio.create_task(adapter.aclose())
            assert (await waiting).verdict.reason == "runtime_error:acs_async_closed"
            assert adapter.closed
            assert adapter.in_flight == 1
            assert not closing.done()
            closing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert (
                await emitter.emit_unchecked(builder().input(content="new"))
            ).verdict.reason == "runtime_error:acs_async_closed"
            assert gate.calls == 1
            gate.release_all()
            await running
            await adapter.aclose()
            await adapter.aclose()
            assert adapter.in_flight == 0

    asyncio.run(run())


@pytest.mark.parametrize("scope", list(Scope))
def test_scoping_preserves_bound_denial_and_other_controls(scope):
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        async with AsyncAcsInterceptor(policy, scope=scope) as adapter:
            emitter = InterceptionEmitter().register(adapter)
            startup = builder().agent_startup(tools_registered=["search"])
            result = await emitter.emit_unchecked(startup)
            if scope is Scope.STRICT:
                assert (
                    result.verdict.reason == "runtime_error:intervention_point_unknown"
                )
            else:
                assert result.verdict.decision.value == "allow"
                assert result.verdicts[0].reason == "acs_point_unbound"
                assert result.verdict.reason is None
            with pytest.raises(InterceptionBlocked) as blocked:
                await emitter.emit(
                    builder().pre_tool_call(call_id="t1", name="search", args={})
                )
            assert blocked.value.result.verdict.reason == "tool_policy_still_enforced"
            if scope is Scope.BOUND_POINTS_ONLY:

                class StartupControl:
                    def intercept(self, context):
                        return Verdict.deny(reason="startup_control")

                emitter.register(StartupControl())
                assert (
                    await emitter.emit_unchecked(startup)
                ).verdict.reason == "startup_control"

    asyncio.run(run())


def test_default_scope_is_strict():
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        async with AsyncAcsInterceptor(policy) as adapter:
            record = (
                await InterceptionEmitter()
                .register(adapter)
                .emit_unchecked(builder().agent_startup(tools_registered=[]))
            )
            assert record.verdict.reason == "runtime_error:intervention_point_unknown"

    asyncio.run(run())


@pytest.mark.parametrize("scope", list(Scope))
@pytest.mark.parametrize("point", ["pre_tool_cal", "", None, 42])
def test_invalid_point_fails_closed_in_both_scopes(scope, point):
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        async with AsyncAcsInterceptor(policy, scope=scope) as adapter:
            context = builder().input(content="x")
            context["interception_point"] = point
            with pytest.raises((ValueError, TypeError)):
                await adapter.intercept(context)
            with pytest.raises(InterceptionBlocked):
                await InterceptionEmitter().register(adapter).emit(context)

    asyncio.run(run())


@pytest.mark.parametrize("scope", list(Scope))
@pytest.mark.parametrize("failure", ["annotator", "policy"])
def test_genuine_bound_failure_is_not_allowed(scope, failure):
    def broken(*args):
        raise RuntimeError("inert dispatcher failure")

    async def run():
        kwargs = (
            {"annotator_dispatcher": broken}
            if failure == "annotator"
            else {
                "annotator_dispatcher": lambda *args: {"completed": True},
                "policy_dispatcher": broken,
            }
        )
        policy = ActivatedPolicy.from_memory(MANIFEST, BUNDLES, **kwargs)
        async with AsyncAcsInterceptor(policy, scope=scope) as adapter:
            with pytest.raises(InterceptionBlocked) as blocked:
                await (
                    InterceptionEmitter()
                    .register(adapter)
                    .emit(builder().input(content="x"))
                )
            assert blocked.value.result.verdict.reason.startswith("runtime_error:")

    asyncio.run(run())


@pytest.mark.parametrize(
    "options",
    [
        {"max_concurrency": 0},
        {"max_concurrency": True},
        {"max_concurrency": 1.5},
        {"max_pending": 0},
        {"admission_timeout": float("nan")},
        {"admission_timeout": float("inf")},
        {"admission_timeout": 0},
        {"admission_timeout": True},
        {"on_saturation": "unbounded"},
        {"scope": "unknown"},
    ],
)
def test_invalid_configuration_is_rejected(options):
    policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
    with pytest.raises(ValueError):
        AsyncAcsInterceptor(policy, **options)


def test_close_is_idempotent_after_owner_loop_closed():
    policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
    adapter = AsyncAcsInterceptor(policy)
    asyncio.run(adapter.aclose())
    asyncio.run(adapter.aclose())
    adapter.close()
    assert adapter.closed
    assert adapter.waiting == adapter.in_flight == 0


def test_cross_loop_evaluation_raises_directly_and_records_a_deny():
    policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
    adapter = AsyncAcsInterceptor(policy)

    async def bind_owner():
        async with adapter:
            return

    async def other_loop():
        context = builder().input(content="x")
        with pytest.raises(AsyncAcsLoopMismatchError, match="event loops"):
            await adapter.intercept(context)
        records = []
        emitter = (
            InterceptionEmitter().register(adapter).set_record_sink(records.append)
        )
        with pytest.raises(InterceptionBlocked):
            await emitter.emit(context)
        assert len(records) == 1
        assert records[0].verdict.reason == "host_error:interceptor_failed"
        assert records[0].verdict.message == "AsyncAcsLoopMismatchError"

    asyncio.run(bind_owner())
    asyncio.run(other_loop())


def test_closed_adapter_rejects_context_entry_and_unbound_scope_bypass():
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        adapter = AsyncAcsInterceptor(policy, scope=Scope.BOUND_POINTS_ONLY)
        await adapter.aclose()
        with pytest.raises(RuntimeError, match="closed"):
            async with adapter:
                pytest.fail("a closed adapter must not re-enter")
        records = []
        emitter = (
            InterceptionEmitter().register(adapter).set_record_sink(records.append)
        )
        with pytest.raises(InterceptionBlocked):
            await emitter.emit(builder().agent_startup(tools_registered=[]))
        assert len(records) == 1
        assert records[0].verdict.reason == "runtime_error:acs_async_closed"
        assert adapter.in_flight == adapter.waiting == 0

    asyncio.run(run())


@pytest.mark.parametrize("mode", [Saturation.REJECT, Saturation.WAIT])
@pytest.mark.parametrize("max_pending", [5, 64])
def test_burst_bounds_running_and_waiting_calls(mode, max_pending):
    async def run():
        release = threading.Event()
        lock = threading.Lock()
        calls = active = peak = 0
        observations = []

        def dispatch(*args):
            nonlocal calls, active, peak
            with lock:
                calls += 1
                active += 1
                peak = max(peak, active)
            try:
                if not release.wait(30):
                    raise RuntimeError("test did not release the burst")
                return {"completed": True}
            finally:
                with lock:
                    active -= 1

        policy = ActivatedPolicy.from_memory(
            MANIFEST, BUNDLES, annotator_dispatcher=dispatch
        )
        max_concurrency = 2
        accepted = max_concurrency + (max_pending if mode is Saturation.WAIT else 0)
        tasks = []
        async with AsyncAcsInterceptor(
            policy,
            max_concurrency=max_concurrency,
            on_saturation=mode,
            max_pending=max_pending,
            admission_timeout=30,
        ) as adapter:
            emitter = InterceptionEmitter(timeout=None).register(adapter)

            async def emit():
                try:
                    return await emitter.emit_unchecked(
                        builder().input(content="burst")
                    )
                finally:
                    observations.append((adapter.in_flight, adapter.waiting))

            async def sample():
                while any(not task.done() for task in tasks):
                    observations.append((adapter.in_flight, adapter.waiting))
                    await asyncio.sleep(0)

            tasks = [asyncio.create_task(emit()) for _ in range(200)]
            sampler = asyncio.create_task(sample())
            try:
                await until(
                    lambda: sum(task.done() for task in tasks) == 200 - accepted
                )
                assert adapter.in_flight == max_concurrency
                assert adapter.waiting == accepted - max_concurrency
                assert not any(
                    task.result().verdict.decision.value == "allow"
                    for task in tasks
                    if task.done()
                )
                release.set()
                records = await asyncio.wait_for(asyncio.gather(*tasks), 10)
            finally:
                release.set()
                await asyncio.gather(*tasks, return_exceptions=True)
                await sampler
            assert calls == accepted
            assert peak <= max_concurrency
            assert len(records) == 200
            assert sum(r.verdict.decision.value == "allow" for r in records) == accepted
            assert (
                sum(
                    r.verdict.reason == "runtime_error:acs_async_capacity_exceeded"
                    for r in records
                )
                == 200 - accepted
            )
            assert observations
            assert max(n for n, _ in observations) <= max_concurrency
            assert max(n for _, n in observations) <= max_pending
            assert adapter.in_flight == adapter.waiting == 0

    asyncio.run(run())


def test_emitter_timeout_covers_admission_without_submitting():
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=3,
        ) as (gate, adapter):
            running = asyncio.create_task(
                InterceptionEmitter(timeout=None)
                .register(adapter)
                .emit(builder().input(content="running"))
            )
            await entered(gate)
            with pytest.raises(InterceptionBlocked) as blocked:
                await (
                    InterceptionEmitter(timeout=0.05)
                    .register(adapter)
                    .emit(builder().input(content="waiting"))
                )
            assert (
                blocked.value.result.verdict.reason == "host_error:interceptor_timeout"
            )
            assert adapter.waiting == 0
            assert gate.calls == 1
            gate.release_all()
            await running

    asyncio.run(run())


def test_unbound_scope_bypass_uses_no_worker_even_when_saturated():
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            scope=Scope.BOUND_POINTS_ONLY,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            running = asyncio.create_task(
                emitter.emit(builder().input(content="running"))
            )
            await entered(gate)
            await emitter.emit(builder().agent_startup(tools_registered=[]))
            assert gate.calls == 1
            assert not gate.finished
            gate.release_all()
            await running

    asyncio.run(run())


def test_submission_failure_is_visible_and_does_not_leak_capacity(monkeypatch):
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        async with AsyncAcsInterceptor(policy, max_concurrency=1) as adapter:

            def broken_submit(*args, **kwargs):
                raise RuntimeError("executor unavailable")

            emitter = InterceptionEmitter().register(adapter)
            with monkeypatch.context() as patch:
                patch.setattr(adapter._executor, "submit", broken_submit)
                record = await emitter.emit_unchecked(builder().input(content="x"))
                assert record.verdict.reason == "host_error:interceptor_failed"
            assert adapter.in_flight == 0
            record = await emitter.emit_unchecked(builder().input(content="x"))
            assert record.verdict.reason == "runtime_error:intervention_point_unknown"

    asyncio.run(run())


def test_boundary_error_never_submits_and_remains_fail_closed():
    async def run():
        async with gated_adapter(max_concurrency=1) as (gate, adapter):
            with pytest.raises(ValueError):
                await adapter.intercept(builder().input(content=float("nan")))
            assert adapter.in_flight == 0
            assert gate.calls == 0
            gate.gates[0].set()
            await (
                InterceptionEmitter()
                .register(adapter)
                .emit(builder().input(content="x"))
            )

    asyncio.run(run())


def test_builtin_operation_deadline_returns_native_timeout_without_emitter_timeout():
    requested = threading.Event()
    release = threading.Event()

    class NoResponse(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            requested.set()
            release.wait(5)
            self.close_connection = True

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), NoResponse)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}
    )
    thread.start()
    try:
        manifest = MANIFEST.replace(
            "type: classifier",
            f"type: endpoint\n    endpoint: http://127.0.0.1:{server.server_port}/\n"
            "    timeout_ms: 100",
        )
        policy = ActivatedPolicy.from_memory(manifest, BUNDLES)

        async def run():
            async with AsyncAcsInterceptor(policy, max_concurrency=1) as adapter:
                record = (
                    await InterceptionEmitter(timeout=None)
                    .register(adapter)
                    .emit_unchecked(builder().input(content="x"))
                )
                assert requested.is_set()
                assert not release.is_set()
                assert record.verdict.reason == "runtime_error:annotation_timeout"
                assert adapter.in_flight == 0

        asyncio.run(run())
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("mode", [Saturation.REJECT, Saturation.WAIT, "reject", "wait"])
def test_saturation_enum_and_string_forms_and_readonly_counters(mode):
    async def run():
        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        adapter = AsyncAcsInterceptor(policy, on_saturation=mode)
        assert adapter.in_flight == adapter.waiting == 0
        assert not adapter.closed
        for name in ("in_flight", "waiting", "closed"):
            with pytest.raises(AttributeError):
                setattr(adapter, name, 1)
        await adapter.aclose()
        assert adapter.closed

    asyncio.run(run())


def test_snapshot_is_serialized_once_without_deepcopy(monkeypatch):
    class Context(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("the adapter must not deep-copy the context")

    async def run():
        entered_native = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()
        original = _evaluation._native.policy_evaluate
        wires = []

        def evaluate(handle, point, wire):
            wires.append(wire)
            loop.call_soon_threadsafe(entered_native.set)
            assert release.wait(5)
            return original(handle, point, wire)

        policy = ActivatedPolicy.from_memory(
            MANIFEST,
            BUNDLES,
            annotator_dispatcher=lambda name, definition, prelim: {
                "completed": prelim["policy_target"]["value"]["content"] == "before"
            },
        )
        async with AsyncAcsInterceptor(policy) as adapter:
            monkeypatch.setattr(_evaluation._native, "policy_evaluate", evaluate)
            context = Context(builder().input(content="before"))
            task = asyncio.create_task(adapter.intercept(context))
            try:
                await asyncio.wait_for(entered_native.wait(), 3)
                context["input"]["content"] = "after"
                assert adapter.in_flight == 1
            finally:
                release.set()
            assert (await task).decision.value == "allow"
            assert len(wires) == 1
            assert json.loads(wires[0])["input"]["content"] == "before"

    asyncio.run(run())


def test_late_worker_exception_is_reported_without_payload(monkeypatch, caplog):
    async def run():
        entered_native = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()

        def broken(*args):
            loop.call_soon_threadsafe(entered_native.set)
            assert release.wait(5)
            raise RuntimeError("private payload")

        policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
        async with AsyncAcsInterceptor(policy, max_concurrency=1) as adapter:
            monkeypatch.setattr(_evaluation._native, "policy_evaluate", broken)
            task = asyncio.create_task(
                InterceptionEmitter(timeout=0.1)
                .register(adapter)
                .emit(builder().input(content="x"))
            )
            try:
                await asyncio.wait_for(entered_native.wait(), 3)
                with pytest.raises(InterceptionBlocked) as blocked:
                    await task
                assert (
                    blocked.value.result.verdict.reason
                    == "host_error:interceptor_timeout"
                )
                assert adapter.in_flight == 1
            finally:
                release.set()
            await until(lambda: adapter.in_flight == 0)

    asyncio.run(run())
    assert "ACS async evaluation raised RuntimeError" in caplog.text
    assert "private payload" not in caplog.text


def test_wait_default_is_five_seconds_in_signature_and_deadline(monkeypatch):
    assert (
        inspect.signature(AsyncAcsInterceptor).parameters["admission_timeout"].default
        == 5.0
    )

    async def run():
        async with gated_adapter(max_concurrency=1, on_saturation="wait") as (
            gate,
            adapter,
        ):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            running = asyncio.create_task(
                emitter.emit(builder().input(content="running"))
            )
            await entered(gate)
            loop = asyncio.get_running_loop()
            original_time = loop.time
            reads = []

            def read_time():
                value = original_time()
                reads.append(value)
                return value

            with monkeypatch.context() as patch:
                patch.setattr(loop, "time", read_time)
                waiting = asyncio.create_task(
                    emitter.emit(builder().input(content="waiting"))
                )
                await until(lambda: adapter.waiting == 1)
                deadline = next(iter(adapter._waiters.values()))
                assert any(deadline == value + 5.0 for value in reads)
            gate.release_all()
            await asyncio.gather(running, waiting)

    asyncio.run(run())


def test_fifo_reservation_prevents_a_ready_newcomer_from_overtaking(monkeypatch):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=30,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            newcomer = []
            complete = adapter._completed

            def complete_with_new_arrival(work):
                if not newcomer:
                    # This task is ready before the older waiter's wakeup.
                    newcomer.append(
                        asyncio.create_task(
                            emitter.emit(builder().input(content="newcomer"))
                        )
                    )
                complete(work)

            monkeypatch.setattr(adapter, "_completed", complete_with_new_arrival)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await entered(gate)
            older = asyncio.create_task(emitter.emit(builder().input(content="older")))
            await until(lambda: adapter.waiting == 1)
            gate.gates[0].set()
            assert (await entered(gate))[0] == 1
            assert gate.inputs == ["first", "older"]
            assert adapter.in_flight == 1
            await until(lambda: adapter.waiting == 1)
            gate.gates[1].set()
            assert (await entered(gate))[0] == 2
            assert gate.inputs == ["first", "older", "newcomer"]
            gate.release_all()
            await asyncio.gather(first, older, *newcomer)
            assert adapter.in_flight == adapter.waiting == adapter._reserved == 0

    asyncio.run(run())


def test_cancellation_after_grant_hands_the_reservation_to_the_next_waiter(monkeypatch):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=30,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            victim = None
            cancelled = False
            wake = adapter._wake_waiters

            def wake_then_cancel_grantee():
                nonlocal cancelled
                wake()
                if victim is not None and adapter._reserved and not cancelled:
                    cancelled = True
                    victim.cancel()

            monkeypatch.setattr(adapter, "_wake_waiters", wake_then_cancel_grantee)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await entered(gate)
            victim = asyncio.create_task(
                emitter.emit(builder().input(content="cancelled"))
            )
            await until(lambda: adapter.waiting == 1)
            survivor = asyncio.create_task(
                emitter.emit(builder().input(content="survivor"))
            )
            await until(lambda: adapter.waiting == 2)
            gate.gates[0].set()
            assert (await entered(gate))[0] == 1
            with pytest.raises(asyncio.CancelledError):
                await victim
            assert gate.inputs == ["first", "survivor"]
            gate.release_all()
            await asyncio.gather(first, survivor)
            assert adapter.in_flight == adapter.waiting == adapter._reserved == 0

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["serialization", "submission"])
def test_failure_after_admission_releases_reserved_capacity(monkeypatch, failure):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=30,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await entered(gate)
            if failure == "serialization":
                failed = asyncio.create_task(
                    adapter.intercept(builder().input(content=float("nan")))
                )
            else:
                submit = adapter._executor.submit
                fail_once = True

                def submit_or_fail(*args, **kwargs):
                    nonlocal fail_once
                    if fail_once:
                        fail_once = False
                        raise RuntimeError("inert submit failure")
                    return submit(*args, **kwargs)

                monkeypatch.setattr(adapter._executor, "submit", submit_or_fail)
                failed = asyncio.create_task(
                    emitter.emit_unchecked(builder().input(content="failed"))
                )
            await until(lambda: adapter.waiting == 1)
            survivor = asyncio.create_task(
                emitter.emit(builder().input(content="survivor"))
            )
            await until(lambda: adapter.waiting == 2)
            gate.gates[0].set()
            assert (await entered(gate))[0] == 1
            assert gate.inputs == ["first", "survivor"]
            if failure == "serialization":
                with pytest.raises(ValueError):
                    await failed
            else:
                assert (await failed).verdict.reason == "host_error:interceptor_failed"
            gate.release_all()
            await asyncio.gather(first, survivor)
            assert adapter.in_flight == adapter.waiting == adapter._reserved == 0

    asyncio.run(run())


def test_close_after_grant_does_not_submit_granted_or_queued_calls(monkeypatch):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=30,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            complete = adapter._completed
            closing = []

            def complete_and_close(work):
                if not closing:
                    closing.append(asyncio.create_task(adapter.aclose()))
                complete(work)

            monkeypatch.setattr(adapter, "_completed", complete_and_close)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await entered(gate)
            waiters = [
                asyncio.create_task(
                    emitter.emit_unchecked(builder().input(content="waiting"))
                )
                for _ in range(2)
            ]
            await until(lambda: adapter.waiting == 2)
            gate.gates[0].set()
            records = await asyncio.gather(*waiters)
            assert all(
                r.verdict.reason == "runtime_error:acs_async_closed" for r in records
            )
            await asyncio.gather(first, *closing)
            assert gate.calls == 1
            assert adapter.in_flight == adapter.waiting == adapter._reserved == 0

    asyncio.run(run())


def test_granted_waiter_delayed_past_deadline_never_starts_native_work(monkeypatch):
    async def run():
        async with gated_adapter(
            max_concurrency=1,
            on_saturation="wait",
            admission_timeout=0.05,
        ) as (gate, adapter):
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            wake = adapter._wake_waiters
            loop = asyncio.get_running_loop()
            stalled = False

            def wake_then_block_loop():
                nonlocal stalled
                deadlines = list(adapter._waiters.values())
                wake()
                if deadlines and adapter._reserved and not stalled:
                    stalled = True
                    # Deliberately prevent the ready waiter and timeout callback
                    # from running until the recorded deadline has passed.
                    time.sleep(max(0, deadlines[0] - loop.time()) + 0.01)

            monkeypatch.setattr(adapter, "_wake_waiters", wake_then_block_loop)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await entered(gate)
            waiting = asyncio.create_task(
                emitter.emit_unchecked(builder().input(content="late"))
            )
            await until(lambda: adapter.waiting == 1)
            gate.gates[0].set()
            record = await waiting
            await first
            assert stalled
            assert record.verdict.reason == "runtime_error:acs_async_admission_timeout"
            assert gate.calls == 1
            assert adapter.waiting == adapter.in_flight == adapter._reserved == 0

    asyncio.run(run())


def test_fifo_notifies_each_waiter_once_and_grants_one_per_completed_slot(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()
        created = []
        notifications = []
        grants_per_completion = []

        class TrackedWaiters(OrderedDict):
            def __setitem__(self, future, deadline):
                created.append(future)
                future.add_done_callback(
                    lambda f: notifications.append(not f.cancelled() and f.result())
                )
                super().__setitem__(future, deadline)

        def dispatch(*args):
            loop.call_soon_threadsafe(started.set)
            if not release.wait(30):
                raise RuntimeError("test did not release the backlog")
            return {"completed": True}

        policy = ActivatedPolicy.from_memory(
            MANIFEST, BUNDLES, annotator_dispatcher=dispatch
        )
        async with AsyncAcsInterceptor(
            policy,
            max_concurrency=1,
            on_saturation="wait",
            max_pending=128,
            admission_timeout=30,
        ) as adapter:
            adapter._waiters = TrackedWaiters()
            completed = adapter._completed

            def count_grants(work):
                before = sum(f.done() for f in created)
                completed(work)
                grants_per_completion.append(sum(f.done() for f in created) - before)

            monkeypatch.setattr(adapter, "_completed", count_grants)
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            first = asyncio.create_task(emitter.emit(builder().input(content="first")))
            await asyncio.wait_for(started.wait(), 3)
            tasks = [
                asyncio.create_task(emitter.emit(builder().input(content="queued")))
                for _ in range(128)
            ]
            try:
                await until(lambda: adapter.waiting == 128)
                assert len(created) == 128
                release.set()
                results = await asyncio.wait_for(asyncio.gather(first, *tasks), 10)
            finally:
                release.set()
                await asyncio.gather(first, *tasks, return_exceptions=True)
            assert all(r.record.verdict.decision.value == "allow" for r in results)
            assert notifications == [True] * 128
            assert sum(grants_per_completion) == 128
            assert max(grants_per_completion) == 1
            assert adapter.in_flight == adapter.waiting == adapter._reserved == 0

    asyncio.run(run())
