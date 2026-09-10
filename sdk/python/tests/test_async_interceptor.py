# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Real emitter and native evaluation, with event-gated local dispatchers."""

import asyncio
import contextvars
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec.async_interceptor import AsyncAcsInterceptor, Scope
from agent_hooks import (
    AgentContextBuilder,
    InterceptionBlocked,
    InterceptionEmitter,
    Verdict,
)

MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: rego
    query: data.gate.verdict
annotators:
  classify:
    type: classifier
intervention_points:
  input:
    policy_target: $.input
    annotations:
      classify:
        from: $target.content
    policy:
      id: gate
"""
BUNDLES = {
    "gate": {
        "modules": {
            "gate.rego": (
                'package gate\nverdict := {"decision": "allow"} '
                "if { input.annotations.classify.completed == true }"
            )
        }
    }
}
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
TRACE = contextvars.ContextVar("acs_test_trace", default=None)


def builder():
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


class GatedAnnotator:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.entered = asyncio.Queue()
        self.gates = [threading.Event() for _ in range(16)]
        self.calls = 0
        self.lock = threading.Lock()
        self.finished = set()

    def dispatch(self, name, definition, policy_input):
        with self.lock:
            index = self.calls
            self.calls += 1
        self.loop.call_soon_threadsafe(self.entered.put_nowait, (index, TRACE.get()))
        if not self.gates[index].wait(5):
            raise RuntimeError("test did not release annotator")
        self.finished.add(index)
        return {"completed": True}

    def release_all(self):
        for gate in self.gates:
            gate.set()


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


async def until(predicate):
    # This is a hang guard, not a performance threshold.
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0)


async def entered(gate):
    return await asyncio.wait_for(gate.entered.get(), 3)


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
            emitter = InterceptionEmitter(timeout=None if cancel else 0.1).register(
                adapter
            )
            task = asyncio.create_task(emitter.emit(builder().input(content="first")))
            assert (await entered(gate))[0] == 0
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                with pytest.raises(InterceptionBlocked) as blocked:
                    await task
                assert (
                    blocked.value.result.verdict.reason
                    == "host_error:interceptor_timeout"
                )
            assert not gate.finished
            record = await emitter.emit_unchecked(builder().input(content="second"))
            assert record.verdict.reason == "acs_async_capacity_exceeded"
            assert gate.calls == 1
            gate.gates[0].set()
            await until(lambda: not adapter._in_flight)
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
            await until(lambda: adapter._waiting == 1)
            overflow = await emitter.emit_unchecked(builder().input(content="overflow"))
            assert overflow.verdict.reason == "acs_async_capacity_exceeded"
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
            emitter = InterceptionEmitter(timeout=None).register(adapter)
            running = asyncio.create_task(
                emitter.emit(builder().input(content="running"))
            )
            await entered(gate)
            waiting = asyncio.create_task(
                emitter.emit_unchecked(builder().input(content="waiting"))
            )
            await until(lambda: adapter._waiting == 1)
            if cancel:
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting
            else:
                assert (await waiting).verdict.reason == "acs_async_admission_timeout"
            assert adapter._waiting == 0
            assert gate.calls == 1
            replacement = asyncio.create_task(
                emitter.emit(builder().input(content="replacement"))
            )
            await until(lambda: adapter._waiting == 1)
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
            await until(lambda: adapter._waiting == 1)
            closing = asyncio.create_task(adapter.aclose())
            assert (await waiting).verdict.reason == "acs_async_closed"
            assert not closing.done()
            closing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert (
                await emitter.emit_unchecked(builder().input(content="new"))
            ).verdict.reason == "acs_async_closed"
            assert gate.calls == 1
            gate.release_all()
            await running
            await adapter.aclose()
            await adapter.aclose()
            assert not adapter._in_flight

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


def test_cross_loop_use_is_rejected():
    policy = ActivatedPolicy.from_memory(TOOL_MANIFEST, {})
    adapter = AsyncAcsInterceptor(policy)
    asyncio.run(adapter.aclose())
    with pytest.raises(RuntimeError, match="event loops"):
        asyncio.run(adapter.aclose())


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
            assert adapter._waiting == 0
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
            assert not adapter._in_flight
            record = await emitter.emit_unchecked(builder().input(content="x"))
            assert record.verdict.reason == "runtime_error:intervention_point_unknown"

    asyncio.run(run())


def test_boundary_error_releases_capacity_and_remains_fail_closed(caplog):
    async def run():
        async with gated_adapter(max_concurrency=1) as (gate, adapter):
            with pytest.raises(ValueError):
                await adapter.intercept(builder().input(content=float("nan")))
            assert not adapter._in_flight
            gate.gates[0].set()
            await (
                InterceptionEmitter()
                .register(adapter)
                .emit(builder().input(content="x"))
            )

    asyncio.run(run())
    assert "ACS async evaluation raised ValueError" in caplog.text


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
                assert not adapter._in_flight

        asyncio.run(run())
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
