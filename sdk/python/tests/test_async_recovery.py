# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pool cleanup remains possible after the owning event loop has closed."""

import asyncio
import threading

import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
    AsyncAcsLoopMismatchError,
)
from agent_hooks import AgentContextBuilder, InterceptionEmitter

from ._async_helpers import BUNDLES, MANIFEST, until


def context():
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s").input(
        content="recovery"
    )


def policy():
    return ActivatedPolicy.from_memory(
        MANIFEST, BUNDLES, annotator_dispatcher=lambda *args: {"completed": True}
    )


@pytest.mark.parametrize("async_recovery", [False, True])
def test_idle_pool_is_joined_after_owner_loop_is_gone(async_recovery):
    adapter = AsyncAcsInterceptor(policy())

    async def use():
        await InterceptionEmitter().register(adapter).emit(context())

    asyncio.run(use())
    threads = list(adapter._executor._threads)
    assert threads and all(thread.is_alive() for thread in threads)
    if async_recovery:
        asyncio.run(adapter.aclose())
    else:
        adapter.close()
    assert all(not thread.is_alive() for thread in threads)
    assert adapter.closed and adapter.in_flight == adapter.waiting == 0
    adapter.close()
    asyncio.run(adapter.aclose())


def test_live_owner_cannot_be_shut_down_from_another_loop_or_sync_close():
    adapter = AsyncAcsInterceptor(policy())
    with asyncio.Runner() as owner:
        owner.run(adapter.__aenter__())
        with pytest.raises(AsyncAcsLoopMismatchError, match="requires"):
            adapter.close()
        with pytest.raises(AsyncAcsLoopMismatchError, match="event loops"):
            asyncio.run(adapter.aclose())
        assert not adapter.closed
        owner.run(adapter.aclose())


def test_close_before_first_async_use():
    adapter = AsyncAcsInterceptor(policy())
    adapter.close()
    adapter.close()

    async def run():
        result = await InterceptionEmitter().register(adapter).emit_unchecked(context())
        assert result.verdict.reason == "runtime_error:acs_async_closed"
        await adapter.aclose()

    asyncio.run(run())


def test_sync_close_is_rejected_inside_the_owning_loop():
    async def run():
        async with AsyncAcsInterceptor(policy()) as adapter:
            with pytest.raises(AsyncAcsLoopMismatchError, match="use aclose"):
                adapter.close()
            assert not adapter.closed

    asyncio.run(run())


@pytest.mark.parametrize("late_failure", [False, True])
def test_recovery_waits_for_native_completion_and_survives_awaiter_cancel(
    monkeypatch, caplog, late_failure
):
    release = threading.Event()
    entered = threading.Event()

    def dispatch(*args):
        entered.set()
        if not release.wait(10):
            raise RuntimeError("test failed to release worker")
        return {"completed": True}

    activated = ActivatedPolicy.from_memory(
        MANIFEST, BUNDLES, annotator_dispatcher=dispatch
    )
    adapter = AsyncAcsInterceptor(activated, max_concurrency=1)
    if late_failure:
        from agent_control_spec import _evaluation

        native = _evaluation._native.policy_evaluate

        def evaluate(*args):
            native(*args)
            raise RuntimeError("private late failure payload")

        monkeypatch.setattr(_evaluation._native, "policy_evaluate", evaluate)

    async def owner():
        result = (
            await InterceptionEmitter(timeout=0.1)
            .register(adapter)
            .emit_unchecked(context())
        )
        assert entered.is_set()
        assert result.verdict.reason == "host_error:interceptor_timeout"
        assert adapter.in_flight == 1

    async def recover():
        close_started = asyncio.Event()
        loop = asyncio.get_running_loop()
        close = adapter.close

        def signal_close():
            loop.call_soon_threadsafe(close_started.set)
            close()

        monkeypatch.setattr(adapter, "close", signal_close)
        recovery = asyncio.create_task(adapter.aclose())
        try:
            await asyncio.wait_for(close_started.wait(), 3)
            await until(lambda: adapter.closed)
            assert not recovery.done()
            assert adapter.in_flight == 1
            assert all(thread.is_alive() for thread in adapter._executor._threads)
            recovery.cancel()
            with pytest.raises(asyncio.CancelledError):
                await recovery
            # The shutdown thread is still joining the native work.
            assert adapter.in_flight == 1
        finally:
            release.set()
            await adapter.aclose()
        assert adapter.in_flight == adapter.waiting == 0
        assert all(not thread.is_alive() for thread in adapter._executor._threads)
        with pytest.raises(AsyncAcsLoopMismatchError):
            await adapter.intercept(context())

    try:
        asyncio.run(owner())
        asyncio.run(recover())
    finally:
        release.set()
        AsyncAcsInterceptor.close(adapter)
    if late_failure:
        assert caplog.text.count("ACS async evaluation raised RuntimeError") == 1
        assert "private late failure payload" not in caplog.text


def test_abandoned_waiter_is_discarded_only_after_workers_finish():
    release = threading.Event()
    entered = threading.Event()

    def dispatch(*args):
        entered.set()
        if not release.wait(10):
            raise RuntimeError("test failed to release worker")
        return {"completed": True}

    activated = ActivatedPolicy.from_memory(
        MANIFEST, BUNDLES, annotator_dispatcher=dispatch
    )
    adapter = AsyncAcsInterceptor(activated, max_concurrency=1, on_saturation="wait")

    async def owner():
        emitter = InterceptionEmitter(timeout=None).register(adapter)
        running = asyncio.create_task(emitter.emit(context()))
        await until(entered.is_set)
        waiting = asyncio.create_task(emitter.emit(context()))
        await until(lambda: adapter.waiting == 1)
        # asyncio.run cancels both tasks, but the native call survives.
        return running, waiting

    try:
        running, waiting = asyncio.run(owner())
        assert running.cancelled() and waiting.cancelled()
        assert adapter.in_flight == 1
        assert adapter.waiting == 0
        release.set()
        adapter.close()
        assert adapter.in_flight == adapter.waiting == adapter._reserved == 0
        assert all(not thread.is_alive() for thread in adapter._executor._threads)
    finally:
        release.set()
        adapter.close()
