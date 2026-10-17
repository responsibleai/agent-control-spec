# Copyright (c) Microsoft. All rights reserved.
"""Managed state, task-affine ownership, completion contracts and cancellation."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
    AsyncPolicyEvaluator,
    ManagedPolicyUsageError,
    PolicyEvaluation,
)
from agent_control_spec import async_interceptor as interceptor_module
from agent_hooks import AgentContextBuilder, Verdict

CONFIG = "remote_policy: {test_owned: true}\n"


def host_context() -> dict[str, object]:
    return dict(
        AgentContextBuilder(agent_id="a", framework="test", session_id="s").input(
            content="host"
        )
    )


@dataclass(frozen=True)
class Completion:
    verdict: Verdict

    def assert_current(self) -> None:
        pass


@dataclass(frozen=True)
class AsyncCheckCompletion:
    verdict: Verdict

    async def assert_current(self) -> None:
        pass


class InvalidVerdictCompletion:
    verdict = "not-a-native-verdict"

    def assert_current(self) -> None:
        pass


class InaccessibleVerdictCompletion:
    @property
    def verdict(self) -> Verdict:
        raise AttributeError("unavailable test verdict")

    def assert_current(self) -> None:
        pass


@dataclass(frozen=True)
class DisguisedAsyncCompletion:
    verdict: Verdict

    def assert_current(self) -> object:
        async def invalid_async_assertion() -> None:
            pass

        return invalid_async_assertion()


class Evaluator:
    async def evaluate(
        self, point: str, context: Mapping[str, object]
    ) -> PolicyEvaluation:
        return Completion(Verdict.from_wire({"decision": "allow"}))


class Loader:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.block_start = False
        self.fail_start = False
        self.exit_started = asyncio.Event()
        self.hold_exit: asyncio.Event | None = None
        self.exits = 0
        self.evaluator = Evaluator()
        self.identity: ContextVar[str] = ContextVar("managed-test", default="outside")

    def is_remote_configuration(self, configuration_yaml: str) -> bool:
        return configuration_yaml == CONFIG

    @asynccontextmanager
    async def open(
        self, configuration_yaml: str
    ) -> AsyncGenerator[AsyncPolicyEvaluator, None]:
        assert configuration_yaml == CONFIG
        owner = asyncio.current_task()
        token = self.identity.set("inside")
        try:
            self.entered.set()
            if self.fail_start:
                raise ValueError("test-owned startup failure")
            if self.block_start:
                await self.release.wait()
            yield self.evaluator
        finally:
            self.exit_started.set()
            if self.hold_exit is not None:
                await self.hold_exit.wait()
            assert asyncio.current_task() is owner
            assert self.identity.get() == "inside"
            self.identity.reset(token)
            self.exits += 1


def activation(tmp_path: Path, loader: Loader) -> ActivatedPolicy:
    path = tmp_path / "remote.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return ActivatedPolicy.activate(str(path), remote_loader=loader)


def test_remote_configure_claim_and_task_affine_close(tmp_path: Path) -> None:
    async def scenario() -> None:
        loader = Loader()
        policy = activation(tmp_path, loader)
        assert not loader.entered.is_set()
        for action in (
            lambda: policy.evaluate("input", host_context()),
            lambda: policy.intervention_points,
            lambda: policy.governs("input"),
        ):
            with pytest.raises(ManagedPolicyUsageError, match="async with"):
                action()
        control = AsyncAcsInterceptor(policy)
        assert control._executor is None
        with pytest.raises(ManagedPolicyUsageError, match=r"activate\(\).*again"):
            AsyncAcsInterceptor(policy)
        with pytest.raises(ManagedPolicyUsageError, match="not READY"):
            await control.intercept(host_context())
        await asyncio.create_task(control.__aenter__())
        assert (await control.intercept(host_context())).decision.value == "allow"
        await asyncio.create_task(control.aclose())
        await control.aclose()
        assert loader.exits == 1 and control.in_flight == 0
        assert (
            await control.intercept(host_context())
        ).reason == "runtime_error:acs_async_closed"
        with pytest.raises(RuntimeError, match="closed"):
            await control.__aenter__()
        assert loader.identity.get() == "outside"

    asyncio.run(scenario())


@pytest.mark.parametrize("close", [False, True])
def test_start_cancel_or_concurrent_close_cleans_owner(
    tmp_path: Path, close: bool
) -> None:
    async def scenario() -> None:
        loader = Loader()
        loader.block_start = True
        loader.hold_exit = asyncio.Event()
        control = AsyncAcsInterceptor(activation(tmp_path, loader))
        entering = asyncio.create_task(control.__aenter__())
        await asyncio.wait_for(loader.entered.wait(), 2)
        with pytest.raises(ManagedPolicyUsageError, match="not READY"):
            await control.intercept(host_context())
        with pytest.raises(ManagedPolicyUsageError, match="single-use"):
            await control.__aenter__()
        closing: asyncio.Task[None] | None = None
        try:
            if close:
                closing = asyncio.create_task(control.aclose())
            else:
                entering.cancel()
                entering.cancel()
            await asyncio.wait_for(loader.exit_started.wait(), 2)
            assert not entering.done()
            assert entering.cancelling() == (0 if close else 2)
        finally:
            loader.hold_exit.set()
            results = await asyncio.gather(entering, return_exceptions=True)
            if closing is not None:
                await closing
        if close:
            assert isinstance(results[0], ManagedPolicyUsageError)
            assert str(results[0]) == "Remote startup was closed"
            assert not entering.cancelled() and entering.cancelling() == 0
        else:
            assert isinstance(results[0], asyncio.CancelledError)
            assert entering.cancelled()
        assert control.closed and loader.exits == 1
        assert not any(
            task.get_name() == "acs-managed-owner" for task in asyncio.all_tasks()
        )

    asyncio.run(scenario())


def test_close_before_entry_consumes_activation_without_starting(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        loader = Loader()
        policy = activation(tmp_path, loader)
        control = AsyncAcsInterceptor(policy)
        await control.aclose()
        assert not loader.entered.is_set() and loader.exits == 0
        with pytest.raises(ManagedPolicyUsageError, match="activate"):
            AsyncAcsInterceptor(policy)

    asyncio.run(scenario())


def test_failed_start_remains_a_clear_usage_error(tmp_path: Path) -> None:
    async def scenario() -> None:
        loader = Loader()
        loader.fail_start = True
        control = AsyncAcsInterceptor(activation(tmp_path, loader))
        with pytest.raises(ValueError, match="startup failure") as failure:
            await control.__aenter__()
        with pytest.raises(ManagedPolicyUsageError, match="failed before READY"):
            await control.intercept(host_context())
        for _ in range(3):
            with pytest.raises(ValueError, match="startup failure") as replay:
                await control.aclose()
            assert replay.value is failure.value
        assert loader.exits == 1

    asyncio.run(scenario())


def test_concurrent_owner_claim_is_atomic(tmp_path: Path) -> None:
    async def scenario() -> None:
        policy = activation(tmp_path, Loader())
        barrier = threading.Barrier(3, timeout=3)

        def claim() -> AsyncAcsInterceptor | ManagedPolicyUsageError:
            barrier.wait()
            try:
                return AsyncAcsInterceptor(policy)
            except ManagedPolicyUsageError as error:
                return error

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(claim) for _ in range(2)]
            barrier.wait()
            outcomes = [future.result(timeout=3) for future in futures]
        winners = [
            value for value in outcomes if isinstance(value, AsyncAcsInterceptor)
        ]
        failures = [
            value for value in outcomes if isinstance(value, ManagedPolicyUsageError)
        ]
        assert len(winners) == len(failures) == 1
        assert "activate() again" in str(failures[0])
        await winners[0].aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        object(),
        Verdict.from_wire({"decision": "allow"}),
        AsyncCheckCompletion(Verdict.from_wire({"decision": "allow"})),
        InvalidVerdictCompletion(),
        InaccessibleVerdictCompletion(),
        DisguisedAsyncCompletion(Verdict.from_wire({"decision": "allow"})),
    ],
)
def test_invalid_custom_completion_is_a_typed_contract_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: object
) -> None:
    async def scenario() -> None:
        loader = Loader()

        async def bad(point: str, context: Mapping[str, object]) -> object:
            return invalid

        monkeypatch.setattr(loader.evaluator, "evaluate", bad)
        async with AsyncAcsInterceptor(activation(tmp_path, loader)) as control:
            with pytest.raises(ManagedPolicyUsageError, match="PolicyEvaluation"):
                await control.intercept(host_context())

    asyncio.run(scenario())


def test_custom_loader_classifier_must_return_a_synchronous_bool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loader = Loader()

    def invalid_classification(configuration_yaml: str) -> object:
        return 1

    monkeypatch.setattr(loader, "is_remote_configuration", invalid_classification)
    with pytest.raises(ManagedPolicyUsageError, match="synchronously return bool"):
        activation(tmp_path, loader)
    assert not loader.entered.is_set()


def test_primary_startup_cancellation_survives_repeated_cleanup_cancellation(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        loader = Loader()
        loader.block_start = True
        loader.hold_exit = asyncio.Event()
        control = AsyncAcsInterceptor(activation(tmp_path, loader))
        entering = asyncio.create_task(control.__aenter__())
        await asyncio.wait_for(loader.entered.wait(), 2)
        entering.cancel("primary")
        await asyncio.wait_for(loader.exit_started.wait(), 2)
        try:
            for _ in range(3):
                entering.cancel("later")
                acknowledged = asyncio.Event()
                asyncio.get_running_loop().call_soon(acknowledged.set)
                await acknowledged.wait()
                assert not entering.done() and loader.exits == 0
        finally:
            loader.hold_exit.set()
        with pytest.raises(asyncio.CancelledError, match="primary"):
            await entering
        assert loader.exits == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("caller_cancel", [False, True])
def test_close_cancels_worker_without_cancelling_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caller_cancel: bool
) -> None:
    async def scenario() -> None:
        loader = Loader()
        entered, drained = asyncio.Event(), asyncio.Event()

        async def held(point: str, context: Mapping[str, object]) -> PolicyEvaluation:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                drained.set()
            raise AssertionError("unreachable")

        monkeypatch.setattr(loader.evaluator, "evaluate", held)
        async with AsyncAcsInterceptor(activation(tmp_path, loader)) as control:
            operation = asyncio.create_task(control.intercept(host_context()))
            await asyncio.wait_for(entered.wait(), 2)
            if caller_cancel:
                operation.cancel()
            await control.aclose()
            if caller_cancel:
                with pytest.raises(asyncio.CancelledError):
                    await operation
            else:
                assert (await operation).reason == "runtime_error:acs_async_closed"
            assert drained.is_set() and control.in_flight == 0

    asyncio.run(scenario())


def test_retained_evaluation_keeps_loader_until_actual_exit_and_allows_drain_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        loader = Loader()
        entered, release = asyncio.Event(), asyncio.Event()

        async def noncooperative(
            point: str, context: Mapping[str, object]
        ) -> PolicyEvaluation:
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
            return Completion(Verdict.from_wire({"decision": "allow"}))

        monkeypatch.setattr(loader.evaluator, "evaluate", noncooperative)
        monkeypatch.setattr(interceptor_module, "_MANAGED_DRAIN_TIMEOUT", 0.02)
        control = AsyncAcsInterceptor(activation(tmp_path, loader))
        await control.__aenter__()
        operation = asyncio.create_task(control.intercept(host_context()))
        await asyncio.wait_for(entered.wait(), 2)
        try:
            for _ in range(3):
                with pytest.raises(ManagedPolicyUsageError, match="remains retained"):
                    await control.aclose()
                assert loader.exits == 0 and control.in_flight == 1
        finally:
            release.set()
            result = await asyncio.wait_for(operation, 2)
            assert result.reason == "runtime_error:acs_async_closed"
            await control.aclose()
        assert loader.exits == 1 and control.in_flight == 0

    asyncio.run(scenario())
