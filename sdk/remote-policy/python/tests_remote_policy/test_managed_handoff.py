# Copyright (c) Microsoft. All rights reserved.
"""PR-001: invalidate after the client's gate but before interceptor resumption."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TypeVar

import pytest
from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor
from agent_control_spec_remote_policy import RemotePolicyFileLoader
from agent_control_spec_remote_policy import client as client_module
from agent_control_spec_remote_policy.client import SnapshotEvaluation
from agent_control_spec_remote_policy.poller import (
    JsonValue,
    PolicyPoller,
    PolicySnapshot,
    PolicySource,
    PolicyUnavailable,
    PollerConfig,
)
from agent_hooks import InterceptionEmitter, Verdict

from .test_client import context
from .test_integration import write_config
from .test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
    document,
    reply,
)

_T = TypeVar("_T")


@pytest.mark.parametrize(
    "change",
    [
        "revision",
        "wall_expiry",
        "monotonic_expiry",
        "fence",
        "close",
        "unchanged",
        "other_agent",
    ],
)
def test_final_gate_follows_backend_task_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    async def scenario() -> None:
        config = configuration()
        clock = FakeClock()
        source = MemorySource(config)
        pollers: list[PolicyPoller] = []
        native_done, allow_inner = asyncio.Event(), asyncio.Event()
        refresh_parked, commit = asyncio.Event(), asyncio.Event()
        order: list[str] = []
        actual_evaluate = client_module.evaluate_policy_snapshot
        actual_completion = client_module.RemotePolicyClient.evaluate_completion
        actual_check = SnapshotEvaluation.assert_current
        actual_wait = asyncio.wait
        arm_refresh = False

        async def real_native_then_park(
            snapshot: PolicySnapshot,
            point: str,
            selected: Mapping[str, JsonValue],
            *,
            timeout_seconds: float = 10,
        ) -> Verdict:
            verdict = await actual_evaluate(
                snapshot, point, selected, timeout_seconds=timeout_seconds
            )
            assert verdict.decision.value == "allow"
            order.append("native")
            native_done.set()
            await allow_inner.wait()
            return verdict

        async def completion_then_release(
            client: client_module.RemotePolicyClient,
            agent_id: str,
            point: str,
            selected: Mapping[str, JsonValue],
            *,
            timeout_seconds: float = 10,
        ) -> SnapshotEvaluation:
            result = await actual_completion(
                client, agent_id, point, selected, timeout_seconds=timeout_seconds
            )
            order.append("inner")
            # Queue the invalidator BEFORE completion queues the outer waiter.
            commit.set()
            return result

        async def parked_wait(
            fs: Iterable[asyncio.Future[_T]],
            *,
            timeout: float | None = None,
            return_when: str = asyncio.ALL_COMPLETED,
        ) -> tuple[set[asyncio.Future[_T]], set[asyncio.Future[_T]]]:
            futures = tuple(fs)
            result = await actual_wait(
                futures, timeout=timeout, return_when=return_when
            )
            if arm_refresh and any(
                isinstance(work, asyncio.Task) and work.get_name() == "acs-policy-fetch"
                for work in futures
            ):
                refresh_parked.set()
                await commit.wait()
            return result

        def make_source(
            selected: PollerConfig, credentials: Mapping[str, client_module.Credential]
        ) -> PolicySource:
            return source

        def make_poller(
            selected: PollerConfig, selected_source: PolicySource
        ) -> PolicyPoller:
            poller = PolicyPoller(selected, selected_source, clock=clock)
            pollers.append(poller)
            return poller

        monkeypatch.setattr(
            client_module, "evaluate_policy_snapshot", real_native_then_park
        )
        monkeypatch.setattr(
            client_module.RemotePolicyClient,
            "evaluate_completion",
            completion_then_release,
        )
        monkeypatch.setattr(asyncio, "wait", parked_wait)
        loader = RemotePolicyFileLoader(
            source_factory=make_source, poller_factory=make_poller
        )
        policy = ActivatedPolicy.activate(
            str(write_config(tmp_path, config)), remote_loader=loader
        )
        async with AsyncAcsInterceptor(policy) as control:
            poller = pollers[0]
            retained = poller.get_policy("agent0")

            def outer_check(result: SnapshotEvaluation) -> None:
                assert order == ["native", "inner"]
                assert control._backend_work is None  # handoff has completed
                if change in ("unchanged", "other_agent"):
                    assert poller.get_policy("agent0") is retained
                elif change == "revision":
                    assert poller.get_policy("agent0").revision == 2
                else:
                    with pytest.raises(PolicyUnavailable):
                        poller.get_policy("agent0")
                order.append("outer")
                actual_check(result)

            monkeypatch.setattr(SnapshotEvaluation, "assert_current", outer_check)
            # agent-hooks b2 annotates sync Interceptor but awaits it at runtime.
            emitter = InterceptionEmitter(timeout=15).register(control)  # pyright: ignore[reportArgumentType]
            operation = asyncio.create_task(emitter.emit_unchecked(context("agent0")))
            mutation: asyncio.Task[object] | None = None
            await asyncio.wait_for(native_done.wait(), 10)
            try:
                if change in ("revision", "unchanged", "other_agent"):
                    target = "agent1" if change == "other_agent" else "agent0"
                    if change != "unchanged":
                        source.responses[target] = reply(
                            document(
                                config.agents[1 if target == "agent1" else 0],
                                revision=2,
                            )
                        )
                    arm_refresh = True
                    mutation = asyncio.create_task(poller.refresh(target))
                    await asyncio.wait_for(refresh_parked.wait(), 2)
                else:

                    async def invalidate() -> None:
                        await commit.wait()
                        if change == "close":
                            await poller.aclose()
                        elif change == "fence":
                            # Source completion fences immediately, before
                            # refresh's awaited wait returns. Inject that exact
                            # synchronous observation after the inner gate.
                            poller._fence(poller._entries["agent0"], "forbidden")
                        elif change == "wall_expiry":
                            clock.advance(0, wall_seconds=901)
                        else:
                            clock.advance(901, wall_seconds=0)

                    mutation = asyncio.create_task(invalidate())
                    # Ensure the invalidator is parked before the backend release.
                    acknowledged = asyncio.Event()
                    asyncio.get_running_loop().call_soon(acknowledged.set)
                    await acknowledged.wait()
                allow_inner.set()
                record = await operation
                assert order == ["native", "inner", "outer"]
                if change in ("unchanged", "other_agent"):
                    assert record.verdict.decision.value == "allow"
                else:
                    assert record.verdict.decision.value == "deny"
                    assert record.verdict.reason == "host_error:interceptor_failed"
            finally:
                allow_inner.set()
                commit.set()
                await asyncio.gather(operation, return_exceptions=True)
                if mutation is not None:
                    await asyncio.gather(mutation, return_exceptions=True)
        assert source.closed and control.in_flight == 0

    asyncio.run(scenario())
