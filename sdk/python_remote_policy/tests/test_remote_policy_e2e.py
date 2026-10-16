# Copyright (c) Microsoft. All rights reserved.
"""Real sockets and real ACS evaluation, including failed engine/worker paths."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec_remote_policy.http import HttpPolicySource
from agent_control_spec_remote_policy.poller import (
    JsonValue,
    PolicyPoller,
    PolicySnapshot,
    PolicyUnavailable,
    decode_json,
    validate_acs_artifacts,
)
from agent_hooks import AgentContextBuilder

from examples.remote_policy import demo
from examples.remote_policy.server import PolicyServer
from sdk.python_remote_policy.tests.test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
    document,
    reply,
)

SCRIPT = (
    Path(__file__).resolve().parents[3].joinpath("examples", "remote_policy", "demo.py")
)


def test_benign_contract_evaluates_in_real_engine() -> None:
    config = configuration(1)
    envelope = document(config.agents[0])
    manifest = envelope["manifest"]
    assert isinstance(manifest, str)
    bundles = validate_acs_artifacts(manifest, envelope["bundles"])
    policy = ActivatedPolicy.from_memory(manifest, bundles)
    builder = AgentContextBuilder(agent_id="agent0", framework="test", session_id="s")
    for amount, expected in ((75, "allow"), (150, "deny")):
        context = decode_json(
            json.dumps(
                builder.pre_tool_call(
                    call_id="real-engine",
                    name="issue_refund",
                    args={"order_id": "example-order", "amount": amount},
                )
            ).encode("utf-8")
        )
        assert isinstance(context, dict)
        verdict = policy.evaluate("pre_tool_call", context)
        assert verdict.decision.value == expected
        assert not (verdict.reason or "").startswith("runtime_error:")


def test_real_http_download_update_isolation_and_local_evaluation() -> None:
    async def scenario() -> None:
        config = configuration()
        with PolicyServer(config.agents) as server:
            server.publish("agent0", limit=100)
            server.publish("agent1", limit=200)
            local = replace(
                config, endpoint=server.endpoint, allow_insecure_localhost=True
            )
            source = HttpPolicySource.from_config(local, {})
            ledger: list[dict[str, JsonValue]] = []
            async with PolicyPoller(local, source) as poller:
                first = await demo.attempt_refund(poller, "agent0", 75, ledger)
                other = poller.get_policy("agent1")
                assert first.decision == "allow"
                revision = server.publish("agent0", limit=50)
                updated = await poller.refresh("agent0")
                assert updated.revision == revision == 2
                assert poller.get_policy("agent1") is other
                denied = await demo.attempt_refund(poller, "agent0", 75, ledger)
                independent = await demo.attempt_refund(poller, "agent1", 75, ledger)
                assert denied.decision == "deny" and independent.decision == "allow"
                assert ledger == [
                    {"agent_id": "agent0", "amount": 75},
                    {"agent_id": "agent1", "amount": 75},
                ]
            assert not poller._requests and not poller._flights

    asyncio.run(scenario())


def test_native_engine_error_is_not_an_allow_or_executed_operation() -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        envelope = document(config.agents[0])
        manifest = envelope["manifest"]
        assert isinstance(manifest, str)
        envelope["manifest"] = manifest.replace(
            "data.refund_limits.verdict", "data.refund_limits.absent"
        )
        source.responses["agent0"] = reply(envelope)
        ledger: list[dict[str, JsonValue]] = []
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            with pytest.raises(PolicyUnavailable, match="failed closed"):
                await demo.attempt_refund(poller, "agent0", 75, ledger)
            assert ledger == []

    asyncio.run(scenario())


def test_snapshot_change_at_real_consumer_final_gate_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        finished_evaluation = asyncio.Event()
        release_result = asyncio.Event()
        actual_evaluate = demo.evaluate_isolated

        async def held_actual_evaluation(
            snapshot: PolicySnapshot, *, amount: float, timeout_seconds: float = 10
        ) -> demo.Evaluation:
            result = await actual_evaluate(
                snapshot, amount=amount, timeout_seconds=timeout_seconds
            )
            finished_evaluation.set()
            await release_result.wait()
            return result

        monkeypatch.setattr(demo, "evaluate_isolated", held_actual_evaluation)
        ledger: list[dict[str, JsonValue]] = []
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            operation = asyncio.create_task(
                demo.attempt_refund(poller, "agent0", 75, ledger)
            )
            await asyncio.wait_for(finished_evaluation.wait(), 10)
            source.responses["agent0"] = reply(document(config.agents[0], revision=2))
            await poller.refresh("agent0")
            release_result.set()
            with pytest.raises(PolicyUnavailable, match="changed"):
                await operation
            assert ledger == []

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_worker_timeout_cancellation_kill_and_drain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cancel: bool,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        created = asyncio.Event()
        processes: list[asyncio.subprocess.Process] = []
        real_spawn = asyncio.create_subprocess_exec

        async def spawn_stalled(
            *args: str, **kwargs: object
        ) -> asyncio.subprocess.Process:
            # The child is real; the barrier selects a non-responsive worker boundary.
            process = await real_spawn(
                sys.executable,
                "-I",
                "-c",
                "import time; time.sleep(60)",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(tmp_path),
                start_new_session=os.name == "posix",
            )
            processes.append(process)
            environment = kwargs.get("env")
            assert isinstance(environment, dict)
            assert "AZURE_CLIENT_SECRET" not in environment
            assert "ACS_REGO_V0" not in environment
            created.set()
            return process

        monkeypatch.setattr(demo.asyncio, "create_subprocess_exec", spawn_stalled)
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            for _ in range(3):
                created.clear()
                task = asyncio.create_task(
                    demo.evaluate_isolated(
                        poller.get_policy("agent0"), amount=75, timeout_seconds=0.05
                    )
                )
                await asyncio.wait_for(created.wait(), 2)
                if cancel:
                    with pytest.raises(PolicyUnavailable, match="busy"):
                        await demo.evaluate_isolated(
                            poller.get_policy("agent0"), amount=75
                        )
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                else:
                    with pytest.raises(PolicyUnavailable):
                        await task
                assert processes[-1].returncode is not None
            assert len(processes) == 3
            assert all(process.returncode is not None for process in processes)

    monkeypatch.setenv("AZURE_CLIENT_SECRET", "unit-test-secret")
    monkeypatch.setenv("ACS_REGO_V0", "true")
    asyncio.run(scenario())


def test_azure_mode_missing_inputs_fails_before_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("POLICY_API_ENDPOINT", raising=False)
    monkeypatch.delenv("POLICY_API_SCOPE", raising=False)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--azure"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 2
    assert "requires an HTTPS --endpoint" in completed.stderr
    assert "Azure API read succeeded" not in completed.stdout
