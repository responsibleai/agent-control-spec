# Copyright (c) Microsoft. All rights reserved.
"""Worker admission, startup budgets, and repeated cancellation ownership."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from agent_control_spec_remote_policy import evaluate_policy_snapshot
from agent_control_spec_remote_policy import evaluation as evaluation_module
from agent_control_spec_remote_policy.poller import (
    PolicyPoller,
    PolicyUnavailable,
    PolicyValidationError,
)

from sdk.python_remote_policy.tests.test_client import context
from sdk.python_remote_policy.tests.test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
)


@pytest.mark.parametrize("failure", ["start", "timeout", "cancel", "late_failure"])
def test_spawn_failure_is_bounded_and_releases_admission(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        entered = asyncio.Event()

        async def fail_spawn(
            *args: str,
            **kwargs: object,
        ) -> asyncio.subprocess.Process:
            entered.set()
            if failure == "start":
                raise OSError("private host details must not escape")
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                if failure == "late_failure":
                    raise RuntimeError("unexpected creation failure") from None
                raise
            raise AssertionError("unreachable")

        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            snapshot = poller.get_policy("agent0")
            with monkeypatch.context() as scoped:
                scoped.setattr(asyncio, "create_subprocess_exec", fail_spawn)
                for _ in range(3):
                    entered.clear()
                    operation = asyncio.create_task(
                        evaluate_policy_snapshot(
                            snapshot,
                            "pre_tool_call",
                            context("agent0"),
                            timeout_seconds=0.05,
                        )
                    )
                    await asyncio.wait_for(entered.wait(), 2)
                    if failure == "cancel":
                        operation.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await operation
                    elif failure == "late_failure":
                        with pytest.raises(RuntimeError, match="creation failure"):
                            await operation
                    else:
                        with pytest.raises(PolicyUnavailable, match="could not start"):
                            await operation
            verdict = await evaluate_policy_snapshot(
                snapshot, "pre_tool_call", context("agent0")
            )
            assert verdict.decision.value == "allow"

    asyncio.run(scenario())


def test_repeated_cancellation_cannot_release_a_draining_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        created, draining, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        processes: list[asyncio.subprocess.Process] = []
        actual_spawn = asyncio.create_subprocess_exec
        actual_drain = evaluation_module._drain_worker

        async def stalled(
            *args: str,
            **kwargs: object,
        ) -> asyncio.subprocess.Process:
            process = await actual_spawn(
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
            created.set()
            return process

        async def held_drain(
            process: asyncio.subprocess.Process,
            tasks: list[asyncio.Task[object]],
        ) -> None:
            draining.set()
            await release.wait()
            await actual_drain(process, tasks)

        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            snapshot = poller.get_policy("agent0")
            with monkeypatch.context() as scoped:
                scoped.setattr(asyncio, "create_subprocess_exec", stalled)
                scoped.setattr(evaluation_module, "_drain_worker", held_drain)
                for _ in range(3):
                    created.clear()
                    draining.clear()
                    release.clear()
                    operation = asyncio.create_task(
                        evaluate_policy_snapshot(
                            snapshot, "pre_tool_call", context("agent0")
                        )
                    )
                    await asyncio.wait_for(created.wait(), 2)
                    operation.cancel()
                    await asyncio.wait_for(draining.wait(), 2)
                    operation.cancel()
                    operation.cancel()
                    await asyncio.wait({operation}, timeout=0)
                    assert not operation.done()
                    with pytest.raises(PolicyUnavailable, match="busy"):
                        await evaluate_policy_snapshot(
                            snapshot, "pre_tool_call", context("agent0")
                        )
                    release.set()
                    with pytest.raises(asyncio.CancelledError):
                        await operation
                    assert processes[-1].returncode is not None
            assert len(processes) == 3
            assert not any(
                task.get_name() == "acs-remote-policy-worker-drain"
                for task in asyncio.all_tasks()
            )
            verdict = await evaluate_policy_snapshot(
                snapshot, "pre_tool_call", context("agent0")
            )
            assert verdict.decision.value == "allow"

    asyncio.run(scenario())


def test_cancel_after_spawn_completion_recovers_the_unreceived_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        actual_spawn = asyncio.create_subprocess_exec
        processes: list[asyncio.subprocess.Process] = []
        operation: asyncio.Task[object] | None = None

        async def spawn_then_cancel(
            *args: str, **kwargs: object
        ) -> asyncio.subprocess.Process:
            process = await actual_spawn(
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
            assert operation is not None
            # Runs before the spawn future's waiter resumes. The caller has
            # not yet received the Process, but the owned spawn task has it.
            asyncio.get_running_loop().call_soon(operation.cancel)
            return process

        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            snapshot = poller.get_policy("agent0")
            with monkeypatch.context() as scoped:
                scoped.setattr(asyncio, "create_subprocess_exec", spawn_then_cancel)
                for _ in range(3):
                    operation = asyncio.create_task(
                        evaluate_policy_snapshot(
                            snapshot, "pre_tool_call", context("agent0")
                        )
                    )
                    with pytest.raises(asyncio.CancelledError):
                        await operation
                    assert processes[-1].returncode is not None
            assert len(processes) == 3
            verdict = await evaluate_policy_snapshot(
                snapshot, "pre_tool_call", context("agent0")
            )
            assert verdict.decision.value == "allow"
            assert not any(
                task.get_name().startswith("acs-remote-policy-spawn")
                for task in asyncio.all_tasks()
            )

    asyncio.run(scenario())


@pytest.mark.parametrize("budget", [True, 0, -1, 31, float("nan"), float("inf")])
def test_invalid_worker_budgets_never_spawn(
    monkeypatch: pytest.MonkeyPatch,
    budget: float,
) -> None:
    async def scenario() -> None:
        async def forbidden(
            *args: str,
            **kwargs: object,
        ) -> asyncio.subprocess.Process:
            raise AssertionError("invalid input must not spawn")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
        config = configuration(1)
        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            with pytest.raises(PolicyValidationError):
                await evaluate_policy_snapshot(
                    poller.get_policy("agent0"),
                    "pre_tool_call",
                    context("agent0"),
                    timeout_seconds=budget,
                )

    asyncio.run(scenario())
