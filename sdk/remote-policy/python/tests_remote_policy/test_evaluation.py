# Copyright (c) Microsoft. All rights reserved.
"""Worker admission, startup budgets, and repeated cancellation ownership."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

import pytest
from agent_control_spec_remote_policy import evaluate_policy_snapshot
from agent_control_spec_remote_policy import evaluation as evaluation_module
from agent_control_spec_remote_policy.poller import (
    PolicyCapacityError,
    PolicyPoller,
    PolicyUnavailable,
    PolicyValidationError,
)

from .test_client import context
from .test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
)


class _Spawn(NamedTuple):
    argv: tuple[str, ...]
    stdin: int
    stdout: int
    stderr: int
    cwd: str
    env: dict[str, str]
    start_new_session: bool
    cwd_existed: bool


def test_worker_spawn_is_isolated_scrubbed_and_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin the child's argv, environment, working directory and session."""
    ambient = {
        "AWS_SECRET_ACCESS_KEY": "ambient-aws-secret",
        "AZURE_CLIENT_SECRET": "ambient-azure-secret",
        "HTTPS_PROXY": "http://proxy.invalid",
        "PYTHONPATH": "/ambient/path",
        "PYTHONSTARTUP": "/ambient/startup.py",
        "ACS_OPA_TIMEOUT_MS": "1",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)
    spawned: list[_Spawn] = []
    actual_spawn = asyncio.create_subprocess_exec

    # Explicit keyword-only parameters also pin the exact set of options passed.
    async def recording_spawn(
        program: str,
        *arguments: str,
        stdin: int,
        stdout: int,
        stderr: int,
        cwd: str,
        env: dict[str, str],
        start_new_session: bool,
    ) -> asyncio.subprocess.Process:
        spawned.append(
            _Spawn(
                (program, *arguments),
                stdin,
                stdout,
                stderr,
                cwd,
                dict(env),
                start_new_session,
                Path(cwd).is_dir(),
            )
        )
        return await actual_spawn(
            program,
            *arguments,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            start_new_session=start_new_session,
        )

    async def scenario() -> None:
        config = configuration(1)
        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            with monkeypatch.context() as scoped:
                scoped.setattr(asyncio, "create_subprocess_exec", recording_spawn)
                verdict = await evaluate_policy_snapshot(
                    poller.get_policy("agent0"), "pre_tool_call", context("agent0")
                )
            assert verdict.decision.value == "allow"

    asyncio.run(scenario())
    [spawn] = spawned
    assert spawn.argv == (
        sys.executable,
        "-I",
        "-m",
        "agent_control_spec_remote_policy._worker",
    )
    pipe = asyncio.subprocess.PIPE
    assert (spawn.stdin, spawn.stdout, spawn.stderr) == (pipe, pipe, pipe)
    assert spawn.env["ACS_OPA_TIMEOUT_MS"] == "5000"
    assert set(spawn.env) <= {
        "ACS_OPA_TIMEOUT_MS",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
    }
    assert not any(secret in spawn.env.values() for secret in ambient.values())
    worker_directory = Path(spawn.cwd)
    assert spawn.cwd_existed and not worker_directory.exists()
    assert worker_directory.name.startswith("acs-policy-worker-")
    assert worker_directory.parent == Path(tempfile.gettempdir())
    assert worker_directory != Path.cwd()
    assert spawn.start_new_session is (os.name == "posix")


def test_busy_worker_denial_names_the_agent_without_spawning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        async def forbidden(
            *args: str,
            **kwargs: object,
        ) -> asyncio.subprocess.Process:
            raise AssertionError("a busy worker must not spawn")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
        config = configuration(2)
        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            assert evaluation_module._WORKER_ADMISSION.acquire(blocking=False)
            try:
                with caplog.at_level(
                    logging.WARNING, logger=evaluation_module.__name__
                ):
                    for agent in ("agent0", "agent1"):
                        with pytest.raises(PolicyCapacityError, match="busy"):
                            await evaluate_policy_snapshot(
                                poller.get_policy(agent),
                                "pre_tool_call",
                                context(agent),
                            )
            finally:
                evaluation_module._WORKER_ADMISSION.release()

    asyncio.run(scenario())
    busy = [
        record
        for record in caplog.records
        if record.getMessage().startswith("policy_worker_busy")
    ]
    assert [getattr(record, "agent_id", None) for record in busy] == [
        "agent0",
        "agent1",
    ]
    assert [record.getMessage() for record in busy] == [
        "policy_worker_busy agent=agent0",
        "policy_worker_busy agent=agent1",
    ]


@pytest.mark.parametrize(
    "wire,failure_code",
    [
        ('{"error":"resource_limit_failed"}', "resource_limit_failed"),
        ('{"error":"evaluation_failed"}', "evaluation_failed"),
        ('{"error":"PRIVATE_WORKER_STDOUT"}', "unknown"),
        ("PRIVATE_WORKER_STDOUT", "unknown"),
        ('{"error":"evaluation_failed","detail":"PRIVATE_WORKER_STDOUT"}', "unknown"),
    ],
    ids=["resource", "evaluation", "unknown", "invalid-json", "extra-fields"],
)
def test_worker_failure_logs_only_allowlisted_codes_and_drains(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    wire: str,
    failure_code: str,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        actual_spawn = asyncio.create_subprocess_exec
        processes: list[asyncio.subprocess.Process] = []

        async def failed_worker(
            *arguments: str, **options: object
        ) -> asyncio.subprocess.Process:
            process = await actual_spawn(
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.stdin.buffer.read(); "
                "sys.stderr.write('PRIVATE_WORKER_STDERR'); "
                f"print({wire!r}); raise SystemExit(2)",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(tmp_path),
                start_new_session=os.name == "posix",
            )
            processes.append(process)
            return process

        async with PolicyPoller(
            config, MemorySource(config), clock=FakeClock()
        ) as poller:
            snapshot = poller.get_policy("agent0")
            with monkeypatch.context() as scoped:
                scoped.setattr(asyncio, "create_subprocess_exec", failed_worker)
                for _ in range(2):
                    with pytest.raises(PolicyUnavailable, match="could not evaluate"):
                        await evaluate_policy_snapshot(
                            snapshot, "pre_tool_call", context("agent0")
                        )
                    assert processes[-1].returncode == 2
            failures = [
                record
                for record in caplog.records
                if record.getMessage().startswith("policy_worker_failed")
            ]
            assert len(failures) == 2
            for record in failures:
                assert getattr(record, "failure_code", None) == failure_code
                assert getattr(record, "exit_code", None) == 2
                assert record.exc_info is None
                assert record.args == (failure_code, 2)
                assert record.getMessage() == (
                    f"policy_worker_failed failure_code={failure_code} exit_code=2"
                )
            assert "PRIVATE_WORKER" not in caplog.text
            verdict = await evaluate_policy_snapshot(
                snapshot, "pre_tool_call", context("agent0")
            )
            assert verdict.decision.value == "allow"
        assert not any(
            task.get_name() == "acs-remote-policy-worker-drain"
            for task in asyncio.all_tasks()
        )

    asyncio.run(scenario())


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
