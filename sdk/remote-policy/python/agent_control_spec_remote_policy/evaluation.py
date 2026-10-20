# Copyright (c) Microsoft. All rights reserved.
"""Bounded isolated evaluation of validated remote ACS policy snapshots."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import signal
import sys
import tempfile
import threading
from collections.abc import Mapping

from agent_hooks import Verdict

from .poller import (
    MAX_EVALUATION_BYTES,
    JsonValue,
    PolicyCapacityError,
    PolicyCloseError,
    PolicySnapshot,
    PolicyUnavailable,
    PolicyValidationError,
    decode_json,
)

_LOG = logging.getLogger(__name__)
_WORKER_ADMISSION = threading.BoundedSemaphore(1)


class _WorkerSlot:
    def __init__(self, agent_id: str) -> None:
        if not _WORKER_ADMISSION.acquire(blocking=False):
            _LOG.warning(
                "policy_worker_busy agent=%s",
                agent_id,
                extra={"event": "policy_worker_busy", "agent_id": agent_id},
            )
            raise PolicyCapacityError("Remote policy evaluator is busy")
        self.deferred = False
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            _WORKER_ADMISSION.release()

    def release_after(
        self, process: asyncio.subprocess.Process, task: asyncio.Task[None]
    ) -> None:
        if task.cancelled() or task.exception() is not None:
            _LOG.error("policy_worker_cleanup_failed")
        if process.returncode is not None:
            self.release()


async def _read_bounded(stream: asyncio.StreamReader, cap: int) -> bytes:
    output = bytearray()
    while chunk := await stream.read(65536):
        output.extend(chunk)
        if len(output) > cap:
            raise PolicyUnavailable("Policy worker exceeded its output limit")
    return bytes(output)


async def _write_input(stream: asyncio.StreamWriter, body: bytes) -> None:
    stream.write(body)
    await stream.drain()
    stream.close()
    await stream.wait_closed()


def _kill_worker(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        _LOG.debug("policy_worker_already_exited")


async def _drain_worker(
    process: asyncio.subprocess.Process, tasks: list[asyncio.Task[object]]
) -> None:
    await process.wait()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException) and not isinstance(
            result, asyncio.CancelledError
        ):
            _LOG.warning("policy_worker_io_failed")


async def _close_worker(
    process: asyncio.subprocess.Process,
    tasks: list[asyncio.Task[object]],
    slot: _WorkerSlot,
) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    drain = asyncio.create_task(
        _drain_worker(process, tasks), name="acs-remote-policy-worker-drain"
    )
    slot.deferred = True
    drain.add_done_callback(lambda done: slot.release_after(process, done))
    try:
        _kill_worker(process)
    except OSError:
        _LOG.error("policy_worker_termination_failed")
        raise PolicyCloseError(1) from None
    deadline = asyncio.get_running_loop().time() + 5
    cancelled = False
    while not drain.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            _LOG.error("policy_worker_cleanup_failed")
            raise PolicyCloseError(1)
        try:
            await asyncio.wait({drain}, timeout=remaining)
        except asyncio.CancelledError:
            cancelled = True
    if drain.cancelled() or drain.exception() is not None:
        _LOG.error("policy_worker_cleanup_failed")
        raise PolicyCloseError(1)
    if cancelled:
        raise asyncio.CancelledError


async def _discard_spawn(
    spawn: asyncio.Task[asyncio.subprocess.Process], slot: _WorkerSlot
) -> None:
    """Recover a completed spawn even if its awaiter never received the child."""
    try:
        process = await spawn
    except (asyncio.CancelledError, OSError):
        slot.release()
        return
    except BaseException:
        # The creation task is terminal: asyncio has closed its transport.
        # Propagate unexpected failure without permanently leaking admission.
        slot.release()
        raise
    await _close_worker(process, [], slot)


async def _close_spawn(
    spawn: asyncio.Task[asyncio.subprocess.Process], slot: _WorkerSlot
) -> None:
    if not spawn.done():
        # asyncio's subprocess creation owns cancellation of its transport.
        # Keep admission until that creation coroutine is actually terminal.
        spawn.cancel()
    slot.deferred = True
    cleanup = asyncio.create_task(
        _discard_spawn(spawn, slot), name="acs-remote-policy-spawn-drain"
    )
    cleanup.add_done_callback(_observe_cleanup)
    deadline = asyncio.get_running_loop().time() + 5
    while not cleanup.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise PolicyCloseError(1)
        try:
            await asyncio.wait({cleanup}, timeout=remaining)
        except asyncio.CancelledError:
            continue
    cleanup.result()


def _observe_cleanup(work: asyncio.Task[None]) -> None:
    if not work.cancelled() and work.exception() is not None:
        _LOG.error("policy_worker_cleanup_failed")


async def evaluate_policy_snapshot(
    snapshot: PolicySnapshot,
    point: str,
    context: Mapping[str, JsonValue],
    *,
    timeout_seconds: float = 10,
) -> Verdict:
    """Evaluate without ambient credentials; callers must still assert freshness.

    Return the native ACS verdict, including deny/transform/error reasons. One
    worker is admitted process-wide; saturation fails closed without queueing.
    Timeout/cancellation kills and drains the worker before its slot is released.
    Use RemotePolicyClient.evaluate to include the final current-policy check.
    """
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 30
    ):
        raise PolicyValidationError("config")
    slot = _WorkerSlot(snapshot.selection.agent_id)
    try:
        return await _evaluate_admitted(
            snapshot, point, context, timeout_seconds=timeout_seconds, slot=slot
        )
    finally:
        if not slot.deferred:
            slot.release()


async def _evaluate_admitted(
    snapshot: PolicySnapshot,
    point: str,
    context: Mapping[str, JsonValue],
    *,
    timeout_seconds: float,
    slot: _WorkerSlot,
) -> Verdict:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    try:
        request = json.dumps(
            {
                "manifest": snapshot.manifest_yaml,
                "bundles": snapshot.bundles(),
                "point": point,
                "context": dict(context),
            },
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        raise PolicyValidationError("json") from None
    if len(request) > MAX_EVALUATION_BYTES:
        raise PolicyUnavailable("Policy worker input is too large")
    environment = {"ACS_OPA_TIMEOUT_MS": "5000"}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        if name in os.environ:
            environment[name] = os.environ[name]
    with tempfile.TemporaryDirectory(prefix="acs-policy-worker-") as directory:
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-m",
                "agent_control_spec_remote_policy._worker",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=directory,
                env=environment,
                start_new_session=os.name == "posix",
            ),
            name="acs-remote-policy-spawn",
        )
        try:
            async with asyncio.timeout_at(deadline):
                process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            await _close_spawn(spawn, slot)
            raise
        except (TimeoutError, OSError):
            await _close_spawn(spawn, slot)
            _LOG.warning("policy_worker_start_failed")
            raise PolicyUnavailable("Policy worker could not start") from None
        tasks: list[asyncio.Task[object]] = []
        try:
            if (
                process.stdin is None
                or process.stdout is None
                or process.stderr is None
            ):
                raise PolicyUnavailable("Policy worker pipes are unavailable")
            writer = asyncio.create_task(_write_input(process.stdin, request))
            stdout = asyncio.create_task(
                _read_bounded(process.stdout, MAX_EVALUATION_BYTES)
            )
            stderr = asyncio.create_task(_read_bounded(process.stderr, 65536))
            waiter = asyncio.create_task(process.wait())
            tasks.extend((writer, stdout, stderr, waiter))
            async with asyncio.timeout_at(deadline):
                await asyncio.gather(*tasks)
            if process.returncode != 0:
                failure_code = {
                    b'{"error":"resource_limit_failed"}': "resource_limit_failed",
                    b'{"error":"evaluation_failed"}': "evaluation_failed",
                }.get(stdout.result().strip(), "unknown")
                _LOG.warning(
                    "policy_worker_failed failure_code=%s exit_code=%s",
                    failure_code,
                    process.returncode,
                    extra={
                        "failure_code": failure_code,
                        "exit_code": process.returncode,
                    },
                )
                raise PolicyUnavailable("Policy worker could not evaluate")
            result = decode_json(stdout.result(), max_bytes=MAX_EVALUATION_BYTES)
            if not isinstance(result, dict):
                raise PolicyUnavailable("Policy worker returned an invalid verdict")
            try:
                return Verdict.from_wire(result)
            except (ValueError, TypeError, KeyError):
                raise PolicyUnavailable(
                    "Policy worker returned an invalid verdict"
                ) from None
        except (TimeoutError, OSError):
            raise PolicyUnavailable("Policy worker timed out or failed") from None
        finally:
            await _close_worker(process, tasks, slot)
