# Copyright (c) Microsoft. All rights reserved.
"""Download per-agent ACS policies and evaluate real Rego before an inert refund."""

from __future__ import annotations

import argparse
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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from agent_control_spec import ActivatedPolicy
from agent_control_spec_remote_policy.auth import Credential, CredentialProviderRegistry
from agent_control_spec_remote_policy.http import HttpPolicySource
from agent_control_spec_remote_policy.poller import (
    CredentialConfig,
    JsonValue,
    PolicyError,
    PolicyPoller,
    PolicySnapshot,
    PolicyUnavailable,
    PolicyValidationError,
    PollerConfig,
    decode_json,
    validate_acs_artifacts,
)
from agent_hooks import AgentContextBuilder

_EXAMPLE = Path(__file__).resolve().parent
_LOG = logging.getLogger(__name__)
MAX_WORKER_BYTES = 2 * 1024 * 1024
_WORKER_ADMISSION = threading.BoundedSemaphore(1)


class _WorkerSlot:
    def __init__(self) -> None:
        if not _WORKER_ADMISSION.acquire(blocking=False):
            _LOG.warning("policy_worker_busy")
            raise PolicyUnavailable("The example policy evaluator is busy")
        self.deferred = False

    def release_after(
        self, process: asyncio.subprocess.Process, task: asyncio.Task[None]
    ) -> None:
        if task.cancelled() or task.exception() is not None:
            _LOG.error("policy_worker_cleanup_failed")
        if process.returncode is not None:
            _WORKER_ADMISSION.release()


class _Options(argparse.Namespace):
    local: bool
    azure: bool
    remote: bool
    worker: bool
    config: Path
    endpoint: str | None
    scope: str | None
    credential: str | None
    managed_identity_client_id: str | None
    poll_interval_seconds: float | None
    watch_seconds: float


@dataclass(frozen=True, slots=True)
class Evaluation:
    """An actual allow/deny decision, not a model response."""

    decision: Literal["allow", "deny"]


def worker_main() -> int:
    """Rego-only child bootstrap; no Azure credential or ambient secret is needed."""
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
    try:
        raw = decode_json(
            sys.stdin.buffer.read(MAX_WORKER_BYTES + 1), max_bytes=MAX_WORKER_BYTES
        )
        if not isinstance(raw, dict) or raw.keys() != {
            "manifest",
            "bundles",
            "agent_id",
            "amount",
        }:
            raise ValueError("Invalid policy worker request")
        manifest, agent_id, amount = raw["manifest"], raw["agent_id"], raw["amount"]
        if (
            not isinstance(manifest, str)
            or not isinstance(agent_id, str)
            or isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not math.isfinite(amount)
            or amount < 0
        ):
            raise ValueError("Invalid policy worker request")
        bundles = validate_acs_artifacts(manifest, raw["bundles"])
        policy = ActivatedPolicy.from_memory(manifest, bundles)
        builder = AgentContextBuilder(
            agent_id=agent_id, framework="remote-policy-example", session_id="local"
        )
        context = decode_json(
            json.dumps(
                builder.pre_tool_call(
                    call_id="inert-refund",
                    name="issue_refund",
                    args={"order_id": "example-order", "amount": amount},
                ),
                allow_nan=False,
            ).encode("utf-8")
        )
        if not isinstance(context, dict):
            raise TypeError("Invalid host context")
        verdict = policy.evaluate("pre_tool_call", context)
        response = {
            "decision": verdict.decision.value,
            "engine_error": (verdict.reason or "").startswith("runtime_error:"),
        }
        print(json.dumps(response, allow_nan=False))
        return 0
    except (PolicyError, ValueError, TypeError, RuntimeError):
        print('{"error":"evaluation_failed"}')
        return 2


async def _read_bounded(stream: asyncio.StreamReader, cap: int) -> bytes:
    output = bytearray()
    while chunk := await stream.read(65536):
        output.extend(chunk)
        if len(output) > cap:
            raise PolicyUnavailable("Local policy worker exceeded its output limit")
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


async def evaluate_isolated(
    snapshot: PolicySnapshot,
    *,
    amount: float,
    timeout_seconds: float = 10,
) -> Evaluation:
    """Single-shot evaluation with wall/output limits and kill/drain on every path."""
    slot = _WorkerSlot()
    try:
        return await _evaluate_admitted(
            snapshot, amount=amount, timeout_seconds=timeout_seconds, slot=slot
        )
    finally:
        if not slot.deferred:
            _WORKER_ADMISSION.release()


async def _evaluate_admitted(
    snapshot: PolicySnapshot,
    *,
    amount: float,
    timeout_seconds: float,
    slot: _WorkerSlot,
) -> Evaluation:
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30:
        raise PolicyValidationError("config")
    request = json.dumps(
        {
            "manifest": snapshot.manifest_yaml,
            "bundles": snapshot.bundles(),
            "agent_id": snapshot.selection.agent_id,
            "amount": amount,
        },
        allow_nan=False,
    ).encode("utf-8")
    if len(request) > MAX_WORKER_BYTES:
        raise PolicyUnavailable("Local policy worker input is too large")
    environment = {"ACS_OPA_TIMEOUT_MS": "5000"}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        if name in os.environ:
            environment[name] = os.environ[name]
    with tempfile.TemporaryDirectory(prefix="acs-policy-worker-") as directory:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--worker",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=directory,
            env=environment,
            start_new_session=os.name == "posix",
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            _kill_worker(process)
            await process.wait()
            raise PolicyUnavailable("Local policy worker pipes are unavailable")
        writer = asyncio.create_task(_write_input(process.stdin, request))
        stdout = asyncio.create_task(_read_bounded(process.stdout, MAX_WORKER_BYTES))
        stderr = asyncio.create_task(_read_bounded(process.stderr, 65536))
        waiter = asyncio.create_task(process.wait())
        tasks: list[asyncio.Task[object]] = [writer, stdout, stderr, waiter]
        try:
            async with asyncio.timeout(timeout_seconds):
                await asyncio.gather(*tasks)
            if process.returncode != 0:
                raise PolicyUnavailable("Local policy worker could not evaluate")
            result = decode_json(stdout.result(), max_bytes=MAX_WORKER_BYTES)
            if not isinstance(result, dict) or result.keys() != {
                "decision",
                "engine_error",
            }:
                raise PolicyUnavailable(
                    "Local policy worker returned an invalid result"
                )
            if result["engine_error"] is not False:
                raise PolicyUnavailable("Native policy evaluation failed closed")
            decision = result["decision"]
            if decision not in ("allow", "deny"):
                raise PolicyUnavailable(
                    "This demo requires an explicit allow/deny policy"
                )
            return Evaluation(decision)
        except (TimeoutError, OSError):
            raise PolicyUnavailable("Local policy worker timed out or failed") from None
        finally:
            _kill_worker(process)
            for task in tasks:
                if not task.done():
                    task.cancel()
            drain = asyncio.create_task(_drain_worker(process, tasks))
            slot.deferred = True
            drain.add_done_callback(lambda done: slot.release_after(process, done))
            await asyncio.shield(drain)


async def attempt_refund(
    poller: PolicyPoller,
    agent_id: str,
    amount: float,
    ledger: list[dict[str, JsonValue]],
) -> Evaluation:
    """Only a current, successful allow may execute; the operation is an inert list."""
    snapshot = poller.get_policy(agent_id)
    result = await evaluate_isolated(snapshot, amount=amount)
    poller.assert_current(agent_id, snapshot)
    if result.decision == "allow":
        ledger.append({"agent_id": agent_id, "amount": amount})
    return result


async def local_demo(config: PollerConfig) -> None:
    """Run real download/update/agent-isolation/evaluation without Azure resources."""
    from examples.remote_policy.server import PolicyServer

    if (
        len(config.agents) != 2
        or len({(agent.tenant_id, agent.policy_id) for agent in config.agents}) != 2
    ):
        raise ValueError("The local demo requires two distinct policy selections")
    first, second = config.agents
    lease = max(
        900,
        math.ceil(2 * config.poll_interval_seconds + config.request_timeout_seconds),
    )
    with PolicyServer(config.agents, lease_seconds=lease) as server:
        server.publish(first.agent_id, limit=100)
        server.publish(second.agent_id, limit=200)
        local = replace(
            config,
            endpoint=server.endpoint,
            credential_ref=None,
            allow_insecure_localhost=True,
        )
        source = HttpPolicySource.from_config(local, {})
        ledger: list[dict[str, JsonValue]] = []
        async with PolicyPoller(local, source) as poller:
            before = await attempt_refund(poller, first.agent_id, 75, ledger)
            print(f"{first.agent_id}: revision=1 decision={before.decision}")
            server.publish(first.agent_id, limit=50)
            await poller.refresh(first.agent_id)
            after = await attempt_refund(poller, first.agent_id, 75, ledger)
            independent = await attempt_refund(poller, second.agent_id, 75, ledger)
            print(
                f"{first.agent_id}: revision=2 decision={after.decision}; "
                f"{second.agent_id}: revision=1 decision={independent.decision}"
            )
            if (
                before.decision != "allow"
                or after.decision != "deny"
                or independent.decision != "allow"
                or len(ledger) != 2
            ):
                raise RuntimeError("Real policy evaluation did not match the example")
            print(
                f"Executed inert refunds: {len(ledger)}; SDK interval={local.poll_interval_seconds:g}s"
            )


async def _poll_and_evaluate(
    config: PollerConfig,
    credentials: Mapping[str, Credential],
    *,
    watch_seconds: float,
    label: Literal["Azure", "Remote"],
) -> None:
    source = HttpPolicySource.from_config(config, credentials)
    async with PolicyPoller(config, source) as poller:
        ledger: list[dict[str, JsonValue]] = []
        for registration in config.agents:
            snapshot = poller.get_policy(registration.agent_id)
            result = await attempt_refund(poller, registration.agent_id, 75, ledger)
            print(
                f"{registration.agent_id}: revision={snapshot.revision} "
                f"decision={result.decision}"
            )
        print(f"{label} API read succeeded; executed inert refunds: {len(ledger)}")
        if watch_seconds:
            print(f"Keeping the poller alive for {watch_seconds:g}s")
            await asyncio.sleep(watch_seconds)
            for registration in config.agents:
                current = poller.get_policy(registration.agent_id)
                print(f"{registration.agent_id}: current revision={current.revision}")


async def configured_demo(
    config: PollerConfig,
    *,
    registry: CredentialProviderRegistry | None = None,
    watch_seconds: float = 0,
) -> None:
    """Select the endpoint and a trusted credential factory from configuration."""
    if (
        isinstance(watch_seconds, bool)
        or not isinstance(watch_seconds, (int, float))
        or not math.isfinite(watch_seconds)
        or not 0 <= watch_seconds <= 3600
    ):
        raise PolicyValidationError("config")
    providers = registry if registry is not None else CredentialProviderRegistry()
    async with providers.open(config) as credentials:
        await _poll_and_evaluate(
            config, credentials, watch_seconds=watch_seconds, label="Remote"
        )


async def azure_demo(
    config: PollerConfig,
    *,
    endpoint: str,
    scope: str,
    credential_kind: str,
    managed_identity_client_id: str | None,
    watch_seconds: float = 0,
) -> None:
    """Use an explicitly selected Azure credential against the configured API."""
    if (
        not endpoint.startswith("https://")
        or not scope
        or config.credential_ref is None
        or not math.isfinite(watch_seconds)
        or not 0 <= watch_seconds <= 3600
    ):
        raise PolicyValidationError("config")
    _LOG.info(
        "--azure uses explicit credential arguments; --remote uses YAML providers."
    )
    remote = replace(config, endpoint=endpoint, allow_insecure_localhost=False)
    if credential_kind == "azure-cli":
        remote = replace(
            remote,
            credentials={
                config.credential_ref: CredentialConfig(
                    "azure_cli", {"scope": scope, "process_timeout_seconds": 5}
                )
            },
        )
        async with CredentialProviderRegistry().open(remote) as credentials:
            await _poll_and_evaluate(
                remote, credentials, watch_seconds=watch_seconds, label="Azure"
            )
        return
    from agent_control_spec_remote_policy.azure import AzureAuthorizationProvider
    from azure.identity.aio import ManagedIdentityCredential, WorkloadIdentityCredential

    if credential_kind == "managed-identity":
        credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
    elif credential_kind == "workload-identity":
        credential = WorkloadIdentityCredential()
    else:
        raise ValueError("Unsupported Azure credential kind")
    async with credential:
        provider = AzureAuthorizationProvider(credential, scope)
        await _poll_and_evaluate(
            remote,
            {config.credential_ref: provider},
            watch_seconds=watch_seconds,
            label="Azure",
        )


def main() -> int:
    """CLI: local demo, configured remote API, or explicit Azure credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true")
    mode.add_argument(
        "--remote", action="store_true", help="Use YAML credential providers"
    )
    mode.add_argument("--azure", action="store_true")
    mode.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--config", type=Path, default=_EXAMPLE.joinpath("policies.yaml")
    )
    parser.add_argument("--endpoint", default=os.environ.get("POLICY_API_ENDPOINT"))
    parser.add_argument("--scope", default=os.environ.get("POLICY_API_SCOPE"))
    parser.add_argument(
        "--credential",
        choices=("azure-cli", "managed-identity", "workload-identity"),
    )
    parser.add_argument("--managed-identity-client-id")
    parser.add_argument("--poll-interval-seconds", type=float)
    parser.add_argument("--watch-seconds", type=float, default=0)
    args = _Options()
    parser.parse_args(namespace=args)
    if args.worker:
        return worker_main()
    if args.azure and (
        not args.endpoint or not args.endpoint.startswith("https://") or not args.scope
    ):
        parser.error("Azure mode requires an HTTPS --endpoint and the API's --scope")
    if args.remote and any(
        option is not None
        for option in (
            args.endpoint,
            args.scope,
            args.credential,
            args.managed_identity_client_id,
        )
    ):
        parser.error("--remote uses YAML; remove explicit Azure arguments/environment")
    try:
        config = PollerConfig.from_yaml(args.config.read_text(encoding="utf-8"))
        if args.poll_interval_seconds is not None:
            config = replace(
                config,
                poll_interval_seconds=args.poll_interval_seconds,
                request_timeout_seconds=min(
                    config.request_timeout_seconds, args.poll_interval_seconds / 2
                ),
            )
        if args.local:
            # Direct script execution does not automatically expose namespace packages.
            sys.path.insert(0, str(_EXAMPLE.parents[1]))
            asyncio.run(local_demo(config))
        elif args.remote:
            asyncio.run(configured_demo(config, watch_seconds=args.watch_seconds))
        else:
            if args.endpoint is None or args.scope is None:
                parser.error("Azure mode requires endpoint and scope")
            asyncio.run(
                azure_demo(
                    config,
                    endpoint=args.endpoint,
                    scope=args.scope,
                    credential_kind=args.credential or "azure-cli",
                    managed_identity_client_id=args.managed_identity_client_id,
                    watch_seconds=args.watch_seconds,
                )
            )
    except PolicyError as failure:
        code = (
            failure.code
            if isinstance(failure, PolicyValidationError)
            else type(failure).__name__
        )
        print(
            f"Remote policy demo blocked: {code}; check SDK audit events.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, RuntimeError, OSError):
        print("Remote policy example configuration or worker failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
