# Copyright (c) Microsoft. All rights reserved.
"""Download per-agent ACS policies and evaluate real Rego before an inert refund."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor
from agent_control_spec_remote_policy import (
    RemotePolicyClient,
    RemotePolicyFileLoader,
    evaluate_policy_snapshot,
)
from agent_control_spec_remote_policy._worker import main as worker_main
from agent_control_spec_remote_policy.auth import Credential, CredentialProviderRegistry
from agent_control_spec_remote_policy.azure import azure_credential_factories
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
)
from agent_hooks import (
    AgentContextBuilder,
    InterceptionBlocked,
    InterceptionEmitter,
    Verdict,
)

_EXAMPLE = Path(__file__).resolve().parent
_LOG = logging.getLogger(__name__)


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


def _refund_context(agent_id: str, amount: float) -> dict[str, JsonValue]:
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
    return context


def _refund_evaluation(verdict: Verdict) -> Evaluation:
    if (verdict.reason or "").startswith("runtime_error:"):
        raise PolicyUnavailable("Native policy evaluation failed closed")
    decision = verdict.decision.value
    if decision not in ("allow", "deny"):
        raise PolicyUnavailable("This demo requires an explicit allow/deny policy")
    return Evaluation(decision)


async def evaluate_isolated(
    snapshot: PolicySnapshot, *, amount: float, timeout_seconds: float = 10
) -> Evaluation:
    """Adapt the generic library evaluator to this example's inert refund."""
    return _refund_evaluation(
        await evaluate_policy_snapshot(
            snapshot,
            "pre_tool_call",
            _refund_context(snapshot.selection.agent_id, amount),
            timeout_seconds=timeout_seconds,
        )
    )


async def attempt_refund(
    poller: PolicyPoller | RemotePolicyClient,
    agent_id: str,
    amount: float,
    ledger: list[dict[str, JsonValue]],
) -> Evaluation:
    """Only a current, successful allow may execute; the operation is an inert list."""
    if isinstance(poller, RemotePolicyClient):
        result = _refund_evaluation(
            await poller.evaluate(
                agent_id, "pre_tool_call", _refund_context(agent_id, amount)
            )
        )
    else:
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
        ledger: list[dict[str, JsonValue]] = []
        async with RemotePolicyClient.open(local) as poller:
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


def _demo_registry() -> CredentialProviderRegistry:
    """Register the Azure CLI factory so the README's `--remote` YAML example works.

    The default registry is empty. A host must register every factory it allows,
    and a registered factory lets the YAML choose its options and the endpoint
    the credential is sent to. Keep the YAML as trusted as host code.
    """
    return CredentialProviderRegistry(azure_credential_factories())


async def _poll_and_evaluate(
    config: PollerConfig,
    credentials: Mapping[str, Credential] | None = None,
    *,
    watch_seconds: float,
    label: Literal["Azure", "Remote"],
    registry: CredentialProviderRegistry | None = None,
) -> None:
    async with RemotePolicyClient.open(
        config, registry=registry, credentials=credentials
    ) as poller:
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
    await _poll_and_evaluate(
        config,
        registry=registry if registry is not None else _demo_registry(),
        watch_seconds=watch_seconds,
        label="Remote",
    )


async def managed_demo(
    path: Path, agent_ids: tuple[str, ...], *, watch_seconds: float = 0
) -> None:
    """Use the same activation/interceptor flow for local or remote YAML.

    Agent IDs are trusted host registrations, not downloaded policy metadata.
    Only real emitter-enforced allows append an inert refund to the ledger.
    """
    if (
        isinstance(watch_seconds, bool)
        or not math.isfinite(watch_seconds)
        or not 0 <= watch_seconds <= 3600
    ):
        raise PolicyValidationError("config")
    loader = RemotePolicyFileLoader(registry=_demo_registry())
    policy = ActivatedPolicy.activate(str(path), remote_loader=loader)
    ledger: list[dict[str, JsonValue]] = []
    async with AsyncAcsInterceptor(policy) as control:
        # agent-hooks b2 annotates sync Interceptor but supports async at runtime.
        emitter = InterceptionEmitter(timeout=15).register(control, control.name)  # pyright: ignore[reportArgumentType]
        for agent_id in agent_ids:
            try:
                outcome = await emitter.emit(_refund_context(agent_id, 75))
            except InterceptionBlocked as blocked:
                result = _refund_evaluation(blocked.result.verdict)
            else:
                result = _refund_evaluation(outcome.record.verdict)
                if result.decision == "allow":
                    ledger.append({"agent_id": agent_id, "amount": 75})
            print(f"{agent_id}: decision={result.decision}")
        print(f"Managed interceptor; executed inert refunds: {len(ledger)}")
        if watch_seconds:
            print(f"Keeping the managed interceptor alive for {watch_seconds:g}s")
            await asyncio.sleep(watch_seconds)


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
        async with _demo_registry().open(remote) as credentials:
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
            if args.poll_interval_seconds is not None:
                # Keep the existing explicit programmatic scheduling override.
                asyncio.run(configured_demo(config, watch_seconds=args.watch_seconds))
            else:
                asyncio.run(
                    managed_demo(
                        args.config,
                        tuple(agent.agent_id for agent in config.agents),
                        watch_seconds=args.watch_seconds,
                    )
                )
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
