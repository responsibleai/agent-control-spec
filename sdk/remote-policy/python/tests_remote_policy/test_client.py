# Copyright (c) Microsoft. All rights reserved.
"""YAML-only consumers, native verdicts, and the final policy authorization gate."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec_remote_policy import RemotePolicyClient
from agent_control_spec_remote_policy import client as client_module
from agent_control_spec_remote_policy.auth import (
    Credential,
    CredentialProviderRegistry,
)
from agent_control_spec_remote_policy.poller import (
    MAX_YAML_BYTES,
    CredentialConfig,
    CredentialOption,
    JsonValue,
    PolicyPoller,
    PolicySnapshot,
    PolicySource,
    PolicySourceError,
    PolicyUnavailable,
    PolicyValidationError,
    PollerConfig,
    StartupError,
    decode_json,
)
from agent_hooks import AgentContextBuilder, Verdict

from examples.remote_policy.server import PolicyServer

from .test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
    document,
    reply,
)


def context(agent_id: str, amount: float = 75) -> dict[str, JsonValue]:
    raw = AgentContextBuilder(
        agent_id=agent_id, framework="client-test", session_id="test"
    ).pre_tool_call(
        call_id="refund-test",
        name="issue_refund",
        args={"order_id": "example-order", "amount": amount},
    )
    decoded = decode_json(json.dumps(raw).encode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def test_yaml_only_client_downloads_updates_and_returns_native_verdicts(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = configuration()
        with PolicyServer(config.agents) as server:
            server.publish("agent0", limit=100)
            server.publish("agent1", limit=200)
            path = tmp_path / "remote-policies.yaml"
            path.write_text(
                json.dumps(
                    {
                        "remote_policy": {
                            "endpoint": server.endpoint,
                            "allow_insecure_localhost": True,
                            "agents": [
                                {
                                    "agent_id": agent.agent_id,
                                    "tenant_id": agent.tenant_id,
                                    "policy_id": agent.policy_id,
                                }
                                for agent in config.agents
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            async with RemotePolicyClient.open(path) as policies:
                assert policies.config.poll_interval_seconds == 300
                assert policies.config.request_timeout_seconds == 10
                snapshot = policies.get_policy("agent0")
                native = ActivatedPolicy.from_memory(
                    snapshot.manifest_yaml, snapshot.bundles()
                ).evaluate("pre_tool_call", context("agent0"))
                verdict = await policies.evaluate(
                    "agent0", "pre_tool_call", context("agent0")
                )
                assert isinstance(verdict, Verdict)
                assert verdict.to_wire() == native.to_wire()
                assert verdict.decision.value == "allow"
                assert await policies.refresh("agent0") is snapshot
                other = policies.get_policy("agent1")
                server.publish("agent0", limit=50)
                await policies.refresh("agent0")
                denied = await policies.evaluate(
                    "agent0", "pre_tool_call", context("agent0")
                )
                independent = await policies.evaluate(
                    "agent1", "pre_tool_call", context("agent1")
                )
                assert denied.decision.value == "deny"
                assert independent.decision.value == "allow"
                assert policies.get_policy("agent1") is other
                assert policies.status("agent0").revision == 2
            with pytest.raises(PolicyUnavailable):
                policies.get_policy("agent0")
            assert isinstance(policies._poller, PolicyPoller)
            assert not policies._poller._requests
            assert not policies._poller._flights

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "content",
    [b"\xff", b"x" * (MAX_YAML_BYTES + 1), b"remote_policy: {}\n", b"a: &a [*a]\n"],
    ids=["invalid-utf8", "oversized", "invalid-config", "yaml-alias"],
)
def test_yaml_file_boundaries_fail_before_network(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "remote-policies.yaml"
    path.write_bytes(content)

    async def scenario() -> None:
        with pytest.raises(PolicyValidationError):
            async with RemotePolicyClient.open(str(path)):
                pytest.fail("Invalid configuration must not start polling")

    asyncio.run(scenario())


def test_yaml_path_must_be_a_regular_file(tmp_path: Path) -> None:
    async def scenario() -> None:
        with pytest.raises(PolicyValidationError):
            async with RemotePolicyClient.open(tmp_path):
                pytest.fail("A directory is not a policy configuration")

    asyncio.run(scenario())


def test_nonregular_configuration_is_rejected_before_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*arguments: object, **options: object) -> int:
        pytest.fail("Nonregular configuration reached os.open")

    with monkeypatch.context() as scoped:
        scoped.setattr(client_module.os, "open", forbidden)
        with pytest.raises(PolicyValidationError):
            client_module._read_config(tmp_path)


def test_configuration_permission_errors_are_not_reclassified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text("remote_policy: {}", encoding="utf-8")

    def denied(*arguments: object, **options: object) -> int:
        raise PermissionError("Configuration read denied")

    with monkeypatch.context() as scoped:
        scoped.setattr(client_module.os, "open", denied)
        with pytest.raises(PermissionError, match="read denied"):
            client_module._read_config(path)


def test_registry_and_injected_credentials_are_mutually_exclusive() -> None:
    async def scenario() -> None:
        with pytest.raises(PolicyValidationError):
            async with RemotePolicyClient.open(
                configuration(1),
                registry=CredentialProviderRegistry({}),
                credentials={},
            ):
                pytest.fail("Ambiguous credential ownership must fail")

    asyncio.run(scenario())


@pytest.mark.parametrize("termination", ["normal", "error", "cancel", "startup"])
def test_client_owns_registry_source_and_poller_in_order(
    monkeypatch: pytest.MonkeyPatch, termination: str
) -> None:
    events: list[str] = []
    clock = FakeClock()
    config = replace(
        configuration(1),
        endpoint="https://policies.example.test",
        credential_ref="reader",
        credentials={"reader": CredentialConfig("custom")},
    )

    class Provider:
        async def authorization(self) -> str:
            return "Bearer unit-test-only"

    provider = Provider()

    @asynccontextmanager
    async def factory(
        options: Mapping[str, CredentialOption],
    ) -> AsyncGenerator[Credential, None]:
        assert not options
        events.append("credential-open")
        try:
            yield provider
        finally:
            events.append("credential-close")

    class Source(MemorySource):
        async def aclose(self) -> None:
            await super().aclose()
            events.append("source-close")

    source = Source(config)
    if termination == "startup":
        source.responses["agent0"] = PolicySourceError("authoritative", "forbidden")

    def make_source(
        selected: PollerConfig, credentials: Mapping[str, Credential]
    ) -> PolicySource:
        assert selected is config and credentials["reader"] is provider
        events.append("source-open")
        return source

    def make_poller(
        selected: PollerConfig, selected_source: PolicySource
    ) -> PolicyPoller:
        return PolicyPoller(selected, selected_source, clock=clock)

    monkeypatch.setattr(client_module.HttpPolicySource, "from_config", make_source)
    monkeypatch.setattr(client_module, "PolicyPoller", make_poller)
    primary = RuntimeError("application failed")

    async def scenario() -> None:
        registry = CredentialProviderRegistry({"custom": factory})
        try:
            async with RemotePolicyClient.open(config, registry=registry):
                events.append("body")
                if termination == "error":
                    raise primary
                if termination == "cancel":
                    raise asyncio.CancelledError("client cancellation")
        except RuntimeError as error:
            assert termination == "error" and error is primary
        except asyncio.CancelledError as error:
            assert termination == "cancel"
            assert str(error) == "client cancellation"
        except StartupError:
            assert termination == "startup"
        else:
            assert termination == "normal"
        assert source.closed
        assert registry.pending_task_count == 0
        assert events[-2:] == ["source-close", "credential-close"]
        assert events[:2] == ["credential-open", "source-open"]
        assert ("body" in events) is (termination != "startup")

    asyncio.run(scenario())


@pytest.mark.parametrize("change", ["revision", "expiry", "fence", "close"])
def test_client_checks_current_policy_after_awaited_evaluation(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock = FakeClock()
        source = MemorySource(config)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def held(
            snapshot: PolicySnapshot,
            point: str,
            selected: Mapping[str, JsonValue],
            *,
            timeout_seconds: float = 10,
        ) -> Verdict:
            assert snapshot.selection.agent_id == "agent0"
            assert point == "pre_tool_call" and selected and timeout_seconds == 10
            entered.set()
            await release.wait()
            return Verdict.from_wire({"decision": "allow"})

        monkeypatch.setattr(client_module, "evaluate_policy_snapshot", held)
        async with PolicyPoller(config, source, clock=clock) as poller:
            policies = RemotePolicyClient(poller)
            operation = asyncio.create_task(
                policies.evaluate("agent0", "pre_tool_call", context("agent0"))
            )
            await asyncio.wait_for(entered.wait(), 2)
            if change == "revision":
                source.responses["agent0"] = reply(
                    document(config.agents[0], revision=2)
                )
                await policies.refresh("agent0")
            elif change == "expiry":
                clock.advance(901)
            elif change == "fence":
                source.responses["agent0"] = PolicySourceError(
                    "authoritative", "forbidden"
                )
                with pytest.raises(PolicySourceError):
                    await policies.refresh("agent0")
            else:
                await poller.aclose()
            release.set()
            with pytest.raises(PolicyUnavailable):
                await operation

    asyncio.run(scenario())


def test_native_engine_error_stays_a_deny_verdict() -> None:
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
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            verdict = await RemotePolicyClient(poller).evaluate(
                "agent0", "pre_tool_call", context("agent0")
            )
            assert verdict.decision.value == "deny"
            assert (verdict.reason or "").startswith("runtime_error:")

    asyncio.run(scenario())


def test_client_freezes_host_context_and_rejects_parallel_admission(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        entered, release = asyncio.Event(), asyncio.Event()
        original = context("agent0")
        expected = json.dumps(original, sort_keys=True)

        async def held(
            snapshot: PolicySnapshot,
            point: str,
            selected: Mapping[str, JsonValue],
            *,
            timeout_seconds: float = 10,
        ) -> Verdict:
            entered.set()
            await release.wait()
            assert json.dumps(selected, sort_keys=True) == expected
            return Verdict.from_wire({"decision": "allow"})

        monkeypatch.setattr(client_module, "evaluate_policy_snapshot", held)
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            policies = RemotePolicyClient(poller)
            operation = asyncio.create_task(
                policies.evaluate("agent0", "pre_tool_call", original)
            )
            await asyncio.wait_for(entered.wait(), 2)
            original.clear()
            with pytest.raises(PolicyUnavailable, match="busy"):
                await policies.evaluate("agent0", "pre_tool_call", context("agent0"))
            busy = [
                record
                for record in caplog.records
                if record.getMessage().startswith("policy_worker_busy")
            ]
            assert [getattr(record, "agent_id", None) for record in busy] == ["agent0"]
            release.set()
            assert (await operation).decision.value == "allow"

    asyncio.run(scenario())


def test_client_exit_cancels_and_drains_its_real_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        created = asyncio.Event()
        processes: list[asyncio.subprocess.Process] = []
        actual_spawn = asyncio.create_subprocess_exec

        async def stalled(*args: str, **kwargs: object) -> asyncio.subprocess.Process:
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

        monkeypatch.setattr(asyncio, "create_subprocess_exec", stalled)
        with PolicyServer(config.agents) as server:
            server.publish("agent0", limit=100)
            local = replace(
                config, endpoint=server.endpoint, allow_insecure_localhost=True
            )
            async with RemotePolicyClient.open(local) as policies:
                operation = asyncio.create_task(
                    policies.evaluate("agent0", "pre_tool_call", context("agent0"))
                )
                await asyncio.wait_for(created.wait(), 3)
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert len(processes) == 1 and processes[0].returncode is not None
            assert policies._evaluation is None
            with pytest.raises(PolicyUnavailable):
                policies.get_policy("agent0")

    asyncio.run(scenario())


@pytest.mark.parametrize("startup_failure", [False, True])
@pytest.mark.parametrize("cancellations", [1, 3])
def test_cancellation_during_source_close_preserves_credential_ownership(
    monkeypatch: pytest.MonkeyPatch,
    startup_failure: bool,
    cancellations: int,
) -> None:
    async def scenario() -> None:
        config = replace(
            configuration(1),
            endpoint="https://policies.example.test",
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom")},
        )
        closing, release = asyncio.Event(), asyncio.Event()
        events: list[str] = []
        pollers: list[PolicyPoller] = []

        class Provider:
            async def authorization(self) -> str:
                return "Bearer test"

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield Provider()
            finally:
                events.append("credential-close")

        class Source(MemorySource):
            async def aclose(self) -> None:
                closing.set()
                await release.wait()
                await super().aclose()
                events.append("source-close")

        source = Source(config)
        if startup_failure:
            source.responses["agent0"] = PolicySourceError("authoritative", "forbidden")

        def make_source(
            selected: PollerConfig,
            credentials: Mapping[str, Credential],
        ) -> PolicySource:
            return source

        def make_poller(
            selected: PollerConfig,
            selected_source: PolicySource,
        ) -> PolicyPoller:
            poller = PolicyPoller(selected, selected_source, clock=FakeClock())
            pollers.append(poller)
            return poller

        monkeypatch.setattr(client_module.HttpPolicySource, "from_config", make_source)
        monkeypatch.setattr(client_module, "PolicyPoller", make_poller)
        registry = CredentialProviderRegistry({"custom": factory})

        async def owner() -> None:
            async with RemotePolicyClient.open(config, registry=registry):
                assert not startup_failure

        operation = asyncio.create_task(owner())
        await asyncio.wait_for(closing.wait(), 2)
        try:
            for _ in range(cancellations):
                operation.cancel("interrupted source shutdown")
                done, _ = await asyncio.wait({operation}, timeout=0.02)
                assert not done, "client exited before its source finished closing"
                assert events == [], "credentials closed while source remained active"
        finally:
            release.set()
            await asyncio.gather(operation, return_exceptions=True)
            await pollers[0].aclose()
        with pytest.raises(asyncio.CancelledError):
            operation.result()
        assert events == ["source-close", "credential-close"]
        assert registry.pending_task_count == 0
        assert source.closed and pollers[0]._closing is not None
        assert pollers[0]._closing.done()
        assert not any(
            task.get_name() == "acs-remote-policy-poller-close"
            for task in asyncio.all_tasks()
        )

    asyncio.run(scenario())
