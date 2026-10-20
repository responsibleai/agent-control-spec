# Copyright (c) Microsoft. All rights reserved.
"""Real agent-hooks consumers of the unified local/remote factory."""
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

import httpx
import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
)
from agent_control_spec_remote_policy import RemotePolicyFileLoader
from agent_control_spec_remote_policy import client as client_module
from agent_control_spec_remote_policy.auth import (
    Credential,
    CredentialOption,
    CredentialProviderRegistry,
)
from agent_control_spec_remote_policy.azure import azure_credential_factories
from agent_control_spec_remote_policy.http import HttpPolicySource
from agent_control_spec_remote_policy.poller import (
    CredentialConfig,
    JsonValue,
    PolicyError,
    PolicyPoller,
    PolicySource,
    PolicySourceError,
    PolicyValidationError,
    PollerConfig,
    validate_acs_artifacts,
)
from agent_hooks import AgentContextBuilder, InterceptionBlocked, InterceptionEmitter

from examples.remote_policy.server import PolicyServer

from .test_client import context
from .test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
    document,
    reply,
)
from .test_remote_policy_http import (
    AzureCredential,
    HmacAuthenticator,
)


def write_config(tmp_path: Path, config: PollerConfig) -> Path:
    path = tmp_path / "configuration.yaml"
    path.write_text(
        json.dumps(
            {
                "remote_policy": {
                    "endpoint": config.endpoint,
                    "allow_insecure_localhost": config.allow_insecure_localhost,
                    "credential_ref": config.credential_ref,
                    "poll_interval_seconds": config.poll_interval_seconds,
                    "request_timeout_seconds": config.request_timeout_seconds,
                    "credentials": {
                        key: {
                            "provider": value.provider,
                            "options": dict(value.options),
                        }
                        for key, value in config.credentials.items()
                    },
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
    return path


def memory_backend(
    monkeypatch: pytest.MonkeyPatch,
    config: PollerConfig,
    source: MemorySource,
    clock: FakeClock,
) -> list[PolicyPoller]:
    pollers: list[PolicyPoller] = []

    def make_source(
        selected: PollerConfig, credentials: Mapping[str, Credential]
    ) -> PolicySource:
        assert selected.agents == config.agents
        return source

    def make_poller(
        selected: PollerConfig, selected_source: PolicySource
    ) -> PolicyPoller:
        poller = PolicyPoller(selected, selected_source, clock=clock)
        pollers.append(poller)
        return poller

    monkeypatch.setattr(client_module.HttpPolicySource, "from_config", make_source)
    monkeypatch.setattr(client_module, "PolicyPoller", make_poller)
    return pollers


def test_yaml_factory_real_http_emitter_and_per_agent_selection(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = configuration()
        with PolicyServer(config.agents) as server:
            server.publish("agent0", limit=50)
            server.publish("agent1", limit=100)
            path = write_config(
                tmp_path,
                replace(
                    config, endpoint=server.endpoint, allow_insecure_localhost=True
                ),
            )
            policy = ActivatedPolicy.activate(str(path))
            async with AsyncAcsInterceptor(policy, "remote-control") as control:
                assert type(control) is AsyncAcsInterceptor
                emitter = InterceptionEmitter(timeout=15).register(
                    # agent-hooks b2 annotates sync Interceptor; runtime awaits it.
                    control,  # pyright: ignore[reportArgumentType]
                    control.name,  # pyright: ignore[reportArgumentType]
                )
                with pytest.raises(InterceptionBlocked) as blocked:
                    await emitter.emit(context("agent0"))
                assert blocked.value.result.verdict.reason == "over_limit"
                allowed = await emitter.emit(context("agent1"))
                assert allowed.record.verdicts[0].reason == "within_limit"
                assert allowed.target == {
                    "order_id": "example-order",
                    "amount": 75,
                }
                for identity in ("unknown", ""):
                    record = await emitter.emit_unchecked(context(identity))
                    assert record.verdict.decision.value == "deny"
                unbound = await emitter.emit_unchecked(
                    AgentContextBuilder(
                        agent_id="agent1", framework="test", session_id="s"
                    ).input(content="strict")
                )
                assert unbound.verdict.decision.value == "deny"
            assert control.closed and control.in_flight == control.waiting == 0
            assert (await control.intercept(context("agent1"))).reason == (
                "runtime_error:acs_async_closed"
            )

    asyncio.run(scenario())


@pytest.mark.parametrize("provider", ["customer_signer", "azure_cli"])
def test_configured_auth_scheduled_refresh_and_path_only_local_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    """Exercise extension wiring, not a real AWS signature or cloud deployment."""
    import azure.identity.aio

    async def scenario() -> None:
        config = replace(
            configuration(1, interval=5, timeout=2),
            endpoint="https://policies.example.test/base",
            credential_ref="reader",
            credentials={
                "reader": CredentialConfig(
                    provider,
                    {"region": "us-east-1", "service": "execute-api"}
                    if provider == "customer_signer"
                    else {
                        "scope": "api://policy/.default",
                        "process_timeout_seconds": 1,
                    },
                )
            },
        )
        signer, azure_credential = HmacAuthenticator(), AzureCredential()
        opened: list[str] = []
        closed: list[str] = []

        @asynccontextmanager
        async def customer_factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            assert options == {"region": "us-east-1", "service": "execute-api"}
            opened.append("customer_signer")
            try:
                yield signer
            finally:
                closed.append("customer_signer")

        def azure_factory(*, process_timeout: int) -> AzureCredential:
            assert process_timeout == 1
            opened.append("azure_cli")
            return azure_credential

        monkeypatch.setattr(azure.identity.aio, "AzureCliCredential", azure_factory)
        registry = CredentialProviderRegistry(
            {**azure_credential_factories(), "customer_signer": customer_factory}
        )
        payload = document(config.agents[0])
        manifest = payload["manifest"]
        assert isinstance(manifest, str)
        bundles = validate_acs_artifacts(manifest, payload["bundles"])
        local_path = tmp_path / "local-policy.yaml"
        local_path.write_text(
            manifest.replace("type: rego\n", "type: rego\n    bundle: ./limits.rego\n"),
            encoding="utf-8",
        )
        (tmp_path / "limits.rego").write_text(
            bundles["gate"]["modules"]["limits.rego"], encoding="utf-8"
        )
        envelope = reply(payload)
        initial_etag = envelope.etag
        observed: list[httpx.Request] = []
        request_times: list[float] = []
        sources: list[HttpPolicySource] = []
        pollers: list[PolicyPoller] = []
        installed = asyncio.Event()
        loop = asyncio.get_running_loop()

        def transport(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == (
                "https://policies.example.test/base/v1/tenants/demo-tenant/policies/policy0"
            )
            assert request.headers["authorization"].startswith(
                "HMAC Signature=" if provider == "customer_signer" else "Bearer "
            )
            observed.append(request)
            request_times.append(loop.time())
            return httpx.Response(
                200,
                content=envelope.body,
                headers={"Content-Type": "application/json", "ETag": envelope.etag},
            )

        def make_source(
            selected: PollerConfig, credentials: Mapping[str, Credential]
        ) -> PolicySource:
            assert selected == config
            assert selected.endpoint is not None
            source = HttpPolicySource(
                selected.endpoint,
                credentials["reader"],
                request_timeout_seconds=selected.request_timeout_seconds,
                transport=httpx.MockTransport(transport),
            )
            source._client.headers["X-Correlation-ID"] = "host-owned"
            sources.append(source)
            return source

        class ObservedPoller(PolicyPoller):
            async def _refresh_all(
                self, agents: tuple[str, ...] | None = None
            ) -> dict[str, PolicyError]:
                failures = await super()._refresh_all(agents)
                if self.status("agent0").revision == 2:
                    installed.set()
                return failures

        def make_poller(selected: PollerConfig, source: PolicySource) -> PolicyPoller:
            poller = ObservedPoller(selected, source, clock=FakeClock())
            pollers.append(poller)
            return poller

        loader = RemotePolicyFileLoader(
            registry=registry,
            source_factory=make_source,
            poller_factory=make_poller,
        )

        def activate(path: Path) -> AsyncAcsInterceptor:
            return AsyncAcsInterceptor(
                ActivatedPolicy.activate(str(path), remote_loader=loader)
            )

        remote = activate(write_config(tmp_path, config))
        assert not opened and not sources and not pollers
        async with remote:
            emitter = InterceptionEmitter(timeout=15).register(remote)  # pyright: ignore[reportArgumentType]
            assert (await emitter.emit(context("agent0"))).target["amount"] == 75
            assert len(observed) == 1  # Evaluation made no policy API call.
            payload["revision"] = 2
            payload["bundles"] = {
                "gate": {
                    "modules": {
                        "limits.rego": bundles["gate"]["modules"][
                            "limits.rego"
                        ].replace("<= 100", "<= 50")
                    }
                }
            }
            envelope = reply(payload)
            await asyncio.wait_for(installed.wait(), 15)
            assert request_times[1] - request_times[0] >= 5
            assert observed[1].headers["if-none-match"] == initial_etag
            assert pollers[0].get_policy("agent0").revision == 2
            with pytest.raises(InterceptionBlocked) as blocked:
                await emitter.emit(context("agent0"))
            assert blocked.value.result.verdict.reason == "over_limit"
            assert len(observed) == 2
        assert opened == [provider] and len(sources) == len(pollers) == 1
        if provider == "customer_signer":
            assert len(signer.requests) == 2 and closed == ["customer_signer"]
            assert not azure_credential.closed
        else:
            assert azure_credential.scopes == ("api://policy/.default",)
            assert azure_credential.closed
            assert not signer.requests and not closed

        async with activate(local_path) as local:
            emitter = InterceptionEmitter(timeout=15).register(local)  # pyright: ignore[reportArgumentType]
            assert (await emitter.emit(context("agent0"))).target["amount"] == 75
            with pytest.raises(InterceptionBlocked) as blocked:
                await emitter.emit(context("agent0", 150))
            assert blocked.value.result.verdict.reason == "over_limit"
        assert opened == [provider] and len(sources) == len(pollers) == 1
        assert len(observed) == 2
        assert sources[0]._client.is_closed and registry.pending_task_count == 0
        assert pollers[0]._scheduler is not None and pollers[0]._scheduler.done()
        assert not pollers[0]._requests and not pollers[0]._flights

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["transform", "engine_error"])
def test_full_native_verdict_and_enforced_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock, source = FakeClock(), MemorySource(config)
        payload = document(config.agents[0])
        if mode == "transform":
            payload["bundles"] = {
                "gate": {
                    "modules": {
                        "limits.rego": "package refund_limits\nverdict := {"
                        '"decision":"transform","reason":"cap",'
                        '"transform":{"path":"$target.amount","value":50}}'
                    }
                }
            }
        else:
            manifest = payload["manifest"]
            assert isinstance(manifest, str)
            payload["manifest"] = manifest.replace(
                "data.refund_limits.verdict", "data.refund_limits.missing"
            )
        source.responses["agent0"] = reply(payload)
        pollers = memory_backend(monkeypatch, config, source, clock)
        path = write_config(tmp_path, config)
        policy = ActivatedPolicy.activate(str(path))
        async with AsyncAcsInterceptor(policy) as control:
            snapshot = pollers[0].get_policy("agent0")
            # This fixture is trusted test-owned policy, not arbitrary remote Rego.
            native = ActivatedPolicy.from_memory(
                snapshot.manifest_yaml, snapshot.bundles()
            ).evaluate("pre_tool_call", context("agent0"))
            assert (
                await control.intercept(context("agent0"))
            ).to_wire() == native.to_wire()
            # agent-hooks b2's sync annotation does not describe its async runtime.
            emitter = InterceptionEmitter(timeout=15).register(control)  # pyright: ignore[reportArgumentType]
            if mode == "transform":
                outcome = await emitter.emit(context("agent0"))
                assert outcome.target == {"order_id": "example-order", "amount": 50}
            else:
                with pytest.raises(InterceptionBlocked) as blocked:
                    await emitter.emit(context("agent0"))
                assert (blocked.value.result.verdict.reason or "").startswith(
                    "runtime_error:"
                )
        assert source.closed

    asyncio.run(scenario())


@pytest.mark.parametrize("agent", [None, "agent0", {}, {"id": 1}, {"id": "other"}])
def test_malformed_identity_cannot_select_another_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: object
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock, source = FakeClock(), MemorySource(config)
        memory_backend(monkeypatch, config, source, clock)
        policy = ActivatedPolicy.activate(str(write_config(tmp_path, config)))
        async with AsyncAcsInterceptor(policy) as control:
            invalid: dict[str, object] = dict(context("agent0"))
            invalid["agent"] = agent
            with pytest.raises(PolicyValidationError, match="scope"):
                await control.intercept(invalid)
            assert control.in_flight == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("injected_loader", [False, True])
def test_yaml_alone_never_sends_a_credential_to_its_chosen_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, injected_loader: bool
) -> None:
    """No host registration means no credential factory, token or request."""
    import agent_control_spec_remote_policy.azure as azure_module

    def forbidden() -> object:
        pytest.fail("the default registry loaded the Azure factory")

    sent: list[httpx.Request] = []

    async def record(
        self: httpx.AsyncClient, request: httpx.Request, **options: object
    ) -> httpx.Response:
        sent.append(request)
        raise AssertionError("a request left the host")

    monkeypatch.setattr(azure_module, "azure_credential_factories", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "send", record)
    config = replace(
        configuration(1),
        endpoint="https://attacker.example.test",
        credential_ref="reader",
        credentials={
            "reader": CredentialConfig("azure_cli", {"scope": "api://victim/.default"})
        },
    )
    path = write_config(tmp_path, config)

    async def scenario() -> None:
        policy = (
            ActivatedPolicy.activate(str(path), remote_loader=RemotePolicyFileLoader())
            if injected_loader
            else ActivatedPolicy.activate(str(path))
        )
        with pytest.raises(PolicyValidationError, match="config"):
            async with AsyncAcsInterceptor(policy):
                pytest.fail("YAML alone opened a credentialed source")

    asyncio.run(scenario())
    assert sent == []


@pytest.mark.parametrize(
    "content",
    [
        'agent_control_specification_version: "0.4.0-alpha.1"\nremote_policy: {}\n',
        "remote_policy: {agents: []}\n",
        "remote_policy: {agents: [], agents: []}\n",
        "remote_policy: &r {agents: []}\n",
        "remote_policy: {}\n---\nremote_policy: {}\n",
        "remote_policy:\n  import: forbidden.module\n",
    ],
)
def test_invalid_or_mixed_root_never_opens_a_loader(
    tmp_path: Path, content: str
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError) as native:
        ActivatedPolicy(str(path))

    async def scenario() -> None:
        with pytest.raises(ValueError) as failure:
            policy = ActivatedPolicy.activate(str(path))
            async with AsyncAcsInterceptor(policy):
                pytest.fail("Invalid YAML yielded a control")
        assert type(failure.value) is type(native.value)
        assert str(failure.value) == str(native.value)

    asyncio.run(scenario())


@pytest.mark.parametrize("change", ["revision", "expiry", "fence", "close"])
def test_emitter_blocks_a_result_when_current_policy_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock, source = FakeClock(), MemorySource(config)
        pollers = memory_backend(monkeypatch, config, source, clock)
        entered, release = asyncio.Event(), asyncio.Event()
        original = client_module.evaluate_policy_snapshot

        async def held(
            snapshot: client_module.PolicySnapshot,
            point: str,
            selected: Mapping[str, JsonValue],
            *,
            timeout_seconds: float = 10,
        ) -> client_module.Verdict:
            # Run the real native producer, then force a refresh/fence before
            # the client's final gate. A producer mock alone is insufficient.
            verdict = await original(
                snapshot, point, selected, timeout_seconds=timeout_seconds
            )
            entered.set()
            await release.wait()
            return verdict

        monkeypatch.setattr(client_module, "evaluate_policy_snapshot", held)
        policy = ActivatedPolicy.activate(str(write_config(tmp_path, config)))
        async with AsyncAcsInterceptor(policy) as control:
            # agent-hooks b2 has a sync-only registration annotation.
            emitter = InterceptionEmitter(timeout=15).register(control)  # pyright: ignore[reportArgumentType]
            operation = asyncio.create_task(emitter.emit_unchecked(context("agent0")))
            await asyncio.wait_for(entered.wait(), 10)
            try:
                poller = pollers[0]
                assert poller.config.poll_interval_seconds == 300
                retained = poller.get_policy("agent0")
                assert await poller.refresh("agent0") is retained  # strong ETag reuse
                if change == "revision":
                    source.responses["agent0"] = reply(
                        document(config.agents[0], revision=2)
                    )
                    await poller.refresh("agent0")
                elif change == "expiry":
                    clock.advance(901)
                elif change == "fence":
                    source.responses["agent0"] = PolicySourceError(
                        "authoritative", "forbidden"
                    )
                    with pytest.raises(PolicySourceError):
                        await poller.refresh("agent0")
                else:
                    await poller.aclose()
            finally:
                release.set()
            record = await operation
            assert record.verdict.decision.value == "deny"
            assert record.verdict.reason == "host_error:interceptor_failed"
        assert source.closed

    asyncio.run(scenario())


@pytest.mark.parametrize("startup_failure", [False, True])
def test_factory_preserves_registry_close_order_under_repeated_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, startup_failure: bool
) -> None:
    async def scenario() -> None:
        from agent_control_spec_remote_policy import CredentialConfig

        config = replace(
            configuration(1),
            endpoint="https://policies.example.test",
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom")},
        )
        clock = FakeClock()
        closing, release = asyncio.Event(), asyncio.Event()
        events: list[str] = []

        class Provider:
            async def authorization(self) -> str:
                return "******"

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
        pollers = memory_backend(monkeypatch, config, source, clock)
        registry = CredentialProviderRegistry({"custom": factory})
        loader = RemotePolicyFileLoader(registry=registry)

        async def owner() -> None:
            policy = ActivatedPolicy.activate(
                str(write_config(tmp_path, config)), remote_loader=loader
            )
            async with AsyncAcsInterceptor(policy):
                assert not startup_failure

        operation = asyncio.create_task(owner())
        await asyncio.wait_for(closing.wait(), 3)
        try:
            for _ in range(3):
                operation.cancel()
                acknowledged = asyncio.Event()
                asyncio.get_running_loop().call_soon(acknowledged.set)
                await acknowledged.wait()
                assert not operation.done()
                assert events == []
        finally:
            release.set()
            await asyncio.gather(operation, return_exceptions=True)
        assert operation.cancelled()
        assert events == ["source-close", "credential-close"]
        assert registry.pending_task_count == 0 and source.closed
        assert pollers[0]._closing is not None and pollers[0]._closing.done()

    asyncio.run(scenario())


def test_factory_close_kills_and_drains_real_remote_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        memory_backend(monkeypatch, config, source, FakeClock())
        created = asyncio.Event()
        processes: list[asyncio.subprocess.Process] = []
        original = asyncio.create_subprocess_exec

        async def stalled(*args: str, **kwargs: object) -> asyncio.subprocess.Process:
            process = await original(
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
        policy = ActivatedPolicy.activate(str(write_config(tmp_path, config)))
        async with AsyncAcsInterceptor(policy) as control:
            # agent-hooks b2 has a sync-only registration annotation.
            emitter = InterceptionEmitter(timeout=15).register(control)  # pyright: ignore[reportArgumentType]
            operation = asyncio.create_task(emitter.emit_unchecked(context("agent0")))
            await asyncio.wait_for(created.wait(), 3)
            saturated = await emitter.emit_unchecked(context("agent0"))
            assert (
                saturated.verdict.reason == "runtime_error:acs_async_capacity_exceeded"
            )
        record = await operation
        assert record.verdict.decision.value == "deny"
        assert record.verdict.reason == "runtime_error:acs_async_closed"
        assert len(processes) == 1 and processes[0].returncode is not None
        assert source.closed and control.in_flight == 0
        assert not any(
            task.get_name().startswith("acs-remote-policy")
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task()
        )

    asyncio.run(scenario())
