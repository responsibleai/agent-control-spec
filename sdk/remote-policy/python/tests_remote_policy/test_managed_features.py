# Copyright (c) Microsoft. All rights reserved.
"""Real managed custom factories, safe diagnostics and retained source ownership."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
    ManagedPolicyUsageError,
    RemotePolicyDependencyError,
)
from agent_control_spec_remote_policy import (
    PolicyPollerFactory,
    PolicyPollerProtocol,
    PolicySourceFactory,
    RemotePolicyClient,
    RemotePolicyFileLoader,
)
from agent_control_spec_remote_policy import client as client_module
from agent_control_spec_remote_policy import evaluation as evaluation_module
from agent_control_spec_remote_policy.auth import (
    Credential,
    CredentialProviderRegistry,
)
from agent_control_spec_remote_policy.poller import (
    CredentialConfig,
    CredentialOption,
    PolicyCloseError,
    PolicyPoller,
    PolicySource,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
    remote_configuration_note,
)
from agent_hooks import InterceptionEmitter

from examples.remote_policy.demo import managed_demo
from examples.remote_policy.server import PolicyServer

from .test_client import context
from .test_integration import write_config
from .test_remote_policy import (
    FakeClock,
    MemorySource,
    configuration,
)


@pytest.mark.parametrize("supported", [False, True])
def test_star_exports_respect_core_capability_in_fresh_process(supported: bool) -> None:
    probe = """
import sys
import agent_control_spec as core

supported = sys.argv[1] == "supported"
if not supported:
    delattr(core, "MANAGED_ACTIVATION_API_VERSION")

from agent_control_spec_remote_policy import *
import agent_control_spec_remote_policy as optional

assert RemotePolicyClient is optional.RemotePolicyClient
assert PolicyPoller is optional.PolicyPoller
assert ("RemotePolicyFileLoader" in optional.__all__) == supported
if supported:
    assert callable(optional.RemotePolicyFileLoader)
else:
    for access in (
        lambda: optional.RemotePolicyFileLoader,
        lambda: hasattr(optional, "RemotePolicyFileLoader"),
    ):
        try:
            access()
        except optional.PolicyUsageError as error:
            assert "managed activation API 1" in str(error)
        else:
            raise AssertionError("unsupported managed access must be actionable")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe, "supported" if supported else "old"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_host_custom_factories_keep_auth_independent_and_start_only_on_entry(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = replace(
            configuration(1),
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom", {"audience": "policy"})},
        )
        source = MemorySource(config)
        events: list[str] = []

        class CredentialImpl:
            async def authorization(self) -> str:
                return "Test unit-provider"

        credential = CredentialImpl()

        @asynccontextmanager
        async def provider(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            assert options == {"audience": "policy"}
            events.append("credential-open")
            try:
                yield credential
            finally:
                events.append("credential-close")

        def make_source(
            selected: PollerConfig, credentials: Mapping[str, Credential]
        ) -> PolicySource:
            assert selected == config
            assert credentials["reader"] is credential
            assert isinstance(credentials, MappingProxyType)
            events.append("source")
            return source

        class CustomerPoller(PolicyPoller):
            """Customer construction can capture configuration without new YAML imports."""

        def make_poller(
            selected: PollerConfig, selected_source: PolicySource
        ) -> PolicyPollerProtocol:
            events.append("poller")
            return CustomerPoller(selected, selected_source, clock=FakeClock())

        source_factory: PolicySourceFactory = make_source
        poller_factory: PolicyPollerFactory = make_poller
        loader = RemotePolicyFileLoader(
            registry=CredentialProviderRegistry({"custom": provider}),
            source_factory=source_factory,
            poller_factory=poller_factory,
        )
        policy = ActivatedPolicy.activate(
            str(write_config(tmp_path, config)), remote_loader=loader
        )
        control = AsyncAcsInterceptor(policy)
        assert events == [] and source.calls == []
        async with control:
            assert events == ["credential-open", "source", "poller"]
            assert (
                await control.intercept(context("agent0"))
            ).decision.value == "allow"
        assert source.closed and events[-1] == "credential-close"

    asyncio.run(scenario())


def test_poller_factory_failure_bounds_source_close_and_retains_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        config = replace(
            configuration(1),
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom")},
        )
        closing, release, credentials_closed = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        events: list[str] = []

        class CredentialImpl:
            async def authorization(self) -> str:
                return "Test unit-provider"

        @asynccontextmanager
        async def provider(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield CredentialImpl()
            finally:
                events.append("credential-close")
                credentials_closed.set()

        class Source(MemorySource):
            async def aclose(self) -> None:
                events.append("source-closing")
                closing.set()
                await release.wait()
                await super().aclose()
                events.append("source-closed")

        source = Source(config)
        registry = CredentialProviderRegistry({"custom": provider})

        def make_source(
            selected: PollerConfig, credentials: Mapping[str, Credential]
        ) -> PolicySource:
            return source

        def fail_poller(
            selected: PollerConfig, selected_source: PolicySource
        ) -> PolicyPollerProtocol:
            raise RuntimeError("test-owned factory failure")

        monkeypatch.setattr(client_module, "_SOURCE_CLOSE_TIMEOUT", 0.02)

        async def enter() -> None:
            async with RemotePolicyClient.open(
                config,
                registry=registry,
                source_factory=make_source,
                poller_factory=fail_poller,
            ):
                pytest.fail("failed constructor cannot yield")

        operation = asyncio.create_task(enter())
        await asyncio.wait_for(closing.wait(), 2)
        with pytest.raises(PolicyCloseError) as failure:
            await asyncio.wait_for(operation, 2)
        assert failure.value.retained_tasks == 1
        assert events == ["source-closing"] and registry.pending_task_count == 1
        owners = [
            task
            for task in asyncio.all_tasks()
            if task.get_name() == "acs-remote-policy-client-owner"
        ]
        assert len(owners) == 1
        try:
            with pytest.raises(PolicyUsageError):
                async with registry.open(config):
                    pytest.fail("retained credentials cannot be reentered")
        finally:
            release.set()
            outcomes = await asyncio.wait_for(
                asyncio.gather(*owners, return_exceptions=True), 2
            )
            assert all(isinstance(result, PolicyCloseError) for result in outcomes)
        assert credentials_closed.is_set()
        assert events == ["source-closing", "source-closed", "credential-close"]
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["interval", "endpoint", "credentials"])
@pytest.mark.parametrize("injected", [False, True])
def test_remote_validation_has_safe_note_without_startup(
    tmp_path: Path, field: str, injected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    config: dict[str, object] = {
        "agents": [{"agent_id": "a", "tenant_id": "t", "policy_id": "p"}]
    }
    secret = "sensitive-test-setting"
    if field == "interval":
        config["poll_interval_seconds"] = 0
    elif field == "endpoint":
        config["endpoint"] = "ftp://" + secret + ".example"
    else:
        config["credentials"] = {
            "reader": {"provider": "custom", "options": {"x": [secret]}}
        }
    path = tmp_path / "remote.yaml"
    path.write_text(json.dumps({"remote_policy": config}), encoding="utf-8")

    def forbidden(*args: object) -> PolicySource:
        pytest.fail("invalid configuration started resources")

    monkeypatch.setattr(client_module.HttpPolicySource, "from_config", forbidden)
    with pytest.raises(ValueError) as failure:
        ActivatedPolicy.activate(
            str(path), remote_loader=RemotePolicyFileLoader() if injected else None
        )
    assert type(failure.value) is ValueError  # The native error with a safe note.
    notes = " ".join(failure.value.__notes__)
    assert "code=config" in notes and "path=remote_policy" in notes
    assert secret not in str(failure.value) + notes


@pytest.mark.parametrize("scalar", ["2024-02-30", "2024-13-01", "2024-01-01T25:00:00Z"])
def test_unconstructable_yaml_scalars_never_mask_the_native_error(
    tmp_path: Path, scalar: str
) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        'agent_control_specification_version: "0.4.0-alpha.1"\n'
        f"metadata: {{created: {scalar}}}\npolices: {{}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as native:
        ActivatedPolicy(str(path))
    with pytest.raises(ValueError) as unified:
        ActivatedPolicy.activate(str(path))
    assert type(unified.value) is type(native.value)
    assert str(unified.value) == str(native.value)


@pytest.mark.parametrize("scalar", ["2024-02-30", "2024-13-01"])
def test_remote_configuration_parsers_reject_bad_scalars_with_typed_errors(
    scalar: str,
) -> None:
    text = f"remote_policy: {{agents: [], created: {scalar}}}\n"
    with pytest.raises(PolicyValidationError):
        PollerConfig.from_yaml(text)
    assert remote_configuration_note(text) is None


def test_remote_activation_with_native_options_has_no_native_side_effects(
    tmp_path: Path,
) -> None:
    path = write_config(tmp_path, configuration(1))
    events: list[object] = []
    with pytest.raises(ManagedPolicyUsageError):
        ActivatedPolicy.activate(str(path), telemetry_sink=events.append)
    assert events == []  # The native-first attempt emitted nothing before routing.


_VALID_AGENTS = "  agents:\n    - {agent_id: a, tenant_id: t, policy_id: p}\n"


def _oversized_number_config(field: str) -> str:
    return (
        f"remote_policy:\n{_VALID_AGENTS}"
        f"  endpoint: https://policies.example.test\n  {field}: {'9' * 400}\n"
    )


@pytest.mark.parametrize("field", ["poll_interval_seconds", "request_timeout_seconds"])
def test_integers_beyond_float_range_are_typed_validation_errors(field: str) -> None:
    with pytest.raises(PolicyValidationError):
        PollerConfig.from_yaml(_oversized_number_config(field))


@pytest.mark.parametrize("field", ["poll_interval_seconds", "request_timeout_seconds"])
@pytest.mark.parametrize("injected", [False, True])
def test_oversized_numbers_never_mask_the_native_error(
    tmp_path: Path, field: str, injected: bool
) -> None:
    path = tmp_path / "remote.yaml"
    path.write_text(_oversized_number_config(field), encoding="utf-8")
    with pytest.raises(ValueError) as native:
        ActivatedPolicy(str(path))
    with pytest.raises(ValueError) as unified:
        ActivatedPolicy.activate(
            str(path), remote_loader=RemotePolicyFileLoader() if injected else None
        )
    assert type(unified.value) is type(native.value)
    assert str(unified.value) == str(native.value)


def test_new_core_rejects_missing_optional_managed_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_control_spec_remote_policy as optional

    path = write_config(tmp_path, configuration(1))
    monkeypatch.delattr(optional, "MANAGED_ACTIVATION_API_VERSION")
    with pytest.raises(RemotePolicyDependencyError, match="managed activation API 1"):
        ActivatedPolicy.activate(str(path))


def test_managed_demo_uses_real_http_emitter_and_native_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        config = configuration()
        with PolicyServer(config.agents) as server:
            server.publish("agent0", limit=100)
            server.publish("agent1", limit=50)
            path = write_config(
                tmp_path,
                replace(
                    config, endpoint=server.endpoint, allow_insecure_localhost=True
                ),
            )
            await managed_demo(path, ("agent0", "agent1"))

    asyncio.run(scenario())
    output = capsys.readouterr().out
    assert "agent0: decision=allow" in output
    assert "agent1: decision=deny" in output
    assert "executed inert refunds: 1" in output


def test_process_wide_worker_saturation_is_an_explicit_emitter_denial(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = configuration(1)

        def source_factory(
            selected: PollerConfig, credentials: Mapping[str, Credential]
        ) -> PolicySource:
            return MemorySource(selected)

        def poller_factory(
            selected: PollerConfig, source: PolicySource
        ) -> PolicyPollerProtocol:
            return PolicyPoller(selected, source, clock=FakeClock())

        policy = ActivatedPolicy.activate(
            str(write_config(tmp_path, config)),
            remote_loader=RemotePolicyFileLoader(
                source_factory=source_factory, poller_factory=poller_factory
            ),
        )
        async with AsyncAcsInterceptor(policy) as control:
            # Reserve the same process-wide admission used by real worker tests.
            slot = evaluation_module._WorkerSlot()
            try:
                # agent-hooks b2 annotates sync Interceptor, supports async at runtime.
                emitter = InterceptionEmitter().register(control)  # pyright: ignore[reportArgumentType]
                record = await emitter.emit_unchecked(context("agent0"))
                assert record.verdict.decision.value == "deny"
                assert (
                    record.verdict.reason == "runtime_error:acs_async_capacity_exceeded"
                )
            finally:
                slot.release()
            assert (
                await control.intercept(context("agent0"))
            ).decision.value == "allow"

    asyncio.run(scenario())
