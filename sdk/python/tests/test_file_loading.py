# Copyright (c) Microsoft. All rights reserved.
"""Unified activation preserves native local behavior and optional isolation."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
    ManifestInvalidError,
)
from agent_hooks import AgentContextBuilder, InterceptionBlocked, InterceptionEmitter

ROOT = Path(__file__).resolve().parents[3]
LOCAL = ROOT / "examples/python_composition/limits.yaml"


@pytest.mark.parametrize("amount", [40, 150, -1])
def test_local_activation_and_interceptor_preserve_full_verdict(amount: int) -> None:
    policy = ActivatedPolicy.activate(str(LOCAL))

    async def scenario() -> None:
        context = AgentContextBuilder(
            agent_id="example", framework="test", session_id="test"
        ).pre_tool_call(
            call_id="refund",
            name="issue_refund",
            args={"order_id": "example", "amount": amount},
        )
        native = policy.evaluate("pre_tool_call", context)
        async with AsyncAcsInterceptor(policy, "local-control") as control:
            assert (await control.intercept(context)).to_wire() == native.to_wire()
            # agent-hooks b2 annotates a sync protocol; its runtime awaits async.
            emitter = InterceptionEmitter().register(control, control.name)  # pyright: ignore[reportArgumentType]
            if amount < 0:
                with pytest.raises(InterceptionBlocked):
                    await emitter.emit(context)
            else:
                result = await emitter.emit(context)
                if amount > 100:
                    assert result.target == {"order_id": "example", "amount": 100}
        assert control.closed and control.in_flight == control.waiting == 0

    asyncio.run(scenario())


def test_relative_extends_remains_within_native_manifest_root(tmp_path: Path) -> None:
    base = tmp_path / "base.yaml"
    base.write_text(
        'agent_control_specification_version: "0.4.0-alpha.1"\n'
        "policies:\n  gate:\n    type: test\n"
        "    verdict: {decision: allow}\n"
        "intervention_points:\n  input:\n"
        "    policy_target: $.input\n    policy: {id: gate}\n",
        encoding="utf-8",
    )
    child = tmp_path / "child.yaml"
    child.write_text(
        'agent_control_specification_version: "0.4.0-alpha.1"\n'
        "extends:\n  - ./base.yaml\n",
        encoding="utf-8",
    )
    direct = ActivatedPolicy(str(child))
    policy = ActivatedPolicy.activate(str(child))
    context = AgentContextBuilder(
        agent_id="example", framework="test", session_id="s"
    ).input(content="local")
    assert (
        policy.evaluate("input", context).to_wire()
        == direct.evaluate("input", context).to_wire()
    )


@pytest.mark.parametrize("kind", ["local", "malformed", "remote"])
def test_core_only_consumer_and_missing_optional_hint(
    tmp_path: Path, kind: str
) -> None:
    path = LOCAL
    if kind != "local":
        path = tmp_path / "configuration.yaml"
        path.write_text(
            "invalid: [\n"
            if kind == "malformed"
            else "remote_policy:\n  agents:\n"
            "    - {agent_id: a, tenant_id: t, policy_id: p}\n",
            encoding="utf-8",
        )
    script = """
import asyncio
import importlib.abc
import sys

class CoreOnly(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "agent_control_spec_remote_policy":
            raise ModuleNotFoundError("optional package absent", name=fullname)
        return None

sys.meta_path.insert(0, CoreOnly())
from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor, ManifestInvalidError

async def run():
    try:
        policy = ActivatedPolicy.activate(sys.argv[1])
        async with AsyncAcsInterceptor(policy):
            assert sys.argv[2] == "local"
    except ManifestInvalidError as error:
        assert sys.argv[2] != "local"
        assert "agent-control-spec-remote-policy" in " ".join(error.__notes__)
    assert not any(name.startswith(("agent_control_spec_remote_policy", "httpx",
                                   "yaml", "azure")) for name in sys.modules)

asyncio.run(run())
"""
    subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), kind],
        check=True,
        capture_output=True,
        timeout=30,
    )


def test_native_activation_error_is_not_remote_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text(
        'agent_control_specification_version: "0.4.0-alpha.1"\n'
        "policies:\n  broken:\n    type: rego\n"
        "    bundle: ./missing.rego\n    query: data.gate.verdict\n"
        "intervention_points:\n  input:\n    policy: {id: broken}\n",
        encoding="utf-8",
    )

    def forbidden(source: str) -> None:
        pytest.fail("Local compiler failure reached remote classification")

    from agent_control_spec_remote_policy.poller import PollerConfig

    monkeypatch.setattr(PollerConfig, "from_yaml", forbidden)
    with pytest.raises((ValueError, RuntimeError)):
        ActivatedPolicy.activate(str(path))


@pytest.mark.parametrize("content", ["", "invalid: [", "remote_policy: {}"])
def test_invalid_configuration_preserves_native_error(
    tmp_path: Path, content: str
) -> None:
    from agent_control_spec import parse_manifest

    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ManifestInvalidError) as original:
        parse_manifest(content)
    with pytest.raises(ManifestInvalidError) as failure:
        ActivatedPolicy.activate(str(path))
    assert str(failure.value) == str(original.value)
