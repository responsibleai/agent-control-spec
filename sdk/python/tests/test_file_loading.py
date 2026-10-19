# Copyright (c) Microsoft. All rights reserved.
"""Unified activation preserves native local behavior and optional isolation."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from agent_control_spec import (
    ActivatedPolicy,
    AsyncAcsInterceptor,
)
from agent_hooks import AgentContextBuilder, InterceptionBlocked, InterceptionEmitter

ROOT = Path(__file__).resolve().parents[3]
LOCAL = ROOT / "examples/python_composition/limits.yaml"
VALID_MANIFEST = (
    'agent_control_specification_version: "0.4.0-alpha.1"\n'
    "policies:\n  gate:\n    type: test\n    verdict: {decision: allow}\n"
    "intervention_points:\n  input:\n    policy_target: $.input\n    policy: {id: gate}\n"
)


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
from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor

async def run():
    try:
        policy = ActivatedPolicy.activate(sys.argv[1])
        async with AsyncAcsInterceptor(policy):
            assert sys.argv[2] == "local"
    except ValueError as error:
        assert sys.argv[2] != "local"
        assert type(error) is ValueError  # the native error, not a wrapper
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

    poller = pytest.importorskip("agent_control_spec_remote_policy.poller")
    monkeypatch.setattr(poller.PollerConfig, "from_yaml", forbidden)
    with pytest.raises((ValueError, RuntimeError)):
        ActivatedPolicy.activate(str(path))


@pytest.mark.parametrize("content", ["", "invalid: [", "remote_policy: {}"])
def test_invalid_configuration_preserves_native_error(
    tmp_path: Path, content: str
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError) as native:
        ActivatedPolicy(str(path))
    with pytest.raises(ValueError) as failure:
        ActivatedPolicy.activate(str(path))
    assert type(failure.value) is type(native.value)
    assert str(failure.value) == str(native.value)


def _unusable_local_path(kind: str, tmp_path: Path) -> Path:
    path = tmp_path / ("manifest.json" if kind.endswith("_json") else "manifest.yaml")
    if kind == "typo":
        path.write_text(VALID_MANIFEST + "polices: {}\n", encoding="utf-8")
    elif kind == "unclosed_flow":
        path.write_text("invalid: [\n", encoding="utf-8")
    elif kind == "empty":
        path.write_text("", encoding="utf-8")
    elif kind == "trailing_comma_json":
        path.write_text(
            '{"agent_control_specification_version": "0.4.0-alpha.1",}',
            encoding="utf-8",
        )
    elif kind == "huge_number_json":
        path.write_text(
            '{"agent_control_specification_version": "0.4.0-alpha.1", "n": 1e99999}',
            encoding="utf-8",
        )
    elif kind == "non_utf8":
        path.write_bytes(b"\xff\xfe\x00not utf-8")
    elif kind == "directory":
        return tmp_path
    elif kind != "missing":
        raise AssertionError(kind)
    return path


@pytest.mark.parametrize(
    "kind",
    [
        "typo",
        "unclosed_flow",
        "empty",
        "trailing_comma_json",
        "huge_number_json",
        "non_utf8",
        "missing",
        "directory",
    ],
)
def test_activate_raises_the_native_error_for_unusable_local_paths(
    tmp_path: Path, kind: str
) -> None:
    path = _unusable_local_path(kind, tmp_path)
    with pytest.raises(ValueError) as native:
        ActivatedPolicy(str(path))
    with pytest.raises(ValueError) as unified:
        ActivatedPolicy.activate(str(path))
    assert type(unified.value) is type(native.value)
    assert str(unified.value) == str(native.value)


def test_json_manifest_with_a_duplicate_key_still_activates(tmp_path: Path) -> None:
    manifest = {
        "agent_control_specification_version": "0.4.0-alpha.1",
        "policies": {"gate": {"type": "test", "verdict": {"decision": "allow"}}},
        "intervention_points": {
            "input": {"policy_target": "$.input", "policy": {"id": "gate"}}
        },
    }
    text = json.dumps(manifest).replace(
        '"gate": {',
        '"gate": {"type": "test", "verdict": {"decision": "deny"}}, "gate": {',
        1,
    )
    path = tmp_path / "manifest.json"
    path.write_text(text, encoding="utf-8")
    native = ActivatedPolicy(str(path))  # The native loader keeps the last key.
    unified = ActivatedPolicy.activate(str(path))
    assert unified.intervention_points == native.intervention_points == ("input",)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes")
def test_named_pipe_manifest_is_read_once_by_native_activation(tmp_path: Path) -> None:
    pipe = tmp_path / "manifest.yaml"
    os.mkfifo(pipe)

    def feed() -> None:
        with open(pipe, "w", encoding="utf-8") as writer:
            writer.write(VALID_MANIFEST)

    feeder = threading.Thread(target=feed, name="acs-test-manifest-pipe", daemon=True)
    feeder.start()
    policy = ActivatedPolicy.activate(str(pipe))
    feeder.join(10)
    assert not feeder.is_alive()
    assert policy.intervention_points == ("input",)


def test_classification_never_opens_a_directory_or_special_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_control_spec import loading

    def forbidden(*arguments: object, **options: object) -> int:
        raise AssertionError("Classification opened a non-regular path")

    with monkeypatch.context() as scoped:
        scoped.setattr(loading.os, "open", forbidden)
        assert loading._read_regular_source(str(tmp_path), 1024) is None  # pyright: ignore[reportPrivateUsage]


def test_invalid_limits_keep_the_native_error(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(VALID_MANIFEST, encoding="utf-8")
    limits = {"max_merged_manifest_bytes": -1}
    with pytest.raises((ValueError, TypeError, OverflowError)) as native:
        ActivatedPolicy(str(path), limits=limits)
    with pytest.raises((ValueError, TypeError, OverflowError)) as unified:
        ActivatedPolicy.activate(str(path), limits=limits)
    assert type(unified.value) is type(native.value)
    assert str(unified.value) == str(native.value)


@pytest.mark.parametrize(
    ("cap", "content"),
    [(2**64, VALID_MANIFEST), (2**63, VALID_MANIFEST + "polices: {}\n")],
    ids=["beyond-64-bit-valid-manifest", "64-bit-edge-invalid-manifest"],
)
def test_huge_manifest_limits_never_replace_the_native_error(
    tmp_path: Path, cap: int, content: str
) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(content, encoding="utf-8")
    limits = {"max_merged_manifest_bytes": cap}
    with pytest.raises((ValueError, TypeError, OverflowError)) as native:
        ActivatedPolicy(str(path), limits=limits)
    with pytest.raises((ValueError, TypeError, OverflowError)) as unified:
        ActivatedPolicy.activate(str(path), limits=limits)
    assert type(unified.value) is type(native.value)
    assert str(unified.value) == str(native.value)
