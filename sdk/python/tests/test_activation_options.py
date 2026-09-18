# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Activation carries resource caps and telemetry into async evaluation."""

import asyncio
from pathlib import Path

import pytest
from agent_control_spec import (
    AcsInterceptor,
    ActivatedPolicy,
    AsyncAcsInterceptor,
)
from agent_hooks import AgentContextBuilder, InterceptionEmitter

from ._async_helpers import (
    BUNDLES,
    GatedAnnotator,
    entered,
    until,
)
from ._async_helpers import (
    MANIFEST as ANNOTATOR_MANIFEST,
)

MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: test
    verdict:
      decision: allow
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: gate
"""


@pytest.fixture(params=["constructor", "activate", "from_memory"])
def activate(request, tmp_path):
    path = tmp_path / "manifest.yaml"

    def make(source=MANIFEST, **kwargs):
        if request.param == "from_memory":
            return ActivatedPolicy.from_memory(source, {}, **kwargs)
        path.write_text(source)
        factory = (
            ActivatedPolicy
            if request.param == "constructor"
            else ActivatedPolicy.activate
        )
        return factory(str(path), **kwargs)

    return make


def context():
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s").input(
        content="hello"
    )


@pytest.mark.parametrize("level", ["off", "external", "full"])
def test_telemetry_and_performance_options_reach_evaluation(activate, level):
    events = []
    policy = activate(telemetry_sink=events.append, perf_telemetry=level)
    verdict = policy.evaluate("input", context())
    assert verdict.decision.value == "allow"
    decisions = [e for e in events if e["event_type"] == "decision"]
    assert len(decisions) == 1
    assert decisions[0]["policy_id"] == "gate"
    timings = [e for e in events if e["event_type"] == "evaluation_timing"]
    assert bool(timings) == (level == "full")
    external = [e for e in events if e["event_type"] == "policy_evaluation"]
    assert bool(external) == (level != "off")


def test_limits_and_telemetry_survive_async_emitter(activate):
    events = []
    policy = activate(limits={"max_snapshot_bytes": 1}, telemetry_sink=events.append)

    async def run():
        async with AsyncAcsInterceptor(policy) as adapter:
            record = (
                await InterceptionEmitter().register(adapter).emit_unchecked(context())
            )
            assert record.verdict.reason == "runtime_error:resource_limit_exceeded"
            assert record.verdict.decision.value == "deny"

    asyncio.run(run())
    assert any(
        e["event_type"] == "decision"
        and e["reason_code"] == "runtime_error:resource_limit_exceeded"
        for e in events
    )


@pytest.mark.parametrize(
    "limits", [{"unknown_cap": 1}, {"max_snapshot_bytes": True}, []]
)
def test_bad_limits_are_rejected_by_all_constructors(activate, limits):
    with pytest.raises((ValueError, TypeError)):
        activate(limits=limits)


def test_bad_perf_level_is_rejected_by_all_constructors(activate):
    with pytest.raises(ValueError, match="perf_telemetry"):
        activate(perf_telemetry="verbose")


def test_defaults_preserve_synchronous_interceptor_behavior(activate, tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text(MANIFEST)
    assert (
        activate().evaluate("input", context()).to_wire()
        == AcsInterceptor(str(path)).intercept(context()).to_wire()
    )


@pytest.mark.parametrize("factory", [ActivatedPolicy, ActivatedPolicy.activate])
def test_loader_uses_host_manifest_limits(factory, tmp_path):
    parent = tmp_path / "parent.yaml"
    parent.write_text(MANIFEST)
    child = tmp_path / "manifest.yaml"
    child.write_text(
        """
agent_control_specification_version: "0.4.0-alpha.1"
extends: ["parent.yaml"]
"""
    )
    assert factory(str(child)).governs("input")
    with pytest.raises(ValueError, match="depth"):
        factory(str(child), limits={"max_extends_depth": 0})


def test_options_do_not_bypass_in_memory_bundle_validation():
    source = MANIFEST.replace(
        "type: test\n    verdict:\n      decision: allow",
        "type: rego\n    query: data.gate.verdict\n    bundle: ./missing",
    )
    with pytest.raises(ValueError, match="relative"):
        ActivatedPolicy.from_memory(
            source,
            {},
            telemetry_sink=lambda event: None,
            perf_telemetry="full",
            limits={"max_snapshot_bytes": 1024},
        )


@pytest.mark.parametrize("custom_policy", [False, True])
def test_activation_passes_url_limits_to_bundled_dispatchers(activate, custom_policy):
    source = (
        Path(__file__).resolve().parents[3] / "fixtures" / "pinned-prompt.yaml"
    ).read_text()
    options = (
        {"policy_dispatcher": lambda invocation: {"decision": "allow"}}
        if custom_policy
        else {}
    )
    policy = activate(source, limits={"manifest_url_timeout_ms": 0}, **options)
    verdict = policy.evaluate("input", context())
    assert verdict.reason == "runtime_error:annotation_failed"
    assert "timeout of 0 ms" in verdict.message

    policy = activate(
        source,
        limits={"manifest_url_timeout_ms": 0},
        annotator_dispatcher=lambda *args: {"label": "safe"},
        **options,
    )
    assert policy.evaluate("input", context()).decision.value == "allow"


def test_adapter_records_and_late_engine_telemetry_describe_different_outcomes():
    async def run():
        events = []
        gate = GatedAnnotator()
        policy = ActivatedPolicy.from_memory(
            ANNOTATOR_MANIFEST,
            BUNDLES,
            annotator_dispatcher=gate,
            telemetry_sink=events.append,
        )
        async with AsyncAcsInterceptor(policy, max_concurrency=1) as adapter:
            emitter = InterceptionEmitter(timeout=0.1).register(adapter)
            task = asyncio.create_task(emitter.emit_unchecked(context()))
            try:
                await entered(gate)
                rejected = await emitter.emit_unchecked(context())
                assert (
                    rejected.verdict.reason
                    == "runtime_error:acs_async_capacity_exceeded"
                )
                assert events == []
                timed_out = await task
                assert timed_out.verdict.reason == "host_error:interceptor_timeout"
                assert events == []
            finally:
                gate.release_all()
            await until(lambda: adapter.in_flight == 0)
            decisions = [e for e in events if e["event_type"] == "decision"]
            assert len(decisions) == 1
            assert decisions[0]["decision"] == "allow"
            assert timed_out.verdict.decision.value == "deny"

    asyncio.run(run())
