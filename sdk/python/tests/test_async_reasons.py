# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Adapter failures are registered and cannot be manufactured by a policy."""

import ast
import json
from pathlib import Path

import pytest
from agent_control_spec import ActivatedPolicy
from agent_hooks import AgentContextBuilder

REASONS = (
    "runtime_error:acs_async_capacity_exceeded",
    "runtime_error:acs_async_admission_timeout",
    "runtime_error:acs_async_closed",
)
MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: rego
    query: data.gate.verdict
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: gate
"""


def test_adapter_reason_literals_match_registered_sdk_producer():
    root = Path(__file__).resolve().parents[3]
    registry = json.loads((root / "spec/reserved-reasons.json").read_text())
    registered = {
        entry["reason"]
        for entry in registry["reasons"]
        if entry["reason"].startswith("runtime_error:acs_async_")
        and entry["producer"] == "sdk-adapter"
    }
    tree = ast.parse(
        (root / "sdk/python/agent_control_spec/async_interceptor.py").read_text()
    )
    used = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("runtime_error:acs_async_")
    }
    assert registered == used == set(REASONS)
    spec = (root / "spec/SPECIFICATION.md").read_text()
    assert all(reason in spec for reason in REASONS)
    assert not any(
        entry["reason"].endswith("acs_point_unbound") for entry in registry["reasons"]
    )


@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("kind", ["rego", "test", "host"])
def test_policy_cannot_impersonate_an_adapter_denial(reason, kind):
    verdict = {"decision": "deny", "reason": reason}
    options = {}
    if kind == "test":
        source = MANIFEST.replace(
            "type: rego\n    query: data.gate.verdict",
            f"type: test\n    verdict: {json.dumps(verdict)}",
        )
        bundles = {}
    else:
        source = MANIFEST
        bundles = {
            "gate": {
                "modules": {
                    "gate.rego": f"package gate\nverdict := {json.dumps(verdict)}"
                }
            }
        }
        if kind == "host":
            options["policy_dispatcher"] = lambda invocation: verdict
    policy = ActivatedPolicy.from_memory(source, bundles, **options)
    context = AgentContextBuilder(agent_id="a", framework="test", session_id="s").input(
        content="x"
    )
    result = policy.evaluate("input", context)
    assert result.decision.value == "deny"
    assert result.reason == "runtime_error:policy_output_invalid"
