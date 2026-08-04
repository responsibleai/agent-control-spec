# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Activation contract: one policy version readied once and evaluated
many times; engine failures fail closed; boundary errors raise."""

import concurrent.futures
import pathlib

import pytest
from agent_control_spec import ActivatedPolicy
from agent_hooks import AgentContextBuilder

MANIFEST = str(pathlib.Path(__file__).parent / "fixtures" / "manifest.yaml")


def builder() -> AgentContextBuilder:
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


def test_activate_then_evaluate_a_bound_point():
    policy = ActivatedPolicy(MANIFEST)
    verdict = policy.evaluate("input", builder().input(content="hello"))
    assert verdict.decision.value == "allow"


def test_activate_classmethod_matches_the_constructor():
    policy = ActivatedPolicy.activate(MANIFEST)
    verdict = policy.evaluate("input", builder().input(content="hello"))
    assert verdict.decision.value == "allow"


def test_one_activation_serves_every_bound_point():
    policy = ActivatedPolicy(MANIFEST)

    denied = policy.evaluate(
        "pre_tool_call",
        builder().pre_tool_call(call_id="t1", name="search", args={"q": "x"}),
    )
    assert denied.decision.value == "deny"
    assert denied.reason == "blocked_by_policy"

    escalated = policy.evaluate("output", builder().output(content="final answer"))
    assert escalated.decision.value == "deny"
    assert escalated.reason == "requires_human"
    assert escalated.approval == {}


def test_intervention_points_report_what_the_version_governs():
    policy = ActivatedPolicy(MANIFEST)
    assert sorted(policy.intervention_points) == [
        "input",
        "output",
        "post_tool_call",
        "pre_tool_call",
    ]
    assert policy.governs("input")
    assert not policy.governs("pre_model_call")


def test_unbound_point_fails_closed_rather_than_raising():
    policy = ActivatedPolicy(MANIFEST)
    verdict = policy.evaluate("pre_model_call", builder().input(content="hello"))
    assert verdict.decision.value == "deny"
    assert verdict.reason.startswith("runtime_error:")


def test_unknown_point_name_is_a_boundary_error():
    policy = ActivatedPolicy(MANIFEST)
    with pytest.raises(ValueError, match="unknown intervention point"):
        policy.evaluate("not_a_point", builder().input(content="hello"))


def test_engine_failure_fails_closed_as_runtime_error_deny():
    policy = ActivatedPolicy(MANIFEST)
    b = builder()
    b.pre_tool_call(call_id="t1", name="search", args={"q": "x"})
    verdict = policy.evaluate(
        "post_tool_call",
        b.post_tool_call(call_id="t1", name="search", args={"q": "x"}, value="r"),
    )
    assert verdict.decision.value == "deny"
    assert verdict.reason.startswith("runtime_error:")


def test_unreadable_manifest_is_an_activation_error():
    # The native manifest loader maps load failures to ValueError
    # (PyValueError in the binding).
    with pytest.raises(ValueError):
        ActivatedPolicy("/nonexistent/manifest.yaml")


def test_concurrent_evaluation_shares_one_activation():
    policy = ActivatedPolicy(MANIFEST)
    cases = [
        ("input", builder().input(content="hello"), "allow"),
        (
            "pre_tool_call",
            builder().pre_tool_call(call_id="t1", name="search", args={"q": "x"}),
            "deny",
        ),
        ("output", builder().output(content="final answer"), "deny"),
    ]

    def run(i: int) -> None:
        point, context, expected = cases[i % len(cases)]
        assert policy.evaluate(point, context).decision.value == expected

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        # `.result()` re-raises, so a failed assertion in any worker
        # fails the test rather than being swallowed.
        for future in [pool.submit(run, i) for i in range(128)]:
            future.result()
