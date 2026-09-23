# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regressions for the three reopened review threads."""

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import (
    GenerationEngine,
    GenerationError,
    StubLanguageModel,
)
from agent_control_spec_generator.conditions import inspect_conditions
from agent_hooks import AgentContextBuilder
from conftest import minimal_plan


@pytest.mark.parametrize(
    "leading", ["- 1", "- count(input.policy_target.value.content)", "# note\n  - 1"]
)
def test_leading_minus_is_not_attached_to_guard_even_when_smoke_is_shielded(leading):
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "smoke",
                "conditions": [
                    'input.policy_target.value.content == "acs-generator smoke evaluation"'
                ],
            },
            {
                "point": "input",
                "decision": "deny",
                "reason": "secret",
                "conditions": [
                    leading,
                    'contains(input.policy_target.value.content, "secret")',
                ],
            },
        ]
    )
    model = StubLanguageModel([plan])
    with pytest.raises(GenerationError, match="cannot start with '-'"):
        GenerationEngine(model, max_attempts=1).generate(
            prompt="synthetic", write=False
        )
    assert len(model.prompts) == 1


def test_explicit_binary_subtraction_preserves_normal_runtime_verdicts():
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "secret",
                "conditions": [
                    "0 - count(input.policy_target.value.content)",
                    'contains(input.policy_target.value.content, "secret")',
                ],
            }
        ]
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="synthetic", write=False
    )
    policy = ActivatedPolicy.from_memory(
        result.manifest_yaml,
        {
            result.slug: {"modules": {"policy.rego": result.rego}},
        },
    )
    builder = AgentContextBuilder(agent_id="a", framework="test", session_id="s")
    denied = policy.evaluate("input", builder.input(content="a secret"))
    allowed = policy.evaluate("input", builder.input(content="public"))
    assert (denied.decision.value, denied.reason) == ("deny", "secret")
    assert allowed.decision.value == "allow"
    assert not (allowed.reason or "").startswith("runtime_error:")


def test_empty_allow_body_still_generates():
    plan = minimal_plan(
        rules=[{"point": "input", "decision": "allow", "conditions": []}]
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="synthetic", write=False
    )
    assert result.attempts == 1


@pytest.mark.parametrize(
    "conditions",
    [
        [
            "a := input.policy_target.value[_]",
            "b := input.policy_target.value[_]",
            "c := input.policy_target.value[_]",
            "d := input.policy_target.value[_]",
            'a.content == "secret"',
            'b.content == "secret"',
            'c.content == "secret"',
            'd.content == "secret"',
        ],
        [
            "rows := input.policy_target.value",
            "a := rows[_]",
            "b := rows[_]",
            'a.content == "secret"',
            'b.content == "secret"',
        ],
        [
            "some i, a in input.policy_target.value",
            "some j, b in input.snapshot.other",
            'a.content == "secret"',
            'b.content == "secret"',
        ],
        [
            "some i, j",
            "input.policy_target.value[i].content == input.snapshot.other[j].content",
        ],
        [
            "a := input.policy_target.value[_]",
            "b := input.snapshot.other[_]",
            'a.content == "secret"',
            'b.content == "secret"',
        ],
    ],
)
def test_wildcard_named_index_and_cross_collection_products_warn(conditions):
    info = inspect_conditions(tuple(conditions), "pre_model_call")
    assert any("Cartesian product" in warning for warning in info.warnings)


@pytest.mark.parametrize(
    "conditions",
    [
        ['input.policy_target.value[0].content == "secret"'],
        ["i := 0", 'input.policy_target.value[i].content == "secret"'],
        ["i = 0", 'input.policy_target.value[i].content == "secret"'],
        [
            "some i",
            'input.policy_target.value[i].content == "secret"',
            'input.policy_target.value[i].role == "user"',
        ],
        [
            "some i, a in input.policy_target.value",
            'input.policy_target.value[i].content == "secret"',
            'a.role == "user"',
        ],
        [
            "a := input.policy_target.value[_]",
            'a.content == "secret"',
            'a.role == "user"',
        ],
    ],
)
def test_fixed_or_reused_bound_indices_do_not_invent_product_warnings(conditions):
    assert not inspect_conditions(tuple(conditions), "pre_model_call").warnings


def test_wildcard_product_warning_reaches_generated_result_and_report():
    plan = minimal_plan(
        rules=[
            {
                "point": "pre_model_call",
                "decision": "deny",
                "reason": "secret",
                "conditions": [
                    "a := input.policy_target.value[_]",
                    "b := input.policy_target.value[_]",
                    'a.content == "secret"',
                    'b.content == "secret"',
                ],
            }
        ]
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="synthetic", write=False
    )
    assert any("Cartesian product" in warning for warning in result.warnings)
    assert "Cartesian product" in result.report
