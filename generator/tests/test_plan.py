# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""What the plan gate refuses, and why each refusal exists.

Every case here is a plan a model can plausibly return. The point of the gate
is that each one fails loudly at generation instead of quietly at evaluation.
"""

from __future__ import annotations

import json

import pytest
from agent_control_spec_generator.plan import PlanError, parse_policy_plan
from conftest import minimal_plan


def parse(plan: dict) -> object:
    return parse_policy_plan(json.dumps(plan))


def test_non_json_response_is_rejected_with_the_decoder_message():
    with pytest.raises(PlanError, match="not valid JSON"):
        parse_policy_plan("here is your policy:\n```yaml\npolicies: {}\n```")


def test_json_that_is_not_an_object_is_rejected():
    with pytest.raises(PlanError, match="must be an object"):
        parse_policy_plan("[1, 2, 3]")


def test_non_array_rules_member_is_rejected():
    with pytest.raises(PlanError, match="'rules' must be a JSON array"):
        parse({"name": "x", "rules": {"point": "input"}})


def test_unknown_intervention_point_names_the_valid_set():
    plan = minimal_plan()
    plan["rules"][0]["point"] = "before_tool"
    with pytest.raises(PlanError) as excinfo:
        parse(plan)
    assert "before_tool" in str(excinfo.value)
    assert "pre_tool_call" in str(excinfo.value)


def test_unknown_decision_is_rejected():
    plan = minimal_plan()
    plan["rules"][0]["decision"] = "block"
    with pytest.raises(PlanError, match="unsupported decision 'block'"):
        parse(plan)


def test_unconditional_blocking_rule_is_rejected():
    """An unconditional deny fires on every request at that point, which is a
    total outage wearing the shape of a policy."""
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = []
    with pytest.raises(PlanError, match="at least one condition"):
        parse(plan)


def test_blank_conditions_do_not_count_as_conditions():
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = ["", "   ", "\n"]
    with pytest.raises(PlanError, match="condition must be a non-empty string"):
        parse(plan)


def test_unconditional_allow_is_permitted():
    """An unconditional allow changes nothing, so it is not a hazard."""
    plan = minimal_plan(
        rules=[
            {"point": "input", "decision": "allow", "reason": "ok", "conditions": []}
        ]
    )
    assert parse(plan).rules[0].decision == "allow"


def test_reserved_runtime_error_reason_is_rejected():
    """The engine rejects a policy reason in its own namespace with
    `runtime_error:policy_output_invalid`, so the gate catches it first."""
    plan = minimal_plan()
    plan["rules"][0]["reason"] = "runtime_error:policy_invocation_failed"
    with pytest.raises(PlanError, match="reserved runtime_error: namespace"):
        parse(plan)


def test_unknown_annotator_type_is_rejected():
    plan = minimal_plan(annotators=[{"name": "pii", "type": "regex"}])
    with pytest.raises(PlanError, match="unsupported annotator type 'regex'"):
        parse(plan)


def test_effects_on_a_deny_are_rejected():
    plan = minimal_plan()
    plan["rules"][0]["effects"] = [
        {"type": "redact", "path": "$target", "pattern": "x"}
    ]
    with pytest.raises(PlanError, match="nothing will be dropped"):
        parse(plan)


def test_append_effect_is_rejected_rather_than_approximated():
    plan = _transform_plan(
        effects=[{"type": "append", "path": "$target.content", "value": "!"}]
    )
    with pytest.raises(PlanError, match="append effect is not expressible"):
        parse(plan)


def test_effect_path_outside_target_is_rejected():
    plan = _transform_plan(
        effects=[{"type": "replace", "path": "$snap.session.id", "value": "x"}]
    )
    with pytest.raises(PlanError, match=r"must start with \$target"):
        parse(plan)


def test_removed_policy_target_root_is_named_in_the_diagnostic():
    """AGENT-HOOKS-0.1 renamed `$policy_target` to `$target` with no alias."""
    plan = _transform_plan(
        effects=[{"type": "replace", "path": "$policy_target.content", "value": "x"}]
    )
    with pytest.raises(PlanError, match=r"removed \$policy_target root"):
        parse(plan)


def test_transform_effects_targeting_two_paths_are_rejected():
    """A verdict carries one transform, one path and one value. Uses `input`,
    where both members exist, so this isolates the multiple-path rule from the
    unknown-member one."""
    plan = _transform_plan(
        point="input",
        effects=[
            {"type": "replace", "path": "$target.content", "value": "a"},
            {"type": "replace", "path": "$target.role", "value": "b"},
        ],
    )
    with pytest.raises(PlanError, match="single path"):
        parse(plan)


def test_a_transform_path_naming_an_absent_member_is_rejected():
    """The engine validates the path grammar and returns the verdict.
    Resolving it against the target is a host obligation, so a syntactically
    valid path naming a member that does not exist passes every downstream
    check and then fails at the host on every firing."""
    plan = _transform_plan(
        point="output",
        effects=[{"type": "replace", "path": "$target.text", "value": "x"}],
    )
    with pytest.raises(PlanError) as excinfo:
        parse(plan)
    assert "'text'" in str(excinfo.value)
    assert "would not resolve" in str(excinfo.value)


def test_mixing_replace_and_redact_is_rejected():
    plan = _transform_plan(
        effects=[
            {"type": "replace", "path": "$target.content", "value": "a"},
            {"type": "redact", "path": "$target.content", "pattern": "a"},
        ]
    )
    with pytest.raises(PlanError, match="cannot mix replace and redact"):
        parse(plan)


def test_two_replace_effects_are_rejected():
    plan = _transform_plan(
        effects=[
            {"type": "replace", "path": "$target.content", "value": "a"},
            {"type": "replace", "path": "$target.content", "value": "b"},
        ]
    )
    with pytest.raises(PlanError, match="at most one replace effect"):
        parse(plan)


def test_redact_without_a_pattern_is_rejected():
    plan = _transform_plan(effects=[{"type": "redact", "path": "$target.content"}])
    with pytest.raises(PlanError, match="requires a 'pattern'"):
        parse(plan)


def test_replace_without_a_value_is_rejected():
    plan = _transform_plan(effects=[{"type": "replace", "path": "$target.content"}])
    with pytest.raises(PlanError, match="requires a 'value'"):
        parse(plan)


@pytest.mark.parametrize(
    "point,suggestion",
    [
        ("input", "$target.content"),
        ("output", "$target.content"),
        ("post_model_call", "$target.content"),
    ],
)
def test_redaction_rooted_at_bare_target_is_rejected_where_it_can_never_fire(
    point: str, suggestion: str
):
    """A regex redaction compiles to a body guarded by `is_string`. At these
    points `$target` is an object, the guard never holds, the rule never
    fires, and the default allow answers. A redaction that silently stops
    redacting must not ship, so the diagnostic names the right member."""
    plan = _transform_plan(
        point=point, effects=[{"type": "redact", "path": "$target", "pattern": "x"}]
    )
    with pytest.raises(PlanError) as excinfo:
        parse(plan)
    assert "can never fire" in str(excinfo.value)
    assert suggestion in str(excinfo.value)


def test_redaction_rooted_at_bare_target_is_allowed_where_the_target_is_a_string():
    """A tool result may itself be a string, so there the bare root is correct."""
    plan = _transform_plan(
        point="post_tool_call",
        effects=[{"type": "redact", "path": "$target", "pattern": "acct_[0-9]+"}],
    )
    assert parse(plan).rules[0].effects[0]["path"] == "$target"


@pytest.mark.parametrize("point", ["agent_startup", "agent_shutdown"])
def test_a_transform_at_startup_or_shutdown_is_rejected(point: str):
    """AGENT-HOOKS-0.1 section 4.3 forbids it and a host must reject it with
    `host_error:transform_target_forbidden`. The ACS engine emits it happily,
    because the obligation is the host's, so nothing downstream catches it."""
    plan = _transform_plan(
        point=point,
        effects=[{"type": "replace", "path": "$target", "value": {}}],
    )
    with pytest.raises(PlanError) as excinfo:
        parse(plan)
    assert "AGENT-HOOKS-0.1 section 4.3" in str(excinfo.value)
    assert "host_error:transform_target_forbidden" in str(excinfo.value)


def test_tool_entries_accept_strings_and_objects():
    plan = minimal_plan(tools=["a", {"id": "b"}, {"name": "c"}])
    assert parse(plan).tools == ("a", "b", "c")


def _transform_plan(*, point: str = "output", effects: list) -> dict:
    # A real condition, because a tautology is now refused in its own right
    # and would mask the rejection each caller is actually testing.
    return minimal_plan(
        guarded_points=[point],
        rules=[
            {
                "point": point,
                "decision": "transform",
                "reason": "rewrite",
                "conditions": ['contains(input.policy_target.value.content, "secret")'],
                "effects": effects,
            }
        ],
    )


def test_a_transform_with_no_effect_is_rejected():
    """With no usable effect the renderer can only emit an identity
    transform, which reports a rewrite and returns the value untouched. A rule
    presented as a redaction would pass every check and redact nothing."""
    plan = minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact",
                "conditions": ['contains(input.policy_target.value.content, "acct")'],
                "effects": [],
            }
        ],
    )
    with pytest.raises(PlanError, match="carries no effect"):
        parse(plan)


@pytest.mark.parametrize("condition", ["true", "1 == 1", "  true  ", "input"])
def test_a_tautological_condition_does_not_count_as_a_gate(condition: str):
    """A non-allow rule gated only by a tautology fires on every request at
    its point, which is the same outage as no condition at all."""
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [condition]
    with pytest.raises(PlanError, match="selects every request"):
        parse(plan)


def test_a_tautology_alongside_a_real_condition_is_fine():
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [
        "true",
        'contains(input.policy_target.value.content, "forbidden")',
    ]
    assert len(parse(plan).rules[0].conditions) == 2


def test_condition_regexes_are_collected_from_every_builtin():
    from agent_control_spec_generator.plan import condition_regex_patterns

    plan = parse(
        minimal_plan(
            rules=[
                {
                    "point": "input",
                    "decision": "deny",
                    "reason": "blocked",
                    "conditions": [
                        'regex.match("a[0-9]+", input.policy_target.value.content)',
                        'regex.replace(input.policy_target.value.content, "b[0-9]+", "x") != ""',
                        "count(regex.split(`c[0-9]+`, input.policy_target.value.content)) > 1",
                    ],
                }
            ]
        )
    )

    assert condition_regex_patterns(plan) == ("a[0-9]+", "b[0-9]+", "c[0-9]+")


def test_a_computed_regex_pattern_is_rejected_instead_of_skipping_validation():
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [
        "pattern := input.snapshot.pattern",
        "regex.match(pattern, input.policy_target.value.content)",
    ]
    with pytest.raises(PlanError, match="computed patterns cannot be validated"):
        parse(plan)
