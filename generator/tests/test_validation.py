# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The checks that catch a policy which loads, evaluates, and enforces nothing.

A rejected manifest is easy. These cover the failures that produce a green
artifact and an unguarded agent.
"""

from __future__ import annotations

import pytest
import yaml
from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import GenerationEngine, StubLanguageModel
from agent_control_spec_generator.validation import (
    ValidationError,
    check_regex_patterns,
    dump_manifest_yaml,
)
from agent_control_spec_generator.vocabulary import manifest_version
from agent_hooks import AgentContextBuilder
from conftest import PROSE, minimal_plan


def generate(plan: dict, tmp_path):
    return GenerationEngine(StubLanguageModel([plan])).generate(
        prompt=PROSE, out_dir=tmp_path / "out", write=False
    )


def redaction_plan(pattern: str) -> dict:
    return minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact",
                "conditions": ['contains(input.policy_target.value.content, "acct")'],
                "effects": [
                    {"type": "redact", "path": "$target.content", "pattern": pattern}
                ],
            }
        ],
    )


def test_a_valid_pattern_is_accepted(tmp_path):
    result = generate(redaction_plan("acct_[0-9]+"), tmp_path)
    assert "acct_[0-9]+" in result.rego


@pytest.mark.parametrize(
    "pattern",
    [
        "[unclosed",
        "(?=lookahead)x",
        "(?<=lookbehind)x",
        r"(a)\1",
        "a{3,1}",
    ],
)
def test_a_pattern_the_engine_rejects_fails_generation(pattern, tmp_path):
    """The failure this guards against is silent. The manifest validates, the
    Rego compiles, and at evaluation the builtin goes undefined, the rule body
    fails, and the default allow answers. The redaction reads as authored and
    removes nothing."""
    with pytest.raises(Exception) as excinfo:
        generate(redaction_plan(pattern), tmp_path)
    assert "silently stop redacting" in str(excinfo.value)


def test_the_silent_fail_open_is_real_without_the_check():
    """Pin the behavior the check exists for, so a future engine that starts
    rejecting a bad pattern at compile time makes this test fail and the
    check can be simplified rather than left as unexplained weight."""
    manifest = dump_manifest_yaml(
        {
            "agent_control_specification_version": manifest_version(),
            "metadata": {"name": "faildemo"},
            "policies": {
                "p": {
                    "type": "rego",
                    "bundle": "./policy",
                    "query": "data.faildemo.verdict",
                }
            },
            "intervention_points": {
                "output": {
                    "policy_target": "$.target",
                    "policy_target_kind": "assistant_output",
                    "policy": {"id": "p", "query": "data.faildemo.verdict"},
                }
            },
        }
    )
    module = (
        "package faildemo\n\nimport rego.v1\n\n"
        'default verdict := {"decision": "allow"}\n\n'
        'verdict := {"decision": "transform", "reason": "redact", '
        '"transform": {"path": "$target.content", "value": v}} if {\n'
        "\tis_string(input.policy_target.value.content)\n"
        '\tv := regex.replace(input.policy_target.value.content, "[unclosed", "X")\n'
        "}\n"
    )
    policy = ActivatedPolicy.from_memory(
        manifest, {"p": {"modules": {"p.rego": module}}}
    )

    verdict = policy.evaluate(
        "output",
        AgentContextBuilder(agent_id="a", framework="t", session_id="s").output(
            content="secret"
        ),
    )
    assert verdict.decision.value == "allow"
    assert not (verdict.reason or "").startswith("runtime_error:")


def test_re2_syntax_python_rejects_is_accepted():
    """RE2 accepts Unicode class syntax that Python's `re` rejects, so the
    engine is the authority and `re` is not consulted."""
    check_regex_patterns((r"\p{Lu}\p{Ll}+",))


def test_python_syntax_re2_rejects_is_refused():
    """The other direction. Python's `re` accepts lookahead, RE2 does not."""
    with pytest.raises(ValidationError, match="silently stop redacting"):
        check_regex_patterns(("(?=secret)",))


def test_no_patterns_is_a_no_op():
    check_regex_patterns(())


def test_a_second_chained_pattern_is_checked_too():
    """A redaction that chains two patterns renders one builtin call inside
    another. Reading the patterns back out of the rendered Rego missed the
    outer one, so the generator passes what it built instead of parsing it."""
    plan = minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact",
                "conditions": ['contains(input.policy_target.value.content, "acct")'],
                "effects": [
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "acct_[0-9]+",
                    },
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "(?=lookahead)",
                    },
                ],
            }
        ],
    )
    with pytest.raises(Exception) as excinfo:
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt=PROSE, out_dir=None, write=False
        )
    assert "(?=lookahead)" in str(excinfo.value)


def test_both_chained_patterns_reach_the_rendered_policy(tmp_path):
    result = GenerationEngine(
        StubLanguageModel(
            [
                minimal_plan(
                    guarded_points=["output"],
                    rules=[
                        {
                            "point": "output",
                            "decision": "transform",
                            "reason": "redact",
                            "conditions": [
                                'contains(input.policy_target.value.content, "acct")'
                            ],
                            "effects": [
                                {
                                    "type": "redact",
                                    "path": "$target.content",
                                    "pattern": "acct_[0-9]+",
                                },
                                {
                                    "type": "redact",
                                    "path": "$target.content",
                                    "pattern": "card_[0-9]+",
                                },
                            ],
                        }
                    ],
                )
            ]
        )
    ).generate(prompt=PROSE, out_dir=tmp_path / "out", write=False)

    assert "acct_[0-9]+" in result.rego
    assert "card_[0-9]+" in result.rego


def test_removed_policy_input_members_are_refused(tmp_path):
    """`input.request` does not error. It evaluates to undefined, the body
    fails, and the default verdict answers, so the rule enforces nothing."""
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "blocked",
                "conditions": ['input.request.user == "x"'],
            }
        ]
    )
    with pytest.raises(Exception, match="removed"):
        generate(plan, tmp_path)


def test_the_removed_transform_root_is_refused():
    from agent_control_spec_generator import GenerationError

    plan = redaction_plan("secret")
    plan["rules"][0]["effects"][0]["path"] = "$policy_target.content"
    with pytest.raises(GenerationError, match=r"removed \$policy_target"):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt=PROSE, write=False
        )


def test_a_rego_module_that_does_not_compile_is_refused(monkeypatch, tmp_path):
    """The engine compiles Rego in process, so there is no optional external
    validator and no path that skips this."""
    import agent_control_spec_generator.engine as engine_module

    original = engine_module.build_rego
    monkeypatch.setattr(
        engine_module,
        "build_rego",
        lambda plan, slug: original(plan, slug) + "\nbroken ::= \n",
    )
    with pytest.raises(Exception, match="engine rejected the generated artifacts"):
        generate(minimal_plan(), tmp_path)


def test_smoke_evaluation_catches_an_unresolvable_policy_target(monkeypatch, tmp_path):
    """The static checks cannot see this. A manifest naming a path the
    snapshot does not carry validates and compiles, then fails closed with
    `runtime_error:path_missing` on every evaluation."""
    import agent_control_spec_generator.manifest_builder as builder_module

    original = builder_module.build_manifest

    def stale_target(plan, inventory):
        manifest, slug = original(plan, inventory)
        for config in manifest["intervention_points"].values():
            config["policy_target"] = "$.model_request"
        return manifest, slug

    monkeypatch.setattr(
        "agent_control_spec_generator.engine.build_manifest", stale_target
    )
    with pytest.raises(Exception) as excinfo:
        generate(minimal_plan(), tmp_path)
    assert "runtime_error:path_missing" in str(excinfo.value)
    assert "fails closed at 'input'" in str(excinfo.value)


def test_smoke_evaluation_answers_annotators_without_a_network_call(tmp_path):
    """A declared `llm` annotator would otherwise reach a bundled dispatcher
    that needs a credential, and fail closed with
    `runtime_error:annotation_failed` for reasons unrelated to the policy."""
    plan = minimal_plan(
        annotators=[{"name": "judge", "type": "llm"}],
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "judged_unsafe",
                "conditions": ['input.annotations.judge.label == "unsafe"'],
            }
        ],
    )
    result = generate(plan, tmp_path)

    document = yaml.safe_load(result.manifest_yaml)
    assert document["annotators"]["judge"]["type"] == "llm"
    assert document["intervention_points"]["input"]["annotations"]["judge"]


def test_every_guarded_point_is_smoke_evaluated(
    payments_plan, tool_inventory, tmp_path
):
    """Each declared tool gets its own context at a tool point, so a catalog
    entry that cannot be projected does not go unexercised."""
    result = GenerationEngine(StubLanguageModel([payments_plan])).generate(
        prompt=PROSE,
        out_dir=tmp_path / "out",
        tool_inventory=tool_inventory,
        write=False,
    )
    assert set(yaml.safe_load(result.manifest_yaml)["intervention_points"]) == {
        "input",
        "pre_tool_call",
        "output",
    }


def test_an_invalid_regex_in_a_rule_condition_is_caught(tmp_path):
    """The same silent fail-open as a bad redact pattern, in the other place a
    model writes a regex. The builtin goes undefined, the body fails, and the
    default allow answers, so a deny rule stops denying."""
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "secret_in_prompt",
                "conditions": [
                    'regex.match("(?=secret)", input.policy_target.value.content)'
                ],
            }
        ]
    )
    with pytest.raises(Exception) as excinfo:
        generate(plan, tmp_path)
    assert "(?=secret)" in str(excinfo.value)


def test_a_valid_regex_in_a_rule_condition_is_accepted_and_fires(tmp_path):
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "secret_in_prompt",
                "conditions": [
                    'regex.match("sk-[A-Za-z0-9]+", input.policy_target.value.content)'
                ],
            }
        ]
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt=PROSE, out_dir=tmp_path / "out"
    )

    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    context = AgentContextBuilder(agent_id="a", framework="t", session_id="s")
    verdict = policy.evaluate("input", context.input(content="my key is sk-AbC123"))
    assert (verdict.decision.value, verdict.reason) == ("deny", "secret_in_prompt")
    assert result.slug


def test_a_nested_regex_call_attributes_the_pattern_to_its_own_call(tmp_path):
    """Argument scanning must respect nesting, or an inner call's pattern is
    read as the outer call's and the real one goes unchecked."""
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "blocked",
                "conditions": [
                    (
                        'regex.match("ok_[0-9]+", regex.replace('
                        'input.policy_target.value.content, "(?<=bad)", "x"))'
                    )
                ],
            }
        ]
    )
    with pytest.raises(Exception) as excinfo:
        generate(plan, tmp_path)
    assert "(?<=bad)" in str(excinfo.value)


def test_a_guarded_tool_point_is_smoke_evaluated_with_no_catalog(monkeypatch, tmp_path):
    """With no catalog the point was previously skipped while the report still
    claimed every guarded point had been evaluated."""
    import agent_control_spec_generator.validation as validation_module

    seen: list[str] = []
    original = validation_module._contexts_for

    def record(point, builder, tool_names):
        contexts = original(point, builder, tool_names)
        seen.extend([point] * len(contexts))
        return contexts

    monkeypatch.setattr(validation_module, "_contexts_for", record)
    generate(
        minimal_plan(
            guarded_points=["pre_tool_call"],
            rules=[
                {
                    "point": "pre_tool_call",
                    "decision": "deny",
                    "reason": "too_large",
                    "conditions": ["input.policy_target.value.amount > 10000"],
                }
            ],
        ),
        tmp_path,
    )

    assert seen.count("pre_tool_call") >= 1
