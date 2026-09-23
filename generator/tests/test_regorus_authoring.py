# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Keep the authoring checks intact while removing the external parser."""

import json
import subprocess
import sys

import pytest
from agent_control_spec import authoring
from agent_control_spec_generator import (
    GenerationEngine,
    GenerationError,
    StubLanguageModel,
)
from agent_control_spec_generator.conditions import inspect_conditions
from conftest import PAYMENTS_PLAN, minimal_plan


def test_generation_requires_neither_opa_nor_a_subprocess(monkeypatch):
    monkeypatch.setenv("PATH", "")

    def no_spawn(*args, **kwargs):
        pytest.fail("authoring must not spawn a parser process")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)
    result = GenerationEngine(StubLanguageModel([PAYMENTS_PLAN])).generate(
        prompt="offline payments example", write=False
    )
    assert result.attempts == 1
    assert "regex.replace" in result.rego
    assert set(result.manifest["intervention_points"]) == {
        "input",
        "pre_tool_call",
        "output",
    }


def test_old_sdk_fails_before_any_model_call(monkeypatch):
    monkeypatch.delattr(authoring, "parse_rego_ast")
    model = StubLanguageModel([minimal_plan()])
    with pytest.raises(RuntimeError, match="same checkout"):
        GenerationEngine(model).generate(prompt="synthetic", write=False)
    assert not model.prompts


def test_unknown_ast_version_fails_before_any_model_call(monkeypatch):
    monkeypatch.setattr(authoring, "REGORUS_AST_VERSION", "future-version")
    model = StubLanguageModel([minimal_plan()])
    with pytest.raises(RuntimeError, match="Regorus 0.12.0"):
        GenerationEngine(model).generate(prompt="synthetic", write=False)
    assert not model.prompts


@pytest.mark.parametrize(
    "body",
    [
        "input.target != null }\nextra := true\ncheck if { input.target != null",
        "input.target != null } else { input.target == null",
        "input.target != null }\nimport data.other as check\nanother if { input.target != null",
    ],
)
def test_injected_rules_and_imports_are_rejected(body):
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [body]
    with pytest.raises(GenerationError):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt="synthetic", write=False
        )


@pytest.mark.parametrize(
    "conditions,point,patterns,names",
    [
        (
            ["p := `sk-[A-Z]+`", "regex.match(p, input.policy_target.value.content)"],
            "input",
            ("sk-[A-Z]+",),
            set(),
        ),
        (
            [
                'p = "acct_[0-9]+"',
                'regex["match"](p, input.policy_target.value.content)',
            ],
            "input",
            ("acct_[0-9]+",),
            set(),
        ),
        (
            ['a := input["annotations"]', 'object.get(a, "pii", {}).detected == true'],
            "input",
            (),
            {"pii"},
        ),
        (["not input.annotations.pii.safe"], "input", (), {"pii"}),
        (["input.policy_target.value.amount > -2"], "pre_tool_call", (), set()),
        (
            ["some i, message in input.policy_target.value", 'message.role == "user"'],
            "pre_model_call",
            (),
            set(),
        ),
    ],
)
def test_regorus_expression_variants_preserve_inspection(
    conditions, point, patterns, names
):
    info = inspect_conditions(tuple(conditions), point)
    assert info.patterns == patterns
    assert info.annotators == names


@pytest.mark.parametrize(
    "body",
    [
        'unused := {p: true | p := "ok"}; some p in input.snapshot.patterns; regex.match(p, input.policy_target.value.content)',
        'every p in ["ok"] { p == "ok" }; input.policy_target.value.content == "secret"',
    ],
)
def test_nested_scopes_cannot_enter_literal_inference(body):
    with pytest.raises(ValueError, match="nested condition scopes"):
        inspect_conditions((body,), "input")


def test_native_parser_errors_remain_repairable():
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = ['contains(input.policy_target.value.content, "x"']
    model = StubLanguageModel([plan, minimal_plan()])
    result = GenerationEngine(model).generate(prompt="synthetic", write=False)
    assert result.attempts == 2
    assert "invalid Rego" in model.prompts[1][1]
    assert (
        json.loads(
            json.loads(model.prompts[1][1].split("requirements:\n")[1])[
                "previous_response"
            ]
        )
        == plan
    )


def test_pathological_nesting_enters_repair_promptly():
    code = """
from agent_control_spec_generator import GenerationEngine, StubLanguageModel
good = {'name': 'good', 'rules': [{
    'point': 'input', 'decision': 'deny', 'reason': 'blocked',
    'conditions': ['input.policy_target.value.content == "secret"']
}]}
bad = {'name': 'bad', 'rules': [{
    'point': 'input', 'decision': 'deny', 'reason': 'blocked',
    'conditions': [
        'x := ' + '[' * 24 + '"ok"' + ']' * 24,
        'input.policy_target.value.content == "ok"'
    ]
}]}
model = StubLanguageModel([bad, good])
result = GenerationEngine(model, max_attempts=2).generate(prompt='synthetic', write=False)
assert result.attempts == 2
assert 'nesting exceeds' in model.prompts[1][1]
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
