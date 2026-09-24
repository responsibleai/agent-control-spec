# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regressions from the source-level review, including failure injection."""

import io
import json
from pathlib import Path

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import (
    GenerationEngine,
    GenerationError,
    StubLanguageModel,
)
from agent_control_spec_generator.conditions import inspect_conditions
from agent_control_spec_generator.llm import (
    OpenAICompatibleLanguageModel,
    ProviderError,
)
from agent_control_spec_generator.output import output_lock
from agent_control_spec_generator.plan import PlanError, parse_policy_plan
from agent_hooks import AgentContextBuilder
from conftest import minimal_plan


def generate(tmp_path, **kwargs):
    return GenerationEngine(StubLanguageModel([minimal_plan()])).generate(
        prompt="synthetic", out_dir=tmp_path / "output", **kwargs
    )


def snapshot(path):
    return {
        str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize("failure", ["staging", "publish"])
def test_write_failure_preserves_the_entire_old_output(tmp_path, monkeypatch, failure):
    generate(tmp_path)
    out = tmp_path / "output"
    before = snapshot(out)
    if failure == "staging":
        original = Path.write_text

        def fail(self, *args, **kwargs):
            if self.name == "report.md":
                raise OSError("injected report write failure")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", fail)
    else:
        original = Path.rename

        def fail(self, target):
            if ".stage-" in self.name:
                raise OSError("injected publication failure")
            return original(self, target)

        monkeypatch.setattr(Path, "rename", fail)
    with pytest.raises(OSError, match="injected"):
        generate(tmp_path, force=True)
    assert snapshot(out) == before
    assert not list(tmp_path.glob("*.lock"))
    assert not list(tmp_path.glob(".*.stage-*"))


def test_replacement_retains_backup_and_drops_stale_modules_only_from_new_output(
    tmp_path,
):
    generate(tmp_path)
    stale = tmp_path / "output/policy/stale.rego"
    stale.write_text("not valid Rego", encoding="utf-8")
    before = snapshot(tmp_path / "output")
    result = generate(tmp_path, force=True)
    assert not stale.exists()
    backups = list(tmp_path.glob(".output.backup-*"))
    assert len(backups) == 1
    assert snapshot(backups[0]) == before
    assert any(str(backups[0]) in item for item in result.warnings)
    ActivatedPolicy.activate(str(tmp_path / "output/manifest.yaml"))


def test_api_refuses_unrelated_output_and_symlinks_before_model_call(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "notes.txt").write_text("keep", encoding="utf-8")
    model = StubLanguageModel([minimal_plan()])
    with pytest.raises(ValueError, match="unrelated"):
        GenerationEngine(model).generate(prompt="x", out_dir=out, force=True)
    assert not model.prompts
    (out / "notes.txt").unlink()
    (out / "policy").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        GenerationEngine(model).generate(prompt="x", out_dir=out, force=True)
    assert not model.prompts


def test_two_writers_cannot_publish_concurrently(tmp_path):
    with (
        output_lock(tmp_path / "output", force=False),
        pytest.raises(ValueError, match="another generation"),
    ):
        generate(tmp_path)


@pytest.mark.parametrize(
    "conditions",
    [
        ['p := "(?=secret)"', "regex.match(p, input.policy_target.value.content)"],
        ['regex["match"](`(?=secret)`, input.policy_target.value.content)'],
        [
            'some p in ["ok", "(?=secret)"]',
            "regex.match(p, input.policy_target.value.content)",
        ],
    ],
)
def test_invalid_regex_spellings_all_reach_the_real_engine_probe(conditions):
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = conditions
    with pytest.raises(GenerationError, match=r"\(\?=secret\)"):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt="x", write=False
        )


@pytest.mark.parametrize(
    "conditions",
    [
        ['input["request"].user == "x"'],
        ["a := input", 'a["stage"] == "input"'],
        ['object.get(input, "resource", {}) == {}'],
        ['input.tool.id == "t"'],
        [
            'http.send({"method": "GET", "url": input.policy_target.value.content}).status_code == 200'
        ],
        ['contains(input.policy_target.value.content, "x") with input as {}'],
        ["input.annotations[input.snapshot.name].detected == true"],
    ],
)
def test_unsupported_or_unsafe_conditions_are_repair_errors(conditions):
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = conditions
    with pytest.raises(PlanError):
        parse_policy_plan(json.dumps(plan))


def test_pre_model_array_shape_is_checked_through_aliases():
    with pytest.raises(ValueError, match="array"):
        inspect_conditions(
            ("m := input.policy_target.value", 'm.content == "x"'), "pre_model_call"
        )


def test_comments_and_literals_do_not_create_dependencies():
    info = inspect_conditions(
        (
            '# input.annotations.fake.flag regex.match("(?=bad)", "")',
            'contains(input.policy_target.value.content, "input.request")',
        ),
        "input",
    )
    assert not info.patterns
    assert not info.annotators


@pytest.mark.parametrize(
    "condition",
    [
        "a := input.annotations; a.pii.detected == true",
        'object.get(input["annotations"], "pii", {}).detected == true',
        'input["annotations"]["pii"].detected == true',
    ],
)
def test_annotation_aliases_are_wired_and_change_a_real_verdict(tmp_path, condition):
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [condition]
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="x", write=False
    )
    calls = []

    def annotator(name, config, preliminary):
        calls.append(name)
        return {"detected": True}

    policy = ActivatedPolicy.from_memory(
        result.manifest_yaml,
        {result.slug: {"modules": {"p.rego": result.rego}}},
        annotator_dispatcher=annotator,
    )
    context = AgentContextBuilder(agent_id="a", framework="t", session_id="s").input(
        content="x"
    )
    assert policy.evaluate("input", context).reason == "blocked"
    assert calls == ["pii"]


@pytest.mark.parametrize("path", ['$target["content"]', "$target.content"])
def test_quoted_transform_paths_are_preserved(tmp_path, path):
    plan = minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact",
                "conditions": ['contains(input.policy_target.value.content, "secret")'],
                "effects": [{"type": "redact", "path": path, "pattern": "secret"}],
            }
        ],
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="x", write=False
    )
    policy = ActivatedPolicy.from_memory(
        result.manifest_yaml,
        {
            result.slug: {"modules": {"p.rego": result.rego}},
        },
    )
    verdict = policy.evaluate(
        "output",
        AgentContextBuilder(
            agent_id="a",
            framework="t",
            session_id="s",
        ).output(content="a secret"),
    )
    assert verdict.transform.path == path
    assert verdict.transform.value == "a [REDACTED]"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan.update(guarded_points=["typo"]),
        lambda plan: plan["rules"][0].update(conditions=[True]),
        lambda plan: plan.update(rules=[]),
        lambda plan: plan.update(extra_rules=[{"deny": True}]),
        lambda plan: plan.update(tools=[{}]),
        lambda plan: plan.update(annotations=[{"point": "wrong", "annotator": "pii"}]),
    ],
)
def test_malformed_plan_fields_cannot_be_silently_dropped(mutate):
    plan = minimal_plan()
    mutate(plan)
    with pytest.raises(PlanError):
        parse_policy_plan(json.dumps(plan))


def test_duplicate_and_nonfinite_json_are_rejected():
    for raw in ['{"name":"a","name":"b"}', '{"name":NaN}']:
        with pytest.raises(PlanError):
            parse_policy_plan(raw)


def test_repair_request_contains_the_actual_rejected_response():
    broken = minimal_plan()
    broken["rules"][0]["conditions"] = []
    model = StubLanguageModel([broken, minimal_plan()])
    result = GenerationEngine(model).generate(
        prompt="keep original requirements", write=False
    )
    assert result.attempts == 2
    repair = model.prompts[1][1].split("requirements:\n", 1)[1]
    assert json.loads(json.loads(repair)["previous_response"]) == broken


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"choices": []},
        {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]},
        {"choices": [{"message": {"content": "{}"}, "finish_reason": "length"}]},
        {
            "choices": [
                {
                    "message": {"refusal": "SECRET", "content": "{}"},
                    "finish_reason": "stop",
                }
            ]
        },
    ],
)
def test_bad_provider_responses_are_explicit_and_do_not_echo_payload(monkeypatch, body):
    from urllib.request import OpenerDirector

    monkeypatch.setattr(
        OpenerDirector, "open", lambda *a, **kw: io.BytesIO(json.dumps(body).encode())
    )
    with pytest.raises(ProviderError) as exc:
        OpenAICompatibleLanguageModel(api_key="SECRET").complete("system", "user")
    assert "SECRET" not in str(exc.value)


def test_provider_success_sends_expected_auth_and_json(monkeypatch):
    from urllib.request import OpenerDirector

    seen = []

    def respond(self, req, **kwargs):
        seen.append(req)
        return io.BytesIO(
            json.dumps(
                {
                    "choices": [
                        {"message": {"content": "{}"}, "finish_reason": "stop"}
                    ],
                }
            ).encode()
        )

    monkeypatch.setattr(OpenerDirector, "open", respond)
    assert (
        OpenAICompatibleLanguageModel(api_key="TEST", model="chosen").complete("s", "u")
        == "{}"
    )
    assert seen[0].get_header("Authorization") == "Bearer TEST"
    assert json.loads(seen[0].data)["model"] == "chosen"


def test_azure_resource_root_builds_the_deployment_url(monkeypatch):
    from urllib.request import OpenerDirector

    seen = []

    def respond(self, req, **kwargs):
        seen.append(req)
        return io.BytesIO(
            b'{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}'
        )

    monkeypatch.setattr(OpenerDirector, "open", respond)
    OpenAICompatibleLanguageModel(
        api_base="https://test.openai.azure.com",
        api_key="TEST",
        model="model-name",
        api_version="2024-10-21",
    ).complete("s", "u")
    assert seen[0].full_url == (
        "https://test.openai.azure.com/openai/deployments/model-name/"
        "chat/completions?api-version=2024-10-21"
    )
    assert seen[0].get_header("Api-key") == "TEST"


@pytest.mark.parametrize(
    "nested",
    [
        'unused := [p | p := "ok"]',
        'unused := {p | p := "ok"}',
        'every p in ["ok"] { p == "ok" }',
    ],
)
def test_nested_scope_cannot_certify_a_request_controlled_pattern(nested):
    plan = minimal_plan(
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "blocked",
                "conditions": [
                    nested,
                    "some p in input.policy_target.value.patterns",
                    "regex.match(p, input.policy_target.value.content)",
                ],
            }
        ]
    )
    with pytest.raises(GenerationError, match="nested condition scopes"):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt="synthetic", write=False
        )


@pytest.mark.parametrize("kind", [[], {}, 1, None])
def test_invalid_effect_type_is_repaired_without_a_typeerror(kind):
    bad = minimal_plan(
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact",
                "conditions": ['contains(input.policy_target.value.content, "secret")'],
                "effects": [{"type": kind, "path": "$target.content", "value": "x"}],
            }
        ]
    )
    model = StubLanguageModel([bad, minimal_plan()])
    result = GenerationEngine(model, max_attempts=2).generate(
        prompt="synthetic", write=False
    )
    assert result.attempts == 2
    assert "effect type" in model.prompts[1][1]


def test_oversized_path_index_is_rejected_even_when_smoke_rule_does_not_match():
    plan = minimal_plan(
        rules=[
            {
                "point": "pre_model_call",
                "decision": "transform",
                "reason": "rewrite",
                "conditions": ['input.snapshot.model.id == "production"'],
                "effects": [
                    {
                        "type": "replace",
                        "path": "$target[18446744073709551616]",
                        "value": {"role": "user", "content": "safe"},
                    }
                ],
            }
        ]
    )
    with pytest.raises(GenerationError, match="engine rejected transform path"):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt="synthetic", write=False
        )
