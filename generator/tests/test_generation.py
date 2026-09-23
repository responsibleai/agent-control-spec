# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Generation end to end, with a scripted model.

The assertions that matter are the ones made through `agent_control_spec`
itself. A generated manifest that parses but denies every tool call, or a
redaction rule that never fires, both look correct as text.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from agent_control_spec import ActivatedPolicy, supported_manifest_versions
from agent_control_spec_generator import (
    GenerationEngine,
    GenerationError,
    StubLanguageModel,
)
from agent_control_spec_generator.vocabulary import INTERVENTION_POINT_NAMES
from agent_hooks import AgentContextBuilder
from conftest import PROSE, minimal_plan


class Classifier:
    """Host annotator returning a fixed detection for the account pattern."""

    def dispatch(self, name: str, annotator: dict, prelim: dict) -> dict:
        value = prelim["policy_target"]["value"]
        text = value.get("content", "") if isinstance(value, dict) else str(value)
        return {"detected": "acct_" in text}


def generate(
    plans: list[Any],
    tmp_path: Path,
    *,
    tool_inventory: dict[str, dict[str, Any]] | None = None,
    prompt: str = PROSE,
    write: bool = True,
):
    """Run one generation against a scripted model, returning both."""
    model = StubLanguageModel(plans)
    result = GenerationEngine(model).generate(
        prompt=prompt,
        out_dir=tmp_path / "out",
        tool_inventory=tool_inventory,
        write=write,
    )
    return result, model


def builder() -> AgentContextBuilder:
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


def test_happy_path_writes_the_three_artifacts(payments_plan, tool_inventory, tmp_path):
    result, model = generate([payments_plan], tmp_path, tool_inventory=tool_inventory)

    assert result.attempts == 1
    assert len(model.prompts) == 1
    out = tmp_path / "out"
    assert (out / "manifest.yaml").read_text(encoding="utf-8") == result.manifest_yaml
    assert (out / "policy" / f"{result.slug}.rego").read_text(
        encoding="utf-8"
    ) == result.rego
    assert (out / "report.md").read_text(encoding="utf-8") == result.report


def test_the_prose_and_the_inventory_both_reach_the_model(
    payments_plan, tool_inventory, tmp_path
):
    _, model = generate([payments_plan], tmp_path, tool_inventory=tool_inventory)
    system, user = model.prompts[0]

    assert "Return JSON only" in system
    for point in INTERVENTION_POINT_NAMES:
        assert point in system
    assert PROSE in user
    assert "wire_transfer" in user


def test_manifest_version_comes_from_the_engine(payments_plan, tmp_path):
    """A literal here would go stale the first time the engine's grammar
    moves, and the manifest would then fail closed at load."""
    result, _ = generate([payments_plan], tmp_path)
    document = yaml.safe_load(result.manifest_yaml)

    assert (
        document["agent_control_specification_version"] in supported_manifest_versions()
    )


def test_the_generated_policy_actually_decides(payments_plan, tool_inventory, tmp_path):
    """The whole point. Load the written artifacts into the runtime a host
    embeds and check each rule produces the verdict the prose asked for."""
    generate([payments_plan], tmp_path, tool_inventory=tool_inventory)
    policy = ActivatedPolicy.activate(
        str(tmp_path / "out" / "manifest.yaml"), annotator_dispatcher=Classifier()
    )
    b = builder()

    denied = policy.evaluate("input", b.input(content="my password is hunter2"))
    assert (denied.decision.value, denied.reason) == ("deny", "credential_in_prompt")

    allowed = policy.evaluate("input", b.input(content="what is my balance"))
    assert allowed.decision.value == "allow"

    # `escalate` normalizes to a liftable deny carrying an approval block.
    escalated = policy.evaluate(
        "pre_tool_call",
        b.pre_tool_call(call_id="c1", name="wire_transfer", args={"amount": 25000}),
    )
    assert escalated.decision.value == "deny"
    assert escalated.reason == "large_wire_needs_approval"
    assert escalated.approval is not None

    small = policy.evaluate(
        "pre_tool_call",
        b.pre_tool_call(call_id="c2", name="wire_transfer", args={"amount": 40}),
    )
    assert small.decision.value == "allow"

    redacted = policy.evaluate("output", b.output(content="sent from acct_99881"))
    assert redacted.decision.value == "transform"
    assert redacted.transform.path == "$target.content"
    assert redacted.transform.value == "sent from [REDACTED]"

    clean = policy.evaluate("output", b.output(content="all set"))
    assert clean.decision.value == "allow"


def test_a_warn_rule_normalizes_to_allow_carrying_a_warning(tmp_path):
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "warn",
                "reason": "off_topic",
                "message": "This looks off topic.",
                "conditions": [
                    'contains(input.policy_target.value.content, "weather")'
                ],
            }
        ]
    )
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))

    verdict = policy.evaluate("input", builder().input(content="the weather today"))
    assert verdict.decision.value == "allow"
    assert [w.reason for w in verdict.warnings] == ["off_topic"]


@pytest.mark.parametrize("point", INTERVENTION_POINT_NAMES)
def test_every_intervention_point_resolves_its_policy_target(point, tmp_path):
    """Regression for the retarget. The predecessor named a per-point L1
    member, and `$.model_request` and `$.model_response` do not exist in an
    agent-hooks context, so `pre_model_call` and `post_model_call` failed
    closed with `runtime_error:path_missing` on every evaluation."""
    plan = minimal_plan(
        guarded_points=[point],
        tools=["calculator"],
        rules=[
            {
                "point": point,
                "decision": "deny",
                "reason": "never_matches",
                "conditions": ['input.snapshot.session.id == "no-such-session"'],
            }
        ],
    )
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    b = builder()
    contexts = {
        "agent_startup": lambda: b.agent_startup(tools_registered=["calculator"]),
        "input": lambda: b.input(content="hi"),
        "pre_model_call": lambda: b.pre_model_call(
            model_id="m", messages=[{"role": "user", "content": "hi"}]
        ),
        "post_model_call": lambda: b.post_model_call(
            model_id="m", content="hi", tool_calls=[], finish_reason="stop"
        ),
        "pre_tool_call": lambda: b.pre_tool_call(
            call_id="c", name="calculator", args={"expr": "1+1"}
        ),
        "post_tool_call": lambda: b.post_tool_call(
            call_id="c", name="calculator", args={"expr": "1+1"}, value="2"
        ),
        "output": lambda: b.output(content="2"),
        "agent_shutdown": lambda: b.agent_shutdown(reason="done"),
    }

    verdict = policy.evaluate(point, contexts[point]())
    assert verdict.decision.value == "allow"
    assert not (verdict.reason or "").startswith("runtime_error:")


def test_tool_projection_is_omitted_when_no_tool_is_declared(tmp_path):
    """`tool_name_from` with an empty catalog fails closed with
    `runtime_error:tool_unknown` on every tool call, turning "guard tool
    arguments" into "deny every tool call"."""
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "too_large",
                "conditions": ["input.policy_target.value.amount > 10000"],
            }
        ],
    )
    result, _ = generate([plan], tmp_path)
    document = yaml.safe_load(result.manifest_yaml)

    assert "tool_name_from" not in document["intervention_points"]["pre_tool_call"]
    assert "tools" not in document
    assert any("guarded without tool projection" in w for w in result.warnings)

    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    verdict = policy.evaluate(
        "pre_tool_call",
        builder().pre_tool_call(call_id="c", name="anything", args={"amount": 1}),
    )
    assert verdict.decision.value == "allow"


def test_tool_names_are_recovered_from_rule_conditions(tmp_path):
    """A name a rule gates on but the plan forgot to list would otherwise
    make every call to that tool fail closed with `runtime_error:tool_unknown`."""
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        tools=[],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "forbidden_tool",
                "conditions": ['input.tool.id == "delete_files"'],
            }
        ],
    )
    result, _ = generate([plan], tmp_path)
    document = yaml.safe_load(result.manifest_yaml)

    assert "delete_files" in document["tools"]
    assert document["intervention_points"]["pre_tool_call"]["tool_name_from"]

    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    verdict = policy.evaluate(
        "pre_tool_call",
        builder().pre_tool_call(call_id="c", name="delete_files", args={}),
    )
    assert (verdict.decision.value, verdict.reason) == ("deny", "forbidden_tool")


def test_annotator_bindings_are_recovered_from_rule_conditions(tmp_path):
    """A rule reading `input.annotations.pii` whose plan declared no binding
    would read an always-empty annotation, so the rule could never fire."""
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "pii_detected",
                "conditions": ["input.annotations.pii.detected == true"],
            }
        ],
    )
    result, _ = generate([plan], tmp_path)
    document = yaml.safe_load(result.manifest_yaml)

    assert document["annotators"]["pii"]["type"] == "classifier"
    assert (
        document["intervention_points"]["input"]["annotations"]["pii"]["from"]
        == "$target"
    )

    policy = ActivatedPolicy.activate(
        str(tmp_path / "out" / "manifest.yaml"),
        annotator_dispatcher=lambda name, annotator, prelim: {"detected": True},
    )
    verdict = policy.evaluate("input", builder().input(content="anything"))
    assert (verdict.decision.value, verdict.reason) == ("deny", "pii_detected")


def test_a_rule_at_an_unguarded_point_still_guards_that_point(tmp_path):
    """A rule whose point the manifest does not guard is compiled into the
    Rego and never queried, so it reads as written and enforces nothing."""
    plan = minimal_plan(
        guarded_points=["input"],
        rules=[
            {
                "point": "output",
                "decision": "deny",
                "reason": "leaked",
                "conditions": ['contains(input.policy_target.value.content, "secret")'],
            }
        ],
    )
    result, _ = generate([plan], tmp_path)

    assert "output" in yaml.safe_load(result.manifest_yaml)["intervention_points"]
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    verdict = policy.evaluate("output", builder().output(content="the secret is x"))
    assert (verdict.decision.value, verdict.reason) == ("deny", "leaked")


def test_target_dot_value_preserves_a_real_nested_tool_result_member(tmp_path):
    plan = _tool_redaction_plan("$target.value")
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    verdict = policy.evaluate(
        "post_tool_call",
        builder().post_tool_call(
            call_id="c",
            name="lookup",
            args={},
            value={"value": "acct_4242", "other": "keep"},
        ),
    )
    assert verdict.transform.path == "$target.value"
    assert verdict.transform.value == "[REDACTED]"


def test_a_redaction_at_the_tool_result_root_compiles_and_fires(tmp_path):
    """The complementary case. At `post_tool_call` the target may itself be a
    string, so the bare root is the right path there."""
    result, _ = generate([_tool_redaction_plan("$target")], tmp_path)

    assert '"path": "$target"' in result.rego
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    verdict = policy.evaluate(
        "post_tool_call",
        builder().post_tool_call(
            call_id="c", name="lookup", args={}, value="found acct_4242"
        ),
    )
    assert verdict.decision.value == "transform"
    assert verdict.transform.value == "found [REDACTED]"


def _tool_redaction_plan(path: str) -> dict:
    return minimal_plan(
        guarded_points=["post_tool_call"],
        tools=["lookup"],
        rules=[
            {
                "point": "post_tool_call",
                "decision": "transform",
                "reason": "mask",
                "conditions": ['input.tool.id == "lookup"'],
                "effects": [{"type": "redact", "path": path, "pattern": "acct_[0-9]+"}],
            }
        ],
    )


def test_effects_on_a_non_transform_decision_fail_generation(tmp_path):
    plan = minimal_plan()
    plan["rules"][0]["effects"] = [
        {"type": "redact", "path": "$target.content", "pattern": "x"}
    ]
    with pytest.raises(GenerationError, match="nothing will be dropped"):
        generate([plan], tmp_path)
    assert not (tmp_path / "out").exists()


def test_a_tool_without_an_inventory_entry_is_reported(tmp_path):
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        tools=["undocumented_tool"],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "blocked",
                "conditions": ['input.tool.id == "undocumented_tool"'],
            }
        ],
    )
    result, _ = generate([plan], tmp_path)

    assert any("undocumented_tool" in warning for warning in result.warnings)


def test_a_rejected_plan_is_repaired_with_the_engine_diagnostic(
    payments_plan, tmp_path
):
    """The repair prompt carries the diagnostic verbatim, so the model fixes
    what was actually wrong instead of guessing."""
    broken = json.loads(json.dumps(payments_plan))
    broken["rules"][0]["conditions"] = []
    result, model = generate([broken, payments_plan], tmp_path)

    assert result.attempts == 2
    assert len(model.prompts) == 2
    repair_prompt = model.prompts[1][1]
    assert "at least one condition" in repair_prompt
    assert PROSE in repair_prompt, "repair must not drop the original intent"


def test_generation_fails_and_writes_nothing_when_every_attempt_is_rejected(tmp_path):
    broken = minimal_plan()
    broken["rules"][0]["point"] = "not_a_point"
    model = StubLanguageModel([broken])
    out = tmp_path / "out"

    with pytest.raises(GenerationError) as excinfo:
        GenerationEngine(model, max_attempts=3).generate(prompt=PROSE, out_dir=out)

    assert len(model.prompts) == 3
    assert "not_a_point" in str(excinfo.value)
    assert not out.exists(), "a failed generation must not leave a partial policy"


def test_write_false_produces_artifacts_without_touching_disk(payments_plan, tmp_path):
    model = StubLanguageModel([payments_plan])
    out = tmp_path / "out"

    result = GenerationEngine(model).generate(prompt=PROSE, out_dir=out, write=False)

    assert result.manifest_yaml
    assert not out.exists()


def test_an_empty_prompt_is_refused_before_any_model_call(tmp_path):
    model = StubLanguageModel([minimal_plan()])

    with pytest.raises(ValueError, match="prompt is empty"):
        GenerationEngine(model).generate(prompt="   ", out_dir=tmp_path / "out")

    assert model.prompts == []


def test_importing_the_package_reads_no_credential_and_calls_nothing(monkeypatch):
    """A CI job that imports the package must not need a provider.

    An audit hook is the precise instrument here: it fails on an actual
    connection attempt rather than on any use of the socket module, which
    the standard library itself imports.
    """
    import subprocess
    import sys

    for name in (
        "ACS_GENERATOR_API_KEY",
        "ACS_GENERATOR_API_BASE",
        "ACS_GENERATOR_MODEL",
        "ACS_GENERATOR_API_VERSION",
    ):
        monkeypatch.delenv(name, raising=False)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "def hook(event, args):\n"
                "    if event in ('socket.connect', 'urllib.Request'):\n"
                "        raise AssertionError('network at import time: ' + event)\n"
                "sys.addaudithook(hook)\n"
                "from agent_control_spec_generator.llm import "
                "OpenAICompatibleLanguageModel\n"
                "print(OpenAICompatibleLanguageModel().api_key is None)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "True"


def test_every_supplied_tool_reaches_the_catalog(tmp_path):
    """A supplied tool left out of the catalog fails closed with
    `runtime_error:tool_unknown` on every call to it. Keeping only the tools a
    rule happens to mention therefore bricks the rest of the agent's tools the
    moment a tool point is guarded."""
    inventory = {
        "wire_transfer": {"type": "Tool", "id": "wire_transfer"},
        "lookup_balance": {"type": "Tool", "id": "lookup_balance"},
        "send_email": {"type": "Tool"},
    }
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        tools=["wire_transfer"],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "blocked",
                "conditions": ['input.tool.id == "wire_transfer"'],
            }
        ],
    )
    generate([plan], tmp_path, tool_inventory=inventory)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))
    b = builder()

    blocked = policy.evaluate(
        "pre_tool_call", b.pre_tool_call(call_id="c", name="wire_transfer", args={})
    )
    assert (blocked.decision.value, blocked.reason) == ("deny", "blocked")
    for name in ("lookup_balance", "send_email"):
        verdict = policy.evaluate(
            "pre_tool_call", b.pre_tool_call(call_id="c", name=name, args={})
        )
        assert verdict.decision.value == "allow", (
            f"{name} was bricked: {verdict.reason}"
        )


def test_a_catalog_entry_without_an_id_still_gates_on_tool_id(tmp_path):
    """Generated rules read `input.tool.id` and fall back to
    `input.tool.name`. An entry carrying neither leaves both undefined, so the
    rule can never fire."""
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        tools=["send_email"],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "no_email",
                "conditions": ['input.tool.id == "send_email"'],
            }
        ],
    )
    generate([plan], tmp_path, tool_inventory={"send_email": {"type": "Tool"}})
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))

    verdict = policy.evaluate(
        "pre_tool_call",
        builder().pre_tool_call(call_id="c", name="send_email", args={}),
    )
    assert (verdict.decision.value, verdict.reason) == ("deny", "no_email")


def test_a_tool_name_compared_the_other_way_round_is_recovered(tmp_path):
    plan = minimal_plan(
        guarded_points=["pre_tool_call"],
        tools=[],
        rules=[
            {
                "point": "pre_tool_call",
                "decision": "deny",
                "reason": "forbidden_tool",
                "conditions": ['"delete_files" == input.tool.id'],
            }
        ],
    )
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))

    verdict = policy.evaluate(
        "pre_tool_call",
        builder().pre_tool_call(call_id="c", name="delete_files", args={}),
    )
    assert (verdict.decision.value, verdict.reason) == ("deny", "forbidden_tool")


def test_a_fully_bracketed_annotation_read_is_wired(tmp_path):
    plan = minimal_plan(
        rules=[
            {
                "point": "input",
                "decision": "deny",
                "reason": "pii_detected",
                "conditions": ['input["annotations"]["pii"].detected == true'],
            }
        ],
    )
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(
        str(tmp_path / "out" / "manifest.yaml"),
        annotator_dispatcher=lambda name, annotator, prelim: {"detected": True},
    )

    verdict = policy.evaluate("input", builder().input(content="anything"))
    assert (verdict.decision.value, verdict.reason) == ("deny", "pii_detected")


def test_a_stale_policy_module_does_not_survive_regeneration(tmp_path):
    """A manifest names its bundle as a directory and the engine loads every
    Rego file in it, so a module left by an earlier run under a different slug
    is still loaded and can fail activation for a policy that just validated."""
    out = tmp_path / "out"
    generate([minimal_plan(name="First")], tmp_path)
    stale = out / "policy" / "stale.rego"
    stale.write_text("package broken\n\nbroken ::= \n", encoding="utf-8")

    GenerationEngine(StubLanguageModel([minimal_plan(name="Second")])).generate(
        prompt=PROSE, out_dir=out, force=True
    )

    assert not stale.exists()
    assert sorted(p.name for p in (out / "policy").iterdir()) == ["second.rego"]
    ActivatedPolicy.activate(str(out / "manifest.yaml"))


def test_two_transform_rules_at_one_point_are_rejected(tmp_path):
    """Rules at a point compile to one else-chain, so the first match wins and
    the second redaction never runs. Its sensitive value would be emitted in
    full by a policy that reads as though it removes both."""
    plan = minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact_account",
                "conditions": ['contains(input.policy_target.value.content, "acct_")'],
                "effects": [
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "acct_[0-9]+",
                    }
                ],
            },
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact_token",
                "conditions": ['contains(input.policy_target.value.content, "tok_")'],
                "effects": [
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "tok_[a-z]+",
                    }
                ],
            },
        ],
    )
    with pytest.raises(GenerationError) as excinfo:
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt=PROSE, out_dir=tmp_path / "out", write=False
        )
    assert "only the first matching one" in str(excinfo.value)


def test_one_rule_carrying_both_patterns_redacts_both(tmp_path):
    """The expressible form the rejection above points the model at."""
    plan = minimal_plan(
        guarded_points=["output"],
        rules=[
            {
                "point": "output",
                "decision": "transform",
                "reason": "redact_secrets",
                "conditions": ['contains(input.policy_target.value.content, "_")'],
                "effects": [
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "acct_[0-9]+",
                    },
                    {
                        "type": "redact",
                        "path": "$target.content",
                        "pattern": "tok_[a-z]+",
                    },
                ],
            }
        ],
    )
    generate([plan], tmp_path)
    policy = ActivatedPolicy.activate(str(tmp_path / "out" / "manifest.yaml"))

    verdict = policy.evaluate(
        "output", builder().output(content="acct_4242 and tok_abc")
    )
    assert verdict.decision.value == "transform"
    assert verdict.transform.value == "[REDACTED] and [REDACTED]"
