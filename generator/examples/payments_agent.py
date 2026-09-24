# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Generate a payments policy from a scripted response and evaluate it with ACS.

Run it:

    python generator/examples/payments_agent.py

The model is a `StubLanguageModel` holding one scripted plan, so the run is
deterministic and needs no provider credential. Swap in
`OpenAICompatibleLanguageModel()` and the same code calls a real provider.

The example annotator below is local test logic, not a content-safety service.
This example evaluates verdicts; it does not execute or enforce host actions.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import GenerationEngine, StubLanguageModel
from agent_hooks import AgentContextBuilder

GUARDRAILS = """
This is a retail banking assistant. It answers balance questions and can move
money with the wire_transfer tool.

Never let a caller paste a password into the conversation.
A wire transfer above 10000 needs a human to approve it before it runs.
Account numbers must never appear in the assistant's final answer.
"""

TOOL_INVENTORY: dict[str, dict[str, Any]] = {
    "wire_transfer": {
        "type": "Tool",
        "id": "wire_transfer",
        "clearance": "confidential",
        "security_labels": ["banking", "payments"],
    }
}

# What a model returns for the prose above. Scripted here so the example is
# reproducible; a live provider returns the same shape.
SCRIPTED_PLAN = {
    "name": "Payments Agent",
    "guarded_points": ["input", "pre_tool_call", "output"],
    "tools": ["wire_transfer"],
    "annotators": [{"name": "pii", "type": "classifier", "labels": ["account_number"]}],
    "rules": [
        {
            "point": "input",
            "decision": "deny",
            "reason": "credential_in_prompt",
            "message": "Do not paste passwords into the conversation.",
            "conditions": [
                'contains(lower(input.policy_target.value.content), "password")'
            ],
        },
        {
            "point": "pre_tool_call",
            "decision": "escalate",
            "reason": "large_wire_needs_approval",
            "message": "A person must approve a wire transfer above 10000.",
            "conditions": [
                'input.tool.id == "wire_transfer"',
                "input.policy_target.value.amount > 10000",
            ],
        },
        {
            "point": "output",
            "decision": "transform",
            "reason": "redact_account_number",
            "message": "Account numbers are masked in the final answer.",
            "conditions": ["input.annotations.pii.detected == true"],
            "effects": [
                {"type": "redact", "path": "$target.content", "pattern": "acct_[0-9]+"}
            ],
        },
    ],
    "warnings": [
        "The 10000 threshold was taken from the prose and is not currency aware."
    ],
}


class AccountNumberClassifier:
    """A local example dispatcher matching the generated annotation contract."""

    def dispatch(
        self,
        annotator_name: str,
        annotator: dict[str, Any],
        preliminary_policy_input: dict[str, Any],
    ) -> dict[str, Any]:
        value = preliminary_policy_input["policy_target"]["value"]
        text = value.get("content", "") if isinstance(value, dict) else str(value)
        return {"detected": "acct_" in text, "labels": ["account_number"]}


def show(verdict: Any, label: str) -> None:
    line = f"  {label:<34} {verdict.decision.value}"
    if verdict.reason:
        line += f"  reason={verdict.reason}"
    if verdict.approval is not None:
        line += "  approval=required"
    if verdict.warnings:
        line += f"  warnings={[w.reason for w in verdict.warnings]}"
    if verdict.transform is not None:
        line += f"  transform={verdict.transform.path}={verdict.transform.value!r}"
    print(line)


def main() -> int:
    engine = GenerationEngine(StubLanguageModel([SCRIPTED_PLAN]))
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "payments"
        result = engine.generate(
            prompt=GUARDRAILS,
            out_dir=out_dir,
            tool_inventory=TOOL_INVENTORY,
        )
        print(f"Generated '{result.slug}' in {result.attempts} model call(s).")
        print(f"Wrote: {', '.join(sorted(p.name for p in out_dir.iterdir()))}")
        for warning in result.warnings:
            print(f"Warning: {warning}")
        print()
        print("manifest.yaml")
        print("-------------")
        print(result.manifest_yaml)
        print(f"policy/{result.slug}.rego")
        print("-" * (len(result.slug) + 12))
        print(result.rego)

        print("Evaluating the generated policy through agent_control_spec")
        print("---------------------------------------------------------")
        policy = ActivatedPolicy.activate(
            str(out_dir / "manifest.yaml"),
            annotator_dispatcher=AccountNumberClassifier(),
        )
        builder = AgentContextBuilder(
            agent_id="payments-demo", framework="example", session_id="session-1"
        )
        show(
            policy.evaluate("input", builder.input(content="my password is hunter2")),
            "input with a password",
        )
        show(
            policy.evaluate("input", builder.input(content="what is my balance")),
            "ordinary input",
        )
        show(
            policy.evaluate(
                "pre_tool_call",
                builder.pre_tool_call(
                    call_id="call-1", name="wire_transfer", args={"amount": 25000}
                ),
            ),
            "wire transfer of 25000",
        )
        show(
            policy.evaluate(
                "pre_tool_call",
                builder.pre_tool_call(
                    call_id="call-2", name="wire_transfer", args={"amount": 40}
                ),
            ),
            "wire transfer of 40",
        )
        show(
            policy.evaluate(
                "output", builder.output(content="Sent from acct_99881 as requested.")
            ),
            "output naming an account",
        )
        show(
            policy.evaluate("output", builder.output(content="All set.")),
            "ordinary output",
        )
        print()
        print(
            "The escalation is a deny carrying an approval block, which the host "
            "lifts through its approval seam. The redaction is a transform the host "
            "applies to the policy target. Neither is enforced by the runtime."
        )
        print()
        print("report.md records what was and was not checked:")
        print(
            "\n".join(
                f"  {line}" for line in result.report.splitlines()[:6] if line.strip()
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
