"""Evaluate refund requests with a local provider. No refunds are executed."""

from pathlib import Path

from agent_control_spec import ActivatedPolicy
from agent_hooks import AgentContextBuilder


def main() -> None:
    calls = []

    def eligibility(name, _invocation, policy_input):
        if name != "eligibility":
            raise ValueError("unknown provider")
        calls.append(policy_input["policy_target"]["value"]["order_id"])
        return {"eligible": True, "max_amount_cents": 20000}

    policy = ActivatedPolicy.activate(
        str(Path(__file__).with_name("manifest.yaml")),
        annotator_dispatcher=eligibility,
    )
    builder = AgentContextBuilder(
        agent_id="refund-agent", framework="example", session_id="example-session"
    )
    for index, amount in enumerate([9999, 12000, 25000]):
        context = builder.pre_tool_call(
            call_id=f"call-{index}",
            name="issue_refund",
            args={"order_id": f"order-{index}", "amount_cents": amount},
        )
        before = len(calls)
        verdict = policy.evaluate("pre_tool_call", context)
        print(
            f"{amount} cents: {verdict.decision.value}, "
            f"provider calls: {len(calls) - before}"
        )


if __name__ == "__main__":
    main()
