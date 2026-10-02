"""Adoption regressions: ordinary application shapes, not invented verdict inputs."""

import asyncio

import pytest
from test_packs import activate, composed, config, context, decide


@pytest.mark.parametrize("mode", ["deny", "redact"])
def test_model_can_request_tools_without_generating_text(mode):
    policy = activate("pii", config={**config("pii"), "action": mode})
    ctx = context("post_model_call")
    ctx["target"].update(
        content=None,
        finish_reason="tool_calls",
        tool_calls=[{"id": "c", "name": "search", "args": {"query": "returns"}}],
    )
    outcome = asyncio.run(composed(policy).emit(ctx))
    assert outcome.target["content"] is None
    assert outcome.target["tool_calls"][0]["name"] == "search"
    ctx["target"]["tool_calls"][0]["args"]["query"] = "a@example.com"
    decide(policy, ctx, "deny")


@pytest.mark.parametrize("value", [None, 0, [], {}, {"records": [{"id": 42}]}])
def test_structured_tool_results_without_pii_are_usable(value):
    ctx = context("post_tool_call")
    ctx["target"] = value
    decide(activate("pii"), ctx, "allow")
    # These filters are meant to compose on the same ordinary tool result.
    assert asyncio.run(
        composed(activate("credentials"), activate("pii")).emit(ctx)
    ).record.proceeds


@pytest.mark.parametrize("mode", ["deny", "redact"])
def test_nested_tool_result_pii_is_not_skipped(mode):
    ctx = context("post_tool_call", target={"records": [{"email": "a@example.com"}]})
    decide(activate("pii", config={**config("pii"), "action": mode}), ctx, "deny")


def test_deployment_approval_does_not_require_a_refund_workflow():
    policy = activate(
        "human-approval", config={"tools": {"deploy": {"mode": "review"}}}
    )
    verdict = decide(policy, context(tool="deploy", target={"version": "v1"}), "deny")
    assert verdict.approval is not None


@pytest.mark.parametrize(
    "value,expected,approvable",
    [
        (0, "allow", False),
        (100, "allow", False),
        (101, "deny", True),
        (True, "deny", False),
        (-1, "deny", False),
    ],
)
def test_generic_nested_argument_threshold(value, expected, approvable):
    policy = activate(
        "human-approval",
        config={
            "tools": {
                "provision": {
                    "mode": "threshold",
                    "argument_path": ["capacity", "instances"],
                    "max_without_approval": 100,
                }
            }
        },
    )
    verdict = decide(
        policy,
        context(tool="provision", target={"capacity": {"instances": value}}),
        expected,
    )
    assert (verdict.approval is not None) == approvable


@pytest.mark.parametrize(
    "rule",
    [
        {"mode": "allow", "max_without_approval": 10},
        {"mode": "threshold", "argument_path": [], "max_without_approval": 10},
        {"mode": "threshold", "argument_path": ["count"], "max_without_approval": True},
        {"mode": "review", "mode_typo": "allow"},
    ],
)
def test_bad_approval_configuration_does_not_enable_an_action(rule):
    policy = activate("human-approval", config={"tools": {"deploy": rule}})
    verdict = decide(policy, context(tool="deploy"), "deny", "approval_data_invalid")
    assert verdict.approval is None
