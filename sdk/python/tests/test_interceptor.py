# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Wrapper contract: manifest-bound evaluation surfaces as agent-hooks
verdicts; engine failures fail closed; boundary errors raise."""

import asyncio
import pathlib

import pytest
from agent_control_spec import AcsInterceptor
from agent_hooks import AgentContextBuilder, EnforcementMode, InterceptionEmitter

MANIFEST = str(pathlib.Path(__file__).parent / "fixtures" / "manifest.yaml")


def builder() -> AgentContextBuilder:
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


def test_allow_policy_permits_input():
    acs = AcsInterceptor(MANIFEST)
    verdict = acs.intercept(builder().input(content="hello"))
    assert verdict.decision.value == "allow"


def test_deny_policy_blocks_tool_call_with_reason():
    acs = AcsInterceptor(MANIFEST)
    verdict = acs.intercept(
        builder().pre_tool_call(call_id="t1", name="search", args={"q": "x"})
    )
    assert verdict.decision.value == "deny"
    assert verdict.reason == "blocked_by_policy"
    assert verdict.approval is None


def test_approval_carrying_deny_is_liftable():
    acs = AcsInterceptor(MANIFEST)
    verdict = acs.intercept(builder().output(content="final answer"))
    assert verdict.decision.value == "deny"
    assert verdict.reason == "requires_human"
    assert verdict.approval == {}


def test_engine_failure_fails_closed_as_runtime_error_deny():
    acs = AcsInterceptor(MANIFEST)
    b = builder()
    b.pre_tool_call(call_id="t1", name="search", args={"q": "x"})
    verdict = acs.intercept(
        b.post_tool_call(call_id="t1", name="search", args={"q": "x"}, value="r")
    )
    assert verdict.decision.value == "deny"
    assert verdict.reason.startswith("runtime_error:")


def test_unreadable_manifest_is_construction_error():
    # The native manifest loader maps load failures to ValueError
    # (PyValueError in the binding).
    with pytest.raises(ValueError):
        AcsInterceptor("/nonexistent/manifest.yaml")


def test_registers_with_agent_hooks_emitter_end_to_end():
    async def run():
        emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
        emitter.register(AcsInterceptor(MANIFEST), "acs")
        b = builder()
        allowed = await emitter.emit_unchecked(b.input(content="hello"))
        assert allowed.verdict.decision.value == "allow"
        denied = await emitter.emit_unchecked(
            b.pre_tool_call(call_id="t1", name="search", args={"q": "x"})
        )
        assert denied.verdict.decision.value == "deny"
        assert denied.verdict.reason == "blocked_by_policy"

    asyncio.run(run())
