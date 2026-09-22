"""Offline native ACS and agent-hooks host example. No model or tool is executed."""

import asyncio
from pathlib import Path

from agent_control_spec import AcsInterceptor
from agent_hooks import (
    AgentContextBuilder,
    CompositionConfig,
    CompositionProfile,
    InterceptionBlocked,
    InterceptionEmitter,
)

PACKS = Path(__file__).resolve().parent


def emitter(*names):
    host = InterceptionEmitter(
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL)
    )
    for name in names:
        host.register(AcsInterceptor(str(PACKS / name / "manifest.yaml")), name=name)
    return host


async def main():
    tools = emitter("tool-permissions", "human-approval", "credentials")
    output = emitter("pii", "credentials")
    builder = AgentContextBuilder(
        agent_id="support", framework="demo", session_id="demo"
    )
    # In a real host these values come from authenticated identity, not tool arguments.
    identity = {"policy_packs": {"subject": "alice", "roles": ["operator"]}}
    cases = [
        (
            "search",
            tools,
            builder.pre_tool_call(call_id="1", name="search", args={"q": "returns"}),
            True,
        ),
        (
            "approval",
            tools,
            builder.pre_tool_call(
                call_id="2", name="send_email", args={"body": "hello"}
            ),
            False,
        ),
        (
            "safe-output",
            output,
            builder.output(content="Your return is on its way"),
            True,
        ),
        (
            "pii-output",
            output,
            builder.output(content="Contact alice@example.com"),
            False,
        ),
        (
            "credential-output",
            output,
            builder.output(content="TOKEN=synthetic-demo-value"),
            False,
        ),
    ]
    for label, host, ctx, expected in cases:
        ctx["extensions"] = identity
        try:
            outcome = await host.emit(ctx)
        except InterceptionBlocked:
            assert not expected, label
            print(f"{label}: blocked")
        else:
            assert expected, label
            # The real operation must consume outcome.target, not pre-emission args.
            assert outcome.target is not None
            print(f"{label}: allowed")
    print("policy packs demo: PASS")


if __name__ == "__main__":
    asyncio.run(main())
