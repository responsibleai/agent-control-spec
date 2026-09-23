# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Two ACS policies guarding one inert tool invocation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from agent_control_spec import AcsInterceptor
from agent_hooks import (
    AgentContextBuilder,
    CompositionConfig,
    EnforcementMode,
    InterceptionBlocked,
    InterceptionEmitter,
    InterceptionRecord,
)

EXAMPLE = Path(__file__).resolve().parent


def make_emitter() -> InterceptionEmitter:
    emitter = InterceptionEmitter(
        mode=EnforcementMode.ENFORCE,
        composition=CompositionConfig.run_all(),
    )
    emitter.register(AcsInterceptor(str(EXAMPLE / "limits.yaml")), "limits")
    emitter.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
    emitter.set_max_records(100)
    return emitter


def issue_refund(ledger: list[dict[str, Any]], *, order_id: str, amount: float) -> None:
    """The operation under control: append to a local ledger, not a payment service."""
    ledger.append({"order_id": order_id, "amount": amount})


async def refund(
    emitter: InterceptionEmitter,
    context: dict[str, Any],
    ledger: list[dict[str, Any]],
) -> InterceptionRecord:
    try:
        outcome = await emitter.emit(context)
    except InterceptionBlocked as blocked:
        return blocked.result
    issue_refund(ledger, **outcome.target)
    return outcome.record


async def main(emitter: InterceptionEmitter) -> None:
    builder = AgentContextBuilder(
        agent_id="refund-assistant", framework="example", session_id="composition"
    )
    ledger: list[dict[str, Any]] = []
    for call_id, order_id, amount in (
        ("allow", "A-1001", 40),
        ("deny", "blocked-order", 40),
        ("transform", "A-1003", 150),
    ):
        context = builder.pre_tool_call(
            call_id=call_id,
            name="issue_refund",
            args={"order_id": order_id, "amount": amount},
        )
        record = await refund(emitter, context, ledger)
        contributions = [
            f"{item.name}={item.decision.value}" for item in record.verdicts
        ]
        print(
            f"{call_id}: combined={record.verdict.decision.value}, "
            f"proceeds={record.proceeds}, controls={', '.join(contributions)}"
        )
        emitter.take_records()
    assert ledger == [
        {"order_id": "A-1001", "amount": 40},
        {"order_id": "A-1003", "amount": 100},
    ]
    print(f"Executed refunds: {ledger}")


if __name__ == "__main__":
    # Construction loads policies before entering the example's event loop.
    asyncio.run(main(make_emitter()))
