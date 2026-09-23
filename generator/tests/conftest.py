# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared fixtures. Every test runs against a scripted model, so the suite
performs no network input or output and needs no provider credential."""

from __future__ import annotations

import copy
from typing import Any

import pytest

PAYMENTS_PLAN: dict[str, Any] = {
    "name": "Payments Agent",
    "guarded_points": ["input", "pre_tool_call", "output"],
    "tools": ["wire_transfer"],
    "annotators": [{"name": "pii", "type": "classifier", "labels": ["account_number"]}],
    "rules": [
        {
            "point": "input",
            "decision": "deny",
            "reason": "credential_in_prompt",
            "message": "Do not paste passwords.",
            "conditions": [
                'contains(lower(input.policy_target.value.content), "password")'
            ],
        },
        {
            "point": "pre_tool_call",
            "decision": "escalate",
            "reason": "large_wire_needs_approval",
            "message": "A person must approve this.",
            "conditions": [
                'input.tool.id == "wire_transfer"',
                "input.policy_target.value.amount > 10000",
            ],
        },
        {
            "point": "output",
            "decision": "transform",
            "reason": "redact_account_number",
            "message": "Account numbers are masked.",
            "conditions": ["input.annotations.pii.detected == true"],
            "effects": [
                {"type": "redact", "path": "$target.content", "pattern": "acct_[0-9]+"}
            ],
        },
    ],
    "warnings": ["The threshold was inferred from the prose."],
}

TOOL_INVENTORY: dict[str, dict[str, Any]] = {
    "wire_transfer": {
        "type": "Tool",
        "id": "wire_transfer",
        "clearance": "confidential",
        "security_labels": ["banking"],
    }
}

PROSE = (
    "Payments agent. Block passwords in prompts, require approval for wire "
    "transfers above 10000, and mask account numbers in the final answer."
)


@pytest.fixture
def payments_plan() -> dict[str, Any]:
    """A fresh deep copy, so a test that mutates it cannot affect another."""
    return copy.deepcopy(PAYMENTS_PLAN)


@pytest.fixture
def tool_inventory() -> dict[str, dict[str, Any]]:
    return copy.deepcopy(TOOL_INVENTORY)


def minimal_plan(**overrides: Any) -> dict[str, Any]:
    """The smallest plan that compiles, for tests about one rule."""
    plan: dict[str, Any] = {
        "name": "Minimal",
        "guarded_points": ["input"],
        "rules": [
            {
                "point": "input",
                "decision": "deny",
                "reason": "blocked",
                "conditions": [
                    'contains(input.policy_target.value.content, "forbidden")'
                ],
            }
        ],
    }
    plan.update(overrides)
    return plan
