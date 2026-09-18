# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared native evaluation of an immutable context snapshot."""

import json

from agent_hooks import Verdict

from agent_control_spec import _native


def evaluate_wire(handle: object, point: str, context_json: str) -> Verdict:
    wire = _native.policy_evaluate(handle, point, context_json)
    return Verdict.from_wire(json.loads(wire))
