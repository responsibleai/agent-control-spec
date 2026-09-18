# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""ACS policy vocabulary and standard agent-hooks target shapes."""

from dataclasses import dataclass

from agent_control_spec import supported_manifest_versions

ANNOTATOR_TYPES = frozenset({"classifier", "llm", "endpoint"})
# warn/escalate are policy intents, not additional agent-hooks verdicts.
DECISIONS = frozenset({"allow", "warn", "deny", "escalate", "transform"})
MAX_REPAIR_ATTEMPTS = 5
POLICY_INPUT_POINT_KEY = "intervention_point"
POLICY_TARGET = "$.target"


@dataclass(frozen=True)
class InterventionPointSpec:
    name: str
    policy_target_kind: str
    tool_name_from: str | None = None


INTERVENTION_POINTS = (
    InterventionPointSpec("agent_startup", "agent_metadata"),
    InterventionPointSpec("input", "user_input"),
    InterventionPointSpec("pre_model_call", "model_request"),
    InterventionPointSpec("post_model_call", "model_response"),
    InterventionPointSpec("pre_tool_call", "tool_args", "$.tool_call.name"),
    InterventionPointSpec("post_tool_call", "tool_result", "$.tool_call.name"),
    InterventionPointSpec("output", "assistant_output"),
    InterventionPointSpec("agent_shutdown", "shutdown_summary"),
)
INTERVENTION_POINT_NAMES = tuple(point.name for point in INTERVENTION_POINTS)
INTERVENTION_POINT_BY_NAME = {point.name: point for point in INTERVENTION_POINTS}
TARGET_SHAPES = {
    "agent_startup": '{"tools_registered": [string]}',
    "input": '{"content": any JSON, "role": string}',
    "pre_model_call": '[{"role": string, "content": any JSON}, ...]',
    "post_model_call": '{"content": any JSON, "tool_calls": [...], "finish_reason": string}',
    "pre_tool_call": "tool arguments object",
    "post_tool_call": "tool result value, any JSON type",
    "output": '{"content": any JSON}',
    "agent_shutdown": '{"reason": string}',
}


def manifest_version() -> str:
    # Do not silently switch to a new grammar that this renderer has not ported.
    version = "0.4.0-alpha.1"
    if version not in supported_manifest_versions():
        raise RuntimeError(
            f"installed engine does not support generator grammar {version}"
        )
    return version
