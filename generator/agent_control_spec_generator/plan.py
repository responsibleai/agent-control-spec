# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Parse the model's JSON plan without coercing or dropping policy fields."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .conditions import ConditionError, inspect_conditions
from .vocabulary import ANNOTATOR_TYPES, DECISIONS, INTERVENTION_POINT_NAMES


class PlanError(ValueError):
    """The model response needs repair."""


@dataclass(frozen=True)
class AnnotatorPlan:
    name: str
    type: str
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnnotationBindingPlan:
    point: str
    annotator: str
    from_path: str


@dataclass(frozen=True)
class RulePlan:
    point: str
    decision: str
    reason: str
    message: str
    conditions: tuple[str, ...] = ()
    effects: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class PolicyPlan:
    name: str
    guarded_points: tuple[str, ...]
    annotators: tuple[AnnotatorPlan, ...] = ()
    annotations: tuple[AnnotationBindingPlan, ...] = ()
    tools: tuple[str, ...] = ()
    rules: tuple[RulePlan, ...] = ()
    warnings: tuple[str, ...] = ()


def _object(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlanError(f"{label} must be an object")
    unknown = value.keys() - allowed
    if unknown:
        raise PlanError(f"unsupported {label} fields: {', '.join(sorted(unknown))}")
    return value


def _string(value: Any, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise PlanError(f"{label} must be a {'non-empty ' if not empty else ''}string")
    return value


def _array(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise PlanError(f"'{key}' must be a JSON array")
    if len(value) > 128:
        raise PlanError(f"'{key}' exceeds the 128-entry authoring limit")
    return value


def _point(value: Any) -> str:
    if value not in INTERVENTION_POINT_NAMES:
        raise PlanError(
            f"unsupported rule point {value!r}; use {', '.join(INTERVENTION_POINT_NAMES)}"
        )
    return value


def _unique(values: list[str], label: str) -> None:
    if len(set(values)) != len(values):
        raise PlanError(f"duplicate {label}")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise PlanError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise PlanError(f"non-finite JSON value {value!r} is not supported")


def parse_policy_plan(raw: str) -> PolicyPlan:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 1_000_000:
        raise PlanError("model response must be text of at most 1 MB")
    try:
        data = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (ValueError, RecursionError) as exc:
        raise PlanError(f"LLM response is not valid JSON: {exc}") from exc
    data = _object(
        data,
        {
            "name",
            "metadata_name",
            "guarded_points",
            "annotators",
            "annotations",
            "tools",
            "rules",
            "warnings",
        },
        "JSON plan",
    )
    guarded = tuple(_point(value) for value in _array(data, "guarded_points"))
    annotators = []
    for item in _array(data, "annotators"):
        item = _object(item, {"name", "type", "labels"}, "annotator")
        kind = _string(item.get("type"), "annotator type")
        if kind not in ANNOTATOR_TYPES:
            raise PlanError(f"unsupported annotator type '{kind}'")
        annotators.append(
            AnnotatorPlan(
                _string(item.get("name"), "annotator name"),
                kind,
                tuple(
                    _string(label, "annotator label")
                    for label in _array(item, "labels")
                ),
            )
        )
    annotations = []
    for item in _array(data, "annotations"):
        item = _object(
            item, {"point", "annotator", "from", "from_path"}, "annotation binding"
        )
        annotations.append(
            AnnotationBindingPlan(
                _point(item.get("point")),
                _string(item.get("annotator"), "annotator name"),
                _string(
                    item.get("from", item.get("from_path", "$target")),
                    "annotation path",
                ),
            )
        )
    tools = []
    for tool in _array(data, "tools"):
        if isinstance(tool, dict):
            tool = _object(tool, {"id", "name"}, "tool reference")
            tool = tool.get("id", tool.get("name"))
        tools.append(_string(tool, "tool name"))
    rules = tuple(_rule(item) for item in _array(data, "rules"))
    if not rules:
        raise PlanError("plan must contain at least one explicit rule")
    transforms = [rule.point for rule in rules if rule.decision == "transform"]
    if len(transforms) != len(set(transforms)):
        raise PlanError(
            "only the first matching one of multiple transform rules would run; "
            "use one transform rule per point, with all same-path redactions in its effects"
        )
    _unique([item.name for item in annotators], "annotator declarations")
    _unique(
        [f"{item.point}/{item.annotator}" for item in annotations],
        "annotation bindings",
    )
    return PolicyPlan(
        _string(data.get("name", data.get("metadata_name")), "plan name"),
        guarded,
        tuple(annotators),
        tuple(annotations),
        tuple(tools),
        rules,
        tuple(_string(item, "warning") for item in _array(data, "warnings")),
    )


def _rule(item: Any) -> RulePlan:
    item = _object(
        item,
        {"point", "decision", "reason", "message", "conditions", "effects"},
        "rule",
    )
    point = _point(item.get("point"))
    decision = _string(item.get("decision"), "decision")
    if decision not in DECISIONS:
        raise PlanError(f"unsupported decision '{decision}'")
    reason = _string(item.get("reason", decision), "reason")
    if reason.startswith(("runtime_error:", "host_error:")):
        raise PlanError(
            "reason uses the reserved runtime_error: namespace or host_error: namespace"
        )
    effects = _array(item, "effects")
    if effects and decision != "transform":
        raise PlanError(
            "effects are allowed only on transform decisions; nothing will be dropped"
        )
    if decision == "transform":
        if point in {"agent_startup", "agent_shutdown"}:
            raise PlanError(
                "AGENT-HOOKS-0.1 section 4.3 forbids lifecycle transforms "
                "(host_error:transform_target_forbidden)"
            )
        if not effects:
            raise PlanError("transform carries no effect")
        for effect in effects:
            _effect(effect, point)
        if len({effect["path"] for effect in effects}) > 1:
            raise PlanError("a transform rule must target a single path")
        replaces = sum(effect["type"] == "replace" for effect in effects)
        if replaces and replaces != len(effects):
            raise PlanError("cannot mix replace and redact")
        if replaces > 1:
            raise PlanError("at most one replace effect is supported")
    conditions = tuple(
        _string(value, "condition") for value in _array(item, "conditions")
    )
    if not conditions and decision != "allow":
        raise PlanError("blocking or transforming rules need at least one condition")
    try:
        inspect_conditions(conditions, point)
    except ConditionError as exc:
        raise PlanError(str(exc)) from exc
    return RulePlan(
        point,
        decision,
        reason,
        _string(item.get("message", ""), "message", empty=True),
        conditions,
        tuple(effects),
    )


def transform_segments(path: str) -> tuple[str | int, ...]:
    """Parse the $target path grammar without changing the requested path."""
    if not path.startswith("$target"):
        raise PlanError(
            "effect path must start with $target (removed $policy_target root is not accepted)"
        )
    remaining = path[len("$target") :]
    segments: list[str | int] = []
    while remaining:
        if remaining.startswith("."):
            match = re.match(r"\.([A-Za-z_][A-Za-z0-9_]*)", remaining)
            if not match:
                raise PlanError("invalid transform path member")
            segments.append(match[1])
            remaining = remaining[match.end() :]
        elif remaining.startswith("["):
            try:
                value, end = json.JSONDecoder().raw_decode(remaining[1:])
            except ValueError:
                raise PlanError("invalid transform path index") from None
            if remaining[end + 1 : end + 2] != "]" or not (
                isinstance(value, str) or type(value) is int and value >= 0
            ):
                raise PlanError(
                    "transform indices must be quoted keys or non-negative integers"
                )
            segments.append(value)
            remaining = remaining[end + 2 :]
        else:
            raise PlanError("invalid transform path suffix")
    return tuple(segments)


def _effect(effect: Any, point: str) -> None:
    effect = _object(
        effect, {"type", "path", "pattern", "value", "replacement"}, "effect"
    )
    kind = _string(effect.get("type"), "effect type")
    if kind not in {"replace", "redact"}:
        raise PlanError(f"{kind} effect is not expressible; use replace or redact")
    path = _string(effect.get("path"), "effect path")
    segments = transform_segments(path)
    if point in {"input", "output", "post_model_call"} and segments:
        members = {
            "input": {"content", "role"},
            "output": {"content"},
            "post_model_call": {"content", "tool_calls", "finish_reason"},
        }[point]
        if segments[0] not in members:
            raise PlanError(
                f"{segments[0]!r} would not resolve in the standard target at '{point}'"
            )
    if point == "pre_model_call" and segments and not isinstance(segments[0], int):
        raise PlanError("pre_model_call target is an array; start with an array index")
    if kind == "replace":
        if "value" not in effect:
            raise PlanError("replace requires a 'value'")
        if "pattern" in effect or "replacement" in effect:
            raise PlanError("replace accepts a value, not pattern or replacement")
    else:
        _string(effect.get("pattern"), "redact requires a 'pattern'")
        if not segments and point != "post_tool_call":
            raise PlanError(
                "bare $target is not a string here; redaction can never fire; use $target.content"
            )
        if "value" in effect and "replacement" in effect:
            raise PlanError("redact accepts value or replacement, not both")
        for field in ("value", "replacement"):
            if field in effect:
                _string(effect[field], "redaction replacement", empty=True)


def redact_patterns(plan: PolicyPlan) -> tuple[str, ...]:
    return tuple(
        effect["pattern"]
        for rule in plan.rules
        for effect in rule.effects
        if effect["type"] == "redact"
    )


def condition_regex_patterns(plan: PolicyPlan) -> tuple[str, ...]:
    return tuple(
        pattern
        for rule in plan.rules
        for pattern in inspect_conditions(rule.conditions, rule.point).patterns
    )
