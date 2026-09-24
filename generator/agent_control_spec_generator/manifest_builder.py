# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Build manifest bindings from the plan and parsed condition dependencies."""

from __future__ import annotations

import json
from typing import Any

from .conditions import inspect_conditions
from .plan import PlanError, PolicyPlan
from .util import slugify
from .vocabulary import INTERVENTION_POINT_BY_NAME, POLICY_TARGET, manifest_version


def validate_inventory(inventory: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(inventory, dict):
        raise ValueError("tool inventory must be a mapping")  # noqa: TRY004 - public input validation
    for name, entry in inventory.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(entry, dict):
            raise ValueError(
                "tool inventory requires non-empty names mapped to objects"
            )
        for field in ("id", "name"):
            if field in entry and (
                not isinstance(entry[field], str) or not entry[field].strip()
            ):
                raise ValueError(f"tool {field} must be a non-empty string")
    try:
        return json.loads(json.dumps(inventory, allow_nan=False))
    except (TypeError, ValueError, RecursionError):
        raise ValueError("tool inventory must contain finite JSON values") from None


def referenced_annotators_by_point(plan: PolicyPlan) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for rule in plan.rules:
        names = inspect_conditions(rule.conditions, rule.point).annotators
        if names:
            result.setdefault(rule.point, set()).update(names)
    return result


def referenced_tool_names(plan: PolicyPlan) -> list[str]:
    return sorted(
        set(plan.tools).union(
            *(
                inspect_conditions(rule.conditions, rule.point).tools
                for rule in plan.rules
            )
        )
    )


def build_tool_catalog(
    plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    catalog = validate_inventory(tool_inventory)
    known_ids = {entry.get("id", name) for name, entry in catalog.items()}
    for name in referenced_tool_names(plan):
        if name not in known_ids:
            catalog.setdefault(name, {})
    for name, entry in catalog.items():
        entry.setdefault("type", "Tool")
        entry.setdefault("id", name)
        entry.setdefault("name", name)
    return catalog


def build_manifest(
    plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], str]:
    slug = slugify(plan.name)
    tools = build_tool_catalog(plan, tool_inventory)
    if not tools and any(
        inspect_conditions(rule.conditions, rule.point).uses_tool for rule in plan.rules
    ):
        raise PlanError(
            "conditions read input.tool but no tools are declared; provide the inventory"
        )
    points = list(
        dict.fromkeys(
            [
                *plan.guarded_points,
                *(rule.point for rule in plan.rules),
                *(binding.point for binding in plan.annotations),
            ]
        )
    )
    references = referenced_annotators_by_point(plan)
    declared = {item.name: {"type": item.type} for item in plan.annotators}
    for binding in plan.annotations:
        if binding.annotator not in declared:
            raise PlanError(
                f"annotation binding names undeclared annotator '{binding.annotator}'"
            )
    manifest: dict[str, Any] = {
        "agent_control_specification_version": manifest_version(),
        "metadata": {"name": slug},
        "policies": {
            slug: {
                "type": "rego",
                "bundle": "./policy",
                "query": f"data.agent_control_specification.{slug}.verdict",
            }
        },
        "intervention_points": {},
    }
    for point in points:
        spec = INTERVENTION_POINT_BY_NAME[point]
        config: dict[str, Any] = {
            "policy_target": POLICY_TARGET,
            "policy_target_kind": spec.policy_target_kind,
            "policy": {
                "id": slug,
                "query": f"data.agent_control_specification.{slug}.{point}_verdict",
            },
        }
        if tools and spec.tool_name_from:
            config["tool_name_from"] = spec.tool_name_from
        annotations = {
            binding.annotator: {"from": binding.from_path}
            for binding in plan.annotations
            if binding.point == point
        }
        for name in sorted(references.get(point, set())):
            declared.setdefault(name, {"type": "classifier"})
            annotations.setdefault(name, {"from": "$target"})
        if annotations:
            config["annotations"] = annotations
        manifest["intervention_points"][point] = config
    if tools:
        manifest["tools"] = tools
    if declared:
        manifest["annotators"] = declared
    return manifest, slug
