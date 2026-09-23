# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compile generated artifacts and run limited smoke cases through ACS.

Condition parsing happens before this module runs. Smoke success establishes
neither policy completeness nor coverage of a host's actual inputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml
from agent_control_spec import ActivatedPolicy
from agent_control_spec import validate_artifacts as _engine_validate
from agent_hooks import AgentContextBuilder

from .vocabulary import manifest_version

_REGEX_PROBE_PACKAGE = "acs_generator_regex_probe"


@dataclass
class ValidationResult:
    warnings: list[str] = field(default_factory=list)


class ValidationError(RuntimeError):
    """A generated artifact the engine rejects. The message is fed back to
    the model as a repair diagnostic."""


class _NullAnnotator:
    """Answers every annotator with an empty annotation.

    Smoke evaluation must not perform network input or output, and a declared
    `llm` or `endpoint` annotator would otherwise reach a bundled dispatcher
    that needs a credential and fail closed with
    `runtime_error:annotation_failed`, which says nothing about the generated
    artifact. An empty annotation still proves the binding resolves.
    """

    def dispatch(
        self,
        annotator_name: str,
        annotator: dict[str, Any],
        preliminary_policy_input: dict[str, Any],
    ) -> dict[str, Any]:
        return {}


def dump_manifest_yaml(manifest: dict[str, Any]) -> str:
    """Serialize a manifest document to YAML the engine parses."""
    return yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False)


def validate_artifacts(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
    *,
    regex_patterns: tuple[str, ...] = (),
    transform_paths: tuple[str, ...] = (),
) -> ValidationResult:
    """Compile the pair, check collected regex patterns, then smoke-evaluate."""
    warnings: list[str] = []
    _validate_with_engine(manifest_yaml, rego, slug)
    check_regex_patterns(tuple(dict.fromkeys(regex_patterns)))
    check_transform_paths(tuple(dict.fromkeys(transform_paths)))
    warnings.extend(smoke_evaluate(manifest, manifest_yaml, rego, slug))
    return ValidationResult(warnings)


def _bundles(rego: str, slug: str) -> dict[str, dict[str, Any]]:
    return {slug: {"modules": {f"{slug}.rego": rego}}}


def check_transform_paths(paths: tuple[str, ...]) -> None:
    """Exercise ACS's authoritative path parser even if no smoke rule fires."""
    if not paths:
        return
    manifest = dump_manifest_yaml(
        {
            "agent_control_specification_version": manifest_version(),
            "policies": {
                "probe": {
                    "type": "rego",
                    "bundle": "./policy",
                    "query": "data.path_probe.verdict",
                }
            },
            "intervention_points": {
                "input": {
                    "policy_target": "$.target",
                    "policy": {"id": "probe"},
                }
            },
        }
    )
    module = """package path_probe
verdict := {"decision": "transform", "transform": {
    "path": input.policy_target.value.content, "value": "probe"
}}
"""
    policy = ActivatedPolicy.from_memory(
        manifest, {"probe": {"modules": {"probe.rego": module}}}
    )
    builder = AgentContextBuilder(
        agent_id="generator", framework="path-check", session_id="probe"
    )
    for path in paths:
        verdict = policy.evaluate("input", builder.input(content=path))
        if verdict.decision.value != "transform":
            raise ValidationError(
                f"engine rejected transform path {path!r}: {verdict.reason}"
            )


def _validate_with_engine(manifest_yaml: str, rego: str, slug: str) -> None:
    diagnostics = _engine_validate(manifest_yaml, _bundles(rego, slug))
    if diagnostics:
        raise ValidationError(
            "engine rejected the generated artifacts: "
            + "; ".join(
                f"{item.get('code')}: {item.get('message')}" for item in diagnostics
            )
        )


def check_regex_patterns(patterns: tuple[str, ...]) -> None:
    """Compile each pattern through the engine's regex engine.

    Python's `re` is not consulted. It accepts lookaround and backreferences
    the engine rejects, and rejects Unicode class syntax such as `\\p{L}` the
    engine accepts, so it would both pass bad patterns and fail good ones.
    """
    if not patterns:
        return
    manifest = dump_manifest_yaml(
        {
            "agent_control_specification_version": manifest_version(),
            "metadata": {"name": _REGEX_PROBE_PACKAGE},
            "policies": {
                "probe": {
                    "type": "rego",
                    "bundle": "./policy",
                    "query": f"data.{_REGEX_PROBE_PACKAGE}.verdict",
                }
            },
            "intervention_points": {
                "input": {
                    "policy_target": "$.target",
                    "policy_target_kind": "user_input",
                    "policy": {
                        "id": "probe",
                        "query": f"data.{_REGEX_PROBE_PACKAGE}.verdict",
                    },
                }
            },
        }
    )
    # `regex.replace("", p, "")` is `""` for any pattern that compiles and is
    # undefined for any that does not, independent of what the pattern
    # matches. The index of each compiling pattern is collected, so one
    # evaluation reports on the whole set.
    module = (
        f"package {_REGEX_PROBE_PACKAGE}\n\n"
        "import rego.v1\n\n"
        f"patterns := {json.dumps(list(patterns))}\n\n"
        "compiles contains i if {\n"
        "\tsome i, p in patterns\n"
        '\tregex.replace("", p, "") == ""\n'
        "}\n\n"
        'verdict := {"decision": "allow", "reason": concat(",", '
        '[sprintf("%d", [i]) | some i in compiles])}\n'
    )
    policy = ActivatedPolicy.from_memory(
        manifest, {"probe": {"modules": {"probe.rego": module}}}
    )
    verdict = policy.evaluate(
        "input",
        AgentContextBuilder(
            agent_id="acs-generator", framework="acs-generator", session_id="probe"
        ).input(content=""),
    )
    reason = verdict.reason or ""
    if reason.startswith("runtime_error:"):
        raise ValidationError(
            f"could not check generated redact patterns against the engine: {reason}"
        )
    compiled = {int(index) for index in reason.split(",") if index}
    rejected = [pattern for i, pattern in enumerate(patterns) if i not in compiled]
    if rejected:
        raise ValidationError(
            "the engine's regex engine rejects these redact patterns, which would "
            "make the redaction rule silently stop redacting: "
            + ", ".join(repr(pattern) for pattern in rejected)
        )


def smoke_evaluate(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
) -> list[str]:
    """Evaluate one synthetic context per guarded point. Returns warnings."""
    warnings: list[str] = []
    try:
        policy = ActivatedPolicy.from_memory(
            manifest_yaml,
            _bundles(rego, slug),
            annotator_dispatcher=_NullAnnotator(),
        )
    except (RuntimeError, ValueError) as exc:
        raise ValidationError(f"generated policy failed to activate: {exc}") from exc
    tool_names = sorted(manifest.get("tools", {}))
    builder = AgentContextBuilder(
        agent_id="acs-generator", framework="acs-generator", session_id="smoke"
    )
    for point in manifest["intervention_points"]:
        contexts = _contexts_for(point, builder, tool_names)
        if not contexts:
            raise ValidationError(
                f"no smoke context could be built for guarded point '{point}', so it "
                "would be reported as evaluated without being evaluated"
            )
        for context in contexts:
            verdict = policy.evaluate(point, context)
            reason = verdict.reason or ""
            if reason.startswith("runtime_error:"):
                raise ValidationError(
                    f"generated policy fails closed at '{point}' on a well-formed "
                    f"agent-hooks context with {reason}"
                )
    if not tool_names:
        guarded_tool_points = [
            point
            for point in manifest["intervention_points"]
            if point in ("pre_tool_call", "post_tool_call")
        ]
        if guarded_tool_points:
            warnings.append(
                "No tool is declared, so "
                + ", ".join(guarded_tool_points)
                + " is guarded without tool projection and input.tool is null in "
                "every evaluation. Supply a tool inventory to gate on tool identity."
            )
    return warnings


def _contexts_for(
    point: str, builder: AgentContextBuilder, tool_names: list[str]
) -> list[dict[str, Any]]:
    """Well-formed agent-hooks contexts for one point.

    Every declared tool gets its own context at a tool point, because tool
    projection is per call and an entry the catalog declares but cannot
    project would otherwise go unexercised. With no catalog the point is
    still exercised once with an arbitrary tool name, because the manifest
    then omits `tool_name_from` and nothing is projected. Skipping it would
    leave a guarded point unevaluated while the report claims otherwise.
    """
    text = "acs-generator smoke evaluation"
    names = tool_names or ["acs_generator_smoke_tool"]
    if point == "agent_startup":
        return [builder.agent_startup(tools_registered=list(tool_names))]
    if point == "input":
        return [builder.input(content=text)]
    if point == "pre_model_call":
        return [
            builder.pre_model_call(
                model_id="acs-generator-smoke",
                messages=[{"role": "user", "content": text}],
            )
        ]
    if point == "post_model_call":
        return [
            builder.post_model_call(
                model_id="acs-generator-smoke",
                content=text,
                tool_calls=[],
                finish_reason="stop",
            )
        ]
    if point == "pre_tool_call":
        return [
            builder.pre_tool_call(call_id=f"smoke-{name}", name=name, args={})
            for name in names
        ]
    if point == "post_tool_call":
        return [
            builder.post_tool_call(
                call_id=f"smoke-{name}", name=name, args={}, value=text
            )
            for name in names
        ]
    if point == "output":
        return [builder.output(content=text)]
    if point == "agent_shutdown":
        return [builder.agent_shutdown(reason="completed")]
    raise ValidationError(f"unsupported smoke point '{point}'")
