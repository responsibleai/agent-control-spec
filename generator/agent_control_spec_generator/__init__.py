# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Generate ACS policy artifacts from natural-language guardrails.

A caller describes an agent, through a system prompt, a plain description,
or a statement of policy, and this package asks a language model for a
constrained policy plan, compiles that plan into an ACS manifest and a Rego
module, and validates both with `agent_control_spec`, the engine that will
evaluate them. Artifacts are written only after validation passes.

    from pathlib import Path
    from agent_control_spec_generator import GenerationEngine
    from agent_control_spec_generator.llm import OpenAICompatibleLanguageModel

    result = GenerationEngine(OpenAICompatibleLanguageModel()).generate(
        prompt="Block wire transfers over 10000 without approval.",
        out_dir=Path("build/payments"),
        tool_inventory={"wire_transfer": {"type": "Tool", "clearance": "confidential"}},
    )

The output is a draft. A model wrote the rules, the engine checked only that
they load and evaluate, and nothing here establishes that they express the
intent of the prose. Review `report.md` and every rule before binding the
policy to an agent.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from .engine import GenerationEngine, GenerationError, GenerationResult
from .llm import LanguageModel, OpenAICompatibleLanguageModel, StubLanguageModel
from .plan import PlanError, PolicyPlan, parse_policy_plan
from .validation import ValidationError

__all__ = [
    "GenerationEngine",
    "GenerationError",
    "GenerationResult",
    "LanguageModel",
    "OpenAICompatibleLanguageModel",
    "PlanError",
    "PolicyPlan",
    "StubLanguageModel",
    "ValidationError",
    "parse_policy_plan",
]

#: Read from the installed distribution rather than written here, for the
#: reason the binding records: a literal is one more version surface, and it
#: is the one nothing checks, so it goes stale quietly.
try:
    __version__ = _distribution_version("agent-control-spec-generator")
except PackageNotFoundError:  # pragma: no cover - source tree, not installed
    __version__ = "0.0.0.dev0"
