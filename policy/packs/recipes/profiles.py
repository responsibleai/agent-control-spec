"""Example assembly of the source policy artifacts. This is not a new public SDK."""

import json
import math
from pathlib import Path

from agent_control_spec import ActivatedPolicy, parse_manifest
from agent_hooks import (
    CompositionConfig,
    CompositionProfile,
    InterceptionEmitter,
    Verdict,
)

ROOT = Path(__file__).resolve().parents[1]


class Control:
    def __init__(self, name, *, config=None, tools=None, dispatcher=None, point=None):
        if name not in {p.parent.name for p in ROOT.glob("*/manifest.yaml")}:
            raise ValueError("Unknown policy control")
        manifest_path = ROOT / name / "manifest.yaml"
        manifest = parse_manifest(manifest_path.read_text())
        if point is not None:
            if point not in manifest["intervention_points"]:
                raise ValueError(f"{name} does not govern {point}")
            manifest["intervention_points"] = {
                point: manifest["intervention_points"][point]
            }
        if tools is not None:
            manifest["tools"] = tools
        definition = manifest["policies"]["gate"]
        modules = {
            "policy.rego": (manifest_path.parent / definition["bundle"]).read_text()
        }
        data = []
        for index, relative in enumerate(definition.pop("data_paths", [])):
            path = manifest_path.parent / relative
            if path.suffix == ".rego":
                modules[f"dependency-{index}.rego"] = path.read_text()
            else:
                document = json.loads(path.read_text())
                data.append(
                    {
                        "mount": [],
                        "document": document if config is None else {"pack": config},
                    }
                )
        self.policy = ActivatedPolicy.from_memory(
            json.dumps(manifest),
            {"gate": {"modules": modules, "data": data}},
            annotator_dispatcher=dispatcher,
        )

    def intercept(self, ctx):
        return self.policy.evaluate(ctx["interception_point"], ctx)


def emitter(*controls, resolver=None, timeout=5):
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Emitter timeout must be finite and positive")
    result = InterceptionEmitter(
        resolver=resolver,
        timeout=timeout,
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL),
    )
    for control in controls:
        result.register(control)
    return result


def document_emitters(*, resolver=None, max_operations=50, timeout=300):
    controls = [
        Control(
            "tool-permissions",
            tools={
                "read_document": {"allowed_roles": ["reader", "editor"]},
                "update_document": {"allowed_roles": ["editor"]},
            },
        ),
        Control(
            "resource-access",
            config={"operations": ["read", "write"], "require_same_tenant": True},
        ),
        Control("budgets", config={"limits": {"tool_calls": max_operations}}),
        Control("credentials"),
        Control(
            "human-approval",
            config={
                "tools": {
                    "read_document": {"mode": "allow"},
                    "update_document": {"mode": "review"},
                }
            },
        ),
    ]
    # The emitters share immutable controls, never mutable decision inputs.
    return (
        emitter(*controls, resolver=resolver, timeout=timeout),
        emitter(*controls, resolver=resolver, timeout=timeout),
    )


def http_emitter(origins):
    return emitter(
        Control("destinations", config={"origins": origins, "methods": ["GET"]}),
        Control("credentials"),
    )


def disclosure_emitter(*, redact=False):
    config = json.loads((ROOT / "pii/config.json").read_text())["pack"]
    config["action"] = "redact" if redact else "deny"
    # Credential denial precedes rewriting so redaction cannot erase that finding.
    return emitter(Control("credentials"), Control("pii", config=config))


class ClassifierDisclosure:
    """Screen every application-content field the supplied adapter will transmit."""

    def __init__(self, point):
        self.point = point
        self.control = Control("credentials", point=point)

    def intercept(self, ctx):
        if ctx["interception_point"] != self.point or self.point == "input":
            return self.control.intercept(ctx)
        extensions = ctx.get("extensions")
        if not isinstance(extensions, dict):
            return Verdict.deny(reason="classifier_context_invalid")
        metadata = extensions.get("policy_packs")
        if not isinstance(metadata, dict):
            return Verdict.deny(reason="classifier_context_invalid")
        prompt = metadata.get("user_prompt")
        if not isinstance(prompt, str) or not prompt:
            return Verdict.deny(reason="classifier_context_invalid")
        check = dict(ctx)
        check["target"] = {"document": ctx["target"], "user_prompt": prompt}
        return self.control.intercept(check)


def content_emitter(dispatcher, *, point="input"):
    if point not in {"input", "post_tool_call"}:
        raise ValueError("Content ingestion must be input or post_tool_call")
    controls = [
        ClassifierDisclosure(point),
        Control("content-safety", dispatcher=dispatcher, point=point),
        Control("prompt-injection", dispatcher=dispatcher, point=point),
    ]
    # Later classifiers perform I/O. Unlike pure policy composition, they must not
    # run after a disclosure denial.
    result = InterceptionEmitter(
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_FIRST_DENY)
    )
    for control in controls:
        result.register(control)
    return result
