"""Example assembly of the source policy artifacts. This is not a new public SDK."""

import json
from pathlib import Path

from agent_control_spec import ActivatedPolicy, parse_manifest
from agent_hooks import CompositionConfig, CompositionProfile, InterceptionEmitter

ROOT = Path(__file__).resolve().parents[1]


class Control:
    def __init__(self, name, *, config=None, tools=None, dispatcher=None):
        if name not in {p.parent.name for p in ROOT.glob("*/manifest.yaml")}:
            raise ValueError("Unknown policy control")
        manifest_path = ROOT / name / "manifest.yaml"
        manifest = parse_manifest(manifest_path.read_text())
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


def emitter(*controls, resolver=None):
    result = InterceptionEmitter(
        resolver=resolver,
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL),
    )
    for control in controls:
        result.register(control)
    return result


def document_emitters(*, resolver=None, max_operations=50):
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
    return emitter(*controls, resolver=resolver), emitter(*controls, resolver=resolver)


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


def content_emitter(dispatcher, *, point="input"):
    if point not in {"input", "post_tool_call"}:
        raise ValueError("Content ingestion must be input or post_tool_call")
    controls = [
        Control("credentials"),
        Control("content-safety", dispatcher=dispatcher),
        Control("prompt-injection", dispatcher=dispatcher),
    ]
    # Later classifiers perform I/O. Unlike pure policy composition, they must not
    # run after a disclosure denial.
    result = InterceptionEmitter(
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_FIRST_DENY)
    )
    for control in controls:
        result.register(control)
    return result
