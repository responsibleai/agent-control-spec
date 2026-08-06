# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Activating a policy whose manifest and Rego are held in memory.

A service that keeps both in a database has no directory to point a
manifest at, so these pin that a bundle supplied as values evaluates,
that two such bundles stay apart in the policy cache, and that the same
policy activated from disk and from memory decides alike.
"""

import pathlib

import pytest
from agent_control_spec import ActivatedPolicy, ManifestInvalidError
from agent_hooks import AgentContextBuilder

MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: python-in-memory
policies:
  gate:
    type: rego
    bundle: ./policy
    query: data.gate.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"""


def module(decision: str, reason: str) -> str:
    return f'package gate\n\nverdict := {{"decision": "{decision}", "reason": "{reason}"}}\n'


def bundle(decision: str, reason: str) -> dict:
    return {"modules": {"gate.rego": module(decision, reason)}}


def activate(decision: str, reason: str) -> ActivatedPolicy:
    return ActivatedPolicy.from_memory(MANIFEST, {"gate": bundle(decision, reason)})


def context():
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s").input(
        content="hello"
    )


def decide(policy: ActivatedPolicy):
    verdict = policy.evaluate("input", context())
    assert not (verdict.reason or "").startswith("runtime_error:"), (
        f"policy failed rather than decided: {verdict.reason}"
    )
    return verdict


def test_bundle_supplied_in_memory_produces_a_verdict():
    verdict = decide(activate("deny", "refused"))
    assert verdict.decision.value == "deny"
    assert verdict.reason == "refused"


def test_two_in_memory_bundles_keep_their_own_verdicts():
    allowing = activate("allow", "permitted")
    denying = activate("deny", "refused")

    # Both orders, because a cache keyed on something other than bundle
    # content would serve whichever was activated first.
    assert decide(denying).reason == "refused"
    assert decide(allowing).reason == "permitted"
    assert decide(activate("deny", "refused")).reason == "refused"


def test_same_policy_from_disk_and_from_memory_decides_alike(tmp_path: pathlib.Path):
    source = module("deny", "refused")
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "gate.rego").write_text(source)
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(MANIFEST)

    from_disk = decide(ActivatedPolicy(str(manifest_path)))
    from_memory = decide(
        ActivatedPolicy.from_memory(
            MANIFEST, {"gate": {"modules": {"gate.rego": source}}}
        )
    )

    assert from_disk.to_wire() == from_memory.to_wire()


def test_data_documents_are_mounted_where_asked():
    supplied = {
        "modules": {
            "gate.rego": (
                "package gate\n\n"
                'default verdict := {"decision": "allow"}\n\n'
                'verdict := {"decision": "deny", "reason": data.limits.reason} '
                "if { data.limits.blocked }\n"
            )
        },
        "data": [
            {"mount": ["limits"], "document": {"blocked": True, "reason": "over_limit"}}
        ],
    }
    verdict = decide(ActivatedPolicy.from_memory(MANIFEST, {"gate": supplied}))
    assert verdict.decision.value == "deny"
    assert verdict.reason == "over_limit"


def test_unsupplied_relative_bundle_path_is_rejected():
    # Nothing supplies `gate`, so its `./policy` would resolve against
    # the process working directory.
    with pytest.raises(ManifestInvalidError, match="relative bundle or data path"):
        ActivatedPolicy.from_memory(MANIFEST, {})


def test_bundle_for_an_undeclared_policy_is_rejected():
    with pytest.raises(ValueError):
        ActivatedPolicy.from_memory(MANIFEST, {"nope": bundle("allow", "permitted")})


def test_unparseable_manifest_is_rejected():
    with pytest.raises(ValueError):
        ActivatedPolicy.from_memory("policies: [", {})


def test_in_memory_activation_governs_the_same_points():
    policy = activate("allow", "permitted")
    assert policy.intervention_points == ("input",)
    assert policy.governs("input")
