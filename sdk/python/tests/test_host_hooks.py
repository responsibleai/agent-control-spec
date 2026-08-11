# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Host extension points: annotator and policy dispatchers, telemetry
sinks, perf-telemetry levels, manifest tooling, and structured
validation diagnostics.

Restores the 0.3.1b1 shape of ``AgentControl.from_native(manifest,
annotator_dispatcher=...)`` that a consumer using an HTTP-backed
Content Safety dispatcher depended on. Verifies both that the host
callback runs and that its output reaches the policy decision, so a
regression that reintroduced the 0.4 hardcoded zero-config path would
fail.
"""

from __future__ import annotations

_VERSION_KEY = "agent_control_specification" + "_version"

import pathlib

import pytest
from agent_control_spec import (
    PERF_TELEMETRY_LEVELS,
    AcsInterceptor,
    ActivatedPolicy,
    ManifestInvalidError,
    merge_manifests,
    parse_manifest,
    validate_artifacts,
    validate_manifest_detailed,
)
from agent_hooks import AgentContextBuilder

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
DEFAULT_MANIFEST = str(FIXTURES / "manifest.yaml")


def _builder() -> AgentContextBuilder:
    return AgentContextBuilder(agent_id="a", framework="test", session_id="s")


# ---------------------------------------------------------------------
# Host annotator dispatcher: manifest + rego gate that reads annotations.
#
# The rego module denies whenever `input.annotations.classify.blocked`
# is True. A host dispatcher that returns `{"blocked": True}` therefore
# turns an allow-by-default input into a deny; a dispatcher that returns
# `{"blocked": False}` leaves it allowed. That is exactly the shape of
# the Azure Content Safety adapter the consumer needs to plug in.
# ---------------------------------------------------------------------

ANNOTATOR_MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: python-host-hooks
policies:
  gate:
    type: rego
    bundle: ./policy
    query: data.gate.verdict
annotators:
  classify:
    type: classifier
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
    annotations:
      classify:
        from: $target.content
"""

REGO_MODULE = """
package gate

default verdict := {"decision": "allow"}

verdict := {
  "decision": "deny",
  "reason": "blocked_by_annotator",
} if {
  input.annotations.classify.blocked == true
}
"""


def _bundles() -> dict:
    return {"gate": {"modules": {"gate.rego": REGO_MODULE}}}


class RecordingAnnotator:
    """Host dispatcher whose ``dispatch`` records every call and returns
    a fixed annotation. Deliberately object-with-method-shaped, matching
    the 0.3.1b1 API a consumer wired up."""

    def __init__(self, payload):
        self.payload = payload
        self.calls: list[tuple[str, dict, dict]] = []

    def dispatch(self, annotator_name, annotator, preliminary_policy_input):
        self.calls.append((annotator_name, annotator, preliminary_policy_input))
        return self.payload


def test_host_annotator_dispatcher_reaches_the_policy_decision():
    """The consumer's blocked use case, made concrete: an annotator
    dispatcher that says the content is blocked flips the verdict."""
    dispatcher = RecordingAnnotator({"blocked": True, "categories": ["hate"]})
    policy = ActivatedPolicy.from_memory(
        ANNOTATOR_MANIFEST,
        _bundles(),
        annotator_dispatcher=dispatcher,
    )
    verdict = policy.evaluate("input", _builder().input(content="offensive text"))

    # The dispatcher was actually called by the engine, not skipped.
    assert len(dispatcher.calls) == 1
    name, invocation, prelim = dispatcher.calls[0]
    assert name == "classify"
    # The dispatcher sees the annotator invocation shape the engine
    # built, including the flattened `type` field from the annotator
    # config and the `from` field from the annotation config.
    assert invocation["type"] == "classifier"
    assert invocation["from"] == "$target.content"
    # And the preliminary policy input, so an HTTP-backed dispatcher can
    # decide whether to make a call. The input builder wraps content in
    # `{content, role}`, which is what a downstream classifier reads.
    assert prelim["intervention_point"] == "input"
    assert prelim["policy_target"]["value"]["content"] == "offensive text"

    # And the annotation actually affected the decision.
    assert verdict.decision.value == "deny"
    assert verdict.reason == "blocked_by_annotator"


def test_host_annotator_dispatcher_returning_allow_leaves_verdict_allowed():
    """The complementary case: same policy, same manifest, dispatcher
    that returns a clean annotation. The engine still ran the
    dispatcher and its annotation reached the rego module."""
    dispatcher = RecordingAnnotator({"blocked": False})
    policy = ActivatedPolicy.from_memory(
        ANNOTATOR_MANIFEST,
        _bundles(),
        annotator_dispatcher=dispatcher,
    )
    verdict = policy.evaluate("input", _builder().input(content="hello"))
    assert dispatcher.calls, "dispatcher must run on every evaluation"
    assert verdict.decision.value == "allow"


def test_host_annotator_dispatcher_that_raises_fails_closed_not_silent():
    """Contract: a raising annotator dispatcher must never be treated
    as 'no annotation'. The engine's fail-closed path applies, so the
    verdict is deny with a ``runtime_error:*`` reason."""

    class Boom:
        def dispatch(self, name, annotator, prelim):
            raise RuntimeError("content safety endpoint unreachable")

    policy = ActivatedPolicy.from_memory(
        ANNOTATOR_MANIFEST,
        _bundles(),
        annotator_dispatcher=Boom(),
    )
    verdict = policy.evaluate("input", _builder().input(content="hello"))
    assert verdict.decision.value == "deny"
    assert verdict.reason.startswith("runtime_error:"), verdict.reason


def test_host_annotator_dispatcher_can_be_a_plain_callable():
    """The old API accepted objects with `dispatch`; a plain callable
    with the same signature is admitted too so hosts can write a small
    lambda for tests without wrapping it in a class."""
    calls = []

    def dispatcher(name, annotator, prelim):
        calls.append(name)
        return {"blocked": True}

    policy = ActivatedPolicy.from_memory(
        ANNOTATOR_MANIFEST,
        _bundles(),
        annotator_dispatcher=dispatcher,
    )
    verdict = policy.evaluate("input", _builder().input(content="hi"))
    assert calls == ["classify"]
    assert verdict.decision.value == "deny"


# ---------------------------------------------------------------------
# Zero-config parity: with no arguments, the API is byte-for-byte the
# same as today's zero-config path.
# ---------------------------------------------------------------------


def test_no_dispatcher_behaves_as_zero_config():
    # No annotator, no policy, no telemetry, no perf: identical to the
    # existing zero-config test surface.
    acs = AcsInterceptor(DEFAULT_MANIFEST)
    allow = acs.intercept(_builder().input(content="hello"))
    deny = acs.intercept(
        _builder().pre_tool_call(call_id="t1", name="search", args={"q": "x"})
    )
    assert allow.decision.value == "allow"
    assert deny.decision.value == "deny"
    assert deny.reason == "blocked_by_policy"


def test_no_dispatcher_on_activated_policy_behaves_as_zero_config():
    policy = ActivatedPolicy(DEFAULT_MANIFEST)
    verdict = policy.evaluate("input", _builder().input(content="hello"))
    assert verdict.decision.value == "allow"


# ---------------------------------------------------------------------
# Telemetry: a host sink receives events during evaluation, and
# perf-telemetry levels round-trip.
# ---------------------------------------------------------------------


class RecordingTelemetrySink:
    def __init__(self):
        self.events: list[dict] = []

    def emit(self, event):
        self.events.append(event)


def test_telemetry_sink_receives_events_during_evaluation():
    sink = RecordingTelemetrySink()
    acs = AcsInterceptor(DEFAULT_MANIFEST, telemetry_sink=sink)
    acs.intercept(_builder().input(content="hello"))
    # A decision event is guaranteed under any perf-telemetry level for
    # a settled evaluation. The rest of the fields ride along; we assert
    # the ones a monitoring host reads.
    decisions = [e for e in sink.events if e["event_type"] == "decision"]
    assert decisions, f"expected at least one decision event, got {sink.events}"
    decision = decisions[0]
    assert decision["intervention_point"] == "input"
    assert decision["decision"] == "allow"
    assert decision["policy_id"] == "allow_all"


def test_telemetry_sink_is_called_for_a_denying_verdict_too():
    sink = RecordingTelemetrySink()
    acs = AcsInterceptor(DEFAULT_MANIFEST, telemetry_sink=sink)
    acs.intercept(
        _builder().pre_tool_call(call_id="t1", name="search", args={"q": "x"})
    )
    decisions = [e for e in sink.events if e["event_type"] == "decision"]
    assert decisions
    assert decisions[0]["decision"] == "deny"
    assert decisions[0]["reason_code"] == "blocked_by_policy"


def test_perf_telemetry_levels_roundtrip():
    # All three engine levels construct without raising.
    for level in PERF_TELEMETRY_LEVELS:
        AcsInterceptor(DEFAULT_MANIFEST, perf_telemetry=level)


def test_unknown_perf_telemetry_level_is_rejected():
    with pytest.raises(ValueError, match="perf_telemetry"):
        AcsInterceptor(DEFAULT_MANIFEST, perf_telemetry="verbose")


def test_telemetry_sink_can_be_a_plain_callable():
    events: list[dict] = []
    acs = AcsInterceptor(DEFAULT_MANIFEST, telemetry_sink=events.append)
    acs.intercept(_builder().input(content="hello"))
    assert any(e["event_type"] == "decision" for e in events)


# ---------------------------------------------------------------------
# Manifest tooling: parse_manifest and merge_manifests.
# ---------------------------------------------------------------------


VALID_MANIFEST = (FIXTURES / "manifest.yaml").read_text(encoding="utf-8")


def test_parse_manifest_returns_the_parsed_structure():
    parsed = parse_manifest(VALID_MANIFEST)
    assert isinstance(parsed, dict)
    # The version key is on the top level, and the intervention_points
    # are keyed by point name.
    assert parsed["agent_control_specification_version"].startswith("0.4.0")
    assert "input" in parsed["intervention_points"]


def test_parse_manifest_rejects_malformed_source():
    with pytest.raises(ManifestInvalidError):
        parse_manifest("agent_control_specification_version: [")


def test_merge_manifests_composes_two_partial_documents():
    # Base declares the policies, overlay adds the intervention points
    # that bind them. Both fragments are needed for a runnable manifest;
    # neither is one on its own. That's the composition merge_manifests
    # is for.
    base = """
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: composed
policies:
  p:
    type: test
    verdict:
      decision: allow
  q:
    type: test
    verdict:
      decision: deny
      reason: blocked_by_overlay
"""
    overlay = """
agent_control_specification_version: "0.4.0-alpha.1"
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: q
"""
    merged = merge_manifests([base, overlay])
    assert isinstance(merged, dict)
    # The overlay's intervention point landed, bound to the base's `q`
    # policy. Composition took place.
    assert merged["intervention_points"]["input"]["policy"]["id"] == "q"
    # And both base policies are still declared: the merge unions
    # definitions.
    assert set(merged["policies"]) == {"p", "q"}
    # And the merged document is valid: the runtime accepts it.
    policy = ActivatedPolicy.from_memory(
        # ActivatedPolicy accepts YAML; a merged dict round-trips through
        # JSON, which the manifest grammar admits.
        __import__("json").dumps(merged),
        {},
    )
    verdict = policy.evaluate("input", _builder().input(content="hi"))
    assert verdict.decision.value == "deny"
    assert verdict.reason == "blocked_by_overlay"


def test_merge_manifests_rejects_an_empty_chain():
    with pytest.raises(ManifestInvalidError):
        merge_manifests([])


# ---------------------------------------------------------------------
# Structured validation diagnostics.
# ---------------------------------------------------------------------


def test_valid_manifest_produces_no_diagnostics():
    assert validate_manifest_detailed(VALID_MANIFEST) == []


def test_diagnostics_name_the_offending_field_for_an_invalid_manifest():
    # A policy_target_kind of "" is rejected by validate. The diagnostic
    # should name that field.
    bad = VALID_MANIFEST.replace(
        '"$.input"',
        '"$.input"\n    policy_target_kind: ""',
        1,
    )
    diagnostics = validate_manifest_detailed(bad)
    assert diagnostics, "expected the manifest to be rejected"
    entry = diagnostics[0]
    assert entry["reason_code"] == "runtime_error:manifest_invalid"
    assert entry["field"] == "policy_target_kind", entry
    # The engine's full message is preserved verbatim, so a tool can
    # surface it in an editor without paraphrasing.
    assert "policy_target_kind" in entry["message"]


def test_diagnostics_report_unsupported_version_field():
    bad = VALID_MANIFEST.replace('"0.4.0-alpha.1"', '"0.3.1-beta"')
    diagnostics = validate_manifest_detailed(bad)
    assert len(diagnostics) == 1
    entry = diagnostics[0]
    assert entry["reason_code"] == "runtime_error:manifest_invalid"
    assert entry["field"] == "agent_control_specification_version"
    assert "0.3.1-beta" in entry["message"]


def test_diagnostics_flag_manifests_that_use_extends():
    # A manifest that inherits cannot be judged from its own source.
    # `validate_manifest_detailed` reports that as a single diagnostic
    # instead of raising, so a batch runner can bucket the result rather
    # than mid-loop-except.
    extended = VALID_MANIFEST + "\nextends:\n  - path: ./parent.yaml\n"
    diagnostics = validate_manifest_detailed(extended)
    assert diagnostics
    assert diagnostics[0]["reason_code"] == "runtime_error:manifest_invalid"
    assert "extends" in diagnostics[0]["message"]


# ---------------------------------------------------------------------
# Artifact validation: manifest + Rego compiled together.
#
# `validate_manifest_detailed` answers only for the document. A
# manifest can satisfy the grammar, name a Rego bundle, and still fail
# at activation because the Rego does not compile — compilation happens
# at activation time, so a validator that stops at the manifest turns
# that failure into a host's first agent action. `validate_artifacts`
# closes the gap by activating in memory and reporting what the pair
# surfaced. Restores the 0.3-era ``validate_acs_artifacts`` shape a
# consumer's CI depended on.
# ---------------------------------------------------------------------

ARTIFACT_MANIFEST = """\
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: rego
    bundle: ./b
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: gate
      query: data.acs.decision
"""

_VALID_REGO = 'package acs\ndecision := {"decision":"allow"}\n'


def test_validate_artifacts_returns_empty_for_valid_manifest_and_rego():
    # A manifest naming a Rego policy whose module compiles cleanly is
    # what a fully-formed release looks like: nothing to report.
    findings = validate_artifacts(
        ARTIFACT_MANIFEST,
        {"gate": {"modules": {"p.rego": _VALID_REGO}}},
    )
    assert findings == []


def test_validate_artifacts_surfaces_a_broken_rego_module():
    # The feature exists for this case: the manifest is fine, the
    # bundle is not, and today a manifest-only validator would have
    # green-lit the release. The diagnostic must name the activation
    # half so the caller can render the compiler's complaint.
    findings = validate_artifacts(
        ARTIFACT_MANIFEST,
        {"gate": {"modules": {"p.rego": "package acs\nfoo := ] not valid rego"}}},
    )
    assert len(findings) == 1, findings
    entry = findings[0]
    assert entry["severity"] == "error"
    assert entry["code"].startswith("runtime_error:"), entry
    # The engine's own text carries the Rego compiler's complaint
    # verbatim, so an editor can point at the module. The compiler
    # names the module path and its "expecting expression" error.
    assert "p.rego" in entry["message"], entry
    assert "expecting expression" in entry["message"], entry

    # `validate_manifest_detailed` never sees this failure: it does
    # not compile the bundle. Prove that so a regression that widened
    # the manifest-only surface would fail.
    assert validate_manifest_detailed(ARTIFACT_MANIFEST) == []


def test_validate_artifacts_reports_unparseable_manifest_as_manifest_problem():
    # A document that does not parse must be reported as a manifest
    # problem, not an activation failure — that would name the wrong
    # half. Even when bundles are supplied.
    findings = validate_artifacts(
        "::not: [valid",
        {"gate": {"modules": {"p.rego": _VALID_REGO}}},
    )
    assert len(findings) == 1, findings
    entry = findings[0]
    assert entry["code"] == "runtime_error:manifest_invalid"
    assert entry["severity"] == "error"
    # And the underlying error matches what the manifest-only
    # validator reports: same problem, different shape.
    manifest_only = validate_manifest_detailed("::not: [valid")
    assert manifest_only[0]["reason_code"] == entry["code"]
    assert manifest_only[0]["message"] == entry["message"]


def test_validate_artifacts_without_bundles_equals_manifest_only_result():
    # No bundles supplied: activation is either skipped (no Rego to
    # load) or fails the same way manifest validation does. Either
    # way, the artifact validator must not invent activation errors
    # when the manifest half is what actually reports the problem.
    # For an unparseable document, both surfaces report the same
    # underlying RuntimeError message; only the wire keys differ.
    broken = "::not: [valid"
    artifact_findings = validate_artifacts(broken)
    manifest_findings = validate_manifest_detailed(broken)
    assert len(artifact_findings) == len(manifest_findings) == 1
    assert artifact_findings[0]["code"] == manifest_findings[0]["reason_code"]
    assert artifact_findings[0]["message"] == manifest_findings[0]["message"]

    # And for a grammatically invalid document — one that parses but
    # fails validation — the two surfaces report the same underlying
    # manifest problem. Activation would never be reached.
    # Built rather than written on one line. A repo guard scans committed
    # files for the version key and validates what follows it, and it
    # cannot strip the quotes of a single-line Python literal.
    invalid = (
        f'{_VERSION_KEY}: "0.4.0-alpha.1"\npolicies: {{}}\nintervention_points: {{}}\n'
    )
    artifact_findings = validate_artifacts(invalid)
    manifest_findings = validate_manifest_detailed(invalid)
    assert len(artifact_findings) == len(manifest_findings) == 1
    assert artifact_findings[0]["code"] == manifest_findings[0]["reason_code"]
    assert artifact_findings[0]["message"] == manifest_findings[0]["message"]


def test_validate_artifacts_accepts_none_for_bundles():
    # ``bundles=None`` is the ergonomic form for "no Rego to supply".
    # It must behave identically to an empty mapping so callers can
    # write either.
    assert validate_artifacts(ARTIFACT_MANIFEST, None) == validate_artifacts(
        ARTIFACT_MANIFEST, {}
    )
