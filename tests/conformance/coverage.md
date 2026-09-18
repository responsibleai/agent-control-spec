# ACS conformance coverage

| Spec section | Status | Claim | Cases and anchors |
| --- | --- | --- | --- |
| 1 Model and invariants | Partial | Stateless, deterministic, fail closed runtime behavior | `core/tests/fixture_cases.rs`, `tests/conformance/fail_closed_error_parity.json`, `core/tests/frozen_contract.rs` |
| 2 Manifest | Partial | Required manifest blocks and validation | `core/tests/manifest_extends.rs`, `core/tests/fixtures/manifests/`, `tests/conformance/fail_closed_error_parity.json` |
| 2.1 Version (dependencies) | Covered | `0.5.0-alpha.1` opt-in, original `0.4.0-alpha.1` extension semantics, unsupported-version rejection, and one version across an entire `extends` chain | `engine/tests/contract.rs`, `engine/tests/annotation_chaining.rs`, `engine/src/artifact_tests.rs`, `tests/conformance/bindings/cross_language_parity.py` |
| 2.2 Extends | Partial | Ordered parent loading coverage retained for ACS compatibility while AGT hosts submit flat manifests | `core/tests/manifest_extends.rs`, `core/tests/fixtures/extends/`, `core/src/manifest.rs` unit tests |
| 3 Paths | Covered | Missing paths, type mismatches, transform target confinement, and version-gated annotation reads with null distinct from missing | `tests/conformance/fail_closed_error_parity.json` cases `path-missing`, `tool-name-from-non-string`, `transform-target-forbidden`; `engine/tests/annotation_chaining.rs` |
| 4 Intervention points | Covered | Closed intervention point set and unconfigured point failure | `spec-08-intervention-points.case-01`, `spec-08-intervention-points.case-02`, `spec-08-intervention-points.case-03`, `spec-08-intervention-points.case-04`, `spec-08-intervention-points.case-05`, `spec-08-intervention-points.case-06`, `spec-08-intervention-points.case-07` |
| 5 Modes | Covered | `enforce` applies transforms while `evaluate_only` validates transforms without mutation | `spec-05-evaluate-only.case-01`, `spec-16-effects.case-01`, `spec-16-effects.case-02` |
| 6 Evaluation order | Covered | Policy target, tool projection, annotations, policy dispatch, normalization, transforms | `spec-10-annotators.case-01`, `spec-12-dispatcher.case-01`, `core/tests/fixture_cases.rs` |
| 7 Policy input | Partial | Canonical five member policy input shape | `core/tests/fixtures/policy-inputs/`, `core/tests/frozen_contract.rs`, `core/tests/wire_schemas.rs` |
| 8 Canonical serialization | Covered | Stable sorted object serialization for action identity | `spec-08-action-identity.case-08`, `core/tests/frozen_contract.rs`, `core/tests/security_conformance.rs` |
| 9 Tools | Covered | Tool projection, unknown tool fail closed behavior, optional host supplied invocation ID | `spec-09-tool-projection.case-01`, `spec-09-tool-projection.case-02`, `tests/conformance/fail_closed_error_parity.json` |
| 10 Annotators | Covered | Legacy lexical dispatch and empty annotations; `0.5.0-alpha.1` Kahn ordering after every completion, exactly-once successful graph execution, direct dependency inputs, and first-error termination | `spec-10-annotators.case-01`, `spec-10-annotators.case-02`, `spec-10-annotators.case-03`, `spec-10-annotators.case-04`, `engine/tests/annotation_chaining.rs`, `tests/conformance/bindings/cross_language_parity.py`, `tests/conformance/fail_closed_error_parity.json` cases `annotation-failed`, `annotation-timeout` |
| 11 Information flow control | Covered | Stateless label flow through source labels and tool metadata | `spec-18-ifc.case-01`, `spec-18-ifc.case-02` |
| 12 Policies | Covered | Rego, Cedar, test, custom policy config and dispatcher boundary | `spec-12-dispatcher.case-01`, `tests/conformance/fail_closed_error_parity.json` cases `policy-invocation-failed`, `policy-output-not-object`, `policy-output-missing-decision` |
| 13 Verdicts | Covered | Verdict normalization for allow, deny, warn, escalate, transform, invalid decisions, result labels, and evidence | `spec-08-intervention-points.case-01`, `spec-08-intervention-points.case-02`, `spec-08-intervention-points.case-03`, `spec-08-intervention-points.case-06`, `spec-14-verdict-normalization.case-01`, `spec-18-ifc.case-01`, `tests/parity/verdict_dispatch_canonical.json` |
| 14 Transforms | Covered | Transform validation, target confinement, application only for transform decisions, denial and escalation suppression | `spec-14-effects.case-06`, `spec-14-effects.case-07`, `spec-16-effects.case-01`, `spec-16-effects.case-02`, `spec-16-effects.case-03`, `spec-16-effects.case-04`, `spec-16-effects.case-05`, `tests/conformance/fail_closed_error_parity.json`, `tests/parity/verdict_dispatch_canonical.json` |
| 15 Resource limits | Covered | Runtime error fail closed resource limit behavior | `spec-15-resource-limits.case-01`, `tests/parity/resource_limits_canonical.json` |
| 16 Reserved reasons | Covered | Runtime errors map only to reserved reasons and legacy effects are rejected per AGT D1 | `tests/conformance/fail_closed_error_parity.json`, `tests/parity/error_mapping_canonical.json`, `spec-16-effects.case-01`, `spec-16-effects.case-02`, `spec-16-effects.case-03`, `spec-16-effects.case-04`, `spec-16-effects.case-05` |
| 17 Host obligations | Partial | Approval identity mismatch and escalation handling | `spec-08-action-identity.case-08`, `spec-17-approval.case-01`, `core/tests/security_conformance.rs` |
| 18 Streaming and parallel tools | Partial | Aggregated streaming outputs and per invocation tool mediation | `tests/conformance/streaming/manifest.json`, `core/tests/contract.rs` |
| 18.1 Incremental stream mediation | Partial | Rust only, behind the `streaming` cargo feature, so these run under `--all-features` as CI uses and are silently empty without it. Watermark contiguity and monotonicity, safety level release, transform and refusal fail closed paths, settlement residue, track separation, and rune counting. No cross SDK vectors, since no other SDK implements the profile; when one does, the set must include a term straddling a segment boundary under a bounded target, which is the case an undersized window silently misses | `engine/src/stream_session.rs`, `engine/tests/stream_session_properties.rs`, `engine/tests/stream_session_metamorphic.rs`, `engine/tests/stream_session_unicode.rs`, `engine/tests/stream_session_mediation.rs`, `engine/tests/stream_wire_conformance.rs` |
| 19 Telemetry and audit | Covered | Low cardinality telemetry, evidence keys, action identity, transform redaction | `tests/parity/telemetry_redaction_canonical.json`, `core/tests/contract.rs`, `core/tests/security_conformance.rs` |
| 20 Conformance | Partial | Runtime and host conformance definitions | This matrix plus SDK parity suites |
| 21 Security considerations | Partial | Fail closed, snapshot trust, annotation distrust, approvals, telemetry redaction | `docs/security-model.md`, `tests/parity/telemetry_redaction_canonical.json`, approval and fail closed fixtures |
| 22 Versioning and stability | Partial | Version pinning and breaking change policy | `core/tests/frozen_contract.rs`, `core/tests/wire_schemas.rs` |
| 23 References | Informative | Reference list only | No executable coverage required |

The chaining fixtures target `0.5.0-alpha.1`. Separate compatibility cases check
that `0.4.0-alpha.1` passes arbitrary `needs` JSON to dispatchers without changing
order or input. The shared binding runner exercises both contracts through Rust,
Python, Node, and .NET callbacks, including their effects on policy verdicts.

Dependency coverage must also distinguish ready-set ordering from layer batching,
direct dependencies from transitive ones, and selected `from` values from the full
dependency outputs and snapshot still visible to dispatchers. Other required
checks are declaration-level `needs` rejection, fetched-declaration provenance
restrictions, version-aware invocation stripping and legacy field forwarding,
preliminary and staged input depth checks without an early aggregate byte cap,
and JSON-encoded array strings in `metadata.annotation_needs` without payloads.
