//! Evidence over the AGENT-HOOKS-0.1 section 5.3 cap degrades the
//! evidence, not the verdict (specification section 13.3).
//!
//! Every test here drives the public `Runtime` API through a custom
//! `PolicyDispatcher`, the way a host that returns its own evidence
//! would.

use agent_control_spec::{
    AcsInterceptor, AnnotatorDispatcher, AnnotatorInvocation, Decision, Evidence,
    InterceptionPoint, JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation, Runtime,
    RuntimeError, Verdict, Warning,
};
use agent_hooks::{
    canonical_json, AgentContextBuilder, EnforcementMode, InterceptionEmitter, InterceptionRecord,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// AGENT-HOOKS-0.1 section 5.3: maximum canonical byte length of the
/// `evidence` member. Restated here so the tests do not lean on the
/// engine's own constant.
const CAP: usize = 10_240;

const TRUNCATED: &str = "evidence_truncated";

const MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
  pre_tool_call:
    policy:
      id: test_policy
    policy_target: $snap.tool_call.args
"#;

struct NoAnnotators;

impl AnnotatorDispatcher for NoAnnotators {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(json!({}))
    }
}

struct StaticPolicy(JsonValue);

impl PolicyDispatcher for StaticPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        Ok(self.0.clone())
    }
}

fn runtime(output: JsonValue) -> Runtime {
    let manifest = Manifest::from_yaml_str(MANIFEST).expect("manifest");
    Runtime::new(
        manifest,
        Arc::new(NoAnnotators),
        Arc::new(StaticPolicy(output)),
    )
    .expect("runtime")
}

fn evaluate(output: JsonValue) -> Verdict {
    runtime(output)
        .evaluate_point(
            InterceptionPoint::Input,
            json!({"input": {"text": "hello"}}),
        )
        .verdict
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `sha256:<hex>` over the RFC 8785 canonical form of `evidence`,
/// computed with the SDK serializer and nothing from the engine.
fn evidence_digest(evidence: &JsonValue) -> String {
    format!(
        "sha256:{}",
        hex(&Sha256::digest(canonical_json(evidence).as_bytes()))
    )
}

fn canonical_len(evidence: &JsonValue) -> usize {
    canonical_json(evidence).len()
}

fn pointer_key(index: usize) -> String {
    format!("ptr_{index:03}")
}

fn pointer_url(index: usize) -> String {
    format!("https://example.com/pointers/{index:03}")
}

/// `count` pointers of identical width, so the kept count below can be
/// derived arithmetically rather than by re-running the engine's rule.
fn pointers(count: usize) -> JsonValue {
    let map: serde_json::Map<String, JsonValue> = (0..count)
        .map(|index| (pointer_key(index), JsonValue::String(pointer_url(index))))
        .collect();
    JsonValue::Object(map)
}

fn evidence_with(artefact: &str, pointer_count: usize) -> JsonValue {
    json!({"artefact": artefact, "verification_pointers": pointers(pointer_count)})
}

/// The largest key-order prefix of equal-width pointers that fits under
/// the cap next to `artefact`. Each extra pointer adds a constant number
/// of canonical bytes, so two measurements fix the whole series.
fn expected_kept(artefact: &str, total: usize) -> usize {
    let one = canonical_len(&evidence_with(artefact, 1));
    let two = canonical_len(&evidence_with(artefact, 2));
    let per_pointer = two - one;
    assert!(one <= CAP, "test shape: one pointer must fit");
    let kept = 1 + (CAP - one) / per_pointer;
    assert!(kept < total, "test shape: not every pointer may fit");
    kept
}

fn the_truncation_warning(verdict: &Verdict) -> &Warning {
    let found: Vec<&Warning> = verdict
        .warnings
        .iter()
        .filter(|warning| warning.reason.as_deref() == Some(TRUNCATED))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one truncation warning: {verdict:#?}"
    );
    found[0]
}

fn assert_no_truncation_warning(verdict: &Verdict) {
    assert!(
        verdict
            .warnings
            .iter()
            .all(|warning| warning.reason.as_deref() != Some(TRUNCATED)),
        "no truncation warning expected: {verdict:#?}"
    );
}

fn kept_evidence(verdict: &Verdict) -> &Evidence {
    verdict.evidence.as_ref().expect("evidence stays present")
}

fn kept_size(verdict: &Verdict) -> usize {
    let value = serde_json::to_value(kept_evidence(verdict)).unwrap();
    canonical_len(&value)
}

// (a) The reporter's shape: a transform verdict with many pointers.

#[test]
fn transform_with_ten_pointers_passes_unchanged() {
    let evidence = evidence_with("sha256:abc", 10);
    let verdict = evaluate(json!({
        "decision": "transform",
        "reason": "redacted",
        "message": "account redacted",
        "transform": {"path": "$target.text", "value": "[redacted]"},
        "evidence": evidence,
        "result_labels": ["pii"],
    }));

    assert_eq!(verdict.decision, Decision::Transform);
    assert_eq!(verdict.reason.as_deref(), Some("redacted"));
    assert_eq!(verdict.message.as_deref(), Some("account redacted"));
    assert!(verdict.warnings.is_empty());
    assert_eq!(
        serde_json::to_value(kept_evidence(&verdict)).unwrap(),
        evidence
    );
}

#[test]
fn transform_with_oversize_pointers_keeps_the_verdict_and_degrades_the_evidence() {
    let artefact = "sha256:abc";
    let total = 250;
    let evidence = evidence_with(artefact, total);
    let original_size = canonical_len(&evidence);
    assert!(
        original_size > CAP,
        "test shape: evidence must exceed the cap"
    );
    let expected_kept = expected_kept(artefact, total);

    let verdict = evaluate(json!({
        "decision": "transform",
        "reason": "redacted",
        "message": "account redacted",
        "transform": {"path": "$target.text", "value": "[redacted]"},
        "evidence": evidence,
        "result_labels": ["pii"],
    }));

    // The verdict is untouched.
    assert_eq!(verdict.decision, Decision::Transform);
    assert_eq!(verdict.reason.as_deref(), Some("redacted"));
    assert_eq!(verdict.message.as_deref(), Some("account redacted"));
    let transform = verdict.transform.as_ref().expect("transform kept");
    assert_eq!(transform.path, "$target.text");
    assert_eq!(transform.value, json!("[redacted]"));
    assert_eq!(verdict.result_labels, vec!["pii".to_string()]);
    verdict
        .validate()
        .expect("degraded verdict passes the section 5 gate");

    // The evidence is present, under the cap, and a key-order prefix.
    let kept = kept_evidence(&verdict);
    assert_eq!(kept.artefact.as_deref(), Some(artefact));
    assert!(kept_size(&verdict) <= CAP);
    assert_eq!(kept.verification_pointers.len(), expected_kept);
    let expected_keys: Vec<String> = (0..expected_kept).map(pointer_key).collect();
    let kept_keys: Vec<String> = kept.verification_pointers.keys().cloned().collect();
    assert_eq!(kept_keys, expected_keys);
    for (index, key) in expected_keys.iter().enumerate() {
        assert_eq!(kept.verification_pointers[key], pointer_url(index));
    }

    // One warning marks the loss.
    assert_eq!(verdict.warnings.len(), 1);
    let warning = the_truncation_warning(&verdict);
    let message = warning.message.as_deref().expect("warning message");
    assert!(message.len() < 256, "message is {} bytes", message.len());
    assert!(message.contains(&original_size.to_string()), "{message}");
    assert!(message.contains(&CAP.to_string()), "{message}");
    assert!(
        message.contains(&format!("{expected_kept} of {total}")),
        "{message}"
    );
    assert!(message.contains(&evidence_digest(&evidence)), "{message}");
}

// (b) The boundary.

fn artefact_only_evidence(canonical_size: usize) -> JsonValue {
    // {"artefact":"<pad>"} is 15 bytes of framing plus the pad.
    let evidence = json!({"artefact": "x".repeat(canonical_size - 15)});
    assert_eq!(canonical_len(&evidence), canonical_size);
    evidence
}

#[test]
fn evidence_exactly_at_the_cap_passes_without_a_warning() {
    let evidence = artefact_only_evidence(CAP);
    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));

    assert_eq!(verdict.decision, Decision::Allow);
    assert!(verdict.warnings.is_empty());
    assert_eq!(
        serde_json::to_value(kept_evidence(&verdict)).unwrap(),
        evidence
    );
}

#[test]
fn evidence_one_byte_over_the_cap_degrades() {
    let evidence = artefact_only_evidence(CAP + 1);
    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));

    assert_eq!(verdict.decision, Decision::Allow);
    let warning = the_truncation_warning(&verdict);
    let message = warning.message.as_deref().unwrap();
    assert!(message.contains(&(CAP + 1).to_string()), "{message}");
    assert!(message.contains(&evidence_digest(&evidence)), "{message}");
    assert!(kept_size(&verdict) <= CAP);
}

// (c) The artefact is all or nothing.

#[test]
fn oversize_artefact_is_dropped_whole_and_the_pointers_survive() {
    let artefact = "x".repeat(CAP);
    let evidence = json!({
        "artefact": artefact,
        "verification_pointers": {
            "issuer_pubkey": "https://example.com/keys/2026.pem",
            "policy_registry": "https://example.com/policies/v1/",
        },
    });
    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));

    let kept = kept_evidence(&verdict);
    assert_eq!(kept.artefact, None, "the artefact is dropped, never cut");
    assert_eq!(kept.verification_pointers.len(), 2);
    assert_eq!(
        kept.verification_pointers["issuer_pubkey"],
        "https://example.com/keys/2026.pem"
    );
    let warning = the_truncation_warning(&verdict);
    let message = warning.message.as_deref().unwrap();
    assert!(message.contains("artefact dropped"), "{message}");
    assert!(message.contains("2 of 2"), "{message}");
    assert!(message.contains(&evidence_digest(&evidence)), "{message}");
}

#[test]
fn fitting_artefact_stays_whole_when_pointers_overflow() {
    let artefact = format!("sha256:{}", "a".repeat(4_000));
    let total = 250;
    let evidence = evidence_with(&artefact, total);
    let expected_kept = expected_kept(&artefact, total);

    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));

    let kept = kept_evidence(&verdict);
    assert_eq!(kept.artefact.as_deref(), Some(artefact.as_str()));
    assert_eq!(kept.verification_pointers.len(), expected_kept);
    assert!(kept_size(&verdict) <= CAP);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains("artefact kept"), "{message}");
}

// (d) Every decision keeps its shape.

#[test]
fn deny_with_oversize_evidence_stays_deny_with_its_reason() {
    let verdict = evaluate(json!({
        "decision": "deny",
        "reason": "blocked_by_policy",
        "message": "no",
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(verdict.reason.as_deref(), Some("blocked_by_policy"));
    assert_eq!(verdict.message.as_deref(), Some("no"));
    assert!(verdict.approval.is_none());
    the_truncation_warning(&verdict);
    assert!(kept_size(&verdict) <= CAP);
}

#[test]
fn allow_with_oversize_evidence_stays_allow() {
    let verdict = evaluate(json!({
        "decision": "allow",
        "reason": "clean",
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.decision, Decision::Allow);
    assert_eq!(verdict.reason.as_deref(), Some("clean"));
    the_truncation_warning(&verdict);
    assert!(kept_size(&verdict) <= CAP);
}

#[test]
fn escalate_with_oversize_evidence_stays_liftable() {
    let verdict = evaluate(json!({
        "decision": "escalate",
        "reason": "human_gate",
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.decision, Decision::Deny);
    assert!(verdict.is_liftable());
    assert_eq!(verdict.reason.as_deref(), Some("human_gate"));
    the_truncation_warning(&verdict);
}

// (e) Malformed evidence still fails closed, without echoing the
// dispatcher's strings.

const MARKER: &str = "MARKER_zq9v";

fn assert_fails_closed_without_echo(output: JsonValue) {
    let verdict = evaluate(output.clone());
    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(
        verdict.reason.as_deref(),
        Some("runtime_error:policy_output_invalid")
    );
    assert!(verdict.evidence.is_none());
    let message = verdict.message.as_deref().unwrap_or_default();
    assert!(
        !message.contains(MARKER),
        "verdict message echoes: {message}"
    );

    let error = agent_control_spec::normalize_policy_output(output).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    assert!(
        !error.detail().contains(MARKER),
        "error detail echoes: {}",
        error.detail()
    );
    assert!(
        error.detail().contains("evidence"),
        "error detail names the failure class: {}",
        error.detail()
    );
}

#[test]
fn pointer_of_the_wrong_type_fails_closed_without_echoing_the_key() {
    assert_fails_closed_without_echo(json!({
        "decision": "allow",
        "evidence": {"verification_pointers": {MARKER: 123}},
    }));
}

#[test]
fn unknown_evidence_member_fails_closed_without_echoing_the_name() {
    assert_fails_closed_without_echo(json!({
        "decision": "allow",
        "evidence": {"artefact": "sha256:abc", MARKER: "https://example.com"},
    }));
}

#[test]
fn non_object_evidence_fails_closed() {
    assert_fails_closed_without_echo(json!({"decision": "allow", "evidence": MARKER}));
}

#[test]
fn artefact_of_the_wrong_type_fails_closed() {
    assert_fails_closed_without_echo(json!({
        "decision": "allow",
        "evidence": {"artefact": {MARKER: 1}},
    }));
}

#[test]
fn pointers_of_the_wrong_type_fail_closed() {
    assert_fails_closed_without_echo(json!({
        "decision": "allow",
        "evidence": {"verification_pointers": [MARKER]},
    }));
}

// (f) Dispatcher warnings are kept and the marker is appended.

#[test]
fn dispatcher_warnings_are_kept_and_the_marker_is_appended() {
    let verdict = evaluate(json!({
        "decision": "allow",
        "warnings": [
            {"reason": "policy_note", "message": "first"},
            {"reason": "policy_note_2"},
        ],
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.warnings.len(), 3);
    assert_eq!(verdict.warnings[0].reason.as_deref(), Some("policy_note"));
    assert_eq!(verdict.warnings[0].message.as_deref(), Some("first"));
    assert_eq!(verdict.warnings[1].reason.as_deref(), Some("policy_note_2"));
    assert_eq!(verdict.warnings[2].reason.as_deref(), Some(TRUNCATED));
}

#[test]
fn warn_intent_keeps_its_own_warning_ahead_of_the_marker() {
    let verdict = evaluate(json!({
        "decision": "warn",
        "reason": "needs_review",
        "message": "look",
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.decision, Decision::Allow);
    assert_eq!(verdict.warnings.len(), 2);
    assert_eq!(verdict.warnings[0].reason.as_deref(), Some("needs_review"));
    assert_eq!(verdict.warnings[1].reason.as_deref(), Some(TRUNCATED));
}

// (g) Determinism.

#[test]
fn the_same_oversize_evidence_degrades_to_identical_output() {
    let output = json!({
        "decision": "transform",
        "transform": {"path": "$target.text", "value": "[redacted]"},
        "evidence": evidence_with("sha256:abc", 250),
    });
    let first = evaluate(output.clone());
    let second = evaluate(output.clone());
    let third = runtime(output)
        .evaluate_point(
            InterceptionPoint::Input,
            json!({"input": {"text": "hello"}}),
        )
        .verdict;

    assert_eq!(first, second);
    assert_eq!(first, third);
    let first_bytes = canonical_json(&serde_json::to_value(&first).unwrap());
    let second_bytes = canonical_json(&serde_json::to_value(&second).unwrap());
    assert_eq!(first_bytes, second_bytes);
}

// (h) The marker lands on the interception record.

#[tokio::test]
async fn truncation_warning_lands_on_the_interception_record() {
    let evidence = evidence_with("sha256:abc", 250);
    let runtime = runtime(json!({
        "decision": "transform",
        "reason": "redacted",
        "transform": {"path": "$target.account", "value": "[redacted]"},
        "evidence": evidence,
    }));

    let records: Arc<Mutex<Vec<InterceptionRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = records.clone();
    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.set_record_sink(move |record| sink.lock().unwrap().push(record.clone()));
    emitter.register(Box::new(AcsInterceptor::new(runtime)));

    let mut builder = AgentContextBuilder::new("demo-agent", "acs-tests", "session-1");
    let mut ctx = builder.pre_tool_call(
        "tc-1",
        "wire_transfer",
        json!({"amount": 100, "account": "CHK-1"}),
    );
    let outcome = emitter.emit(&mut ctx).await.expect("transform proceeds");

    assert_eq!(outcome.record.verdict.decision, Decision::Transform);
    assert_eq!(outcome.target["account"], json!("[redacted]"));

    let records = records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.verdict.decision, Decision::Transform);
    assert_eq!(record.verdict.reason.as_deref(), Some("redacted"));
    let warning = the_truncation_warning(&record.verdict);
    assert_eq!(warning.reason.as_deref(), Some(TRUNCATED));
    let message = warning.message.as_deref().unwrap();
    assert!(message.len() < 256, "message is {} bytes", message.len());
    assert!(message.contains(&evidence_digest(&evidence)), "{message}");
    assert!(record.verdict.evidence.is_some());
    assert!(kept_size(&record.verdict) <= CAP);
}

// A pointer map that already fits is never touched, whatever the order
// the dispatcher wrote it in.

#[test]
fn fitting_pointers_are_returned_in_key_order_unchanged() {
    let verdict = evaluate(json!({
        "decision": "allow",
        "evidence": {
            "verification_pointers": {
                "zeta": "https://example.com/z",
                "alpha": "https://example.com/a",
            },
        },
    }));

    assert_no_truncation_warning(&verdict);
    let expected: BTreeMap<String, String> = [
        ("alpha".to_string(), "https://example.com/a".to_string()),
        ("zeta".to_string(), "https://example.com/z".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(kept_evidence(&verdict).verification_pointers, expected);
}

// (i) The runtime owns the evidence_truncated reason. A dispatcher
// warning that carries it fails closed, whichever way it arrives, so
// a policy cannot forge the marker or stand a second one next to the
// runtime's.

fn assert_forged_marker_fails_closed(output: JsonValue) {
    let verdict = evaluate(output.clone());
    assert_eq!(verdict.decision, Decision::Deny, "{verdict:#?}");
    assert_eq!(
        verdict.reason.as_deref(),
        Some("runtime_error:policy_output_invalid")
    );
    assert_no_truncation_warning(&verdict);
    assert!(verdict.evidence.is_none());
    let message = verdict.message.as_deref().unwrap_or_default();
    assert!(
        !message.contains(MARKER),
        "verdict message echoes: {message}"
    );

    let error = agent_control_spec::normalize_policy_output(output).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    assert!(
        !error.detail().contains(MARKER),
        "error detail echoes: {}",
        error.detail()
    );
    assert!(
        error.detail().contains(TRUNCATED),
        "error detail names the rule: {}",
        error.detail()
    );
}

#[test]
fn a_dispatcher_warning_with_the_runtime_owned_reason_fails_closed() {
    assert_forged_marker_fails_closed(json!({
        "decision": "allow",
        "warnings": [{"reason": TRUNCATED, "message": MARKER}],
        "evidence": {"artefact": "sha256:abc"},
    }));
}

#[test]
fn the_warn_intent_cannot_mint_the_runtime_owned_reason() {
    assert_forged_marker_fails_closed(json!({
        "decision": "warn",
        "reason": TRUNCATED,
        "message": MARKER,
        "evidence": {"artefact": "sha256:abc"},
    }));
}

#[test]
fn a_forged_marker_next_to_oversize_evidence_fails_closed() {
    assert_forged_marker_fails_closed(json!({
        "decision": "allow",
        "warnings": [{"reason": TRUNCATED, "message": MARKER}],
        "evidence": evidence_with("sha256:abc", 250),
    }));
}

#[tokio::test]
async fn a_forged_marker_never_reaches_the_interception_record() {
    let runtime = runtime(json!({
        "decision": "allow",
        "warnings": [{"reason": TRUNCATED, "message": MARKER}],
        "evidence": {"artefact": "sha256:abc"},
    }));

    let records: Arc<Mutex<Vec<InterceptionRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = records.clone();
    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.set_record_sink(move |record| sink.lock().unwrap().push(record.clone()));
    emitter.register(Box::new(AcsInterceptor::new(runtime)));

    let mut builder = AgentContextBuilder::new("demo-agent", "acs-tests", "session-1");
    let mut ctx = builder.pre_tool_call("tc-1", "wire_transfer", json!({"amount": 100}));
    let blocked = emitter
        .emit(&mut ctx)
        .await
        .expect_err("the fail closed deny blocks the call");
    assert_eq!(blocked.record.verdict.decision, Decision::Deny);

    let records = records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.verdict.decision, Decision::Deny);
    assert_eq!(
        record.verdict.reason.as_deref(),
        Some("runtime_error:policy_output_invalid")
    );
    assert_no_truncation_warning(&record.verdict);
    assert!(record.verdict.evidence.is_none());
}

// (j) The size and the digest cover the canonical form of the
// normalized evidence object, in which a null artefact and an empty
// pointer map are absent.

#[test]
fn a_null_artefact_is_absent_from_the_measured_and_digested_bytes() {
    let raw = json!({"artefact": null, "verification_pointers": pointers(250)});
    let normalized = json!({"verification_pointers": pointers(250)});
    assert_ne!(canonical_json(&raw), canonical_json(&normalized));

    let verdict = evaluate(json!({"decision": "allow", "evidence": raw}));
    assert_eq!(verdict.decision, Decision::Allow);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains(&evidence_digest(&normalized)), "{message}");
    assert!(!message.contains(&evidence_digest(&raw)), "{message}");
    assert!(
        message.contains(&format!("{} canonical bytes", canonical_len(&normalized))),
        "{message}"
    );
    assert_eq!(kept_evidence(&verdict).artefact, None);
}

#[test]
fn an_empty_pointer_map_is_absent_from_the_measured_and_digested_bytes() {
    let raw = json!({"artefact": "x".repeat(CAP), "verification_pointers": {}});
    let normalized = json!({"artefact": "x".repeat(CAP)});
    assert_ne!(canonical_json(&raw), canonical_json(&normalized));

    let verdict = evaluate(json!({"decision": "allow", "evidence": raw}));
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains(&evidence_digest(&normalized)), "{message}");
    assert!(
        message.contains(&format!("{} canonical bytes", canonical_len(&normalized))),
        "{message}"
    );
}

// (k) The boundary of each fit step is inclusive, and nothing fitting
// leaves the empty object.

#[test]
fn an_artefact_landing_exactly_on_the_cap_is_kept_when_a_pointer_overflows() {
    let evidence = artefact_only_evidence(CAP);
    let artefact = evidence["artefact"].as_str().unwrap().to_string();
    let verdict = evaluate(json!({
        "decision": "allow",
        "evidence": {"artefact": artefact, "verification_pointers": {"a": "1"}},
    }));

    let kept = kept_evidence(&verdict);
    assert_eq!(kept.artefact.as_deref(), Some(artefact.as_str()));
    assert!(kept.verification_pointers.is_empty());
    assert_eq!(kept_size(&verdict), CAP);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains("artefact kept"), "{message}");
    assert!(message.contains("kept 0 of 1"), "{message}");
}

#[test]
fn a_pointer_prefix_landing_exactly_on_the_cap_is_kept() {
    // {"verification_pointers":{"a":"<pad>"}} is 34 bytes of framing
    // plus the pad, so this single pointer is exactly the cap.
    let pad = "p".repeat(CAP - 34);
    assert_eq!(
        canonical_len(&json!({"verification_pointers": {"a": pad}})),
        CAP
    );
    let verdict = evaluate(json!({
        "decision": "allow",
        "evidence": {"verification_pointers": {"a": pad, "b": "2"}},
    }));

    let kept = kept_evidence(&verdict);
    assert_eq!(kept.verification_pointers.len(), 1);
    assert_eq!(kept.verification_pointers["a"], pad);
    assert_eq!(kept_size(&verdict), CAP);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains("kept 1 of 2"), "{message}");
}

#[test]
fn when_nothing_fits_the_evidence_is_the_empty_object() {
    let verdict = evaluate(json!({
        "decision": "allow",
        "evidence": {
            "artefact": "a".repeat(CAP + 1),
            "verification_pointers": {"k".repeat(CAP + 1): "v"},
        },
    }));

    assert_eq!(verdict.decision, Decision::Allow, "{verdict:#?}");
    verdict
        .validate()
        .expect("the empty object passes the section 5 gate");
    assert_eq!(
        serde_json::to_value(kept_evidence(&verdict)).unwrap(),
        json!({})
    );
    assert_eq!(kept_size(&verdict), 2);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains("artefact dropped"), "{message}");
    assert!(message.contains("kept 0 of 1"), "{message}");
}

// (l) The kept pointers are a prefix of the RFC 8785 member list, which
// orders keys by UTF-16 code units rather than by scalar value.

#[test]
fn kept_pointers_are_a_prefix_of_the_canonical_member_list() {
    // U+FF5E sorts before U+10000 by scalar value and after it by
    // UTF-16 code units (D800 DC00 < FF5E), so the astral key comes
    // first in the canonical bytes and is the one kept when one fits.
    let pad = "v".repeat(CAP / 2);
    let bmp = "\u{FF5E}";
    let astral = "\u{10000}";
    let evidence = json!({"verification_pointers": {bmp: pad, astral: pad}});
    let canonical = canonical_json(&evidence);
    assert!(canonical.len() > CAP);
    assert!(canonical.find(astral) < canonical.find(bmp), "{canonical}");

    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));
    let kept: Vec<&str> = kept_evidence(&verdict)
        .verification_pointers
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(kept, [astral]);
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.contains("kept 1 of 2"), "{message}");
    // The digest and the size come from the SDK serializer. Only here do
    // RFC 8785 and plain serde_json order the members differently, so
    // this is the check that ties the engine to the SDK's byte order.
    assert!(message.contains(&evidence_digest(&evidence)), "{message}");
    assert!(
        message.contains(&format!("{} canonical bytes", canonical.len())),
        "{message}"
    );
}

// (m) Shapes that must keep holding around the degrade path.

#[test]
fn a_deny_approval_block_survives_degrade() {
    let verdict = evaluate(json!({
        "decision": "deny",
        "reason": "needs_sign_off",
        "approval": {"approvers": ["cfo"], "ttl_s": 600},
        "evidence": evidence_with("sha256:abc", 250),
    }));

    assert_eq!(verdict.decision, Decision::Deny);
    assert!(verdict.is_liftable());
    assert_eq!(
        verdict.approval.as_ref().unwrap().get("approvers"),
        Some(&json!(["cfo"]))
    );
    the_truncation_warning(&verdict);
}

#[test]
fn the_marker_stays_under_256_bytes_with_many_tiny_pointers() {
    let map: serde_json::Map<String, JsonValue> = (0..20_000)
        .map(|index| (index.to_string(), JsonValue::String(String::new())))
        .collect();
    let evidence = json!({"verification_pointers": map});
    assert!(canonical_len(&evidence) < 262_144, "under the output limit");

    let verdict = evaluate(json!({"decision": "allow", "evidence": evidence}));
    let message = the_truncation_warning(&verdict).message.clone().unwrap();
    assert!(message.len() < 256, "{} bytes: {message}", message.len());
    assert!(kept_size(&verdict) <= CAP);
}

#[test]
fn a_wrong_typed_pointer_behind_oversize_siblings_fails_closed_before_degrade() {
    let mut map = pointers(250);
    map.as_object_mut()
        .unwrap()
        .insert("zzz_last".to_string(), json!([MARKER]));
    assert_fails_closed_without_echo(json!({
        "decision": "allow",
        "evidence": {"verification_pointers": map},
    }));
}
