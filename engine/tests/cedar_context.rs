#![cfg(feature = "cedar")]
//! Bundled Cedar dispatcher driven through the public `Runtime` API.
//!
//! Covers the three parts of `spec/SPECIFICATION.md` 12.4 that the
//! dispatcher owns: the request context built from the policy input, the
//! deny reason taken from the contributing policy's `@id`, and `@advice`
//! translation. The first group binds the stock library at
//! `policy/cedar-lib/agt_default.cedar` with entity fixtures shaped like
//! the library's own `_test.json` files, so a context that never reaches
//! Cedar shows up as a gate that never fires. The rest use inline
//! policies to pin the translation rules for floats, nulls, reserved
//! keys, schemas, and the ordering of contributing policies.

use agent_control_spec::{
    AnnotatorDispatcher, AnnotatorInvocation, CedarBuiltinDispatcher, Decision, InterceptionPoint,
    JsonValue, Manifest, PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
    Verdict,
};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const POLICY_INVOCATION_FAILED: &str = "runtime_error:policy_invocation_failed";

/// Returns the fixture output registered under the annotator's name.
struct FixtureAnnotators(JsonValue);

impl AnnotatorDispatcher for FixtureAnnotators {
    fn dispatch(
        &self,
        annotator_name: &str,
        _: &AnnotatorInvocation,
        _: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.0.get(annotator_name).cloned().ok_or_else(|| {
            RuntimeError::AnnotationFailed(format!("no fixture output for {annotator_name}"))
        })
    }
}

/// Wraps the bundled dispatcher and keeps the last error's reason and
/// detail. Per 12.3 the runtime folds every dispatcher error into a
/// `runtime_error:policy_invocation_failed` verdict, so the error kind
/// the dispatcher chose and the key its detail names are only visible
/// here.
struct RecordingDispatcher {
    inner: CedarBuiltinDispatcher,
    last_error: Mutex<Option<(String, String)>>,
}

impl PolicyDispatcher for RecordingDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let result = self.inner.evaluate(invocation);
        if let Err(error) = &result {
            *self.last_error.lock().unwrap() =
                Some((error.reason().to_string(), error.detail().to_string()));
        }
        result
    }
}

fn test_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("cedar-context-tests");
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_fixture(name: &str, content: &str) -> String {
    let path = test_dir().join(name);
    fs::write(&path, content).unwrap();
    path.display().to_string()
}

fn library_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("policy")
        .join("cedar-lib")
        .join("agt_default.cedar")
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn manifest(policy: JsonValue, annotators: &[&str]) -> Manifest {
    let mut point = json!({
        "policy_target": "$snap.tool_call.args",
        "policy_target_kind": "tool_args",
        "tool_name_from": "$snap.tool_call.name",
        "policy": {"id": "gate"}
    });
    let mut doc = json!({
        "agent_control_specification_version": "0.4.0-alpha.1",
        "tools": {
            "pay": {"type": "Tool"},
            "http_get": {"type": "Tool"},
            "search": {"type": "Tool"}
        },
        "policies": {"gate": policy}
    });
    if !annotators.is_empty() {
        let mut declared = serde_json::Map::new();
        let mut bound = serde_json::Map::new();
        for name in annotators {
            declared.insert(name.to_string(), json!({"type": "classifier"}));
            bound.insert(name.to_string(), json!({"from": "$target"}));
        }
        doc["annotators"] = JsonValue::Object(declared);
        point["annotations"] = JsonValue::Object(bound);
    }
    doc["intervention_points"] = json!({"pre_tool_call": point});
    Manifest::from_json_str(&doc.to_string()).expect("manifest parses")
}

fn inline(policy_set: &str) -> JsonValue {
    json!({"type": "cedar", "policy_set": policy_set})
}

/// Binds `agt_default.cedar` with the given entity store, written next to
/// the other fixtures under `target/`.
fn library(name: &str, entities: JsonValue) -> JsonValue {
    let agent = json!({"uid": {"type": "Agent", "id": "agent-1"}, "attrs": {}, "parents": []});
    let mut store = entities.as_array().cloned().unwrap();
    store.push(agent);
    let entities_path = write_fixture(
        &format!("{name}.entities.json"),
        &JsonValue::Array(store).to_string(),
    );
    json!({
        "type": "cedar",
        "policy_path": library_path(),
        "entities_path": entities_path
    })
}

fn tool_entity(name: &str, attrs: JsonValue) -> JsonValue {
    json!({"uid": {"type": "Tool", "id": name}, "attrs": attrs, "parents": []})
}

/// Snapshot in the AGT envelope shape that `build_cedar_request` reads
/// the principal from.
fn envelope_snapshot(tool: &str, args: JsonValue, tool_call_count: u64) -> JsonValue {
    json!({
        "envelope": {
            "agent": {"id": "agent-1", "version": "1.0", "name": "agent-1"},
            "session": {"id": "sess-1", "started_at": "2026-01-01T00:00:00Z"},
            "intervention_point": "pre_tool_call",
            "timestamp": "2026-01-01T00:00:01Z",
            "budgets": {"tool_call_count": tool_call_count, "token_count": 0}
        },
        "tool_call": {"name": tool, "args": args, "id": "call-1"}
    })
}

struct Outcome {
    verdict: Verdict,
    /// The dispatcher's error as `(reason, detail)`, when it returned one.
    dispatcher_error: Option<(String, String)>,
}

impl Outcome {
    fn error_detail(&self) -> Option<&str> {
        self.dispatcher_error
            .as_ref()
            .map(|(_, detail)| detail.as_str())
    }

    fn error_reason(&self) -> Option<&str> {
        self.dispatcher_error
            .as_ref()
            .map(|(reason, _)| reason.as_str())
    }
}

fn evaluate(policy: JsonValue, snapshot: JsonValue) -> Outcome {
    evaluate_with_annotators(policy, &[], json!({}), snapshot)
}

fn evaluate_with_annotators(
    policy: JsonValue,
    annotators: &[&str],
    outputs: JsonValue,
    snapshot: JsonValue,
) -> Outcome {
    let dispatcher = Arc::new(RecordingDispatcher {
        inner: CedarBuiltinDispatcher::new(),
        last_error: Mutex::new(None),
    });
    let runtime = Runtime::new(
        manifest(policy, annotators),
        Arc::new(FixtureAnnotators(outputs)),
        dispatcher.clone(),
    )
    .expect("runtime builds");
    let result = runtime.evaluate_point(InterceptionPoint::PreToolCall, snapshot);
    let dispatcher_error = dispatcher.last_error.lock().unwrap().clone();
    Outcome {
        verdict: result.verdict,
        dispatcher_error,
    }
}

fn assert_plain_deny(outcome: &Outcome, reason: &str) {
    assert_eq!(
        outcome.verdict.decision,
        Decision::Deny,
        "{:?}",
        outcome.verdict
    );
    assert_eq!(outcome.verdict.reason.as_deref(), Some(reason));
    assert!(!outcome.verdict.is_liftable(), "{:?}", outcome.verdict);
    assert!(outcome.verdict.approval.is_none());
}

fn assert_plain_allow(outcome: &Outcome) {
    assert_eq!(
        outcome.verdict.decision,
        Decision::Allow,
        "{:?}",
        outcome.verdict
    );
    assert!(outcome.verdict.warnings.is_empty());
    assert!(outcome.verdict.transform.is_none());
}

fn assert_fails_closed_naming(outcome: &Outcome, key: &str) {
    assert_eq!(
        outcome.verdict.decision,
        Decision::Deny,
        "{:?}",
        outcome.verdict
    );
    assert_eq!(
        outcome.verdict.reason.as_deref(),
        Some(POLICY_INVOCATION_FAILED)
    );
    assert_eq!(outcome.error_reason(), Some(POLICY_INVOCATION_FAILED));
    let detail = outcome
        .error_detail()
        .expect("dispatcher reported an error");
    assert!(
        detail.contains(key),
        "error detail should name {key}: {detail}"
    );
}

// ── stock library through the runtime ────────────────────────────────

#[test]
fn library_allows_a_clean_request() {
    let outcome = evaluate(
        library("clean", json!([tool_entity("search", json!({}))])),
        envelope_snapshot("search", json!({"q": "hello"}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn library_egress_denies_a_host_outside_the_allowlist() {
    let outcome = evaluate(
        library(
            "egress",
            json!([tool_entity(
                "http_get",
                json!({"security_labels": ["api.example.com"]})
            )]),
        ),
        envelope_snapshot("http_get", json!({"host": "attacker.example.org"}), 0),
    );
    assert_plain_deny(&outcome, "egress_destination_not_allowed");
}

#[test]
fn library_egress_allows_a_host_inside_the_allowlist() {
    let outcome = evaluate(
        library(
            "egress-ok",
            json!([tool_entity(
                "http_get",
                json!({"security_labels": ["api.example.com"]})
            )]),
        ),
        envelope_snapshot("http_get", json!({"host": "api.example.com"}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn library_budget_denies_when_the_envelope_count_reaches_the_limit() {
    let outcome = evaluate(
        library(
            "budget",
            json!([tool_entity("search", json!({"max_tool_calls": 10}))]),
        ),
        envelope_snapshot("search", json!({"q": "x"}), 10),
    );
    assert_plain_deny(&outcome, "budget_tool_calls_exceeded");
}

#[test]
fn library_budget_allows_below_the_limit() {
    let outcome = evaluate(
        library(
            "budget-ok",
            json!([tool_entity("search", json!({"max_tool_calls": 10}))]),
        ),
        envelope_snapshot("search", json!({"q": "x"}), 9),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn library_approval_escalates_to_a_liftable_deny() {
    let outcome = evaluate(
        library(
            "approval",
            json!([tool_entity("pay", json!({"approvers": ["alice"]}))]),
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    let verdict = &outcome.verdict;
    assert_eq!(verdict.decision, Decision::Deny, "{verdict:?}");
    assert!(verdict.is_liftable(), "{verdict:?}");
    assert!(verdict.approval.is_some(), "{verdict:?}");
    assert_eq!(verdict.reason.as_deref(), Some("approval_required"));
}

#[test]
fn library_content_hash_denies_when_no_hash_was_observed() {
    let outcome = evaluate(
        library(
            "hash",
            json!([tool_entity("pay", json!({"content_hash": "sha256:abc"}))]),
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    assert_plain_deny(&outcome, "tool_content_hash_mismatch_observed_missing");
}

#[test]
fn library_content_hash_denies_a_mismatch() {
    let mut snapshot = envelope_snapshot("pay", json!({"amount": 1}), 0);
    snapshot["tool_call"]["content_hash"] = json!("sha256:zzz");
    let outcome = evaluate(
        library(
            "hash-mismatch",
            json!([tool_entity("pay", json!({"content_hash": "sha256:abc"}))]),
        ),
        snapshot,
    );
    assert_plain_deny(&outcome, "tool_content_hash_mismatch");
}

#[test]
fn library_reads_annotator_output_as_a_nested_record() {
    let outcome = evaluate_with_annotators(
        library(
            "confidence",
            json!([tool_entity("search", json!({"min_confidence": 50}))]),
        ),
        &["confidence"],
        json!({"confidence": {"score": 20}}),
        envelope_snapshot("search", json!({"q": "x"}), 0),
    );
    assert_plain_deny(&outcome, "confidence_below_threshold");
}

// ── inline context-gated policies ────────────────────────────────────

const FORBID_GUARDED: &str = r#"
@id("amount_too_high")
forbid(principal, action, resource) when {
  context has tool_call && context.tool_call has args &&
  context.tool_call.args has amount && context.tool_call.args.amount > 100
};
permit(principal, action, resource);
"#;

const FORBID_UNGUARDED: &str = r#"
@id("amount_too_high")
forbid(principal, action, resource) when { context.tool_call.args.amount > 100 };
permit(principal, action, resource);
"#;

const PERMIT_GUARDED: &str = r#"
permit(principal, action, resource) when {
  context has tool_call && context.tool_call has args &&
  context.tool_call.args has amount && context.tool_call.args.amount <= 100
};
"#;

const PERMIT_UNGUARDED: &str = r#"
permit(principal, action, resource) when { context.tool_call.args.amount <= 100 };
"#;

#[test]
fn guarded_forbid_denies_on_context() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "amount_too_high");
}

#[test]
fn guarded_forbid_allows_below_threshold() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": 50}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn unguarded_forbid_denies_on_context() {
    let outcome = evaluate(
        inline(FORBID_UNGUARDED),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "amount_too_high");
}

#[test]
fn guarded_permit_allows_on_context() {
    let outcome = evaluate(
        inline(PERMIT_GUARDED),
        envelope_snapshot("pay", json!({"amount": 50}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn guarded_permit_denies_when_the_condition_fails() {
    let outcome = evaluate(
        inline(PERMIT_GUARDED),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "no_matching_policy");
}

#[test]
fn unguarded_permit_allows_on_context() {
    let outcome = evaluate(
        inline(PERMIT_UNGUARDED),
        envelope_snapshot("pay", json!({"amount": 50}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn unguarded_access_to_a_missing_attribute_fails_closed() {
    let outcome = evaluate(
        inline(FORBID_UNGUARDED),
        envelope_snapshot("pay", json!({"q": "no amount here"}), 0),
    );
    assert_eq!(outcome.verdict.decision, Decision::Deny);
    assert_eq!(
        outcome.verdict.reason.as_deref(),
        Some(POLICY_INVOCATION_FAILED)
    );
}

#[test]
fn envelope_is_part_of_the_context() {
    let outcome = evaluate(
        inline(
            r#"
@id("agent_blocked")
forbid(principal, action, resource) when { context.envelope.agent.id == "agent-1" };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    assert_plain_deny(&outcome, "agent_blocked");
}

/// A snapshot in the wire shape of `spec/schema/wire/snapshot.schema.json`
/// carries `agent` at the top level and no `envelope` block. The
/// dispatcher still reads the principal from `envelope.agent.id` (see
/// https://github.com/responsibleai/agent-control-spec/issues/84), so
/// the wire shape is tested with a minimal envelope added. The
/// context-gated rule sees the same `tool_call` either way.
#[test]
fn wire_shaped_snapshot_reaches_the_same_context_gated_verdict() {
    let wire = json!({
        "envelope": {"agent": {"id": "agent-1"}},
        "agent": {"id": "agent-1", "name": "agent-1", "version": "1.0"},
        "session": {"id": "sess-1"},
        "tool_call": {"name": "pay", "args": {"amount": 500}, "id": "call-1"}
    });
    let from_wire = evaluate(inline(FORBID_GUARDED), wire);
    let from_envelope = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&from_wire, "amount_too_high");
    assert_eq!(from_wire.verdict.reason, from_envelope.verdict.reason);
    assert_eq!(from_wire.verdict.decision, from_envelope.verdict.decision);
}

// ── deny reason ordering and fallback ────────────────────────────────

#[test]
fn deny_reason_is_the_first_contributing_forbid_in_declaration_order() {
    // The ids sort the other way round lexicographically, so a reason
    // picked by string order would surface `a_declared_second`.
    let outcome = evaluate(
        inline(
            r#"
@id("z_declared_first")
forbid(principal, action, resource) when { context.tool_call.args.amount > 10 };
@id("a_declared_second")
forbid(principal, action, resource) when { context.tool_call.args.amount > 100 };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "z_declared_first");
}

#[test]
fn deny_reason_falls_back_to_the_cedar_policy_id_without_an_id_annotation() {
    let outcome = evaluate(
        inline(
            r#"
permit(principal, action, resource);
forbid(principal, action, resource) when { context.tool_call.args.amount > 100 };
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "policy1");
}

#[test]
fn empty_id_annotation_falls_back_to_the_cedar_policy_id() {
    // Cedar reports a bare `@id` as the empty string. An empty reason
    // code is no use to a host, so each of these is treated as absent.
    for id in ["@id", "@id(\"\")", "@id(\"  \")"] {
        let outcome = evaluate(
            inline(&format!(
                "{id}\nforbid(principal, action, resource);\npermit(principal, action, resource);\n"
            )),
            envelope_snapshot("pay", json!({"amount": 1}), 0),
        );
        assert_plain_deny(&outcome, "policy0");
    }
}

#[test]
fn an_evaluation_error_in_any_policy_fails_closed_even_when_a_forbid_fires() {
    // The first forbid is satisfied; the second reads an attribute the
    // snapshot lacks. Cedar denies and reports the error. The verdict is
    // the runtime reason, not the firing forbid's `@id`: a policy set
    // that errors is not one the host can trust to have been evaluated.
    let outcome = evaluate(
        inline(
            r#"
@id("fires")
forbid(principal, action, resource) when { context.tool_call.args.amount > 1 };
@id("errors")
forbid(principal, action, resource) when { context.tool_call.args.missing > 1 };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_fails_closed_naming(&outcome, "authorizer reported errors");
    assert_ne!(outcome.verdict.reason.as_deref(), Some("fires"));
}

// ── advice translation ───────────────────────────────────────────────

#[test]
fn escalate_advice_becomes_a_liftable_deny() {
    let outcome = evaluate(
        inline(
            r#"
@advice("{\"verdict\":\"escalate\",\"reason\":\"approval_required\",\"message\":\"needs sign-off\"}")
@id("needs_approval")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    let verdict = &outcome.verdict;
    assert_eq!(verdict.decision, Decision::Deny, "{verdict:?}");
    assert!(verdict.is_liftable(), "{verdict:?}");
    assert!(verdict.approval.is_some(), "{verdict:?}");
    assert_eq!(verdict.reason.as_deref(), Some("approval_required"));
    assert_eq!(verdict.message.as_deref(), Some("needs sign-off"));
}

#[test]
fn transform_advice_becomes_a_transform_verdict() {
    let outcome = evaluate(
        inline(
            r#"
@advice("{\"verdict\":\"transform\",\"reason\":\"redaction_applied\",\"transform\":{\"path\":\"$target.value\",\"value\":\"[REDACTED]\"}}")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    let verdict = &outcome.verdict;
    assert_eq!(verdict.decision, Decision::Transform, "{verdict:?}");
    let transform = verdict.transform.as_ref().expect("transform present");
    assert_eq!(transform.path, "$target.value");
    assert_eq!(transform.value, json!("[REDACTED]"));
    assert_eq!(verdict.reason.as_deref(), Some("redaction_applied"));
}

#[test]
fn warn_advice_becomes_an_allow_with_a_warning() {
    let outcome = evaluate(
        inline(
            r#"
@advice("{\"verdict\":\"warn\",\"reason\":\"drift_detected\"}")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    let verdict = &outcome.verdict;
    assert_eq!(verdict.decision, Decision::Allow, "{verdict:?}");
    assert_eq!(verdict.warnings.len(), 1);
    assert_eq!(
        verdict.warnings[0].reason.as_deref(),
        Some("drift_detected")
    );
}

const WARN_ADVICE: &str = r#"@advice("{\"verdict\":\"warn\",\"reason\":\"noted\"}")"#;
const TRANSFORM_ADVICE: &str = r#"@advice("{\"verdict\":\"transform\",\"reason\":\"redaction_applied\",\"transform\":{\"path\":\"$target.value\",\"value\":\"[REDACTED]\"}}")"#;
const ESCALATE_ADVICE: &str =
    r#"@advice("{\"verdict\":\"escalate\",\"reason\":\"approval_required\"}")"#;

/// Two permits that both match. The first is unconditional; the second
/// fires on `amount > 100`.
fn two_advice_permits(first: &str, second: &str) -> JsonValue {
    inline(&format!(
        "{first}\npermit(principal, action, resource);\n\
         {second}\npermit(principal, action, resource) when {{ context.tool_call.args.amount > 100 }};\n"
    ))
}

fn assert_escalated(outcome: &Outcome) {
    let verdict = &outcome.verdict;
    assert_eq!(verdict.decision, Decision::Deny, "{verdict:?}");
    assert!(verdict.is_liftable(), "{verdict:?}");
    assert_eq!(verdict.reason.as_deref(), Some("approval_required"));
}

#[test]
fn escalate_advice_declared_first_still_wins() {
    let outcome = evaluate(
        two_advice_permits(ESCALATE_ADVICE, WARN_ADVICE),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_escalated(&outcome);
}

/// Cedar gives policy order no meaning, so nothing warns an author who
/// declares a lenient permit ahead of a stricter one. Taking the first
/// advice in text order would let the action proceed with a warning
/// attached and without the approval the second permit required.
#[test]
fn a_warn_permit_declared_first_does_not_hide_an_escalate_permit() {
    let outcome = evaluate(
        two_advice_permits(WARN_ADVICE, ESCALATE_ADVICE),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_escalated(&outcome);
}

#[test]
fn a_transform_permit_declared_first_does_not_hide_an_escalate_permit() {
    let outcome = evaluate(
        two_advice_permits(TRANSFORM_ADVICE, ESCALATE_ADVICE),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_escalated(&outcome);
}

#[test]
fn a_warn_permit_declared_first_does_not_hide_a_transform_permit() {
    let outcome = evaluate(
        two_advice_permits(WARN_ADVICE, TRANSFORM_ADVICE),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_eq!(
        outcome.verdict.decision,
        Decision::Transform,
        "{:?}",
        outcome.verdict
    );
    assert_eq!(outcome.verdict.reason.as_deref(), Some("redaction_applied"));
}

#[test]
fn a_lenient_permit_that_does_not_match_leaves_the_stricter_advice_in_place() {
    // Below the threshold only the warn permit contributes.
    let outcome = evaluate(
        two_advice_permits(WARN_ADVICE, ESCALATE_ADVICE),
        envelope_snapshot("pay", json!({"amount": 50}), 0),
    );
    assert_eq!(
        outcome.verdict.decision,
        Decision::Allow,
        "{:?}",
        outcome.verdict
    );
    assert_eq!(outcome.verdict.warnings.len(), 1);
    assert_eq!(outcome.verdict.warnings[0].reason.as_deref(), Some("noted"));
}

#[test]
fn advice_of_the_same_kind_ties_break_on_declaration_order() {
    let outcome = evaluate(
        inline(
            r#"
@advice("{\"verdict\":\"warn\",\"reason\":\"declared_first\"}")
permit(principal, action, resource);
@advice("{\"verdict\":\"warn\",\"reason\":\"declared_second\"}")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    assert_eq!(outcome.verdict.decision, Decision::Allow);
    assert_eq!(outcome.verdict.warnings.len(), 1);
    assert_eq!(
        outcome.verdict.warnings[0].reason.as_deref(),
        Some("declared_first")
    );
}

#[test]
fn malformed_advice_on_any_contributing_permit_fails_closed() {
    // The escalate permit is valid; the second contributing permit's
    // advice is not JSON. Ranking must not paper over it.
    let outcome = evaluate(
        two_advice_permits(ESCALATE_ADVICE, r#"@advice("not json")"#),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_eq!(
        outcome.error_reason(),
        Some("runtime_error:policy_output_invalid")
    );
    assert_eq!(outcome.verdict.decision, Decision::Deny);
    assert_eq!(
        outcome.verdict.reason.as_deref(),
        Some(POLICY_INVOCATION_FAILED)
    );
}

#[test]
fn advice_that_is_not_json_fails_closed_as_policy_output_invalid() {
    let outcome = evaluate(
        inline(
            r#"
@advice("not json")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    // The dispatcher reports malformed advice as policy output; the
    // runtime then folds any dispatcher error into the 12.3 reason.
    assert_eq!(
        outcome.error_reason(),
        Some("runtime_error:policy_output_invalid")
    );
    assert_eq!(outcome.verdict.decision, Decision::Deny);
    assert_eq!(
        outcome.verdict.reason.as_deref(),
        Some(POLICY_INVOCATION_FAILED)
    );
}

#[test]
fn a_forbid_wins_over_a_permit_with_advice() {
    let outcome = evaluate(
        inline(
            r#"
@id("blocked")
forbid(principal, action, resource) when { context.tool_call.args.amount > 100 };
@advice("{\"verdict\":\"warn\",\"reason\":\"noted\"}")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "blocked");
}

// ── floats, nulls, reserved keys ─────────────────────────────────────

const FORBID_DECIMAL_OVER_100: &str = r#"
@id("amount_too_high")
forbid(principal, action, resource) when {
  context.tool_call.args.amount.greaterThan(decimal("100.0"))
};
permit(principal, action, resource);
"#;

#[test]
fn float_reaches_the_policy_as_a_decimal() {
    let outcome = evaluate(
        inline(
            r#"
@id("exact_amount")
forbid(principal, action, resource) when { context.tool_call.args.amount == decimal("12.5") };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 12.5}), 0),
    );
    assert_plain_deny(&outcome, "exact_amount");
}

#[test]
fn float_comparison_uses_decimal_methods() {
    let over = evaluate(
        inline(FORBID_DECIMAL_OVER_100),
        envelope_snapshot("pay", json!({"amount": 100.5}), 0),
    );
    assert_plain_deny(&over, "amount_too_high");
    let under = evaluate(
        inline(FORBID_DECIMAL_OVER_100),
        envelope_snapshot("pay", json!({"amount": 99.5}), 0),
    );
    assert_plain_allow(&under);
}

#[test]
fn float_beyond_four_fractional_digits_rounds_to_the_nearest_decimal() {
    // 100.00004 rounds down to 100.0000, which is not greater than 100.0.
    let rounds_down = evaluate(
        inline(FORBID_DECIMAL_OVER_100),
        envelope_snapshot("pay", json!({"amount": 100.00004}), 0),
    );
    assert_plain_allow(&rounds_down);
    // 100.00006 rounds up to 100.0001, which is.
    let rounds_up = evaluate(
        inline(FORBID_DECIMAL_OVER_100),
        envelope_snapshot("pay", json!({"amount": 100.00006}), 0),
    );
    assert_plain_deny(&rounds_up, "amount_too_high");
}

#[test]
fn integral_float_is_a_decimal_not_a_long() {
    // `0.0` is a JSON float and arrives as decimal("0.0"); a Long
    // comparison against it is a type error and fails closed. The
    // library's `_test.json` fixtures use integer counts for this reason.
    let outcome = evaluate(
        inline(
            r#"
@id("zero")
forbid(principal, action, resource) when { context.tool_call.args.amount == decimal("0.0") };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 0.0}), 0),
    );
    assert_plain_deny(&outcome, "zero");
}

#[test]
fn float_outside_the_decimal_range_fails_closed_naming_the_key() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": 1e300}), 0),
    );
    assert_fails_closed_naming(&outcome, "context.tool_call.args.amount");
    assert_detail_omits_the_value(&outcome, &["1e300", "1e+300"]);
}

#[test]
fn integer_beyond_i64_fails_closed_naming_the_key() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": u64::MAX}), 0),
    );
    assert_fails_closed_naming(&outcome, "context.tool_call.args.amount");
    assert_detail_omits_the_value(&outcome, &[&u64::MAX.to_string()]);
}

/// The value at the offending key is snapshot data (an amount, a token
/// count) and stays out of the error detail.
fn assert_detail_omits_the_value(outcome: &Outcome, renderings: &[&str]) {
    let detail = outcome
        .error_detail()
        .expect("dispatcher reported an error");
    for rendering in renderings {
        assert!(
            !detail.contains(rendering),
            "error detail leaks the value {rendering}: {detail}"
        );
    }
}

#[test]
fn null_record_member_is_dropped() {
    let outcome = evaluate(
        inline(
            r#"
@id("has_note")
forbid(principal, action, resource) when { context.tool_call.args has note };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1, "note": null}), 0),
    );
    assert_plain_allow(&outcome);
}

#[test]
fn null_set_element_is_dropped() {
    let outcome = evaluate(
        inline(
            r#"
@id("only_a")
forbid(principal, action, resource) when { context.tool_call.args.tags == ["a"] };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"tags": ["a", null]}), 0),
    );
    assert_plain_deny(&outcome, "only_a");
}

#[test]
fn reserved_cedar_escape_key_fails_closed_naming_the_key() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot(
            "pay",
            json!({"amount": 1, "__entity": {"type": "Agent", "id": "admin"}}),
            0,
        ),
    );
    assert_fails_closed_naming(&outcome, "__entity");
}

// ── schema ───────────────────────────────────────────────────────────

const SCHEMA_WITHOUT_CONTEXT_SHAPE: &str = r#"{
  "": {
    "entityTypes": {
      "Agent": {"shape": {"type": "Record", "attributes": {}}},
      "Tool": {"shape": {"type": "Record", "attributes": {}}},
      "PolicyTarget": {"shape": {"type": "Record", "attributes": {}}}
    },
    "actions": {
      "pre_tool_call": {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Tool"]}}
    }
  }
}"#;

const SCHEMA_WITH_CONTEXT_SHAPE: &str = r#"{
  "": {
    "entityTypes": {
      "Agent": {"shape": {"type": "Record", "attributes": {}}},
      "Tool": {"shape": {"type": "Record", "attributes": {}}},
      "PolicyTarget": {"shape": {"type": "Record", "attributes": {}}}
    },
    "actions": {
      "pre_tool_call": {"appliesTo": {
        "principalTypes": ["Agent"], "resourceTypes": ["Tool"],
        "context": {"type": "Record", "attributes": {
          "envelope": {"type": "Record", "attributes": {
            "agent": {"type": "Record", "attributes": {
              "id": {"type": "String"},
              "version": {"type": "String", "required": false},
              "name": {"type": "String", "required": false}
            }},
            "session": {"type": "Record", "required": false, "attributes": {
              "id": {"type": "String"},
              "started_at": {"type": "String", "required": false}
            }},
            "intervention_point": {"type": "String", "required": false},
            "timestamp": {"type": "String", "required": false},
            "budgets": {"type": "Record", "required": false, "attributes": {
              "tool_call_count": {"type": "Long", "required": false},
              "token_count": {"type": "Long", "required": false}
            }}
          }},
          "tool_call": {"type": "Record", "attributes": {
            "name": {"type": "String"},
            "id": {"type": "String", "required": false},
            "args": {"type": "Record", "attributes": {
              "amount": {"type": "Long", "required": false}
            }}
          }},
          "annotations": {"type": "Record", "attributes": {}}
        }}
      }}
    }
  }
}"#;

fn with_schema(policy_set: &str, name: &str, schema: &str) -> JsonValue {
    json!({
        "type": "cedar",
        "policy_set": policy_set,
        "schema_path": write_fixture(&format!("{name}.schema.json"), schema)
    })
}

#[test]
fn schema_declaring_the_context_shape_accepts_the_request() {
    let outcome = evaluate(
        with_schema(FORBID_GUARDED, "with-context", SCHEMA_WITH_CONTEXT_SHAPE),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_plain_deny(&outcome, "amount_too_high");
}

#[test]
fn schema_without_a_context_shape_fails_closed() {
    let outcome = evaluate(
        with_schema(
            FORBID_GUARDED,
            "without-context",
            SCHEMA_WITHOUT_CONTEXT_SHAPE,
        ),
        envelope_snapshot("pay", json!({"amount": 500}), 0),
    );
    assert_fails_closed_naming(&outcome, "context");
}

#[test]
fn schema_type_mismatch_in_the_context_fails_closed() {
    let outcome = evaluate(
        with_schema(FORBID_GUARDED, "type-mismatch", SCHEMA_WITH_CONTEXT_SHAPE),
        envelope_snapshot("pay", json!({"amount": "five hundred"}), 0),
    );
    assert_fails_closed_naming(&outcome, "context");
}
