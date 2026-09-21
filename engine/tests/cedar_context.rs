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

/// A manifest binding `policy` at one intervention point. The harness
/// models the two tool points and the input point.
fn manifest(point: InterceptionPoint, policy: JsonValue, annotators: &[&str]) -> Manifest {
    let mut binding = match point {
        InterceptionPoint::PreToolCall => json!({
            "policy_target": "$snap.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$snap.tool_call.name",
            "policy": {"id": "gate"}
        }),
        InterceptionPoint::PostToolCall => json!({
            "policy_target": "$snap.tool_result",
            "policy_target_kind": "tool_result",
            "tool_name_from": "$snap.tool_call.name",
            "policy": {"id": "gate"}
        }),
        InterceptionPoint::Input => json!({
            "policy_target": "$snap.input",
            "policy_target_kind": "user_input",
            "policy": {"id": "gate"}
        }),
        other => panic!("the harness binds pre_tool_call, post_tool_call and input, not {other}"),
    };
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
        binding["annotations"] = JsonValue::Object(bound);
    }
    doc["intervention_points"] = json!({ point.as_str(): binding });
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

fn policy_target_entity(kind: &str, attrs: JsonValue) -> JsonValue {
    json!({"uid": {"type": "PolicyTarget", "id": kind}, "attrs": attrs, "parents": []})
}

/// The AGT envelope block that `build_cedar_request` reads the principal
/// from.
fn envelope(point: InterceptionPoint, tool_call_count: u64) -> JsonValue {
    json!({
        "agent": {"id": "agent-1", "version": "1.0", "name": "agent-1"},
        "session": {"id": "sess-1", "started_at": "2026-01-01T00:00:00Z"},
        "intervention_point": point.as_str(),
        "timestamp": "2026-01-01T00:00:01Z",
        "budgets": {"tool_call_count": tool_call_count, "token_count": 0}
    })
}

/// Snapshot for the tool point in the AGT envelope shape.
fn envelope_snapshot(tool: &str, args: JsonValue, tool_call_count: u64) -> JsonValue {
    json!({
        "envelope": envelope(InterceptionPoint::PreToolCall, tool_call_count),
        "tool_call": {"name": tool, "args": args, "id": "call-1"}
    })
}

/// Snapshot for the post-tool point in the AGT envelope shape. The AGT
/// host writes `error: null` and a float `duration_ms` on every
/// successful call, so a post-tool request always carries both.
fn post_tool_snapshot(
    tool: &str,
    value: JsonValue,
    error: JsonValue,
    duration_ms: JsonValue,
) -> JsonValue {
    json!({
        "envelope": envelope(InterceptionPoint::PostToolCall, 1),
        "tool_call": {"name": tool, "args": {}, "id": "call-1"},
        "tool_result": {"value": value, "error": error, "duration_ms": duration_ms}
    })
}

/// Snapshot for the input point in the AGT envelope shape.
fn input_snapshot(input: JsonValue) -> JsonValue {
    json!({
        "envelope": envelope(InterceptionPoint::Input, 0),
        "input": input
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
    evaluate_at(InterceptionPoint::PreToolCall, policy, snapshot)
}

fn evaluate_at(point: InterceptionPoint, policy: JsonValue, snapshot: JsonValue) -> Outcome {
    run(point, policy, &[], json!({}), snapshot)
}

fn evaluate_with_annotators(
    policy: JsonValue,
    annotators: &[&str],
    outputs: JsonValue,
    snapshot: JsonValue,
) -> Outcome {
    run(
        InterceptionPoint::PreToolCall,
        policy,
        annotators,
        outputs,
        snapshot,
    )
}

fn run(
    point: InterceptionPoint,
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
        manifest(point, policy, annotators),
        Arc::new(FixtureAnnotators(outputs)),
        dispatcher.clone(),
    )
    .expect("runtime builds");
    let result = runtime.evaluate_point(point, snapshot);
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

/// The library's IFC gate at the input point tests the source labels
/// against the sink's clearance with `containsAll`. A `null` label has
/// no `has` guard, so dropping it would shorten the set and pass the
/// gate. The request fails closed instead and the detail names the
/// element.
#[test]
fn library_ifc_fails_closed_on_a_null_source_label() {
    let policy = library(
        "ifc-null",
        json!([policy_target_entity(
            "user_input",
            json!({"clearance_dominated_labels": ["public"]})
        )]),
    );
    let labelled =
        |labels: JsonValue| input_snapshot(json!({"body": "hi", "ifc": {"source_labels": labels}}));

    let control = evaluate_at(
        InterceptionPoint::Input,
        policy.clone(),
        labelled(json!(["public", "secret"])),
    );
    assert_plain_deny(&control, "ifc_clearance_violation_input");
    let clean = evaluate_at(
        InterceptionPoint::Input,
        policy.clone(),
        labelled(json!(["public"])),
    );
    assert_plain_allow(&clean);

    let outcome = evaluate_at(
        InterceptionPoint::Input,
        policy.clone(),
        labelled(json!(["public", null])),
    );
    assert_fails_closed_naming(&outcome, "'context.input.ifc.source_labels[1]'");
    let outcome = evaluate_at(
        InterceptionPoint::Input,
        policy,
        labelled(json!([null, null])),
    );
    assert_fails_closed_naming(&outcome, "'context.input.ifc.source_labels[0]'");
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
    assert_fails_closed_naming(
        &outcome,
        "policy `policy0`: a record attribute does not exist",
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

/// Cedar reports the contributing policies as a set whose iteration
/// order changes from one response to the next. With two policies and
/// one evaluation, a dispatcher that dropped the declaration sort would
/// still pass half the time. The order tests declare eight policies
/// whose ids sort against declaration order and repeat the evaluation
/// this many times, so a reason picked by set order or by string order
/// shows up.
const ORDER_RUNS: usize = 20;

/// Eight ids in declaration order. Each sorts before the one declared
/// ahead of it, so string order disagrees with declaration order at
/// every position.
const IDS_SORTED_AGAINST_DECLARATION: [&str; 8] = [
    "z_first",
    "y_second",
    "x_third",
    "w_fourth",
    "v_fifth",
    "u_sixth",
    "t_seventh",
    "s_eighth",
];

/// One `forbid` per id, each firing on `amount > 10`, then a permit.
fn forbids_with_ids(ids: &[&str]) -> String {
    let mut policy = String::new();
    for id in ids {
        policy.push_str(&format!(
            "@id(\"{id}\")\nforbid(principal, action, resource) when {{ context.tool_call.args.amount > 10 }};\n"
        ));
    }
    policy.push_str("permit(principal, action, resource);\n");
    policy
}

#[test]
fn deny_reason_is_the_first_contributing_forbid_in_declaration_order() {
    let policy = forbids_with_ids(&IDS_SORTED_AGAINST_DECLARATION);
    for _ in 0..ORDER_RUNS {
        let outcome = evaluate(
            inline(&policy),
            envelope_snapshot("pay", json!({"amount": 500}), 0),
        );
        assert_plain_deny(&outcome, "z_first");
    }
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
fn fallback_ids_follow_declaration_order_not_string_order() {
    // policy0 permits, policy1 does not fire, policy2 to policy11 fire.
    // A sort by the id's text would put `policy10` ahead of `policy2`.
    let mut policy = String::from(
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) when { context.tool_call.args.amount > 1000 };\n",
    );
    for _ in 0..10 {
        policy.push_str(
            "forbid(principal, action, resource) when { context.tool_call.args.amount > 10 };\n",
        );
    }
    for _ in 0..ORDER_RUNS {
        let outcome = evaluate(
            inline(&policy),
            envelope_snapshot("pay", json!({"amount": 500}), 0),
        );
        assert_plain_deny(&outcome, "policy2");
    }
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

/// Cedar's message for an integer overflow quotes both operands, and its
/// message for a failed extension call quotes the argument. Both can be
/// snapshot values, so the detail names the policy and the kind of error
/// instead.
#[test]
fn evaluation_error_detail_names_the_policy_and_the_kind_not_the_operands() {
    let overflow = evaluate(
        inline(
            r#"
@id("overflow")
forbid(principal, action, resource) when {
  context.tool_call.args.amount * 9223372036854775807 > 1
};
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 424242}), 0),
    );
    assert_fails_closed_naming(&overflow, "policy `policy0`: integer overflow");
    assert_detail_omits_the_value(&overflow, &["424242", "9223372036854775807"]);

    let extension = evaluate(
        inline(
            r#"
@id("loopback")
forbid(principal, action, resource) when { ip(context.tool_call.args.host).isLoopback() };
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"host": "not-an-address-7f3a"}), 0),
    );
    assert_fails_closed_naming(&extension, "policy `policy0`: an extension function failed");
    assert_detail_omits_the_value(&extension, &["not-an-address-7f3a"]);
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
    // Eight warn permits whose reasons sort against declaration order;
    // see ORDER_RUNS for why there are eight and why the loop.
    let mut policy = String::new();
    for reason in IDS_SORTED_AGAINST_DECLARATION {
        policy.push_str(&format!(
            "@advice(\"{{\\\"verdict\\\":\\\"warn\\\",\\\"reason\\\":\\\"{reason}\\\"}}\")\n\
             permit(principal, action, resource);\n"
        ));
    }
    for _ in 0..ORDER_RUNS {
        let outcome = evaluate(
            inline(&policy),
            envelope_snapshot("pay", json!({"amount": 1}), 0),
        );
        assert_eq!(
            outcome.verdict.decision,
            Decision::Allow,
            "{:?}",
            outcome.verdict
        );
        assert_eq!(outcome.verdict.warnings.len(), 1);
        assert_eq!(
            outcome.verdict.warnings[0].reason.as_deref(),
            Some("z_first")
        );
    }
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

/// A Cedar annotation is a string literal, so the JSON's quotes and
/// backslashes are escaped.
fn advice_annotation(json: &str) -> String {
    format!(
        "@advice(\"{}\")",
        json.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

/// Well-formed JSON that the advice schema rejects, through the bundled
/// dispatcher. `normalize_policy_output` would also refuse most of these,
/// but a verdict of `allow` or `deny` would pass it, and a member the
/// schema does not list would be dropped in silence; 12.4 promises a
/// closed failure for every mismatch.
#[test]
fn advice_outside_the_schema_fails_closed_as_policy_output_invalid() {
    let cases = [
        ("verdict outside the set", r#"{"verdict":"approve"}"#),
        ("verdict allow", r#"{"verdict":"allow"}"#),
        ("verdict deny", r#"{"verdict":"deny"}"#),
        ("missing verdict", r#"{"reason":"no_verdict"}"#),
        ("array", "[]"),
        ("string", r#""warn""#),
        ("empty string", r#""""#),
        ("non-string reason", r#"{"verdict":"warn","reason":7}"#),
        (
            "warn with a transform body",
            r#"{"verdict":"warn","transform":{"path":"$target.value","value":1}}"#,
        ),
        ("transform without a body", r#"{"verdict":"transform"}"#),
        ("unknown member", r#"{"verdict":"warn","extra":1}"#),
        (
            "misspelt transform",
            r#"{"verdict":"warn","tranform":{"path":"$target.value","value":1}}"#,
        ),
        (
            "warnings smuggled in",
            r#"{"verdict":"escalate","warnings":[{"reason":"smuggled"}]}"#,
        ),
        (
            "approval smuggled in",
            r#"{"verdict":"warn","approval":{"x":1}}"#,
        ),
        (
            "result_labels smuggled in",
            r#"{"verdict":"warn","result_labels":["smuggled"]}"#,
        ),
        (
            "evidence smuggled in",
            r#"{"verdict":"warn","evidence":{"artefact":"x"}}"#,
        ),
        (
            "unknown transform member",
            r#"{"verdict":"transform","transform":{"path":"$target.value","value":1,"extra":true}}"#,
        ),
    ];
    let mut annotations = cases
        .iter()
        .map(|(label, json)| (*label, advice_annotation(json)))
        .collect::<Vec<_>>();
    annotations.push(("bare @advice", "@advice".to_string()));

    for (label, annotation) in annotations {
        let outcome = evaluate(
            inline(&format!(
                "{annotation}\npermit(principal, action, resource);\n"
            )),
            envelope_snapshot("pay", json!({"amount": 1}), 0),
        );
        assert_eq!(
            outcome.error_reason(),
            Some("runtime_error:policy_output_invalid"),
            "{label}: {:?}",
            outcome.dispatcher_error
        );
        let verdict = &outcome.verdict;
        assert_eq!(verdict.decision, Decision::Deny, "{label}: {verdict:?}");
        assert_eq!(
            verdict.reason.as_deref(),
            Some(POLICY_INVOCATION_FAILED),
            "{label}: {verdict:?}"
        );
        assert!(verdict.approval.is_none(), "{label}: {verdict:?}");
        assert!(verdict.transform.is_none(), "{label}: {verdict:?}");
        assert!(verdict.warnings.is_empty(), "{label}: {verdict:?}");
        assert!(verdict.result_labels.is_empty(), "{label}: {verdict:?}");
        assert!(verdict.evidence.is_none(), "{label}: {verdict:?}");
    }
}

/// Advice on a `forbid` has no meaning: the dispatcher reads `@advice`
/// only when Cedar allows.
#[test]
fn advice_on_a_forbid_leaves_the_deny_plain() {
    let outcome = evaluate(
        inline(
            r#"
@advice("{\"verdict\":\"warn\",\"reason\":\"noted\"}")
@id("blocked")
forbid(principal, action, resource);
@advice("{\"verdict\":\"warn\",\"reason\":\"also_noted\"}")
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    assert_plain_deny(&outcome, "blocked");
    assert!(outcome.verdict.warnings.is_empty());
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

/// A tie at the fifth fractional digit rounds to the even neighbour, the
/// IEEE 754 default. Both amounts below scale to an exact half in f64, so
/// the outcome does not depend on how the product rounds.
#[test]
fn float_tie_at_the_fourth_fractional_digit_rounds_to_even() {
    // 100.00005 scales to 1000000.5. The even neighbour is 100.0000,
    // which is not greater than 100.0. Ties away from zero would give
    // 100.0001 and fire the gate.
    let rounds_down_to_even = evaluate(
        inline(FORBID_DECIMAL_OVER_100),
        envelope_snapshot("pay", json!({"amount": 100.00005}), 0),
    );
    assert_plain_allow(&rounds_down_to_even);
    // 100.00035 scales to 1000003.5. The even neighbour is 100.0004,
    // which is greater than 100.0003. Truncation would give 100.0003 and
    // miss the gate.
    let rounds_up_to_even = evaluate(
        inline(
            r#"
@id("amount_too_high")
forbid(principal, action, resource) when {
  context.tool_call.args.amount.greaterThan(decimal("100.0003"))
};
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"amount": 100.00035}), 0),
    );
    assert_plain_deny(&rounds_up_to_even, "amount_too_high");
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

/// Every successful post-tool snapshot from the AGT host carries
/// `tool_result.error: null` and a float `duration_ms`. The null drops,
/// so `has error` is false, and `0.0` arrives as `decimal("0.0")`.
#[test]
fn post_tool_snapshot_with_null_error_and_float_duration_evaluates() {
    let policy = inline(
        r#"
@id("tool_errored")
forbid(principal, action, resource) when { context.tool_result has error };
@id("tool_too_slow")
forbid(principal, action, resource) when {
  context.tool_result.duration_ms.greaterThan(decimal("1000.0"))
};
permit(principal, action, resource);
"#,
    );
    let success = evaluate_at(
        InterceptionPoint::PostToolCall,
        policy.clone(),
        post_tool_snapshot("search", json!({"hits": 3}), json!(null), json!(0.0)),
    );
    assert_plain_allow(&success);

    let errored = evaluate_at(
        InterceptionPoint::PostToolCall,
        policy.clone(),
        post_tool_snapshot("search", json!(null), json!("timeout"), json!(0.0)),
    );
    assert_plain_deny(&errored, "tool_errored");

    let slow = evaluate_at(
        InterceptionPoint::PostToolCall,
        policy,
        post_tool_snapshot("search", json!({"hits": 3}), json!(null), json!(1500.5)),
    );
    assert_plain_deny(&slow, "tool_too_slow");
}

/// A set gate such as an allowlist checked with `containsAll` has no
/// `has` guard for one element. Dropping a `null` element would evaluate
/// the gate on the shorter set; the request fails closed instead.
#[test]
fn null_set_element_fails_closed_naming_the_path() {
    let policy = inline(
        r#"
@id("unknown_recipient")
forbid(principal, action, resource) when {
  context.tool_call.args has recipients &&
  !(["alice@example.com", "bob@example.com"].containsAll(context.tool_call.args.recipients))
};
permit(principal, action, resource);
"#,
    );
    let control = evaluate(
        policy.clone(),
        envelope_snapshot(
            "pay",
            json!({"recipients": ["alice@example.com", "mallory@evil.example"]}),
            0,
        ),
    );
    assert_plain_deny(&control, "unknown_recipient");

    let outcome = evaluate(
        policy,
        envelope_snapshot("pay", json!({"recipients": ["alice@example.com", null]}), 0),
    );
    assert_fails_closed_naming(&outcome, "'context.tool_call.args.recipients[1]'");
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

/// The 12.4 context shape for `envelope_snapshot`, with the attributes
/// of `tool_call.args` given by the `ARGS_ATTRIBUTES` marker. Cedar
/// records are closed: a member the snapshot carries and the schema does
/// not declare is an error.
const SCHEMA_TEMPLATE: &str = r#"{
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
            "args": {"type": "Record", "attributes": {ARGS_ATTRIBUTES}}
          }},
          "annotations": {"type": "Record", "attributes": {}}
        }}
      }}
    }
  }
}"#;

const LONG_AMOUNT: &str = r#"{"type": "Long", "required": false}"#;
const DECIMAL_AMOUNT: &str = r#"{"type": "Extension", "name": "decimal", "required": false}"#;

fn schema_with_args(attributes: &str) -> String {
    SCHEMA_TEMPLATE.replace("ARGS_ATTRIBUTES", attributes)
}

fn schema_typing_amount(amount_type: &str) -> String {
    schema_with_args(&format!("\"amount\": {amount_type}"))
}

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
        with_schema(
            FORBID_GUARDED,
            "with-context",
            &schema_typing_amount(LONG_AMOUNT),
        ),
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
        with_schema(
            FORBID_GUARDED,
            "type-mismatch",
            &schema_typing_amount(LONG_AMOUNT),
        ),
        envelope_snapshot("pay", json!({"amount": "five hundred"}), 0),
    );
    assert_fails_closed_naming(&outcome, "context");
}

/// Cedar rejects an attribute the schema does not declare rather than
/// dropping it, so a schema narrower than the snapshot cannot starve a
/// gate of the member it reads.
#[test]
fn schema_narrower_than_the_snapshot_fails_closed() {
    let outcome = evaluate(
        with_schema(FORBID_GUARDED, "narrow", &schema_typing_amount(LONG_AMOUNT)),
        envelope_snapshot(
            "pay",
            json!({"amount": 500, "host": "attacker.example.org"}),
            0,
        ),
    );
    assert_fails_closed_naming(&outcome, "rejected the request context");
}

// ── Long and decimal across types ────────────────────────────────────

const FORBID_AMOUNT_EQ_100: &str = r#"
@id("blocked_amount")
forbid(principal, action, resource) when {
  context.tool_call.args has amount && context.tool_call.args.amount == 100
};
permit(principal, action, resource);
"#;

/// Assert an allow and name the case in the failure message.
fn assert_allowed_for(outcome: &Outcome, case: &str) {
    assert_eq!(
        outcome.verdict.decision,
        Decision::Allow,
        "{case}: {:?} / {:?}",
        outcome.verdict,
        outcome.dispatcher_error
    );
    assert!(
        outcome.dispatcher_error.is_none(),
        "{case}: {:?}",
        outcome.dispatcher_error
    );
}

/// The rule 12.4 states. A JSON number with a fraction or an exponent is
/// a decimal, and Cedar's `==` and set membership across `Long` and
/// `decimal` are value comparisons that yield false with no error. `100`,
/// `100.0`, `1e2` and `-0` are one number to the tool that receives the
/// call but two Cedar types here, so an equality gate against a `Long`
/// literal is silent for the decimal forms, while `!=` fires. This test
/// pins that so any change to the number translation is deliberate; the
/// tests that follow pin the loud half and the schema mitigation.
#[test]
fn long_equality_against_a_decimal_is_false_without_a_schema() {
    let control = evaluate(
        inline(FORBID_AMOUNT_EQ_100),
        envelope_snapshot("pay", json!({"amount": 100}), 0),
    );
    assert_plain_deny(&control, "blocked_amount");
    for text in ["100.0", "1e2", "100E0"] {
        let amount: JsonValue = serde_json::from_str(text).unwrap();
        let outcome = evaluate(
            inline(FORBID_AMOUNT_EQ_100),
            envelope_snapshot("pay", json!({"amount": amount}), 0),
        );
        assert_allowed_for(&outcome, text);
    }

    // serde_json reads `-0` as the float -0.0.
    let zero_gate = r#"
@id("zero_amount")
forbid(principal, action, resource) when {
  context.tool_call.args has amount && context.tool_call.args.amount == 0
};
permit(principal, action, resource);
"#;
    let minus_zero: JsonValue = serde_json::from_str("-0").unwrap();
    let outcome = evaluate(
        inline(zero_gate),
        envelope_snapshot("pay", json!({"amount": minus_zero}), 0),
    );
    assert_allowed_for(&outcome, "-0");

    let blocklist = r#"
@id("blocked_account")
forbid(principal, action, resource) when {
  context.tool_call.args has account && [4242, 9999].contains(context.tool_call.args.account)
};
permit(principal, action, resource);
"#;
    let control = evaluate(
        inline(blocklist),
        envelope_snapshot("pay", json!({"account": 4242}), 0),
    );
    assert_plain_deny(&control, "blocked_account");
    let outcome = evaluate(
        inline(blocklist),
        envelope_snapshot("pay", json!({"account": 4242.0}), 0),
    );
    assert_allowed_for(&outcome, "4242.0 against a Long blocklist");

    let not_equal = r#"
@id("mode_not_one")
forbid(principal, action, resource) when {
  context.tool_call.args has mode && context.tool_call.args.mode != 1
};
permit(principal, action, resource);
"#;
    let outcome = evaluate(
        inline(not_equal),
        envelope_snapshot("pay", json!({"mode": 1.0}), 0),
    );
    assert_plain_deny(&outcome, "mode_not_one");
}

#[test]
fn ordering_against_a_decimal_is_a_type_error_and_fails_closed() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!({"amount": 500.0}), 0),
    );
    assert_fails_closed_naming(&outcome, "policy `policy0`: type error");
}

#[test]
fn schema_typed_long_rejects_a_decimal_in_the_request() {
    let outcome = evaluate(
        with_schema(
            FORBID_AMOUNT_EQ_100,
            "long-amount",
            &schema_typing_amount(LONG_AMOUNT),
        ),
        envelope_snapshot("pay", json!({"amount": 100.0}), 0),
    );
    assert_fails_closed_naming(&outcome, "rejected the request context");
}

#[test]
fn schema_typed_decimal_rejects_a_long_comparison_at_validation() {
    let outcome = evaluate(
        with_schema(
            FORBID_AMOUNT_EQ_100,
            "decimal-amount",
            &schema_typing_amount(DECIMAL_AMOUNT),
        ),
        envelope_snapshot("pay", json!({"amount": 100.0}), 0),
    );
    assert_fails_closed_naming(&outcome, "failed schema validation");
}

/// The guarded form of `FORBID_DECIMAL_OVER_100`: the schema declares
/// `amount` optional, so a validated read needs the `has` guard.
const FORBID_GUARDED_DECIMAL_OVER_100: &str = r#"
@id("amount_too_high")
forbid(principal, action, resource) when {
  context.tool_call.args has amount &&
  context.tool_call.args.amount.greaterThan(decimal("100.0"))
};
permit(principal, action, resource);
"#;

#[test]
fn schema_typed_decimal_accepts_a_float_and_the_gate_fires() {
    let policy = with_schema(
        FORBID_GUARDED_DECIMAL_OVER_100,
        "decimal-float",
        &schema_typing_amount(DECIMAL_AMOUNT),
    );
    let outcome = evaluate(
        policy.clone(),
        envelope_snapshot("pay", json!({"amount": 100.5}), 0),
    );
    assert_plain_deny(&outcome, "amount_too_high");
    let outcome = evaluate(policy, envelope_snapshot("pay", json!({"amount": 99.5}), 0));
    assert_plain_allow(&outcome);
}

/// The context is built without the schema and checked against it
/// afterwards, so a `decimal` typed attribute matches a JSON number only.
/// A string there is not read as the constructor argument, and it is
/// snapshot data, so it stays out of the detail.
#[test]
fn schema_typed_decimal_rejects_a_string_without_quoting_it() {
    let outcome = evaluate(
        with_schema(
            FORBID_GUARDED_DECIMAL_OVER_100,
            "decimal-string",
            &schema_typing_amount(DECIMAL_AMOUNT),
        ),
        envelope_snapshot("pay", json!({"amount": "SECRET-not-a-decimal"}), 0),
    );
    assert_fails_closed_naming(&outcome, "rejected the request context");
    assert_detail_omits_the_value(&outcome, &["SECRET-not-a-decimal"]);
}

/// A schema can type a context attribute as an entity. Built with the
/// schema, Cedar would read a `{"type", "id"}` record there as an entity
/// reference, and `tool_call.args` is model output, so a request could
/// name any entity in the store. The context is built without the
/// schema, so the record stays a record and the schema check rejects the
/// request for a member of the group and for a stranger alike.
#[test]
fn schema_typed_entity_attribute_is_not_forgeable_from_args() {
    let mut schema: JsonValue = serde_json::from_str(&schema_with_args(
        r#""approver": {"type": "Entity", "name": "Agent"}"#,
    ))
    .unwrap();
    schema[""]["entityTypes"]["Group"] = json!({"shape": {"type": "Record", "attributes": {}}});
    schema[""]["entityTypes"]["Agent"]["memberOfTypes"] = json!(["Group"]);
    let entities = json!([
        {"uid": {"type": "Agent", "id": "agent-1"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Agent", "id": "alice"}, "attrs": {}, "parents": [{"type": "Group", "id": "approvers"}]},
        {"uid": {"type": "Group", "id": "approvers"}, "attrs": {}, "parents": []},
        tool_entity("pay", json!({}))
    ]);
    let mut policy = with_schema(
        r#"
@id("approved")
permit(principal, action, resource) when {
  context.tool_call.args.approver in Group::"approvers"
};
"#,
        "entity-attr",
        &schema.to_string(),
    );
    policy["entities_path"] = json!(write_fixture(
        "entity-attr.entities.json",
        &entities.to_string()
    ));

    for approver in ["alice", "mallory"] {
        let outcome = evaluate(
            policy.clone(),
            envelope_snapshot(
                "pay",
                json!({"approver": {"type": "Agent", "id": approver}}),
                0,
            ),
        );
        assert_fails_closed_naming(&outcome, "rejected the request context");
        assert_detail_omits_the_value(&outcome, &[approver]);
    }
}

// ── keys, string args, principal id ──────────────────────────────────

#[test]
fn reserved_key_inside_a_set_inside_an_annotation_fails_closed_naming_the_path() {
    let outcome = evaluate_with_annotators(
        inline("permit(principal, action, resource);"),
        &["judge"],
        json!({"judge": {"labels": [{"__extn": {"fn": "ip", "arg": "10.0.0.1"}}]}}),
        envelope_snapshot("pay", json!({"amount": 1}), 0),
    );
    assert_fails_closed_naming(&outcome, "context.annotations.judge.labels[0].__extn");
}

#[test]
fn dotted_and_unicode_keys_reach_the_policy_verbatim() {
    let outcome = evaluate(
        inline(
            r#"
@id("dotted")
forbid(principal, action, resource) when {
  context.tool_call.args has "a.b" && context.tool_call.args["a.b"] == "x" &&
  context.tool_call.args has "hös-t" && context.tool_call.args["hös-t"] == "evil"
};
permit(principal, action, resource);
"#,
        ),
        envelope_snapshot("pay", json!({"a.b": "x", "hös-t": "evil"}), 0),
    );
    assert_plain_deny(&outcome, "dotted");
}

/// Args that arrive as a string holding JSON, a common model output, hit
/// `has` on a string. That is an evaluation error, so the request fails
/// closed instead of skipping the guarded forbid.
#[test]
fn string_valued_args_fail_closed_on_has() {
    let outcome = evaluate(
        inline(FORBID_GUARDED),
        envelope_snapshot("pay", json!("{\"amount\": 500}"), 0),
    );
    assert_fails_closed_naming(&outcome, "policy `policy0`: type error");
}

/// The principal id is spliced into `Agent::"<id>"`. A Cedar string
/// escape in the snapshot id does not decode to another id:
/// `EntityUid::from_str` wants a normalized uid and rejects it.
#[test]
fn principal_id_with_a_cedar_escape_fails_closed() {
    let policy = r#"permit(principal == Agent::"alice", action, resource);"#;
    let mut snapshot = envelope_snapshot("pay", json!({"amount": 1}), 0);
    snapshot["envelope"]["agent"]["id"] = json!("\\u{61}lice");
    let outcome = evaluate(inline(policy), snapshot);
    assert_fails_closed_naming(&outcome, "principal entity");

    let mut snapshot = envelope_snapshot("pay", json!({"amount": 1}), 0);
    snapshot["envelope"]["agent"]["id"] = json!("bob");
    let control = evaluate(inline(policy), snapshot);
    assert_plain_deny(&control, "no_matching_policy");
}
