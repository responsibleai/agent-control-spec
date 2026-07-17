//! AGENT-HOOKS-0.1 conformance for the agent-control-spec reference
//! host, plus an end-to-end session registering [`AcsInterceptor`]
//! with an agent-hooks emitter.
//!
//! The host adapter under claim is the emitter loop shipped with the
//! agent-hooks SDK, which is exactly this repository's documented
//! bootstrap ("register interceptors with an `InterceptionEmitter`").
//! The corpus runs against that loop via the SDK's reference harness;
//! the vendored vectors and their provenance are under
//! `conformance/agent-hooks/`.

use agent_control_spec::{
    AcsInterceptor, AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Manifest,
    PolicyDispatcher, PreparedPolicyInvocation, RuntimeError,
};
use agent_hooks::ctk::{load_vectors, run_vector, ReferenceHarness};
use agent_hooks::{AgentContextBuilder, Decision, EnforcementMode, InterceptionEmitter};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn reference_host_passes_the_agent_hooks_conformance_corpus() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/agent-hooks/vectors"
    );
    let vectors = load_vectors(dir).expect("load vendored vectors");
    assert!(
        vectors.len() >= 40,
        "expected the full corpus, got {}",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut passed = 0usize;
    let mut by_part: std::collections::BTreeMap<String, (usize, usize)> = Default::default();

    for vector in &vectors {
        let mut host = ReferenceHarness::new();
        let result = run_vector(&mut host, vector).await;
        let part = vector
            .get("part")
            .and_then(|value| value.as_str())
            .unwrap_or("unspecified")
            .to_string();
        match result.status {
            "skip" => skipped.push(result.id.clone()),
            "pass" => {
                passed += 1;
                by_part.entry(part).or_default().0 += 1;
            }
            _ => {
                by_part.entry(part).or_default().1 += 1;
                failures.push(format!("{}: {:?}", result.id, result.failures));
            }
        }
    }

    // Persist the per-part report next to the vendored corpus so the
    // conformance claim carries its evidence.
    let mut report = String::from(
        "# AGENT-HOOKS-0.1 conformance report\n\n\
         Host adapter: `agent-control-spec-reference-host` (agent-hooks\n\
         emitter loop; see `engine/tests/agent_hooks_conformance.rs`).\n\
         Corpus: vendored per `PROVENANCE.md`.\n\n\
         | Part | Passed | Failed |\n| --- | --- | --- |\n",
    );
    for (part, (pass, fail)) in &by_part {
        report.push_str(&format!("| {part} | {pass} | {fail} |\n"));
    }
    report.push_str(&format!(
        "\nTotal: {} passed, {} failed, {} skipped (capability-gated) of {}.\n",
        passed,
        failures.len(),
        skipped.len(),
        vectors.len()
    ));
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/agent-hooks/REPORT.md"
        ),
        report,
    )
    .expect("write conformance report");

    assert!(failures.is_empty(), "{failures:#?}");
}

/// A policy that denies wire transfers above a threshold with an
/// approval block, redacts account identifiers on tool results, and
/// allows everything else.
struct DemoPolicy;

impl PolicyDispatcher for DemoPolicy {
    fn evaluate(
        &self,
        invocation: &PreparedPolicyInvocation,
    ) -> Result<serde_json::Value, agent_control_spec::RuntimeError> {
        let input = invocation.policy_input().expect("policy input");
        let target = &input["policy_target"]["value"];
        if target["amount"].as_u64().unwrap_or(0) > 10_000 {
            return Ok(json!({
                "decision": "escalate",
                "reason": "large_wire_transfer_requires_review"
            }));
        }
        if target["account"].as_str().is_some() {
            return Ok(json!({
                "decision": "transform",
                "reason": "account_identifier_redacted",
                "transform": {"path": "$target.account", "value": "[redacted]"}
            }));
        }
        Ok(json!({"decision": "allow"}))
    }
}

const DEMO_MANIFEST: &str = r#"
agent_control_specification_version: 0.4.0-alpha.1
policies:
  demo:
    type: test
intervention_points:
  pre_tool_call:
    policy:
      id: demo
    policy_target: $snap.tool_call.args
  post_tool_call:
    policy:
      id: demo
    policy_target: $snap.tool_result
"#;

#[tokio::test]
async fn acs_interceptor_drives_control_through_an_emitter_session() {
    let manifest = Manifest::from_yaml_str(DEMO_MANIFEST).expect("manifest");
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
    let runtime =
        agent_control_spec::Runtime::new(manifest, Arc::new(NoAnnotators), Arc::new(DemoPolicy))
            .expect("runtime");

    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.register(Box::new(AcsInterceptor::new(runtime)));

    // Small transfer with an account identifier: the policy transforms.
    let mut builder = AgentContextBuilder::new("demo-agent", "acs-tests", "session-1");
    let mut ctx = builder.pre_tool_call(
        "tc-1",
        "wire_transfer",
        json!({"amount": 100, "account": "CHK-1"}),
    );
    let outcome = emitter.emit(&mut ctx).await.expect("transform proceeds");
    assert_eq!(outcome.record.verdict.decision, Decision::Transform);
    assert_eq!(outcome.target["account"], json!("[redacted]"));

    // Large transfer: the escalation intent surfaces as a liftable deny
    // and, with no resolver registered, the deny stands (AGENT-HOOKS-0.1
    // §9) — the emitter reports the block.
    let mut ctx = builder.pre_tool_call("tc-2", "wire_transfer", json!({"amount": 50_000}));
    let blocked = emitter.emit(&mut ctx).await.expect_err("deny blocks");
    assert_eq!(blocked.record.verdict.decision, Decision::Deny);
    assert!(blocked.record.verdict.approval.is_some());
    assert_eq!(
        blocked.record.verdict.reason.as_deref(),
        Some("large_wire_transfer_requires_review")
    );
}
