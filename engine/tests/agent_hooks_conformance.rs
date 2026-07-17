//! AGENT-HOOKS-0.1 conformance for the agent-control-spec reference
//! host, plus an end-to-end session registering [`AcsInterceptor`]
//! with an agent-hooks emitter.
//!
//! The host adapter under claim is `agent-control-spec-reference-host`:
//! this repository's own [`Harness`] implementation over the emitter
//! loop, which is exactly the documented bootstrap ("register
//! interceptors with an `InterceptionEmitter`"). The vendored vectors
//! and their provenance are under `conformance/agent-hooks/`.

use agent_control_spec::{
    AcsInterceptor, AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Manifest,
    PolicyDispatcher, PreparedPolicyInvocation, RuntimeError,
};
use agent_hooks::ctk::{load_vectors, run_vector, Harness, IdentityPair, RunRecord, VectorSetup};
use agent_hooks::{
    apply_transform_to_ctx, AgentContextBuilder, Decision, EnforcementMode, InterceptionBlocked,
    InterceptionEmitter, Transform,
};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

/// This repository's CTK host adapter: a minimal in-memory agent loop
/// over the agent-hooks emitter, wired per [`VectorSetup`].
#[derive(Default)]
struct AcsReferenceHost {
    scenario: Value,
    emitter: Option<InterceptionEmitter>,
    builder: Option<AgentContextBuilder>,
    tool_log: Vec<Value>,
    session_counter: u64,
}

impl AcsReferenceHost {
    fn invoke_tool(&self, name: &str, args: &Value) -> (Value, bool) {
        let tools = self.scenario["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let spec = tools
            .iter()
            .find(|tool| tool["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("tool {name} not in scenario"));
        for behavior in spec["behavior"].as_array().into_iter().flatten() {
            let matched = match behavior.get("when_args") {
                None => true,
                Some(when_args) => when_args == args,
            };
            if matched {
                return (
                    behavior["return"].clone(),
                    behavior
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                );
            }
        }
        panic!("tool {name} invoked with {args}: no matching behavior");
    }

    async fn do_tool_call(&mut self, tool_call: &Value) -> Result<Value, InterceptionBlocked> {
        let id = tool_call["id"].as_str().unwrap_or("").to_owned();
        let name = tool_call["name"].as_str().unwrap_or("").to_owned();
        let mut ctx = self.builder.as_mut().expect("setup").pre_tool_call(
            &id,
            &name,
            tool_call["args"].clone(),
        );
        self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;
        let args = ctx["tool_call"]["args"].clone(); // post-transform (§4.3)

        let (value, is_error) = self.invoke_tool(&name, &args);
        self.tool_log.push(json!({ "name": name, "args": args }));

        let mut ctx = self.builder.as_mut().expect("setup").post_tool_call(
            &id,
            &name,
            args,
            value.clone(),
            is_error,
        );
        self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;
        Ok(json!({ "role": "tool", "content": value }))
    }

    /// The agent loop proper; a block verdict unwinds via `Err`.
    async fn run_inner(&mut self) -> Result<Value, InterceptionBlocked> {
        let scenario = self.scenario.clone();
        let mut final_output = Value::Null;

        let mut tool_names: Vec<String> = scenario["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect();
        tool_names.sort();

        let mut ctx = self
            .builder
            .as_mut()
            .expect("setup")
            .agent_startup(tool_names);
        self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;

        let input = &scenario["input"];
        let content = input["content"].clone();
        let role = input["role"].as_str().unwrap_or("user").to_owned();
        let mut ctx = self
            .builder
            .as_mut()
            .expect("setup")
            .input(content.clone(), &role);
        self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;

        let mut messages = vec![json!({ "role": role, "content": content })];

        for step in scenario["model_script"].as_array().into_iter().flatten() {
            let resp = &step["respond"];

            let mut ctx = self
                .builder
                .as_mut()
                .expect("setup")
                .pre_model_call("mock", messages.clone());
            self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;
            // may be transformed (§4.3)
            messages = ctx["messages"].as_array().cloned().unwrap_or(messages);

            let tool_calls = resp["tool_calls"].as_array().cloned().unwrap_or_default();
            let mut ctx = self.builder.as_mut().expect("setup").post_model_call(
                "mock",
                resp["content"].clone(),
                tool_calls.clone(),
                resp["finish_reason"].as_str().unwrap_or(""),
            );
            self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;

            if tool_calls.is_empty() {
                final_output = resp["content"].clone();
                break;
            }
            for tool_call in &tool_calls {
                match self.do_tool_call(tool_call).await {
                    Ok(tool_msg) => messages.push(tool_msg),
                    Err(blocked) => messages.push(json!({
                        "role": "tool",
                        "content": format!(
                            "blocked: {}",
                            blocked.record.verdict.reason.as_deref().unwrap_or("")
                        ),
                    })),
                }
            }
            let assistant_content = if resp["content"].is_null() {
                json!("")
            } else {
                resp["content"].clone()
            };
            messages.push(json!({ "role": "assistant", "content": assistant_content }));
        }

        if !final_output.is_null() {
            let mut ctx = self.builder.as_mut().expect("setup").output(final_output);
            self.emitter.as_mut().expect("setup").emit(&mut ctx).await?;
            final_output = ctx["output"]["content"].clone();
        }
        Ok(final_output)
    }
}

#[async_trait]
impl Harness for AcsReferenceHost {
    fn name(&self) -> &str {
        "agent-control-spec-reference-host"
    }

    fn capabilities(&self) -> Vec<String> {
        // bigint_json is NOT claimed: serde_json coerces beyond-u64
        // vector literals to f64 at load, so this host cannot present
        // such a context faithfully. int64_json holds: i64 loads
        // losslessly (§4.4).
        vec![
            "model_calls".into(),
            "tool_calls".into(),
            "int64_json".into(),
        ]
    }

    fn setup(&mut self, setup: VectorSetup) {
        self.scenario = setup.scenario;
        self.tool_log.clear();
        self.session_counter += 1;
        let mut emitter = InterceptionEmitter::new(setup.mode, setup.resolver);
        emitter.set_composition(setup.composition);
        emitter
            .set_identity_provider(setup.identity_provider)
            .expect("CTK provider names are valid by construction");
        let redact_for_approval = setup.redact_for_approval;
        if !redact_for_approval.is_empty() {
            // §9 redaction seam, CTK convention: each listed path is
            // replaced with "[redacted]" via the §5.2/§4.3 transform
            // machinery; a path that does not resolve at the escalating
            // point is left untouched.
            emitter.set_approval_redactor(move |ctx| {
                let mut redacted = ctx.clone();
                for path in &redact_for_approval {
                    let transform = Transform {
                        path: path.clone(),
                        value: Value::String("[redacted]".into()),
                    };
                    let _ = apply_transform_to_ctx(&mut redacted, &transform);
                }
                redacted
            });
        }
        for interceptor in setup.interceptors {
            emitter.register(interceptor);
        }
        self.emitter = Some(emitter);
        self.builder = Some(AgentContextBuilder::new(
            "acs-agent",
            "agent-control-spec-reference-host",
            &format!("sess-{}", self.session_counter),
        ));
    }

    async fn run(&mut self) -> RunRecord {
        let (outcome, final_output) = match self.run_inner().await {
            Ok(output) => ("completed", output),
            Err(_) => ("blocked", Value::Null),
        };

        let mut ctx =
            self.builder
                .as_mut()
                .expect("setup")
                .agent_shutdown(if outcome == "completed" {
                    "completed"
                } else {
                    "error"
                });
        let emitter = self.emitter.as_mut().expect("setup");
        emitter.emit_unchecked(&mut ctx).await;

        RunRecord {
            outcome: outcome.to_owned(),
            final_output,
            tool_invocations: self.tool_log.clone(),
            error: None,
            identities: emitter
                .records()
                .iter()
                .map(|record| IdentityPair {
                    input_identity: record.input_identity.clone(),
                    enforced_identity: record.enforced_identity.clone(),
                })
                .collect(),
            records: emitter
                .records()
                .iter()
                .map(|record| serde_json::to_value(record).expect("record serializes"))
                .collect(),
        }
    }

    fn teardown(&mut self) {
        self.emitter = None;
        self.builder = None;
    }
}

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

    let mut host = AcsReferenceHost::default();
    for vector in &vectors {
        let result = run_vector(&mut host, vector).await;
        let part = if result.part.is_empty() {
            "unspecified".to_string()
        } else {
            result.part.clone()
        };
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
         Host adapter: `agent-control-spec-reference-host` (this\n\
         repository's `ctk::Harness` over the agent-hooks emitter loop;\n\
         see `engine/tests/agent_hooks_conformance.rs`).\n\
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
