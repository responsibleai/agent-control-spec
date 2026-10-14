//! AGENT-HOOKS-0.1 conformance for the agent-control-spec reference
//! host, plus an end-to-end session registering [`AcsInterceptor`]
//! with an agent-hooks emitter.
//!
//! The host adapter under claim is `agent-control-spec-reference-host`:
//! this repository's own [`Harness`] implementation over the emitter
//! loop, which is exactly the documented bootstrap ("register
//! interceptors with an `InterceptionEmitter`"). The vendored vectors
//! and their provenance are under `conformance/agent-hooks/`.

// The harness returns the SDK's `InterceptionBlocked` as its `Err`; that
// type is large by design and the test does not box it.
#![allow(clippy::result_large_err)]

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

mod common;

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
            // `postures` (0.1.0-beta.1) and `load` (0.1.0-beta.2) are
            // runner-owned: the runner fills them from the Harness
            // declaration. Spread the default so later runner-owned
            // fields do not break this build.
            ..Default::default()
        }
    }

    fn teardown(&mut self) {
        self.emitter = None;
        self.builder = None;
    }
}

/// The result the committed report records. The counts are pinned so a
/// capability dropped from the harness, a vector deleted from the
/// vendored corpus, or a regression that turns a pass into a skip fails
/// this test instead of silently rewriting `REPORT.md`.
const EXPECTED_VECTORS: usize = 73;
const EXPECTED_PASSED: usize = 46;
const EXPECTED_FAILED: usize = 0;
/// Skipped vectors by the undeclared capability that gates them.
const EXPECTED_SKIPS: &[(&str, usize)] = &[
    ("bigint_json", 1),
    ("host_declaration", 22),
    ("incremental_output", 4),
];

/// The identity provider the host runs the corpus under when a vector
/// does not pick one. `jcs-sha256` is content-derived: a pure function
/// of the projected context (AGENT-HOOKS-0.1 section 10).
const IDENTITY_PROVIDER: &str = "jcs-sha256";

fn conformance_dir() -> std::path::PathBuf {
    common::repo_root().join("conformance").join("agent-hooks")
}

/// What `PROVENANCE.md` records about the vendored corpus.
struct Provenance {
    tag: String,
    commit: String,
    files: usize,
    digest: String,
}

fn read_provenance() -> Provenance {
    let text = std::fs::read_to_string(conformance_dir().join("PROVENANCE.md"))
        .expect("read conformance/agent-hooks/PROVENANCE.md");
    // `- Label: `value`` or `- Label: value (note)`: the first token.
    let field = |label: &str| -> String {
        let prefix = format!("- {label}: ");
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .map(|rest| rest.trim_start_matches('`'))
            .and_then(|rest| rest.split(['`', ' ']).next())
            .unwrap_or_else(|| panic!("PROVENANCE.md has no `- {label}:` line"))
            .to_owned()
    };
    Provenance {
        tag: field("Tag"),
        commit: field("Commit"),
        files: field("Files").parse().expect("PROVENANCE.md file count"),
        digest: field("Digest"),
    }
}

/// The `agent-hooks-sdk` version the engine resolves, read from the
/// workspace lock file so the report names the SDK the run used.
fn agent_hooks_sdk_version() -> String {
    let lock =
        std::fs::read_to_string(common::repo_root().join("Cargo.lock")).expect("read Cargo.lock");
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"agent-hooks-sdk\"" {
            return lines
                .next()
                .and_then(|next| next.trim().strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .expect("Cargo.lock: version follows the package name")
                .to_owned();
        }
    }
    panic!("Cargo.lock does not resolve agent-hooks-sdk");
}

/// The capabilities a vector needs that the host does not declare.
fn undeclared_capabilities(vector: &Value, declared: &[String]) -> Vec<String> {
    vector["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|capability| !declared.iter().any(|have| have == capability))
        .map(str::to_owned)
        .collect()
}

/// Recomputes the corpus digest the way `PROVENANCE.md` documents:
/// `LC_ALL=C sha256sum AH-CTK-*.json | LC_ALL=C sort | sha256sum`
/// from inside `vectors/`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The SHA-256 of one vector as `sha256sum` reports it on the LF file
/// the upstream repository holds. A checkout that converts text files
/// to CRLF (Windows with `core.autocrlf`) would otherwise change every
/// byte digest, so `\r\n` is normalised to `\n` before hashing; the
/// vectors contain no bare `\r`, and `.gitattributes` pins them to LF.
fn vector_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut normalised = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().peekable();
    while let Some(&byte) = iter.next() {
        if byte == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        normalised.push(byte);
    }
    hex(&Sha256::digest(&normalised))
}

/// The corpus digest over a list of `<sha256>  <name>` lines, the way
/// `LC_ALL=C sort | sha256sum` computes it.
fn corpus_digest(mut lines: Vec<String>) -> String {
    use sha2::{Digest, Sha256};
    // `LC_ALL=C sort` orders by byte value.
    lines.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    hex(&Sha256::digest(lines.concat().as_bytes()))
}

#[test]
fn vector_digest_ignores_crlf_conversion_but_not_content_edits() {
    let lf = b"{\n  \"id\": \"AH-CTK-000\"\n}\n";
    let crlf = b"{\r\n  \"id\": \"AH-CTK-000\"\r\n}\r\n";
    let edited = b"{\n  \"id\": \"AH-CTK-001\"\n}\n";
    assert_eq!(vector_digest(lf), vector_digest(crlf));
    assert_ne!(vector_digest(lf), vector_digest(edited));
    // `printf '{\n  "id": "AH-CTK-000"\n}\n' | sha256sum`, so the recipe
    // in PROVENANCE.md and this helper agree.
    assert_eq!(
        vector_digest(lf),
        "9331bcc16ca1a4b006f38e4b859a596e06445696146010d851533b5b30fbb216"
    );
}

#[test]
fn vendored_vectors_match_the_provenance_digest() {
    let provenance = read_provenance();
    let dir = conformance_dir().join("vectors");
    let lines: Vec<String> = std::fs::read_dir(&dir)
        .expect("list vendored vectors")
        .map(|entry| entry.expect("directory entry").file_name())
        .filter_map(|name| name.into_string().ok())
        .filter(|name| name.starts_with("AH-CTK-") && name.ends_with(".json"))
        .map(|name| {
            let bytes = std::fs::read(dir.join(&name)).expect("read vector");
            format!("{}  {name}\n", vector_digest(&bytes))
        })
        .collect();
    assert_eq!(
        lines.len(),
        provenance.files,
        "PROVENANCE.md records {} vector files, the directory holds {}; \
         follow the refresh procedure in PROVENANCE.md",
        provenance.files,
        lines.len()
    );
    assert_eq!(
        corpus_digest(lines),
        provenance.digest,
        "the vendored vectors do not match the digest in PROVENANCE.md; \
         a vector was edited or added in-tree. Re-vendor the corpus from \
         agent-hooks {} ({}) or update PROVENANCE.md per its refresh procedure",
        provenance.tag,
        provenance.commit
    );
}

#[tokio::test]
async fn reference_host_passes_the_agent_hooks_conformance_corpus() {
    let provenance = read_provenance();
    let dir = conformance_dir().join("vectors");
    let vectors = load_vectors(&dir).expect("load vendored vectors");
    assert_eq!(
        vectors.len(),
        EXPECTED_VECTORS,
        "expected the full {EXPECTED_VECTORS}-vector corpus, got {}",
        vectors.len()
    );
    assert_eq!(
        vectors.len(),
        provenance.files,
        "PROVENANCE.md records a different file count than the directory holds"
    );

    let mut host = AcsReferenceHost::default();
    let declared = host.capabilities();
    let surface = host.host_surface();

    let mut failures: Vec<String> = Vec::new();
    // Skipped vector id -> the undeclared capabilities that gate it.
    let mut skipped: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut passed = 0usize;
    // part -> (passed, failed, skipped)
    let mut by_part: std::collections::BTreeMap<String, (usize, usize, usize)> = Default::default();

    for vector in &vectors {
        let result = run_vector(&mut host, vector).await;
        let part = if result.part.is_empty() {
            "unspecified".to_string()
        } else {
            result.part.clone()
        };
        match result.status {
            "skip" => {
                by_part.entry(part.clone()).or_default().2 += 1;
                skipped.push((
                    result.id.clone(),
                    part,
                    undeclared_capabilities(vector, &declared),
                ));
            }
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

    // Skip inventory by gating capability. Every skip must trace to a
    // capability this host does not declare; anything else is a runner
    // behaviour this report does not describe.
    let mut skips_by_capability: std::collections::BTreeMap<String, Vec<(String, String)>> =
        Default::default();
    for (id, part, gating) in &skipped {
        assert_eq!(
            gating.len(),
            1,
            "{id}: skipped for {gating:?}; the report attributes each skip to one capability"
        );
        skips_by_capability
            .entry(gating[0].clone())
            .or_default()
            .push((id.clone(), part.clone()));
    }

    // Persist the report next to the vendored corpus so the conformance
    // claim carries its evidence and the AGENT-HOOKS-0.1 section 13.3
    // claim tuple can be copied from it.
    let sdk_version = agent_hooks_sdk_version();
    let mut profiles: Vec<String> = surface
        .profiles
        .keys()
        .map(|profile| profile.as_str().to_owned())
        .collect();
    profiles.sort();
    let mut report = String::from(
        "# AGENT-HOOKS-0.1 conformance report\n\n\
         Generated by `engine/tests/agent_hooks_conformance.rs`; do not edit by hand.\n\n\
         ## Claim\n\n\
         The AGENT-HOOKS-0.1 section 13.3 tuple for this run.\n\n\
         | Field | Value |\n| --- | --- |\n",
    );
    report.push_str(&format!(
        "| Framework | `agent-control-spec` (host adapter `{}`) |\n",
        host.name()
    ));
    report.push_str(&format!(
        "| Adapter version | `{}` |\n",
        env!("CARGO_PKG_VERSION")
    ));
    report.push_str("| Spec | `agent-hooks/0.1` |\n");
    report.push_str(&format!(
        "| Capabilities | {} |\n",
        declared
            .iter()
            .map(|capability| format!("`{capability}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    report.push_str(&format!(
        "| Profiles | {} (every knob value each profile consults) |\n",
        profiles
            .iter()
            .map(|profile| format!("`{profile}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    report.push_str(&format!(
        "| Identity provider | `{IDENTITY_PROVIDER}`, content-derived (a pure function of the \
         projected context); the `identity_provider` vectors also run the vector-scoped \
         `null` provider |\n"
    ));
    report.push_str(&format!("| SDK | `rust@{sdk_version}` |\n"));
    report.push_str(&format!(
        "| Posture | `tool_seam_host_error: {}` (the default) |\n",
        surface.tool_seam_host_error.as_str()
    ));
    report.push_str(&format!(
        "| Buffered output | `{}`; `incremental_output` is not declared, so the \
         `streaming/incremental` vectors are skipped |\n",
        !surface.streams_unbuffered
    ));
    report.push_str(&format!(
        "| Kit | agent-hooks `{}` (commit `{}`), {} vectors vendored per `PROVENANCE.md` |\n",
        provenance.tag, provenance.commit, provenance.files
    ));
    report.push_str(
        "\nThe harness registers this repository's `AcsInterceptor` with the\n\
         agent-hooks `InterceptionEmitter` and drives the production dispatch\n\
         path with mocked model and tool I/O.\n\n\
         ## Results by part\n\n\
         | Part | Passed | Failed | Skipped |\n| --- | --- | --- | --- |\n",
    );
    for (part, (pass, fail, skip)) in &by_part {
        report.push_str(&format!("| {part} | {pass} | {fail} | {skip} |\n"));
    }
    report.push_str(&format!(
        "\nTotal: {} passed, {} failed, {} skipped (capability-gated) of {}.\n\n\
         ## Skipped vectors\n\n\
         Each skip is gated on one capability this host does not declare.\n\n",
        passed,
        failures.len(),
        skipped.len(),
        vectors.len()
    ));
    for (capability, ids) in &skips_by_capability {
        report.push_str(&format!(
            "### `{capability}` ({} vector{})\n\n",
            ids.len(),
            if ids.len() == 1 { "" } else { "s" }
        ));
        for (id, part) in ids {
            report.push_str(&format!("- `{id}` ({part})\n"));
        }
        report.push('\n');
    }
    std::fs::write(conformance_dir().join("REPORT.md"), report).expect("write conformance report");

    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(failures.len(), EXPECTED_FAILED);
    assert_eq!(
        passed, EXPECTED_PASSED,
        "pass count changed; if the change is intended, update the pinned \
         expectation, the regenerated REPORT.md and the CHANGELOG entry together"
    );
    let skip_counts: Vec<(&str, usize)> = skips_by_capability
        .iter()
        .map(|(capability, ids)| (capability.as_str(), ids.len()))
        .collect();
    assert_eq!(
        skip_counts, EXPECTED_SKIPS,
        "skip inventory changed; a pass turned into a skip or a declared \
         capability was dropped. If intended, update the pinned expectation, \
         the regenerated REPORT.md and the CHANGELOG entry together"
    );
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
