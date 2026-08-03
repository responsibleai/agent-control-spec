#![cfg(feature = "rego")]

use agent_control_spec::{
    canonical_json, AnnotatorDispatcher, AnnotatorInvocation, InterceptionPoint, JsonValue,
    Manifest, PolicyDispatcher, PreparedPolicyInvocation, RegoPolicyInvocation,
    RegorusPolicyDispatcher, RegorusRegoRunner, Runtime, RuntimeError, TestPolicyInvocation,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct NoopAnnotator;

impl AnnotatorDispatcher for NoopAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(json!({}))
    }
}

#[test]
fn rego_dispatcher_needs_no_external_binary() {
    assert!(RegorusRegoRunner::new().is_available());
}

#[test]
fn rego_dispatcher_rejects_non_rego_invocations() {
    let input = json!({"policy_target": {"value": {"text": "hello"}}});
    let invocation = PreparedPolicyInvocation::Test(TestPolicyInvocation {
        adapter_config: BTreeMap::new(),
        canonical_input: canonical_json(&input).unwrap(),
        input,
    });

    let error = RegorusPolicyDispatcher::new()
        .evaluate(&invocation)
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(error.detail().contains("only supports Rego"));
    assert!(error.detail().contains("test invocation"));
}

#[test]
fn rego_dispatcher_evaluates_query_with_data_paths_from_adapter_config() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));
    let dispatcher = RegorusPolicyDispatcher::new();

    let allow = dispatcher
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            adapter_config.clone(),
            json!({"policy_target": {"value": {"text": "hello"}}}),
        ))
        .unwrap();
    let deny = dispatcher
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            adapter_config,
            json!({"policy_target": {"value": {"text": "please block this"}}}),
        ))
        .unwrap();

    assert_eq!(allow, json!({"decision": "allow"}));
    assert_eq!(
        deny,
        json!({
            "decision": "deny",
            "reason": "blocked_text",
            "message": "Input contained blocked text."
        })
    );
}

#[test]
fn rego_dispatcher_loads_a_bundle_directory_with_policies_and_data() {
    let dir = test_artifact_dir("rego-bundle-directory");
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(
        dir.join("nested").join("limits.json"),
        r#"{"limits": {"max_amount": 500}}"#,
    )
    .unwrap();
    fs::write(dir.join("labels.yaml"), "labels:\n  tier: gold\n").unwrap();
    fs::write(
        dir.join("policy.rego"),
        r#"package bundle

import rego.v1

default verdict := {"decision": "allow", "tier": "unknown"}

verdict := {"decision": "deny", "reason": "over_limit"} if {
    input.policy_target.value.amount > data.limits.max_amount
}

verdict := {"decision": "allow", "tier": data.labels.tier} if {
    input.policy_target.value.amount <= data.limits.max_amount
}
"#,
    )
    .unwrap();
    // A non-policy sibling file must be ignored rather than fail the load.
    fs::write(dir.join("README.md"), "not a policy").unwrap();

    let dispatcher = RegorusPolicyDispatcher::new();
    let allow = dispatcher
        .evaluate(&rego_invocation(
            "data.bundle.verdict",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {"amount": 100}}}),
        ))
        .unwrap();
    let deny = dispatcher
        .evaluate(&rego_invocation(
            "data.bundle.verdict",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {"amount": 900}}}),
        ))
        .unwrap();

    assert_eq!(allow, json!({"decision": "allow", "tier": "gold"}));
    assert_eq!(deny, json!({"decision": "deny", "reason": "over_limit"}));
}

#[test]
fn rego_dispatcher_reports_a_packaged_bundle_archive_clearly() {
    let dir = test_artifact_dir("rego-packaged-bundle");
    let archive = dir.join("bundle.tar.gz");
    fs::write(&archive, b"not really a bundle").unwrap();

    let error = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.bundle.verdict",
            Some(archive.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("packaged OPA bundle archive"),
        "{}",
        error.detail()
    );
}

#[test]
fn rego_dispatcher_reports_a_missing_bundle_clearly() {
    let error = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.bundle.verdict",
            Some(fixture("does-not-exist")),
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("failed to read Rego bundle"),
        "{}",
        error.detail()
    );
}

#[test]
fn rego_dispatcher_reports_a_policy_parse_failure_clearly() {
    let dir = test_artifact_dir("rego-parse-failure");
    fs::write(dir.join("broken.rego"), "package broken\n\nverdict := \n").unwrap();

    let error = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.broken.verdict",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("failed to load Rego policy"),
        "{}",
        error.detail()
    );
}

#[test]
fn rego_dispatcher_fails_closed_on_an_undefined_query() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));

    let error = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.agent_control_specification.input.no_such_rule",
            None,
            adapter_config,
            json!({"policy_target": {"value": {"text": "hello"}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("Rego query returned no result"),
        "{}",
        error.detail()
    );
}

#[test]
fn rego_dispatcher_rejects_malformed_adapter_data_paths() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([42]));

    let error = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.x.verdict",
            None,
            adapter_config,
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error
            .detail()
            .contains("must be a string or array of strings"),
        "{}",
        error.detail()
    );
}

/// The cooperative deadline `regorus` observes while interpreting Rego.
#[test]
fn rego_dispatcher_times_out_a_pathological_policy() {
    let dir = test_artifact_dir("rego-pathological-policy");
    fs::write(
        dir.join("heavy.rego"),
        r#"package heavy

import rego.v1

verdict contains x if {
    some i in numbers.range(1, 2000000)
    x := i * 2
}
"#,
    )
    .unwrap();
    let dispatcher = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new().with_eval_timeout(Duration::from_millis(50)),
    );

    let started = Instant::now();
    let error = dispatcher
        .evaluate(&rego_invocation(
            "data.heavy.verdict",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("Rego eval exceeded timeout"),
        "{}",
        error.detail()
    );
}

/// The hard deadline. `regorus` cannot interrupt a single long-running
/// builtin call, so the dispatcher abandons the evaluation thread and
/// returns to the caller on time regardless.
#[test]
fn rego_dispatcher_honours_the_deadline_inside_an_uninterruptible_builtin() {
    let dispatcher = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new().with_eval_timeout(Duration::from_millis(50)),
    );

    let started = Instant::now();
    let error = dispatcher
        .evaluate(&rego_invocation(
            "x := numbers.range(1, 100000000)",
            None,
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "returned after {:?}",
        started.elapsed()
    );
    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("Rego eval exceeded timeout"),
        "{}",
        error.detail()
    );
}

/// Turning the hard deadline off keeps the cooperative deadline, so
/// runaway Rego is still cut off — only the uninterruptible builtin case
/// loses its guarantee.
#[test]
fn rego_dispatcher_without_a_hard_deadline_still_stops_runaway_rego() {
    let dir = test_artifact_dir("rego-inline-deadline");
    fs::write(
        dir.join("heavy.rego"),
        r#"package heavy

import rego.v1

verdict contains x if {
    some i in numbers.range(1, 2000000)
    x := i * 2
}
"#,
    )
    .unwrap();
    let runner = RegorusRegoRunner::new()
        .with_eval_timeout(Duration::from_millis(50))
        .with_hard_deadline(false);
    assert!(!runner.hard_deadline());
    assert!(RegorusRegoRunner::new().hard_deadline());

    let error = RegorusPolicyDispatcher::with_runner(runner)
        .evaluate(&rego_invocation(
            "data.heavy.verdict",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    assert!(
        error.detail().contains("Rego eval exceeded timeout"),
        "{}",
        error.detail()
    );
}

/// The pooled evaluation threads are reused across calls and shared by
/// clones of a runner, so a dispatcher stays correct under concurrency.
#[test]
fn rego_dispatcher_evaluates_concurrently_on_pooled_threads() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));
    let dispatcher = Arc::new(RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new().with_policy_cache(true),
    ));

    let handles: Vec<_> = (0..16)
        .map(|index| {
            let dispatcher = Arc::clone(&dispatcher);
            let adapter_config = adapter_config.clone();
            std::thread::spawn(move || {
                let text = if index % 2 == 0 {
                    "hello"
                } else {
                    "please block this"
                };
                let verdict = dispatcher
                    .evaluate(&rego_invocation(
                        "data.agent_control_specification.input.verdict",
                        None,
                        adapter_config,
                        json!({"policy_target": {"value": {"text": text}}}),
                    ))
                    .unwrap();
                (index, verdict["decision"].as_str().unwrap().to_string())
            })
        })
        .collect();

    for handle in handles {
        let (index, decision) = handle.join().unwrap();
        let expected = if index % 2 == 0 { "allow" } else { "deny" };
        assert_eq!(decision, expected, "worker {index}");
    }
}

/// A worker that blew its deadline must not poison later evaluations with
/// a stale result.
#[test]
fn rego_dispatcher_recovers_after_a_timed_out_evaluation() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));
    let dispatcher = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new()
            .with_policy_cache(true)
            .with_eval_timeout(Duration::from_millis(50)),
    );

    let timed_out = dispatcher
        .evaluate(&rego_invocation(
            "x := numbers.range(1, 100000000)",
            None,
            BTreeMap::new(),
            json!({"policy_target": {"value": {}}}),
        ))
        .unwrap_err();
    assert!(timed_out.detail().contains("Rego eval exceeded timeout"));

    for _ in 0..3 {
        let verdict = dispatcher
            .evaluate(&rego_invocation(
                "data.agent_control_specification.input.verdict",
                None,
                adapter_config.clone(),
                json!({"policy_target": {"value": {"text": "hello"}}}),
            ))
            .unwrap();
        assert_eq!(verdict, json!({"decision": "allow"}));
    }
}

#[test]
fn rego_default_timeout_allows_nontrivial_policy_input() {
    let dir = test_artifact_dir("rego-default-timeout-nontrivial");
    let policy_path = dir.join("nontrivial.rego");
    fs::write(
        &policy_path,
        r#"package agent_control_specification.heavy

import rego.v1

matching_numbers := [n | some n in input.policy_target.value.numbers; n % 3 == 0]

verdict := {"decision": "allow", "matched": count(matching_numbers)} if {
    count(matching_numbers) >= 1000
}
"#,
    )
    .unwrap();
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert(
        "data_paths".to_string(),
        json!([policy_path.display().to_string()]),
    );
    let input = json!({"policy_target": {"value": {"numbers": (1..=5000).collect::<Vec<_>>()}}});

    let started = Instant::now();
    let output = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.agent_control_specification.heavy.verdict",
            None,
            adapter_config,
            input,
        ))
        .unwrap();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(output["decision"], json!("allow"));
    assert_eq!(output["matched"], json!(1666));
}

#[test]
fn rego_timeout_env_override_is_read_from_the_environment() {
    let _guard = ENV_LOCK.lock().unwrap();
    let old_timeout = env::var_os("ACS_OPA_TIMEOUT_MS");

    env::set_var("ACS_OPA_TIMEOUT_MS", "1");
    assert_eq!(
        RegorusRegoRunner::from_environment().eval_timeout(),
        Duration::from_millis(1)
    );

    env::set_var("ACS_OPA_TIMEOUT_MS", "5000");
    assert_eq!(
        RegorusRegoRunner::from_environment().eval_timeout(),
        Duration::from_secs(5)
    );

    // A malformed or zero value leaves the default in place rather than
    // disabling the deadline.
    env::set_var("ACS_OPA_TIMEOUT_MS", "0");
    assert_eq!(
        RegorusRegoRunner::from_environment().eval_timeout(),
        Duration::from_secs(5)
    );
    env::set_var("ACS_OPA_TIMEOUT_MS", "not-a-number");
    assert_eq!(
        RegorusRegoRunner::from_environment().eval_timeout(),
        Duration::from_secs(5)
    );

    restore_env("ACS_OPA_TIMEOUT_MS", old_timeout);
}

/// The cache is an optimization, never a behaviour change: a cached
/// runner must return exactly what an uncached one returns.
#[test]
fn rego_policy_cache_is_opt_in_and_preserves_results() {
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([fixture("verdict.rego")]));
    let uncached = RegorusRegoRunner::new();
    let cached = RegorusRegoRunner::new().with_policy_cache(true);
    assert!(!uncached.policy_cache_enabled());
    assert!(cached.policy_cache_enabled());

    let dispatcher = RegorusPolicyDispatcher::with_runner(cached.clone());
    let invocation = |text: &str| {
        rego_invocation(
            "data.agent_control_specification.input.verdict",
            None,
            adapter_config.clone(),
            json!({"policy_target": {"value": {"text": text}}}),
        )
    };

    let first = dispatcher.evaluate(&invocation("hello")).unwrap();
    let second = dispatcher
        .evaluate(&invocation("please block this"))
        .unwrap();
    let third = dispatcher.evaluate(&invocation("hello")).unwrap();

    assert_eq!(first, json!({"decision": "allow"}));
    assert_eq!(second["decision"], json!("deny"));
    assert_eq!(third, first);
    assert_eq!(
        RegorusPolicyDispatcher::with_runner(uncached)
            .evaluate(&invocation("hello"))
            .unwrap(),
        first
    );

    // Clearing forces a re-read without changing the verdict.
    cached.clear_policy_cache();
    assert_eq!(dispatcher.evaluate(&invocation("hello")).unwrap(), first);
}

#[test]
fn runtime_can_use_rego_policy_dispatcher_for_rego_policy() {
    let manifest = Manifest::from_yaml_str(&format!(
        r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  input_rego_policy:
    type: rego
    data_paths:
      - "{}"
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_rego_policy
      query: data.agent_control_specification.input.verdict
    policy_target: $snap.input"#,
        yaml_double_quoted(&fixture_path("verdict.rego"))
    ))
    .unwrap();
    let runtime = Runtime::new(
        manifest,
        Arc::new(NoopAnnotator),
        Arc::new(RegorusPolicyDispatcher::new()),
    )
    .unwrap();

    let allow = runtime.evaluate_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "hello"}}),
    );
    let deny = runtime.evaluate_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "please block this"}}),
    );

    assert_eq!(allow.verdict.decision.as_str(), "allow");
    assert_eq!(deny.verdict.decision.as_str(), "deny");
    assert_eq!(deny.verdict.reason.as_deref(), Some("blocked_text"));
}

fn rego_invocation(
    query: &str,
    bundle: Option<String>,
    adapter_config: BTreeMap<String, JsonValue>,
    input: JsonValue,
) -> PreparedPolicyInvocation {
    PreparedPolicyInvocation::Rego(RegoPolicyInvocation {
        query: query.to_string(),
        bundle,
        adapter_config,
        canonical_input: canonical_json(&input).unwrap(),
        input,
    })
}

fn fixture(name: &str) -> String {
    fixture_path(name).display().to_string()
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("opa")
        .join(name)
}

fn test_artifact_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("rego-tests")
        .join(format!("{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn restore_env(key: &str, value: Option<std::ffi::OsString>) {
    match value {
        Some(value) => env::set_var(key, value),
        None => env::remove_var(key),
    }
}

fn yaml_double_quoted(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
