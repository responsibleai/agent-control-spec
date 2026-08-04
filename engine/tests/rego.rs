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
    // Inside a bundle root, `opa eval` accepts only documents named
    // `data.*`, so that is what a bundle fixture must use.
    fs::write(dir.join("data.json"), r#"{"limits": {"max_amount": 500}}"#).unwrap();
    fs::write(dir.join("data.yaml"), "labels:\n  tier: gold\n").unwrap();
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
    // Neither of these may contribute: one is not a policy or data file,
    // the other is a data document a bundle root ignores by name.
    fs::write(dir.join("README.md"), "not a policy").unwrap();
    fs::write(
        dir.join("nested").join("limits.json"),
        r#"{"ignored": true}"#,
    )
    .unwrap();

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
    assert!(
        dispatcher
            .evaluate(&rego_invocation(
                "data.nested.ignored",
                Some(dir.display().to_string()),
                BTreeMap::new(),
                json!({}),
            ))
            .is_err(),
        "a bundle root must ignore a data document not named data.*"
    );
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
            "x := numbers.range(1, 1000000)",
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
    // The deadline has to be generous enough that the trivial recovery
    // evaluations below are not themselves timed out by scheduling delay:
    // the rest of this suite runs hundreds of threads in parallel, and at
    // 50ms these intermittently failed. The heavy query takes ~300ms, so
    // it still blows a 200ms deadline by a wide margin.
    let dispatcher = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new()
            .with_policy_cache(true)
            .with_eval_timeout(Duration::from_millis(200)),
    );

    let timed_out = dispatcher
        .evaluate(&rego_invocation(
            "x := numbers.range(1, 2000000)",
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

/// `opa eval --bundle` mounts a data document under the `data` path its
/// DIRECTORY implies, and inside a bundle it only accepts documents named
/// `data.*`. Verified against the real `opa` binary.
#[test]
fn rego_bundle_mounts_data_documents_the_way_opa_does() {
    let dir = test_artifact_dir("rego-bundle-data-mount");
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("data.json"), r#"{"top": true}"#).unwrap();
    fs::write(dir.join("nested").join("data.json"), r#"{"max": 5}"#).unwrap();
    // Not named data.*, so a bundle root must ignore it entirely.
    fs::write(dir.join("nested").join("limits.json"), r#"{"other": "x"}"#).unwrap();
    fs::write(
        dir.join("p.rego"),
        "package t\n\nimport rego.v1\n\nv := 1\n",
    )
    .unwrap();
    let bundle = dir.display().to_string();
    let dispatcher = RegorusPolicyDispatcher::new();
    let eval = |query: &str| {
        dispatcher.evaluate(&rego_invocation(
            query,
            Some(bundle.clone()),
            BTreeMap::new(),
            json!({}),
        ))
    };

    assert_eq!(eval("data.top").unwrap(), json!(true));
    // Mounted under its directory, NOT flattened onto the data root.
    assert_eq!(eval("data.nested.max").unwrap(), json!(5));
    assert!(
        eval("data.max").is_err(),
        "must not flatten nested data onto the root"
    );
    assert!(
        eval("data.other").is_err(),
        "a bundle must ignore non-data.* documents"
    );
    assert!(eval("data.nested.other").is_err());
}

/// A `data_paths` root follows `opa eval --data`: every `.json`/`.yaml`
/// counts, still mounted by directory rather than by file name.
#[test]
fn rego_data_paths_mount_every_document_by_directory() {
    let dir = test_artifact_dir("rego-data-path-mount");
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("nested").join("limits.json"), r#"{"other": "x"}"#).unwrap();
    fs::write(
        dir.join("p.rego"),
        "package t\n\nimport rego.v1\n\nv := 1\n",
    )
    .unwrap();
    let mut adapter_config = BTreeMap::new();
    adapter_config.insert("data_paths".to_string(), json!([dir.display().to_string()]));

    let verdict = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.nested.other",
            None,
            adapter_config,
            json!({}),
        ))
        .unwrap();

    assert_eq!(verdict, json!("x"));
}

/// A worker abandoned at its deadline cannot be killed, so the pool must
/// stop spawning rather than grow a thread per timed-out decision.
#[test]
fn rego_repeated_timeouts_do_not_grow_threads_without_bound() {
    let runner = RegorusRegoRunner::new().with_eval_timeout(Duration::from_millis(10));
    let dispatcher = Arc::new(RegorusPolicyDispatcher::with_runner(runner.clone()));
    // Concurrency rather than a bigger query is what piles abandoned
    // workers up here. Reaching the ceiling by making each evaluation
    // long enough would need a 40M-element range, which is 960MB per
    // abandoned worker and aborted the Windows CI job; 200k elements is
    // ~4MB and still ~40ms, comfortably past a 10ms deadline.
    let concurrency = 48;
    let mut refused = 0;

    for _ in 0..3 {
        let handles: Vec<_> = (0..concurrency)
            .map(|_| {
                let dispatcher = Arc::clone(&dispatcher);
                std::thread::spawn(move || {
                    dispatcher.evaluate(&rego_invocation(
                        "count(numbers.range(0, 200000))",
                        None,
                        BTreeMap::new(),
                        json!({}),
                    ))
                })
            })
            .collect();
        for handle in handles {
            if let Err(error) = handle.join().unwrap() {
                if error.detail().contains("running past their timeout") {
                    refused += 1;
                }
            }
        }
        // Counted on the pool itself rather than by reading
        // /proc/self/task, which the rest of this suite perturbs, and
        // which does not exist on every platform this runs on.
        assert!(
            runner.abandoned_evaluations()
                <= agent_control_spec::rego::MAX_ABANDONED_WORKERS + concurrency,
            "abandoned evaluations grew past the gate plus in-flight work: {}",
            runner.abandoned_evaluations()
        );
    }

    assert!(
        refused > 0,
        "sustained timeouts should have hit the abandoned ceiling"
    );
}

/// Loading the bundle must be inside the deadline, not before it.
#[test]
fn rego_bundle_load_is_bounded_by_the_eval_timeout() {
    let dir = test_artifact_dir("rego-load-inside-deadline");
    // Large enough that loading it dwarfs the deadline: with the load
    // outside, elapsed tracks the file count; with it inside, elapsed is
    // the deadline whatever the count. Measured on the fixed tree, 2500
    // and 6000 files both return in 20.4ms against a 20ms deadline.
    for index in 0..6000 {
        fs::write(
            dir.join(format!("p{index}.rego")),
            format!("package p{index}\n\nimport rego.v1\n\nv := {index}\n"),
        )
        .unwrap();
    }
    let dispatcher = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new().with_eval_timeout(Duration::from_millis(20)),
    );

    // One measurement, not a best-of-N: each timed-out call abandons a
    // worker that goes on reading all 6000 files, so repeating the
    // measurement makes later samples slower rather than cleaner.
    let started = Instant::now();
    let _ = dispatcher.evaluate(&rego_invocation(
        "data.p0.v",
        Some(dir.display().to_string()),
        BTreeMap::new(),
        json!({}),
    ));
    let elapsed = started.elapsed();

    // Generous against CI hardware, which adds a fixed overhead on top of
    // the deadline: this returned in 121ms on a macOS runner when the
    // deadline was 50ms. Loading 6000 files takes several hundred
    // milliseconds, so the two regimes stay far apart.
    assert!(
        elapsed < Duration::from_millis(300),
        "bundle load escaped the deadline: {elapsed:?}"
    );
}

/// A bundle written for OPA 0.x needs the v0 escape hatch.
#[test]
fn rego_v0_dialect_is_available_behind_an_opt_in() {
    let dir = test_artifact_dir("rego-v0-dialect");
    fs::write(dir.join("v0.rego"), "package v0\nallow = 42 { 1 == 1 }\n").unwrap();
    let bundle = dir.display().to_string();
    let invocation = || {
        rego_invocation(
            "data.v0.allow",
            Some(bundle.clone()),
            BTreeMap::new(),
            json!({}),
        )
    };

    let under_v1 = RegorusPolicyDispatcher::new().evaluate(&invocation());
    let under_v0 =
        RegorusPolicyDispatcher::with_runner(RegorusRegoRunner::new().with_rego_v0(true))
            .evaluate(&invocation());

    assert!(under_v1.is_err(), "v0 grammar must not parse as v1");
    assert_eq!(under_v0.unwrap(), json!(42));
    assert!(!RegorusRegoRunner::new().rego_v0());
    assert!(RegorusRegoRunner::new().with_rego_v0(true).rego_v0());
}

/// A directory whose name ends in an archive suffix is still a directory.
#[test]
fn rego_directory_named_like_an_archive_still_loads() {
    let root = test_artifact_dir("rego-archive-named-dir");
    let dir = root.join("policies.tar");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("p.rego"),
        "package t\n\nimport rego.v1\n\nv := 7\n",
    )
    .unwrap();

    let verdict = RegorusPolicyDispatcher::new()
        .evaluate(&rego_invocation(
            "data.t.v",
            Some(dir.display().to_string()),
            BTreeMap::new(),
            json!({}),
        ))
        .unwrap();

    assert_eq!(verdict, json!(7));
}

/// Ordinary parallel load must not be mistaken for runaway evaluation:
/// only threads abandoned past a deadline are capped.
#[test]
fn rego_healthy_concurrency_is_not_refused() {
    // 256 callers released together against a cold pool. The defect this
    // guards is a race in the window where a worker is being spawned, so
    // detection is probabilistic and driven by how many callers are
    // spawning at once: measured at 25% with 128 callers and 40% with
    // 256. Repeating the burst does not help, because every observed
    // detection landed on the first one. The 300k-element range this
    // once used detected no better and cost 1.1GB of peak RSS, enough to
    // matter on a CI runner; 100k holds the catch rate at 294MB.
    let runner = RegorusRegoRunner::new()
        .with_policy_cache(true)
        .with_eval_timeout(Duration::from_secs(30));
    let dispatcher = Arc::new(RegorusPolicyDispatcher::with_runner(runner.clone()));
    let callers = 256;
    let barrier = Arc::new(std::sync::Barrier::new(callers));

    let handles: Vec<_> = (0..callers)
        .map(|_| {
            let dispatcher = Arc::clone(&dispatcher);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                dispatcher.evaluate(&rego_invocation(
                    "count(numbers.range(0, 100000))",
                    None,
                    BTreeMap::new(),
                    json!({}),
                ))
            })
        })
        .collect();

    let mut refused = Vec::new();
    for handle in handles {
        if let Err(error) = handle.join().unwrap() {
            refused.push(error.detail().to_string());
        }
    }

    assert!(
        refused.is_empty(),
        "{} of {callers} healthy concurrent evaluations were refused, first: {:?}",
        refused.len(),
        refused.first()
    );
    // A settled sanity check rather than the discriminating signal: by the
    // time every caller has joined, nothing came near the 30s deadline, so
    // nothing may still be charged as abandoned.
    assert_eq!(
        runner.abandoned_evaluations(),
        0,
        "evaluations remained charged as abandoned without timing out"
    );
}

/// A bundle root matches file names the way `opa` does, case included.
#[test]
fn rego_bundle_data_file_matching_is_case_sensitive_like_opa() {
    let dir = test_artifact_dir("rego-data-case");
    fs::write(
        dir.join("p.rego"),
        "package t\n\nimport rego.v1\n\nv := 1\n",
    )
    .unwrap();
    fs::write(dir.join("data.JSON"), r#"{"upper_ext": true}"#).unwrap();
    fs::write(dir.join("DATA.json"), r#"{"upper_stem": true}"#).unwrap();
    fs::write(dir.join("database.json"), r#"{"prefix_only": true}"#).unwrap();
    let bundle = dir.display().to_string();
    let dispatcher = RegorusPolicyDispatcher::new();
    let eval = |query: &str| {
        dispatcher.evaluate(&rego_invocation(
            query,
            Some(bundle.clone()),
            BTreeMap::new(),
            json!({}),
        ))
    };

    for query in ["data.upper_ext", "data.upper_stem", "data.prefix_only"] {
        assert!(
            eval(query).is_err(),
            "{query} must not load; opa ignores these names"
        );
    }
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
