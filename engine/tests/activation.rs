#![cfg(all(feature = "rego", feature = "default-dispatchers"))]

use agent_control_spec::{
    ActivatedPolicy, AnnotatorDispatcher, AnnotatorInvocation, InterceptionPoint, JsonValue,
    Manifest, PolicyDispatcher, PreparedPolicyInvocation, RegoPolicyInvocation, RegorusRegoRunner,
    RuntimeError,
};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn bank_agent_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("bank_agent")
}

fn test_artifact_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("activation-tests")
        .join(format!("{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn snapshot(stem: &str) -> JsonValue {
    serde_json::from_str(
        &std::fs::read_to_string(
            bank_agent_dir()
                .join("snapshots")
                .join(format!("{stem}.json")),
        )
        .unwrap(),
    )
    .unwrap()
}

/// The bench manifest, not `manifest.yaml`: every annotator the latter
/// declares calls an HTTP endpoint that nothing serves, so both arms
/// would fail closed at annotation and agree on
/// `runtime_error:annotation_failed` without either reaching Rego. The
/// assertion would hold and prove nothing.
#[test]
fn activation_evaluates_the_same_verdicts_as_a_lazy_runtime() {
    let dir = bank_agent_dir();
    let manifest = Manifest::from_path(dir.join("manifest.bench.yaml")).unwrap();
    let lazy = agent_control_spec::Runtime::new(
        manifest.clone(),
        agent_control_spec::dispatchers::default_annotator_dispatcher(),
        agent_control_spec::dispatchers::default_policy_dispatcher(&manifest).unwrap(),
    )
    .unwrap();
    let activated = ActivatedPolicy::activate_manifest(manifest).unwrap();

    for (stem, point) in [
        ("input", InterceptionPoint::Input),
        ("output", InterceptionPoint::Output),
        ("pre_tool_call", InterceptionPoint::PreToolCall),
        ("agent_shutdown", InterceptionPoint::AgentShutdown),
    ] {
        let context = snapshot(stem);
        let lazy_verdict = lazy.evaluate_point(point, context.clone()).verdict;
        let active_verdict = activated.evaluate(point, context).verdict;
        assert!(
            !lazy_verdict
                .reason
                .as_deref()
                .unwrap_or_default()
                .starts_with("runtime_error"),
            "{point} never reached the policy: {:?}",
            lazy_verdict.reason
        );
        assert_eq!(
            serde_json::to_value(&lazy_verdict).unwrap(),
            serde_json::to_value(&active_verdict).unwrap(),
            "activation changed the verdict at {point}"
        );
    }
}

#[test]
fn activation_reports_the_points_the_manifest_binds() {
    let dir = bank_agent_dir();
    let policy = ActivatedPolicy::activate_from_path(dir.join("manifest.yaml")).unwrap();

    assert_eq!(policy.intervention_points().len(), 8);
    assert!(policy.governs(InterceptionPoint::Input));
    assert!(policy.governs(InterceptionPoint::PreToolCall));
}

/// The point of activation: the bundle is read and compiled once, not
/// per decision.
#[test]
fn activation_warms_every_bound_policy_exactly_once() {
    #[derive(Default)]
    struct CountingDispatcher {
        warmed: AtomicUsize,
        evaluated: AtomicUsize,
    }
    impl PolicyDispatcher for CountingDispatcher {
        fn warm(&self, _: &PreparedPolicyInvocation) -> Result<(), RuntimeError> {
            self.warmed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn evaluate(&self, _: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
            self.evaluated.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"decision": "allow"}))
        }
    }
    struct NoAnnotations;
    impl AnnotatorDispatcher for NoAnnotations {
        fn dispatch(
            &self,
            _: &str,
            _: &AnnotatorInvocation,
            _: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            Ok(json!({}))
        }
    }

    let dir = bank_agent_dir();
    let manifest = Manifest::from_path(dir.join("manifest.yaml")).unwrap();
    let bound_points = manifest.intervention_points.len();
    let dispatcher = Arc::new(CountingDispatcher::default());

    let policy = ActivatedPolicy::activate_with(
        manifest,
        Arc::new(NoAnnotations),
        dispatcher.clone() as Arc<dyn PolicyDispatcher>,
    )
    .unwrap();

    assert_eq!(
        dispatcher.warmed.load(Ordering::SeqCst),
        bound_points,
        "every bound intervention point should be warmed once"
    );
    assert_eq!(
        dispatcher.evaluated.load(Ordering::SeqCst),
        0,
        "activation must not evaluate a verdict"
    );

    policy.evaluate(InterceptionPoint::Input, snapshot("input"));
    assert_eq!(dispatcher.evaluated.load(Ordering::SeqCst), 1);
    assert_eq!(
        dispatcher.warmed.load(Ordering::SeqCst),
        bound_points,
        "evaluating must not warm again"
    );
}

/// A dispatcher with nothing to prepare keeps the default no-op, so
/// activation stays available to every backend.
#[test]
fn activation_tolerates_a_dispatcher_that_cannot_warm() {
    struct Plain;
    impl PolicyDispatcher for Plain {
        fn evaluate(&self, _: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
            Ok(json!({"decision": "allow"}))
        }
    }
    struct NoAnnotations;
    impl AnnotatorDispatcher for NoAnnotations {
        fn dispatch(
            &self,
            _: &str,
            _: &AnnotatorInvocation,
            _: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            Ok(json!({}))
        }
    }

    let dir = bank_agent_dir();
    let manifest = Manifest::from_path(dir.join("manifest.yaml")).unwrap();
    let policy =
        ActivatedPolicy::activate_with(manifest, Arc::new(NoAnnotations), Arc::new(Plain)).unwrap();

    assert_eq!(
        policy
            .evaluate(InterceptionPoint::Input, snapshot("input"))
            .verdict
            .decision
            .as_str(),
        "allow"
    );
}

/// A manifest names its bundle relative to itself, not to whatever
/// directory the host happens to be running in. Worth pinning: the
/// bindings document this to their callers, and getting it backwards
/// would send hosts chdir-ing around a process they do not own.
#[test]
fn activation_resolves_bundles_relative_to_the_manifest_not_the_process() {
    let smoke = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join("smoke")
        .canonicalize()
        .unwrap();
    let policy = ActivatedPolicy::activate_from_path(smoke.join("manifest.yaml")).unwrap();

    // Evaluated from a directory that has nothing to do with the bundle.
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let result = policy.evaluate(
        InterceptionPoint::Input,
        json!({"input": {"text": "hello"}}),
    );
    std::env::set_current_dir(previous).unwrap();

    assert_eq!(result.verdict.decision.as_str(), "allow");
    assert_eq!(
        result.verdict.reason.as_deref(),
        None,
        "a bundle that failed to load would fail closed with a runtime_error reason"
    );
}

/// Activation readies a policy, and readying is bounded by the same
/// deadline evaluation uses. A policy whose entrypoint does input
/// independent work would otherwise run unbounded on the caller's
/// thread, turning `activate` into a call that never returns: worse for
/// a host than a slow first decision, and in a Node binding it would
/// block the event loop outright.
#[test]
fn activation_is_bounded_by_the_eval_deadline() {
    let dir = test_artifact_dir("activation-deadline");
    fs::create_dir_all(dir.join("policy")).unwrap();
    // Costly regardless of input, so warming cannot skip it.
    fs::write(
        dir.join("policy").join("hang.rego"),
        r#"package acs.hang

import rego.v1

big := count([x | x := numbers.range(1, 60000000)[_]])

input_verdict := {"decision": "allow"} if big > 0
"#,
    )
    .unwrap();
    fs::write(
        dir.join("manifest.yaml"),
        r#"agent_control_specification_version: "0.4.0-alpha.1"
policies:
  p:
    type: rego
    bundle: ./policy
    query: data.acs.hang.input_verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: p
"#,
    )
    .unwrap();

    let started = Instant::now();
    let policy = ActivatedPolicy::activate_with(
        Manifest::from_path(dir.join("manifest.yaml")).unwrap(),
        agent_control_spec::dispatchers::default_annotator_dispatcher(),
        Arc::new(agent_control_spec::RegorusPolicyDispatcher::with_runner(
            agent_control_spec::RegorusRegoRunner::new()
                .with_policy_cache(true)
                .with_eval_timeout(Duration::from_millis(200)),
        )),
    )
    .expect("a policy too slow to warm still activates");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "activation ran past the deadline it is supposed to honour: {elapsed:?}"
    );
    // Left unwarmed rather than unusable: evaluation applies the same
    // deadline and fails closed, which is the documented behaviour.
    let verdict = policy
        .evaluate(InterceptionPoint::Input, json!({"input": {"text": "hi"}}))
        .verdict;
    assert_eq!(verdict.decision.as_str(), "deny");
}

/// A host on the emitter path must be able to use an activated policy,
/// or activation and the documented integration surface would be
/// mutually exclusive.
#[test]
fn activation_is_usable_through_the_interceptor_surface() {
    use agent_hooks::Interceptor;

    let dir = bank_agent_dir();
    let policy = ActivatedPolicy::activate_from_path(dir.join("manifest.bench.yaml")).unwrap();
    let interceptor = policy.interceptor();
    // An emitter names the point in the context; a recorded snapshot on
    // its own does not carry it, which is why the direct API takes the
    // point as an argument and this one reads it.
    let mut context = snapshot("pre_tool_call");
    context
        .as_object_mut()
        .unwrap()
        .insert("interception_point".to_string(), json!("pre_tool_call"));

    let direct = policy
        .evaluate(InterceptionPoint::PreToolCall, context.clone())
        .verdict;
    let through_emitter = futures_lite_block_on(
        interceptor.intercept(context.as_object().expect("snapshot is an object")),
    );

    assert_eq!(
        serde_json::to_value(&direct).unwrap(),
        serde_json::to_value(&through_emitter).unwrap(),
        "the emitter path and the direct path must agree"
    );
    assert_eq!(interceptor.name().as_deref(), Some("acs"));
}

/// Minimal executor: this crate has no async runtime dependency and the
/// interceptor trait is the only async surface here.
fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A saturated warming pool must not turn activation into a rubber
/// stamp.
///
/// The bundle is loaded inside the deadline-bounded closure, so when no
/// warming worker can be obtained nothing is read, parsed, or checked.
/// Reporting success there would claim a policy is ready without having
/// looked at it, which is how a manifest naming a bundle that does not
/// exist came to activate cleanly and fail only at the first live
/// decision.
#[test]
fn activation_does_not_claim_success_when_it_could_not_look_at_the_policy() {
    let dir = test_artifact_dir("activation-saturated-warm-pool");
    fs::create_dir_all(dir.join("policy")).unwrap();
    // A single builtin call, because that is the one thing regorus
    // cannot interrupt: a Rego-level loop is cut by the cooperative
    // timer, the worker finishes, and nothing is ever abandoned. 200k
    // elements is ~5MB and ~25ms, far past the 2ms deadline below, and
    // small enough that the workers this deliberately strands cannot
    // exhaust a CI runner the way a 40M range did in ec04178.
    fs::write(
        dir.join("policy").join("slow.rego"),
        "package slow\n\nimport rego.v1\n\n         big := count(numbers.range(1, 200000))\n\n         verdict := {\"decision\": \"allow\"} if big > 0\n",
    )
    .unwrap();

    // One runner, shared, as a multi-tenant host would.
    let runner = RegorusRegoRunner::new()
        .with_policy_cache(true)
        .with_eval_timeout(Duration::from_millis(20));

    // Sustained load rather than one burst: each worker holds its slot
    // only until its evaluation ends, so a burst leaves a window of tens
    // of milliseconds in which the pool is full. Warming in a loop keeps
    // it full for as long as the test needs, at a bounded number of
    // strandings in flight.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bundle = dir.join("policy").display().to_string();
    let saturating: Vec<_> = (0..24)
        .map(|thread| {
            let runner = runner.clone();
            let bundle = bundle.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut round = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = runner.warm(&RegoPolicyInvocation {
                        // A distinct cache key per attempt, so each
                        // really loads and warms rather than hitting the
                        // entry a sibling just cached.
                        query: format!("data.slow.verdict # {thread}.{round}"),
                        bundle: Some(bundle.clone()),
                        inline_bundle: None,
                        adapter_config: Default::default(),
                        input: json!({}),
                        canonical_input: "{}".to_string(),
                    });
                    round += 1;
                }
            })
        })
        .collect();

    // Wait for the state under test rather than assuming timing reached
    // it. If the fixture is ever too fast to saturate the pool, this
    // fails loudly instead of passing for the wrong reason.
    let ceiling = agent_control_spec::rego::MAX_ABANDONED_WORKERS;
    let deadline = Instant::now() + Duration::from_secs(30);
    while runner.abandoned_evaluations() < ceiling && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    let reached = runner.abandoned_evaluations();

    // With the pool provably saturated, ask it to ready a bundle that
    // does not exist.
    let missing = RegoPolicyInvocation {
        query: "data.nope.verdict".to_string(),
        bundle: Some(dir.join("does-not-exist").display().to_string()),
        inline_bundle: None,
        adapter_config: Default::default(),
        input: json!({}),
        canonical_input: "{}".to_string(),
    };
    // Retried, because a run in which this warm happens to get a slot and
    // then blow its own deadline is inconclusive rather than passing.
    // With the defect present the pool is saturated and every attempt
    // returns Ok, so this still fails there.
    let mut outcome = Ok(());
    for _ in 0..5 {
        outcome = runner.warm(&missing);
        if outcome.is_err() {
            break;
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for handle in saturating {
        handle.join().unwrap();
    }

    assert!(
        reached >= ceiling,
        "fixture never saturated the warming pool: {reached} abandoned, need {ceiling}"
    );

    assert!(
        outcome.is_err(),
        "warming reported success for a bundle it never read (abandoned={})",
        runner.abandoned_evaluations()
    );
}

#[test]
fn activation_fails_when_the_manifest_cannot_be_read() {
    let error = ActivatedPolicy::activate_from_path("does-not-exist.yaml").unwrap_err();
    assert!(
        error.reason().starts_with("runtime_error:"),
        "{}",
        error.reason()
    );
}

/// One activated policy is shared across threads by cloning, which is a
/// refcount bump rather than a re-activation.
#[test]
fn activation_is_shared_across_threads_by_cloning() {
    let dir = bank_agent_dir();
    let policy = ActivatedPolicy::activate_from_path(dir.join("manifest.yaml")).unwrap();
    let context = snapshot("input");
    // Whatever the single-threaded verdict is for this context, every
    // concurrent evaluation must agree with it. Asserting a specific
    // decision would instead assert what the bundled annotators happen
    // to produce, which is not what this test is about.
    let expected = policy
        .evaluate(InterceptionPoint::Input, context.clone())
        .verdict
        .decision
        .as_str()
        .to_string();

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let policy = policy.clone();
            let context = context.clone();
            std::thread::spawn(move || {
                (0..25)
                    .map(|_| {
                        policy
                            .evaluate(InterceptionPoint::Input, context.clone())
                            .verdict
                            .decision
                            .as_str()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    for handle in handles {
        for decision in handle.join().unwrap() {
            assert_eq!(decision, expected, "concurrency changed the verdict");
        }
    }
}
