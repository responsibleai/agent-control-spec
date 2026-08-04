#![cfg(all(feature = "rego", feature = "default-dispatchers"))]

use agent_control_spec::{
    ActivatedPolicy, AnnotatorDispatcher, AnnotatorInvocation, InterceptionPoint, JsonValue,
    Manifest, PolicyDispatcher, PreparedPolicyInvocation, RuntimeError,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

fn bank_agent_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("bank_agent")
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

#[test]
fn activation_evaluates_the_same_verdicts_as_a_lazy_runtime() {
    let dir = bank_agent_dir();
    let manifest = Manifest::from_path(dir.join("manifest.yaml")).unwrap();
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
