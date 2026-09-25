//! Spec section 10: an annotation may consume the results of the
//! annotations it names in `needs`.
//!
//! Every test here drives a real `Runtime::evaluate_point`, so it
//! exercises ordering, the staged policy input each dispatcher receives
//! and the fail closed path together, rather than a dependency sort in
//! isolation.

use agent_control_spec::{
    AnnotatorDispatcher, AnnotatorInvocation, Decision, InterceptionPoint, JsonPath, JsonValue,
    Manifest, PathEnv, PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
    TelemetryEvent, TelemetryEventType, TelemetrySink,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Records the order annotators were dispatched in and what each one was
/// shown, and resolves its own `from` path the way a real dispatcher
/// does, so a broken staged input surfaces as a failed resolution rather
/// than a silently empty annotation.
struct ChainAnnotator {
    outputs: Mutex<BTreeMap<String, Result<JsonValue, RuntimeError>>>,
    calls: Mutex<Vec<AnnotationCall>>,
}

#[derive(Clone, Debug)]
struct AnnotationCall {
    name: String,
    /// What `$pi.annotations` held for this dispatch.
    visible_annotations: JsonValue,
    /// What this annotation's own `from` path resolved to.
    resolved_from: Option<JsonValue>,
}

impl ChainAnnotator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            outputs: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn set_output(self: &Arc<Self>, name: &str, output: JsonValue) -> Arc<Self> {
        self.outputs
            .lock()
            .unwrap()
            .insert(name.to_string(), Ok(output));
        Arc::clone(self)
    }

    fn set_error(self: &Arc<Self>, name: &str, error: RuntimeError) -> Arc<Self> {
        self.outputs
            .lock()
            .unwrap()
            .insert(name.to_string(), Err(error));
        Arc::clone(self)
    }

    fn calls(&self) -> Vec<AnnotationCall> {
        self.calls.lock().unwrap().clone()
    }

    fn order(&self) -> Vec<String> {
        self.calls().into_iter().map(|call| call.name).collect()
    }

    fn call(&self, name: &str) -> AnnotationCall {
        self.calls()
            .into_iter()
            .find(|call| call.name == name)
            .unwrap_or_else(|| panic!("annotator '{name}' was never dispatched"))
    }
}

impl AnnotatorDispatcher for ChainAnnotator {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let path = JsonPath::parse_with_snapshot_alias(annotator.input_from().unwrap()).unwrap();
        let resolved_from = Some(path.resolve(&PathEnv::with_pi_and_snap(
            policy_input,
            &policy_input["snapshot"],
        ))?);
        self.calls.lock().unwrap().push(AnnotationCall {
            name: annotator_name.to_string(),
            visible_annotations: policy_input
                .get("annotations")
                .cloned()
                .expect("runtime must supply annotations"),
            resolved_from,
        });
        self.outputs
            .lock()
            .unwrap()
            .get(annotator_name)
            .cloned()
            .unwrap_or(Ok(json!({"label": "unset"})))
    }
}

struct CapturingPolicy {
    seen: Mutex<Vec<JsonValue>>,
}

impl CapturingPolicy {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
        })
    }

    fn final_annotations(&self) -> JsonValue {
        self.seen
            .lock()
            .unwrap()
            .last()
            .expect("policy should have been called")
            .get("annotations")
            .cloned()
            .expect("policy input carries annotations")
    }
}

impl PolicyDispatcher for CapturingPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        self.seen.lock().unwrap().push(
            invocation
                .policy_input()
                .expect("test policy invocation carries policy input")
                .clone(),
        );
        Ok(json!({"decision": "allow"}))
    }
}

fn manifest(annotations: &str, annotators: &str) -> Result<Manifest, RuntimeError> {
    Manifest::from_yaml_str(&format!(
        "agent_control_specification_version: 0.5.0-alpha.1\n\
         policies:\n\
        \x20 test_policy:\n\
        \x20   type: test\n\
         intervention_points:\n\
        \x20 input:\n\
        \x20   policy_target: $snap.input\n\
        \x20   policy:\n\
        \x20     id: test_policy\n\
        \x20   annotations:\n{annotations}\
         annotators:\n{annotators}"
    ))
}

fn runtime(
    annotations: &str,
    annotators: &str,
    annotator: Arc<ChainAnnotator>,
    policy: Arc<CapturingPolicy>,
) -> Runtime {
    Runtime::new(
        manifest(annotations, annotators).expect("manifest should load"),
        annotator as Arc<dyn AnnotatorDispatcher>,
        policy as Arc<dyn PolicyDispatcher>,
    )
    .expect("runtime should build")
}

fn snapshot() -> JsonValue {
    json!({"input": {"text": "hello"}})
}

fn evaluate(runtime: &Runtime) -> Decision {
    runtime
        .evaluate_point(InterceptionPoint::Input, snapshot())
        .verdict
        .decision
}

fn verdict_reason(runtime: &Runtime) -> String {
    runtime
        .evaluate_point(InterceptionPoint::Input, snapshot())
        .verdict
        .reason
        .unwrap_or_default()
}

/// Two classifier declarations, used by most of the graphs below.
const TWO_CLASSIFIERS: &str = "  alpha:\n    type: classifier\n  beta:\n    type: classifier\n";
const THREE_CLASSIFIERS: &str =
    "  alpha:\n    type: classifier\n  beta:\n    type: classifier\n  gamma:\n    type: classifier\n";

#[test]
fn independent_annotators_keep_name_order_and_see_no_annotations() {
    let annotator = ChainAnnotator::new();
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      beta:\n        from: $target.text\n      alpha:\n        from: $target.text\n",
        TWO_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    // Ascending annotator name, exactly as before `needs` existed, and
    // independent of the order the manifest listed them in.
    assert_eq!(annotator.order(), vec!["alpha", "beta"]);
    for call in annotator.calls() {
        assert_eq!(
            call.visible_annotations,
            json!({}),
            "an annotation that declares no needs sees an empty annotations object"
        );
    }
}

#[test]
fn downstream_annotator_reads_upstream_result() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"spans": [{"start": 0, "end": 5}]}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.spans\n",
        TWO_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(annotator.order(), vec!["alpha", "beta"]);
    let beta = annotator.call("beta");
    assert_eq!(
        beta.visible_annotations,
        json!({"alpha": {"spans": [{"start": 0, "end": 5}]}})
    );
    assert_eq!(
        beta.resolved_from,
        Some(json!([{"start": 0, "end": 5}])),
        "beta's from path resolves against alpha's recorded result"
    );
}

#[test]
fn a_to_b_to_c_runs_in_dependency_order() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"value": 1}));
    annotator.set_output("beta", json!({"value": 2}));
    annotator.set_output("gamma", json!({"value": 3}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
         \x20     gamma:\n        needs: [beta]\n        from: $pi.annotations.beta.value\n",
        THREE_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(annotator.order(), vec!["alpha", "beta", "gamma"]);
    assert_eq!(
        annotator.call("gamma").visible_annotations,
        json!({"beta": {"value": 2}}),
        "gamma declared only beta, so alpha stays out of its view"
    );
    assert_eq!(
        policy.final_annotations(),
        json!({"alpha": {"value": 1}, "beta": {"value": 2}, "gamma": {"value": 3}}),
        "the policy still receives every completed annotation"
    );
}

#[test]
fn a_shared_upstream_is_dispatched_once() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"value": 1}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
         \x20     gamma:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n",
        THREE_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(
        annotator.order(),
        vec!["alpha", "beta", "gamma"],
        "alpha runs once and both dependents reuse its recorded result"
    );
    assert_eq!(
        annotator
            .calls()
            .iter()
            .filter(|call| call.name == "alpha")
            .count(),
        1
    );
}

#[test]
fn a_dependency_orders_ahead_of_its_name() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("zebra", json!({"value": 9}));
    let policy = CapturingPolicy::new();
    // `alpha` sorts first but needs `zebra`, so a name ordering would run
    // it too early. The manifest also lists alpha first, which must not
    // decide anything either.
    let runtime = runtime(
        "      alpha:\n        needs: [zebra]\n        from: $pi.annotations.zebra.value\n\
         \x20     zebra:\n        from: $target.text\n",
        "  alpha:\n    type: classifier\n  zebra:\n    type: classifier\n",
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(annotator.order(), vec!["zebra", "alpha"]);
    assert_eq!(
        annotator.call("alpha").resolved_from,
        Some(json!(9)),
        "a forward reference is ordered, not rejected"
    );
}

#[test]
fn an_explicit_null_upstream_value_is_not_a_missing_one() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"label": null}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n",
        TWO_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(
        annotator.call("beta").resolved_from,
        Some(JsonValue::Null),
        "a label that is present and null resolves, and beta runs"
    );
}

#[test]
fn a_missing_upstream_member_fails_closed() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"other": 1}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n",
        TWO_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    let result = runtime.evaluate_point(InterceptionPoint::Input, snapshot());
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:path_missing"),
        "an absent member is distinguishable from one that is present and null"
    );
    assert_eq!(
        annotator.order(),
        vec!["alpha"],
        "beta is never dispatched without the input it declared"
    );
}

#[test]
fn a_failed_dependency_denies_and_does_not_run_its_dependent() {
    let annotator = ChainAnnotator::new();
    annotator.set_error(
        "alpha",
        RuntimeError::AnnotationFailed("upstream unavailable".to_string()),
    );
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
         \x20     gamma:\n        from: $target.text\n",
        THREE_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    let result = runtime.evaluate_point(InterceptionPoint::Input, snapshot());
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    assert_eq!(
        annotator.order(),
        vec!["alpha"],
        "the evaluation fails closed at the first failure, so neither the dependent nor the independent annotator runs"
    );
    assert!(
        policy.seen.lock().unwrap().is_empty(),
        "the policy is never reached"
    );
}

#[test]
fn a_dispatcher_cannot_reach_another_annotators_recorded_result() {
    /// Mutates everything it is handed, then reports what the next
    /// dispatch saw.
    struct MutatingAnnotator {
        seen: Mutex<Vec<JsonValue>>,
    }

    impl AnnotatorDispatcher for MutatingAnnotator {
        fn dispatch(
            &self,
            annotator_name: &str,
            _annotator: &AnnotatorInvocation,
            policy_input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            // The contract hands out a shared reference, so a dispatcher
            // can only mutate a clone it makes itself. Take one, corrupt
            // it, and confirm the runtime's copy is untouched next time.
            let mut stolen = policy_input.clone();
            if let Some(object) = stolen.as_object_mut() {
                object.insert("annotations".to_string(), json!({"alpha": "tampered"}));
                object.insert("snapshot".to_string(), json!("tampered"));
            }
            self.seen.lock().unwrap().push(policy_input.clone());
            Ok(json!({"value": annotator_name}))
        }
    }

    let annotator = Arc::new(MutatingAnnotator {
        seen: Mutex::new(Vec::new()),
    });
    let policy = CapturingPolicy::new();
    let runtime = Runtime::new(
        manifest(
            "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n",
            TWO_CLASSIFIERS,
        )
        .expect("manifest should load"),
        Arc::clone(&annotator) as Arc<dyn AnnotatorDispatcher>,
        Arc::clone(&policy) as Arc<dyn PolicyDispatcher>,
    )
    .expect("runtime should build");

    assert_eq!(evaluate(&runtime), Decision::Allow);
    let seen = annotator.seen.lock().unwrap().clone();
    assert_eq!(
        seen[1].get("snapshot"),
        Some(&json!({"input": {"text": "hello"}}))
    );
    assert_eq!(
        seen[1].get("annotations"),
        Some(&json!({"alpha": {"value": "alpha"}})),
        "beta sees alpha's real result, not the first dispatcher's tampering"
    );
    assert_eq!(
        policy.final_annotations(),
        json!({"alpha": {"value": "alpha"}, "beta": {"value": "beta"}})
    );
}

#[test]
fn the_same_graph_evaluates_identically_every_time() {
    let build = || {
        let annotator = ChainAnnotator::new();
        annotator.set_output("alpha", json!({"value": 1}));
        annotator.set_output("beta", json!({"value": 2}));
        let policy = CapturingPolicy::new();
        let runtime = runtime(
            "      alpha:\n        from: $target.text\n\
             \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
             \x20     gamma:\n        needs: [alpha, beta]\n        from: $target.text\n",
            THREE_CLASSIFIERS,
            Arc::clone(&annotator),
            Arc::clone(&policy),
        );
        assert_eq!(evaluate(&runtime), Decision::Allow);
        (annotator.order(), policy.final_annotations())
    };

    let (first_order, first_annotations) = build();
    for _ in 0..5 {
        let (order, annotations) = build();
        assert_eq!(order, first_order);
        assert_eq!(annotations, first_annotations);
    }
    assert_eq!(first_order, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn input_and_output_graphs_have_independent_order_and_evaluation_state() {
    let loaded = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.5.0-alpha.1
policies:
  test_policy:
    type: test
annotators:
  alpha:
    type: classifier
  beta:
    type: classifier
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: test_policy
    annotations:
      alpha:
        from: $target.text
      beta:
        needs: [alpha]
        from: $pi.annotations.alpha.label
  output:
    policy_target: $snap.output
    policy:
      id: test_policy
    annotations:
      alpha:
        needs: [beta]
        from: $pi.annotations.beta.label
      beta:
        from: $target.text
"#,
    )
    .unwrap();
    let annotator = ChainAnnotator::new();
    let policy = CapturingPolicy::new();
    let runtime = Runtime::new(loaded, annotator.clone(), policy.clone()).unwrap();

    for (round, (point, upstream, downstream, text)) in [
        (InterceptionPoint::Input, "alpha", "beta", "input text"),
        (InterceptionPoint::Output, "beta", "alpha", "output text"),
        (InterceptionPoint::Input, "alpha", "beta", "input text"),
    ]
    .into_iter()
    .enumerate()
    {
        let upstream_output = json!({"label": format!("upstream-{round}")});
        let downstream_output = json!({"label": format!("downstream-{round}")});
        annotator.set_output(upstream, upstream_output.clone());
        annotator.set_output(downstream, downstream_output.clone());
        let result = runtime.evaluate_point(
            point,
            json!({"input": {"text": "input text"}, "output": {"text": "output text"}}),
        );
        assert_eq!(result.verdict.decision, Decision::Allow);
        let calls = annotator.calls();
        assert_eq!(calls.len(), (round + 1) * 2);
        let calls = &calls[round * 2..];
        assert_eq!(calls[0].name, upstream);
        assert_eq!(calls[1].name, downstream);
        assert_eq!(calls[0].visible_annotations, json!({}));
        assert_eq!(calls[0].resolved_from, Some(json!(text)));
        assert_eq!(
            calls[1].visible_annotations,
            json!({(upstream): upstream_output.clone()})
        );
        assert_eq!(
            calls[1].resolved_from,
            Some(upstream_output["label"].clone())
        );
        assert_eq!(policy.seen.lock().unwrap().len(), round + 1);
        assert_eq!(
            policy.final_annotations(),
            json!({(upstream): upstream_output, (downstream): downstream_output}),
            "each evaluation must use only fresh results from its own point"
        );
    }
}

#[test]
fn fan_in_shows_every_declared_need() {
    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"value": 1}));
    annotator.set_output("beta", json!({"value": 2}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        from: $target.text\n\
         \x20     gamma:\n        needs: [alpha, beta]\n        from: $target.text\n",
        THREE_CLASSIFIERS,
        Arc::clone(&annotator),
        Arc::clone(&policy),
    );

    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(
        annotator.call("gamma").visible_annotations,
        json!({"alpha": {"value": 1}, "beta": {"value": 2}}),
        "a need that `from` does not name is still shown, which is what makes fan in work"
    );
    assert_eq!(
        annotator.call("gamma").resolved_from,
        Some(json!("hello")),
        "gamma's own from path still reads the snapshot"
    );
}

#[test]
fn telemetry_names_the_failed_annotation_and_its_dependencies() {
    struct CollectingTelemetry {
        events: Mutex<Vec<TelemetryEvent>>,
    }

    impl TelemetrySink for CollectingTelemetry {
        fn emit(&self, event: TelemetryEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    let annotator = ChainAnnotator::new();
    annotator.set_output("alpha", json!({"other": 1}));
    let policy = CapturingPolicy::new();
    let telemetry = Arc::new(CollectingTelemetry {
        events: Mutex::new(Vec::new()),
    });
    let runtime = Runtime::with_telemetry(
        manifest(
            "      alpha:\n        from: $target.text\n\
             \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n\
             \x20     gamma:\n        needs: [alpha, beta]\n        from: $target.text\n",
            THREE_CLASSIFIERS,
        )
        .expect("manifest should load"),
        Arc::clone(&annotator) as Arc<dyn AnnotatorDispatcher>,
        Arc::clone(&policy) as Arc<dyn PolicyDispatcher>,
        Arc::clone(&telemetry) as Arc<dyn TelemetrySink>,
    )
    .expect("runtime should build");

    runtime.evaluate_point(InterceptionPoint::Input, snapshot());

    let events = telemetry.events.lock().unwrap().clone();
    let failed = events
        .iter()
        .find(|event| event.event_type == TelemetryEventType::AnnotatorFailed)
        .expect("a failed annotation should be reported");
    assert_eq!(failed.annotators, vec!["beta".to_string()]);
    assert_eq!(
        failed.reason_code.as_deref(),
        Some("runtime_error:path_missing")
    );
    assert_eq!(
        failed.metadata.get("annotation_needs").map(String::as_str),
        Some("[\"alpha\"]"),
        "the event names the dependency beta was reading"
    );
    for event in &events {
        let rendered = format!("{event:?}");
        assert!(
            !rendered.contains("hello") && !rendered.contains("other"),
            "no annotation or snapshot payload reaches telemetry: {rendered}"
        );
    }
}

// Manifest validation: every rejection below happens at load, before any
// dispatcher runs.

fn load_error(annotations: &str, annotators: &str) -> String {
    let error = manifest(annotations, annotators).expect_err("manifest should be rejected");
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    error.detail().to_string()
}

#[test]
fn a_self_dependency_is_rejected() {
    let detail = load_error(
        "      alpha:\n        needs: [alpha]\n        from: $target.text\n",
        "  alpha:\n    type: classifier\n",
    );
    assert!(detail.contains("must not depend on itself"), "{detail}");
}

#[test]
fn a_cycle_is_rejected() {
    let detail = load_error(
        "      alpha:\n        needs: [beta]\n        from: $pi.annotations.beta.value\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n",
        TWO_CLASSIFIERS,
    );
    assert!(detail.contains("cycle"), "{detail}");
    assert!(detail.contains("alpha, beta"), "{detail}");
}

#[test]
fn a_cycle_reports_downstream_nodes_as_unresolved_not_as_cycle_members() {
    let detail = load_error(
        "      alpha:\n        needs: [beta]\n        from: $pi.annotations.beta.value\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
         \x20     gamma:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n",
        THREE_CLASSIFIERS,
    );
    assert!(
        detail.contains(
            "unresolvable annotation needs (cycle or blocked by one) among: alpha, beta, gamma"
        ),
        "gamma is blocked downstream, not a member of the alpha/beta cycle: {detail}"
    );
}

#[test]
fn a_longer_cycle_is_rejected() {
    let detail = load_error(
        "      alpha:\n        needs: [gamma]\n        from: $pi.annotations.gamma.value\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value\n\
         \x20     gamma:\n        needs: [beta]\n        from: $pi.annotations.beta.value\n",
        THREE_CLASSIFIERS,
    );
    assert!(detail.contains("cycle"), "{detail}");
}

#[test]
fn reading_an_annotation_without_declaring_it_is_rejected() {
    let detail = load_error(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        from: $pi.annotations.alpha.value\n",
        TWO_CLASSIFIERS,
    );
    assert!(detail.contains("without naming it in needs"), "{detail}");
}

#[test]
fn reading_the_whole_annotations_map_is_rejected() {
    let detail = load_error(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        needs: [alpha]\n        from: $pi.annotations\n",
        TWO_CLASSIFIERS,
    );
    assert!(detail.contains("must read a named annotation"), "{detail}");
}

#[test]
fn needing_an_annotator_the_point_does_not_opt_into_is_rejected() {
    let detail = load_error(
        "      beta:\n        needs: [alpha]\n        from: $target.text\n",
        TWO_CLASSIFIERS,
    );
    assert!(
        detail.contains("which the point does not opt into"),
        "{detail}"
    );
}

#[test]
fn needing_an_annotation_bound_only_at_another_point_is_rejected() {
    let error = Manifest::from_yaml_str(
        r#"agent_control_specification_version: 0.5.0-alpha.1
policies:
  test_policy:
    type: test
annotators:
  alpha:
    type: classifier
  beta:
    type: classifier
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: test_policy
    annotations:
      alpha:
        from: $target.text
  output:
    policy_target: $snap.output
    policy:
      id: test_policy
    annotations:
      beta:
        needs: [alpha]
        from: $target.text
"#,
    )
    .expect_err("a binding at input cannot satisfy a need at output");
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    for needle in [
        "output",
        "beta",
        "alpha",
        "which the point does not opt into",
    ] {
        assert!(error.detail().contains(needle), "{error}");
    }
}

#[test]
fn a_repeated_need_is_rejected() {
    let detail = load_error(
        "      alpha:\n        from: $target.text\n\
         \x20     beta:\n        needs: [alpha, alpha]\n        from: $target.text\n",
        TWO_CLASSIFIERS,
    );
    assert!(detail.contains("more than once"), "{detail}");
}

#[test]
fn needs_does_not_reach_the_dispatched_invocation() {
    let annotator = ChainAnnotator::new();
    let policy = CapturingPolicy::new();
    let loaded = manifest(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n",
        TWO_CLASSIFIERS,
    )
    .expect("manifest should load");
    let binding = &loaded.intervention_points[&InterceptionPoint::Input].annotations["beta"];
    assert_eq!(binding.fields["needs"], json!(["alpha"]));
    let invocation =
        AnnotatorInvocation::from_annotation_in(&loaded, &loaded.annotators["beta"], binding);
    assert!(
        invocation.field("needs").is_none(),
        "the engine consumes needs only for the versioned invocation"
    );

    let runtime = Runtime::new(
        loaded,
        Arc::clone(&annotator) as Arc<dyn AnnotatorDispatcher>,
        Arc::clone(&policy) as Arc<dyn PolicyDispatcher>,
    )
    .expect("runtime should build");
    assert_eq!(evaluate(&runtime), Decision::Allow);
}

#[test]
fn a_graph_over_the_annotator_limit_still_fails_closed() {
    let mut annotations = String::new();
    let mut annotators = String::new();
    // One more than the default `max_annotators_per_point`, chained so
    // the limit is reached through dependencies rather than breadth.
    for index in 0..17 {
        let name = format!("a{index:02}");
        annotators.push_str(&format!("  {name}:\n    type: classifier\n"));
        if index == 0 {
            annotations.push_str(&format!("      {name}:\n        from: $target.text\n"));
        } else {
            let previous = format!("a{:02}", index - 1);
            annotations.push_str(&format!(
                "      {name}:\n        needs: [{previous}]\n        from: $pi.annotations.{previous}.value\n"
            ));
        }
    }

    let runtime = runtime(
        &annotations,
        &annotators,
        ChainAnnotator::new(),
        CapturingPolicy::new(),
    );
    assert_eq!(
        verdict_reason(&runtime),
        "runtime_error:resource_limit_exceeded"
    );
}

#[test]
fn programmatic_needs_uses_the_same_validation_and_serialization() {
    let mut loaded = manifest(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n",
        TWO_CLASSIFIERS,
    )
    .expect("manifest should load");

    loaded
        .intervention_points
        .get_mut(&InterceptionPoint::Input)
        .expect("input point")
        .annotations
        .get_mut("beta")
        .expect("beta binding")
        .fields
        .insert("needs".to_string(), json!("shadow"));

    let error = loaded
        .validate()
        .expect_err("a needs annotator field must be refused");
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(error.detail().contains("array of names"));

    let serialized = serde_json::to_string(&loaded).expect("serialize");
    assert_eq!(serialized.matches("\"needs\"").count(), 1);
    assert!(Manifest::from_json_str(&serialized).is_err());
    loaded
        .intervention_points
        .get_mut(&InterceptionPoint::Input)
        .unwrap()
        .annotations
        .get_mut("beta")
        .unwrap()
        .fields
        .insert("needs".into(), json!(["alpha"]));
    loaded.validate().unwrap();
    assert_eq!(
        Manifest::from_json_str(&serde_json::to_string(&loaded).unwrap()).unwrap(),
        loaded
    );
    assert_eq!(
        Manifest::from_yaml_str(&serde_json::to_string(&loaded).unwrap()).unwrap(),
        loaded
    );
}

#[test]
fn legacy_needs_remains_an_opaque_host_field_and_preserves_the_verdict() {
    struct LegacyAnnotator {
        expected: JsonValue,
        calls: Mutex<Vec<String>>,
    }
    impl AnnotatorDispatcher for LegacyAnnotator {
        fn dispatch(
            &self,
            name: &str,
            invocation: &AnnotatorInvocation,
            input: &JsonValue,
        ) -> Result<JsonValue, RuntimeError> {
            self.calls.lock().unwrap().push(name.to_string());
            assert_eq!(input["annotations"], json!({}));
            Ok(json!({"blocked": invocation.field("needs") == Some(&self.expected)}))
        }
    }
    struct Gate;
    impl PolicyDispatcher for Gate {
        fn evaluate(
            &self,
            invocation: &PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            let blocked =
                invocation.policy_input().unwrap()["annotations"]["alpha"]["blocked"] == true;
            Ok(json!({"decision": if blocked { "deny" } else { "allow" }}))
        }
    }
    for value in [
        json!("strict"),
        json!(["beta"]),
        json!([]),
        json!(null),
        json!({"host": true}),
    ] {
        let mut loaded = manifest(
            "      alpha:\n        from: $target.text\n      beta:\n        from: $target.text\n",
            TWO_CLASSIFIERS,
        )
        .unwrap();
        loaded.agent_control_specification_version = "0.4.0-alpha.1".into();
        loaded
            .intervention_points
            .get_mut(&InterceptionPoint::Input)
            .unwrap()
            .annotations
            .get_mut("alpha")
            .unwrap()
            .fields
            .insert("needs".into(), value.clone());
        let json = serde_json::to_string(&loaded).unwrap();
        let loaded = Manifest::from_json_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&loaded).unwrap(), json);
        let dispatcher = Arc::new(LegacyAnnotator {
            expected: value,
            calls: Mutex::new(vec![]),
        });
        let runtime = Runtime::new(loaded, dispatcher.clone(), Arc::new(Gate)).unwrap();
        assert_eq!(evaluate(&runtime), Decision::Deny);
        assert_eq!(*dispatcher.calls.lock().unwrap(), ["alpha", "beta"]);
    }
}

#[test]
fn the_original_rust_config_literal_and_constructor_remain_compatible() {
    let binding = agent_control_spec::AnnotationConfig {
        from: "$target".into(),
        fields: BTreeMap::from([("needs".into(), json!("legacy"))]),
    };
    let loaded = manifest("      alpha:\n        from: $target\n", TWO_CLASSIFIERS).unwrap();
    let invocation = AnnotatorInvocation::from_annotation(&loaded.annotators["alpha"], &binding);
    assert_eq!(invocation.field("needs"), Some(&json!("legacy")));
}

#[test]
fn legacy_version_cannot_read_annotations_even_with_a_needs_array() {
    let mut document = serde_json::to_value(manifest(
        "      alpha:\n        from: $target.text\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.label\n",
        TWO_CLASSIFIERS,
    ).unwrap()).unwrap();
    document["agent_control_specification_version"] = json!("0.4.0-alpha.1");
    assert_eq!(
        Manifest::from_json_str(&document.to_string())
            .unwrap_err()
            .reason(),
        "runtime_error:manifest_invalid"
    );
}

#[test]
fn new_version_rejects_malformed_needs_and_declaration_level_needs() {
    let valid = manifest("      alpha:\n        from: $target\n", TWO_CLASSIFIERS).unwrap();
    for value in [
        json!(null),
        json!("strict"),
        json!([null]),
        json!([""]),
        json!(["  "]),
        json!({}),
    ] {
        let mut loaded = valid.clone();
        loaded
            .intervention_points
            .get_mut(&InterceptionPoint::Input)
            .unwrap()
            .annotations
            .get_mut("alpha")
            .unwrap()
            .fields
            .insert("needs".into(), value);
        assert_eq!(
            loaded.validate().unwrap_err().reason(),
            "runtime_error:manifest_invalid"
        );
    }
    let mut loaded = valid;
    loaded
        .annotators
        .get_mut("alpha")
        .unwrap()
        .fields
        .insert("needs".into(), json!([]));
    assert!(loaded
        .validate()
        .unwrap_err()
        .detail()
        .contains("intervention-point binding"));
    loaded.agent_control_specification_version = "0.4.0-alpha.1".into();
    loaded.validate().unwrap();
}

#[test]
fn merged_chains_require_one_contract_version_and_preserve_needs() {
    let loaded = manifest(
        "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $target\n",
        TWO_CLASSIFIERS,
    ).unwrap();
    // JSON is a YAML subset, so this exercises the YAML loader without a
    // dependency on the YAML parser's serialization API.
    let source = serde_json::to_string(&loaded).unwrap();
    let merged = Manifest::from_yaml_chain(&[source.as_str(), source.as_str()]).unwrap();
    assert_eq!(
        merged.intervention_points[&InterceptionPoint::Input].annotations["beta"].fields["needs"],
        json!(["alpha"])
    );
    let old = source.replace("0.5.0-alpha.1", "0.4.0-alpha.1");
    assert_eq!(
        Manifest::from_yaml_chain(&[source.as_str(), old.as_str()])
            .unwrap_err()
            .reason(),
        "runtime_error:manifest_invalid"
    );
}

#[test]
fn extends_duplicate_bindings_conflict_when_child_adds_needs_even_if_empty() {
    let parent = manifest(
        "      alpha:\n        from: $target\n      beta:\n        from: $target\n",
        TWO_CLASSIFIERS,
    )
    .unwrap();
    let parent_source = serde_json::to_string(&parent).unwrap();
    for needs in [json!(["alpha"]), json!([])] {
        let mut child = parent.clone();
        child
            .intervention_points
            .get_mut(&InterceptionPoint::Input)
            .unwrap()
            .annotations
            .get_mut("beta")
            .unwrap()
            .fields
            .insert("needs".into(), needs);
        let child_source = serde_json::to_string(&child).unwrap();
        // Bindings merge as whole definitions: even an explicit empty
        // needs array differs from an omitted one, rather than adding to it.
        for sources in [
            [parent_source.as_str(), child_source.as_str()],
            [child_source.as_str(), parent_source.as_str()],
        ] {
            let error = Manifest::from_yaml_chain(&sources).unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(
                error.detail().contains(
                    "manifest extends conflict for intervention_points.input.annotations.beta"
                ),
                "{error}"
            );
        }
        let merged =
            Manifest::from_yaml_chain(&[child_source.as_str(), child_source.as_str()]).unwrap();
        assert_eq!(merged, child, "identical duplicate bindings still merge");
    }
}

#[test]
fn same_version_merges_ignore_surrounding_whitespace() {
    let mut loaded = manifest(
        "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $target\n",
        TWO_CLASSIFIERS,
    ).unwrap();
    for version in ["0.4.0-alpha.1", "0.5.0-alpha.1"] {
        loaded.agent_control_specification_version = version.into();
        let plain = serde_json::to_string(&loaded).unwrap();
        for padding in [" ", "\t\n", "\u{85}", "\u{a0}", "\u{3000}"] {
            loaded.agent_control_specification_version = format!("{padding}{version}{padding}");
            let padded = serde_json::to_string(&loaded).unwrap();
            for inputs in [
                [plain.as_str(), padded.as_str()],
                [padded.as_str(), plain.as_str()],
            ] {
                let merged = Manifest::from_yaml_chain(&inputs).unwrap();
                assert_eq!(merged.agent_control_specification_version.trim(), version);
                let runtime =
                    Runtime::new(merged, ChainAnnotator::new(), CapturingPolicy::new()).unwrap();
                assert_eq!(evaluate(&runtime), Decision::Allow);
            }
        }
    }
}

#[test]
fn file_extends_uses_the_same_version_comparison() {
    struct TempDirectory(std::path::PathBuf);

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!("failed to clean up {}: {error}", self.0.display());
            }
        }
    }

    let path = std::env::temp_dir().join(format!(
        "acs-annotation-chaining-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    let directory = TempDirectory(path);
    let loaded = manifest("      alpha:\n        from: $target\n", TWO_CLASSIFIERS).unwrap();
    std::fs::write(
        directory.0.join("parent.yaml"),
        serde_json::to_string(&loaded).unwrap(),
    )
    .unwrap();
    let root = directory.0.join("root.json");
    std::fs::write(
        &root,
        json!({
            "agent_control_specification_version": "\u{85}0.5.0-alpha.1 ",
            "extends": ["parent.yaml"],
        })
        .to_string(),
    )
    .unwrap();
    let merged = Manifest::from_path(&root).unwrap();
    let runtime = Runtime::new(merged, ChainAnnotator::new(), CapturingPolicy::new()).unwrap();
    assert_eq!(evaluate(&runtime), Decision::Allow);
}

#[test]
fn ready_nodes_are_reconsidered_after_each_completion() {
    let annotator = ChainAnnotator::new();
    let runtime = runtime(
        "      alpha:\n        needs: [beta]\n        from: $target\n      beta:\n        from: $target\n      gamma:\n        from: $target\n",
        THREE_CLASSIFIERS, annotator.clone(), CapturingPolicy::new(),
    );
    assert_eq!(evaluate(&runtime), Decision::Allow);
    assert_eq!(annotator.order(), ["beta", "alpha", "gamma"]);
}

#[test]
fn dependency_errors_timeouts_and_invalid_outputs_stop_every_remaining_dispatch() {
    for error in [
        RuntimeError::AnnotationFailed("synthetic failure".into()),
        RuntimeError::AnnotationTimeout("synthetic timeout".into()),
    ] {
        let annotator = ChainAnnotator::new().set_error("alpha", error.clone());
        let policy = CapturingPolicy::new();
        let runtime = runtime(
            "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $target\n      gamma:\n        from: $target\n",
            THREE_CLASSIFIERS, annotator.clone(), policy.clone(),
        );
        let result = runtime.evaluate_point(InterceptionPoint::Input, snapshot());
        assert_eq!(result.verdict.reason.as_deref(), Some(error.reason()));
        assert_eq!(annotator.order(), ["alpha"]);
        assert!(policy.seen.lock().unwrap().is_empty());
    }
    for output in [
        json!({"nested": {"reason": "runtime_error:forged"}}),
        json!("x".repeat(agent_control_spec::Limits::default().max_annotator_output_bytes + 1)),
    ] {
        let annotator = ChainAnnotator::new().set_output("alpha", output);
        let policy = CapturingPolicy::new();
        let runtime = runtime(
            "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $target\n",
            TWO_CLASSIFIERS, annotator.clone(), policy.clone(),
        );
        assert_eq!(verdict_reason(&runtime), "runtime_error:annotation_failed");
        assert_eq!(annotator.order(), ["alpha"]);
        assert!(policy.seen.lock().unwrap().is_empty());
    }
}

#[test]
fn dependency_values_obey_path_types_and_staged_depth_limits() {
    let annotator = ChainAnnotator::new().set_output("alpha", json!({"value": null}));
    let policy = CapturingPolicy::new();
    let runtime = runtime(
        "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $pi.annotations.alpha.value.member\n",
        TWO_CLASSIFIERS, annotator.clone(), policy.clone(),
    );
    assert_eq!(verdict_reason(&runtime), "runtime_error:path_type_mismatch");
    assert_eq!(annotator.order(), ["alpha"]);
    assert!(policy.seen.lock().unwrap().is_empty());

    let loaded = manifest(
        "      alpha:\n        from: $target\n      beta:\n        needs: [alpha]\n        from: $target\n",
        TWO_CLASSIFIERS,
    ).unwrap();
    for (depth, expected_order) in [(5, vec!["alpha"]), (6, vec!["alpha", "beta"])] {
        let annotator = ChainAnnotator::new().set_output("alpha", json!([[[[0]]]]));
        let policy = CapturingPolicy::new();
        let runtime = Runtime::with_limits(
            loaded.clone(),
            annotator.clone(),
            policy.clone(),
            agent_control_spec::Limits {
                max_policy_input_depth: depth,
                ..Default::default()
            },
        )
        .unwrap();
        let result = runtime.evaluate_point(InterceptionPoint::Input, snapshot());
        assert_eq!(annotator.order(), expected_order);
        if depth == 5 {
            assert_eq!(
                result.verdict.reason.as_deref(),
                Some("runtime_error:resource_limit_exceeded")
            );
            assert!(policy.seen.lock().unwrap().is_empty());
        } else {
            assert_eq!(result.verdict.decision, Decision::Allow);
        }
    }
}
