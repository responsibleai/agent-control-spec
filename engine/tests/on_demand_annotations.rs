#![cfg(feature = "rego")]

use agent_control_spec::{
    ActivatedPolicy, AnnotatorDispatcher, AnnotatorInvocation, Decision, InMemoryRegoBundle,
    InterceptionPoint, JsonValue, Limits, Manifest, NoopTelemetrySink, PerfTelemetry, PolicyConfig,
    RegorusPolicyDispatcher, RegorusRegoRunner, Runtime, RuntimeError, TelemetryEvent,
    TelemetryEventType, TelemetrySink,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

type Callback =
    dyn Fn(&str, &AnnotatorInvocation, &JsonValue) -> Result<JsonValue, RuntimeError> + Send + Sync;

struct Annotator {
    callback: Box<Callback>,
    caller_thread: bool,
}

impl AnnotatorDispatcher for Annotator {
    fn requires_caller_thread(&self) -> bool {
        self.caller_thread
    }

    fn dispatch(
        &self,
        name: &str,
        invocation: &AnnotatorInvocation,
        input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        (self.callback)(name, invocation, input)
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<TelemetryEvent>>);

impl TelemetrySink for Events {
    fn emit(&self, event: TelemetryEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn manifest(bindings: JsonValue, source: &str) -> Manifest {
    let annotators: serde_json::Map<_, _> = bindings
        .as_object()
        .unwrap()
        .keys()
        .map(|name| (name.clone(), json!({"type":"endpoint"})))
        .collect();
    let mut manifest = Manifest::from_yaml_str(
        &json!({
            "agent_control_specification_version":"0.6.0-alpha.1",
            "policies":{"gate":{"type":"rego","query":"data.gate.verdict"}},
            "annotators":annotators,
            "intervention_points":{"input":{
                "policy_target":"$snap.input",
                "policy":{"id":"gate"},
                "annotations":bindings
            }}
        })
        .to_string(),
    )
    .unwrap();
    let PolicyConfig::Rego(config) = manifest.policies.get_mut("gate").unwrap() else {
        unreachable!()
    };
    config.inline_bundle = Some(Arc::new(
        InMemoryRegoBundle::new(
            BTreeMap::from([(
                "gate.rego".into(),
                format!("package gate\nimport rego.v1\n{source}"),
            )]),
            vec![],
        )
        .unwrap(),
    ));
    manifest
}

fn runtime(
    manifest: Manifest,
    callback: impl Fn(&str, &AnnotatorInvocation, &JsonValue) -> Result<JsonValue, RuntimeError>
        + Send
        + Sync
        + 'static,
    caller_thread: bool,
    timeout: Duration,
    events: Arc<dyn TelemetrySink>,
) -> Runtime {
    Runtime::with_telemetry_perf_and_limits(
        manifest,
        Arc::new(Annotator {
            callback: Box::new(callback),
            caller_thread,
        }),
        Arc::new(RegorusPolicyDispatcher::with_runner(
            RegorusRegoRunner::new()
                .with_policy_cache(true)
                .with_eval_timeout(timeout),
        )),
        events,
        PerfTelemetry::default(),
        Limits::default(),
    )
    .unwrap()
}

fn binding() -> JsonValue {
    json!({"probe":{"from":"$target","execution":"on_demand"}})
}

#[test]
fn guarded_calls_are_lazy_memoized_and_do_not_mutate_policy_input() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let events = Arc::new(Events::default());
    let source = r#"
first := acs.annotate("probe", input.policy_target.value.required)
second := acs.annotate("probe", input.policy_target.value.required)
skipped := acs.annotate("probe", false)
default verdict := {"decision":"deny"}
verdict := {"decision":"allow"} if {
    first == second
    skipped.status == "not_required"
    count(input.annotations) == 0
    first.status == "not_required"
}
verdict := {"decision":"allow"} if {
    first == second
    skipped.status == "not_required"
    count(input.annotations) == 0
    first.value.id == input.policy_target.value.id
}"#;
    let runtime = runtime(
        manifest(binding(), source),
        move |name, invocation, input| {
            assert!(!invocation.fields.contains_key("execution"));
            assert_eq!(input["annotations"], json!({}));
            recorded.lock().unwrap().push(name.to_string());
            Ok(json!({"id":input["policy_target"]["value"]["id"]}))
        },
        false,
        Duration::from_secs(5),
        events.clone(),
    );
    let activated = ActivatedPolicy::activate(runtime).unwrap();
    assert!(
        calls.lock().unwrap().is_empty(),
        "activation must not invoke the provider"
    );
    for (required, id) in [(false, "skip"), (true, "one"), (true, "two")] {
        let result = activated.evaluate(
            InterceptionPoint::Input,
            json!({"input":{"required":required,"id":id}}),
        );
        assert_eq!(
            result.verdict.decision,
            Decision::Allow,
            "{:?}",
            result.verdict
        );
        assert_eq!(result.policy_input.unwrap()["annotations"], json!({}));
    }
    assert_eq!(calls.lock().unwrap().len(), 2);
    let events = events.0.lock().unwrap();
    let reports: Vec<_> = events
        .iter()
        .filter(|event| event.event_type == TelemetryEventType::AnnotationResolution)
        .collect();
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0].metadata["provider_calls"], "0");
    assert_eq!(reports[1].metadata["provider_calls"], "1");
    assert_eq!(reports[2].metadata["provider_calls"], "1");
}

#[test]
fn false_guard_does_not_resolve_missing_paths_or_dependencies() {
    let bindings = json!({
        "base":{"from":"$snap.absent","execution":"on_demand"},
        "probe":{"from":"$pi.annotations.base.value","needs":["base"],"execution":"on_demand"}
    });
    let source = r#"verdict := {"decision":"allow"} if acs.annotate("probe", false).status == "not_required""#;
    let runtime = runtime(
        manifest(bindings, source),
        |_, _, _| panic!("false must not dispatch any provider"),
        false,
        Duration::from_secs(5),
        Arc::new(NoopTelemetrySink),
    );
    assert_eq!(
        runtime
            .evaluate_point(InterceptionPoint::Input, json!({"input":{}}))
            .verdict
            .decision,
        Decision::Allow
    );
}

#[test]
fn demanded_dependency_closure_uses_raw_outputs_once_in_order() {
    let bindings = json!({
        "z_base":{"from":"$target","execution":"on_demand"},
        "a_child":{"from":"$pi.annotations.z_base.value","needs":["z_base"],"execution":"on_demand"},
        "unused":{"from":"$snap.absent","execution":"on_demand"}
    });
    let source = r#"
verdict := {"decision":"allow"} if {
    acs.annotate("z_base", false).status == "not_required"
    acs.annotate("a_child", true).value.value == 8
    acs.annotate("z_base", true).value.value == 7
}"#;
    let order = Arc::new(Mutex::new(Vec::new()));
    let observed = order.clone();
    let runtime = runtime(
        manifest(bindings, source),
        move |name, invocation, input| {
            observed.lock().unwrap().push(name.to_string());
            assert!(!invocation.fields.contains_key("needs"));
            if name == "z_base" {
                assert_eq!(input["annotations"], json!({}));
                Ok(json!({"value":7}))
            } else {
                assert_eq!(name, "a_child");
                assert_eq!(input["annotations"], json!({"z_base":{"value":7}}));
                Ok(json!({"value":8}))
            }
        },
        false,
        Duration::from_secs(5),
        Arc::new(NoopTelemetrySink),
    );
    assert_eq!(
        runtime
            .evaluate_point(InterceptionPoint::Input, json!({"input":{}}))
            .verdict
            .decision,
        Decision::Allow
    );
    assert_eq!(*order.lock().unwrap(), vec!["z_base", "a_child"]);
}

#[test]
fn provider_failures_and_invalid_guards_never_leave_default_allow() {
    for expression in [
        r#"acs.annotate("probe", true)"#,
        r#"acs.annotate("probe", null)"#,
        r#"acs.annotate("missing", false)"#,
    ] {
        let source = format!(
            r#"
default verdict := {{"decision":"allow"}}
verdict := {{"decision":"deny"}} if {expression}.value.blocked
"#
        );
        let calls = Arc::new(Mutex::new(0));
        let recorded = calls.clone();
        let runtime = runtime(
            manifest(binding(), &source),
            move |_, _, _| {
                *recorded.lock().unwrap() += 1;
                Err(RuntimeError::AnnotationTimeout("injected timeout".into()))
            },
            false,
            Duration::from_secs(5),
            Arc::new(NoopTelemetrySink),
        );
        let result = runtime.evaluate_point(InterceptionPoint::Input, json!({"input":{}}));
        assert_eq!(result.verdict.decision, Decision::Deny, "{expression}");
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:policy_invocation_failed")
        );
        assert!(*calls.lock().unwrap() <= 1);
    }
}

#[test]
fn failed_paths_report_zero_provider_calls_and_stop_resolution() {
    let events = Arc::new(Events::default());
    let source = r#"verdict := acs.annotate("probe", true).value"#;
    let runtime = runtime(
        manifest(
            json!({"probe":{"from":"$snap.absent","execution":"on_demand"}}),
            source,
        ),
        |_, _, _| panic!("missing input path must fail before dispatch"),
        false,
        Duration::from_secs(5),
        events.clone(),
    );
    let result = runtime.evaluate_point(InterceptionPoint::Input, json!({"input":{}}));
    assert_eq!(result.verdict.decision, Decision::Deny);
    let events = events.0.lock().unwrap();
    let report = events
        .iter()
        .find(|event| event.event_type == TelemetryEventType::AnnotationResolution)
        .unwrap();
    assert_eq!(report.metadata["provider_calls"], "0");
    assert_eq!(report.metadata["status"], "failed");
}

#[test]
fn caller_thread_callbacks_stay_on_the_caller_and_late_success_is_denied() {
    let caller = thread::current().id();
    let source = r#"verdict := acs.annotate("probe", true).value"#;
    let runtime = runtime(
        manifest(binding(), source),
        move |_, _, _| {
            assert_eq!(thread::current().id(), caller);
            thread::sleep(Duration::from_millis(40));
            Ok(json!({"decision":"allow"}))
        },
        true,
        Duration::from_millis(20),
        Arc::new(NoopTelemetrySink),
    );
    let result = runtime.evaluate_point(InterceptionPoint::Input, json!({"input":{}}));
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );
}

#[test]
fn concurrent_evaluations_do_not_share_provider_results() {
    let source = r#"
default verdict := {"decision":"deny"}
verdict := {"decision":"allow"} if {
    acs.annotate("probe", true).value.id == input.policy_target.value.id
}"#;
    let runtime = runtime(
        manifest(binding(), source),
        |_, _, input| Ok(json!({"id":input["policy_target"]["value"]["id"]})),
        false,
        Duration::from_secs(5),
        Arc::new(NoopTelemetrySink),
    );
    let threads: Vec<_> = (0..8)
        .map(|id| {
            let runtime = runtime.clone();
            thread::spawn(move || {
                runtime
                    .evaluate_point(InterceptionPoint::Input, json!({"input":{"id":id}}))
                    .verdict
                    .decision
            })
        })
        .collect();
    for task in threads {
        assert_eq!(task.join().unwrap(), Decision::Allow);
    }
}

#[test]
fn on_demand_policies_cannot_read_ambient_clock() {
    let source = r#"verdict := {"decision":"allow"} if time.now_ns() > 0"#;
    let runtime = runtime(
        manifest(binding(), source),
        |_, _, _| panic!("unused"),
        false,
        Duration::from_secs(5),
        Arc::new(NoopTelemetrySink),
    );
    assert_eq!(
        runtime
            .evaluate_point(InterceptionPoint::Input, json!({"input":{}}))
            .verdict
            .decision,
        Decision::Deny
    );
}

#[test]
fn execution_mode_is_versioned_and_schema_validated() {
    let schema: JsonValue =
        serde_json::from_str(include_str!("../../spec/schema/manifest.schema.json")).unwrap();
    let approval: JsonValue =
        serde_json::from_str(include_str!("../../spec/schema/approval.schema.json")).unwrap();
    let registry = jsonschema::Registry::new()
        .add(approval["$id"].as_str().unwrap(), &approval)
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let base = manifest(binding(), r#"verdict := {"decision":"allow"}"#);
    for mode in [
        json!(null),
        json!(false),
        json!(5),
        json!("later"),
        json!([]),
    ] {
        let mut invalid = base.clone();
        invalid
            .intervention_points
            .get_mut(&InterceptionPoint::Input)
            .unwrap()
            .annotations
            .get_mut("probe")
            .unwrap()
            .fields
            .insert("execution".into(), mode.clone());
        assert!(invalid.validate().is_err(), "{mode}");
        assert!(
            !validator.is_valid(&serde_json::to_value(&invalid).unwrap()),
            "{mode}"
        );
        for version in ["0.4.0-alpha.1", "0.5.0-alpha.1"] {
            let mut legacy = invalid.clone();
            legacy.agent_control_specification_version = version.into();
            assert!(legacy.validate().is_ok(), "{version} {mode}");
            assert!(
                validator.is_valid(&serde_json::to_value(&legacy).unwrap()),
                "{version} {mode}"
            );
        }
    }
    let mut declaration = base.clone();
    declaration
        .annotators
        .get_mut("probe")
        .unwrap()
        .fields
        .insert("execution".into(), json!("on_demand"));
    assert!(declaration.validate().is_err());
    assert!(!validator.is_valid(&serde_json::to_value(&declaration).unwrap()));

    let mut dependency = base.clone();
    dependency
        .annotators
        .insert("eager".into(), dependency.annotators["probe"].clone());
    dependency
        .intervention_points
        .get_mut(&InterceptionPoint::Input)
        .unwrap()
        .annotations
        .insert(
            "eager".into(),
            agent_control_spec::AnnotationConfig {
                from: "$target".into(),
                fields: BTreeMap::from([("needs".into(), json!(["probe"]))]),
            },
        );
    assert!(dependency
        .validate()
        .unwrap_err()
        .detail()
        .contains("eager"));
}

#[test]
fn legacy_execution_fields_remain_opaque_and_eager() {
    for version in ["0.4.0-alpha.1", "0.5.0-alpha.1"] {
        let mut manifest = manifest(binding(), r#"verdict := {"decision":"allow"}"#);
        manifest.agent_control_specification_version = version.into();
        let calls = Arc::new(Mutex::new(0));
        let recorded = calls.clone();
        let runtime = runtime(
            manifest,
            move |_, invocation, _| {
                assert_eq!(invocation.fields["execution"], json!("on_demand"));
                *recorded.lock().unwrap() += 1;
                Ok(json!({}))
            },
            false,
            Duration::from_secs(5),
            Arc::new(NoopTelemetrySink),
        );
        assert_eq!(
            runtime
                .evaluate_point(InterceptionPoint::Input, json!({"input":{}}))
                .verdict
                .decision,
            Decision::Allow
        );
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}

#[test]
fn unsupported_policy_dispatchers_reject_at_construction() {
    struct Unsupported;
    impl agent_control_spec::PolicyDispatcher for Unsupported {
        fn evaluate(
            &self,
            _: &agent_control_spec::PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            panic!("unsupported dispatcher must not run")
        }
    }
    let result = Runtime::new(
        manifest(binding(), r#"verdict := {"decision":"allow"}"#),
        Arc::new(Annotator {
            callback: Box::new(|_, _, _| panic!("unsupported")),
            caller_thread: false,
        }),
        Arc::new(Unsupported),
    );
    assert!(matches!(result, Err(RuntimeError::ManifestInvalid(_))));
}

#[test]
fn invalid_provider_outputs_fail_before_policy_can_allow() {
    let source = r#"verdict := {"decision":"allow"} if count(acs.annotate("probe", true)) > 0"#;
    for payload in [
        json!({"reason":"runtime_error:forged"}),
        json!("x".repeat(Limits::default().max_annotator_output_bytes + 1)),
    ] {
        let runtime = runtime(
            manifest(binding(), source),
            move |_, _, _| Ok(payload.clone()),
            false,
            Duration::from_secs(5),
            Arc::new(NoopTelemetrySink),
        );
        let result = runtime.evaluate_point(InterceptionPoint::Input, json!({"input":{}}));
        assert_eq!(result.verdict.decision, Decision::Deny);
        assert_eq!(
            result.verdict.reason.as_deref(),
            Some("runtime_error:policy_invocation_failed")
        );
    }
}

#[test]
fn retained_resolver_cannot_dispatch_after_evaluation_finishes() {
    struct Capture(Arc<Mutex<Option<agent_control_spec::OnDemandAnnotations>>>);
    impl agent_control_spec::PolicyDispatcher for Capture {
        fn supports_on_demand_annotations(&self) -> bool {
            true
        }
        fn evaluate(
            &self,
            _: &agent_control_spec::PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            panic!("callable dispatch expected")
        }
        fn evaluate_with_annotations(
            &self,
            _: &agent_control_spec::PreparedPolicyInvocation,
            resolver: agent_control_spec::OnDemandAnnotations,
        ) -> Result<JsonValue, RuntimeError> {
            *self.0.lock().unwrap() = Some(resolver);
            Ok(json!({"decision":"allow"}))
        }
    }
    let captured = Arc::new(Mutex::new(None));
    let runtime = Runtime::new(
        manifest(binding(), r#"verdict := {"decision":"allow"}"#),
        Arc::new(Annotator {
            callback: Box::new(|_, _, _| panic!("closed resolver must not dispatch")),
            caller_thread: false,
        }),
        Arc::new(Capture(captured.clone())),
    )
    .unwrap();
    assert_eq!(
        runtime
            .evaluate_point(InterceptionPoint::Input, json!({"input":{}}))
            .verdict
            .decision,
        Decision::Allow
    );
    let resolver = captured.lock().unwrap().take().unwrap();
    assert!(resolver.annotate("probe", true).is_err());
}

#[test]
fn a_dispatcher_cannot_recover_an_annotation_failure_into_allow() {
    struct Recover;
    impl agent_control_spec::PolicyDispatcher for Recover {
        fn supports_on_demand_annotations(&self) -> bool {
            true
        }
        fn evaluate(
            &self,
            _: &agent_control_spec::PreparedPolicyInvocation,
        ) -> Result<JsonValue, RuntimeError> {
            panic!("callable dispatch expected")
        }
        fn evaluate_with_annotations(
            &self,
            _: &agent_control_spec::PreparedPolicyInvocation,
            resolver: agent_control_spec::OnDemandAnnotations,
        ) -> Result<JsonValue, RuntimeError> {
            assert!(resolver.annotate("probe", true).is_err());
            Ok(json!({"decision":"allow"}))
        }
    }
    let runtime = Runtime::new(
        manifest(binding(), r#"verdict := {"decision":"allow"}"#),
        Arc::new(Annotator {
            callback: Box::new(|_, _, _| Err(RuntimeError::AnnotationFailed("failed".into()))),
            caller_thread: false,
        }),
        Arc::new(Recover),
    )
    .unwrap();
    let result = runtime.evaluate_point(InterceptionPoint::Input, json!({"input":{}}));
    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:policy_invocation_failed")
    );
}
