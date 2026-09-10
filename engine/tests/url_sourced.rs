//! Manifest provenance seen through the public API.
//!
//! A manifest that folded in a fetched document is URL sourced. The
//! runtime stamps that onto every annotator invocation it dispatches, and
//! the bundled dispatchers refuse every host environment read for such an
//! invocation, provider defaults included. The flag never leaves the
//! process: it is not in the JSON a host dispatcher receives.

use agent_control_spec::{
    AnnotatorDispatcher, AnnotatorInvocation, InterceptionPoint, JsonValue, Manifest,
    PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

const MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
    endpoint: http://127.0.0.1:9/v1
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      judge:
        from: $target.text
"#;

struct RecordingAnnotator {
    seen: Mutex<Vec<AnnotatorInvocation>>,
}

impl RecordingAnnotator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<AnnotatorInvocation> {
        self.seen.lock().unwrap().clone()
    }
}

impl AnnotatorDispatcher for RecordingAnnotator {
    fn dispatch(
        &self,
        _annotator_name: &str,
        annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        self.seen.lock().unwrap().push(annotator.clone());
        Ok(json!({"label": "safe"}))
    }
}

struct CountingAllowPolicy {
    calls: Mutex<usize>,
}

impl CountingAllowPolicy {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
        })
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl PolicyDispatcher for CountingAllowPolicy {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        *self.calls.lock().unwrap() += 1;
        Ok(json!({"decision": "allow"}))
    }
}

fn manifest(marked: bool) -> Manifest {
    let manifest = Manifest::from_yaml_str(MANIFEST).unwrap();
    if marked {
        manifest.mark_url_sourced()
    } else {
        manifest
    }
}

#[test]
fn runtime_stamps_url_sourced_onto_invocation() {
    for marked in [false, true] {
        let annotations = RecordingAnnotator::new();
        let runtime = Runtime::new(
            manifest(marked),
            annotations.clone(),
            CountingAllowPolicy::new(),
        )
        .unwrap();

        let result = runtime.evaluate_point(
            InterceptionPoint::Input,
            json!({"input": {"text": "hello"}}),
        );

        assert_eq!(result.verdict.reason, None, "{:?}", result.verdict);
        let seen = annotations.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url_sourced, marked);
        assert_eq!(seen[0].fields["endpoint"], json!("http://127.0.0.1:9/v1"));
    }
}

#[test]
fn invocation_json_has_no_provenance_key() {
    let annotations = RecordingAnnotator::new();
    let runtime = Runtime::new(
        manifest(true),
        annotations.clone(),
        CountingAllowPolicy::new(),
    )
    .unwrap();

    runtime.evaluate_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "hello"}}),
    );

    let invocation = &annotations.seen()[0];
    assert!(invocation.url_sourced);
    let wire = serde_json::to_value(invocation).unwrap();
    assert!(wire.get("url_sourced").is_none(), "{wire}");
    assert_eq!(wire["type"], json!("llm"));
}

/// Attack shape 3, the dispatch half: a URL sourced `llm` annotator with
/// no credential field would otherwise read `OPENAI_API_KEY` and post it
/// to the endpoint the fetched document chose. The bundled dispatcher
/// refuses before any request, and the runtime turns that into the
/// fail-closed annotator verdict.
#[cfg(feature = "default-dispatchers")]
#[test]
fn marked_manifest_default_env_denies_at_verdict() {
    use agent_control_spec::{
        dispatchers::default_annotator_dispatcher, Decision, TelemetryEvent, TelemetryEventType,
        TelemetrySink,
    };

    struct RecordingTelemetry {
        events: Arc<Mutex<Vec<TelemetryEvent>>>,
    }

    impl TelemetrySink for RecordingTelemetry {
        fn emit(&self, event: TelemetryEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let policy = CountingAllowPolicy::new();
    let runtime = Runtime::with_telemetry(
        manifest(true),
        default_annotator_dispatcher(),
        policy.clone(),
        Arc::new(RecordingTelemetry {
            events: events.clone(),
        }),
    )
    .unwrap();

    let result = runtime.evaluate_point(
        InterceptionPoint::Input,
        json!({"input": {"text": "hello"}}),
    );

    assert_eq!(result.verdict.decision, Decision::Deny);
    assert_eq!(
        result.verdict.reason.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    let message = result.verdict.message.clone().unwrap_or_default();
    assert!(message.contains("URL sourced manifest"), "{message}");
    assert!(message.contains("OPENAI_API_KEY"), "{message}");
    assert_eq!(
        policy.calls(),
        0,
        "the policy must not run after the refusal"
    );

    let events = events.lock().unwrap().clone();
    let event_types: Vec<_> = events.iter().map(|event| event.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            TelemetryEventType::AnnotatorFailed,
            TelemetryEventType::Decision
        ]
    );
    assert_eq!(events[0].annotators, vec!["judge".to_string()]);
    assert_eq!(
        events[0].reason_code.as_deref(),
        Some("runtime_error:annotation_failed")
    );
    assert_eq!(events[0].error_class.as_deref(), Some("runtime_error"));
}
