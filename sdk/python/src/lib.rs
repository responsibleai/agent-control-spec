// Python native binding over the Agent Control Specification runtime.
//
// Deliberately thin, mirroring the Node binding: construct a runtime
// from a manifest (zero-config dispatchers), evaluate one context,
// return the verdict as wire JSON. Evaluation failures never surface
// as Python exceptions — the runtime normalizes them into fail-closed
// `deny` verdicts with `runtime_error:*` reasons. Exceptions on this
// boundary mean a boundary problem only (unreadable manifest,
// non-object context JSON).

use agent_control_spec::annotation::{AnnotatorDispatcher, AnnotatorInvocation};
use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::policy::PreparedPolicyInvocation;
use agent_control_spec::runtime::PolicyDispatcher;
use agent_control_spec::telemetry::{TelemetryEvent, TelemetrySink};
use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, Manifest, PerfTelemetry, Runtime,
    RuntimeError, SafetyLevel, SegmentOutcome, StreamEndReason, StreamError, StreamSession,
    StreamSessionConfig, StreamSourceType, StreamSpan, StreamTrack, Verdict, SUPPORTED_VERSIONS,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------
// Host-supplied dispatchers, telemetry, and perf-telemetry level.
//
// These wrappers hold a `Py<PyAny>` and adapt a Python object into the
// engine's `AnnotatorDispatcher`, `PolicyDispatcher`, or `TelemetrySink`
// trait. The engine calls them from its evaluation path, so failures
// raised on the Python side must become `RuntimeError` on the Rust side:
// the engine then normalizes them into fail-closed `runtime_error:*`
// verdicts and never treats a raising dispatcher as "no annotation".
//
// `Py<PyAny>` is `Send + Sync` in pyo3; the wrappers acquire the GIL
// inside each callback for the actual Python call.
// ---------------------------------------------------------------------

/// Convert a `serde_json::Value` into a Python object using only the
/// standard container types, so a host dispatcher receives plain
/// `dict`/`list`/`str`/`bool`/`int`/`float`/`None` values.
fn json_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any())
            } else if let Some(f) = n.as_f64() {
                Ok(PyFloat::new(py, f).into_any())
            } else {
                // Neither i64/u64/f64 accepted the number, which means an
                // arbitrary-precision integer serde_json exposed only as
                // string. Round-trip through JSON to preserve the value.
                let s = n.to_string();
                Ok(PyString::new(py, &s).into_any())
            }
        }
        Value::String(s) => Ok(PyString::new(py, s).into_any()),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, value) in map {
                dict.set_item(key, json_to_py(py, value)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

/// Convert a Python object into a `serde_json::Value`. Used to accept a
/// host dispatcher's return value, and structured with the same
/// vocabulary that `json_to_py` produces so a callback that echoes its
/// input round-trips.
fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = value.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if let Ok(i) = value.cast::<PyInt>() {
        if let Ok(v) = i.extract::<i64>() {
            return Ok(Value::from(v));
        }
        if let Ok(v) = i.extract::<u64>() {
            return Ok(Value::from(v));
        }
        // Fall through for oversized integers: represent as string, which
        // is the same fallback `json_to_py` uses for arbitrary-precision
        // numbers.
        return Ok(Value::String(i.str()?.to_string_lossy().into_owned()));
    }
    if let Ok(f) = value.cast::<PyFloat>() {
        let v = f.value();
        // `serde_json::Number::from_f64` rejects NaN/Inf, matching the
        // JSON grammar the engine's inputs assume elsewhere.
        return serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err("dispatcher returned a non-finite float"));
    }
    if let Ok(s) = value.cast::<PyString>() {
        return Ok(Value::String(s.to_string_lossy().into_owned()));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for item in list.iter() {
            out.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut out = Map::new();
        for (key, val) in dict.iter() {
            let key_str = key
                .cast::<PyString>()
                .map_err(|_| {
                    PyValueError::new_err("dispatcher returned a dict with a non-string key")
                })?
                .to_string_lossy()
                .into_owned();
            out.insert(key_str, py_to_json(&val)?);
        }
        return Ok(Value::Object(out));
    }
    // Fall through: reject anything that is not a plain JSON-compatible
    // Python value. Silent conversion via `str()` would hide contract
    // violations in host code.
    Err(PyValueError::new_err(format!(
        "dispatcher returned a value that does not fit the JSON grammar: {}",
        value.get_type().name()?
    )))
}

/// Turn a `PyErr` raised inside a host dispatcher into a Rust
/// `RuntimeError` variant. Distinct variant per role, so the engine's
/// normalized `runtime_error:*` reason names the pipeline stage that
/// failed rather than a generic bucket.
fn py_err_to_annotation_failure(annotator_name: &str, err: PyErr) -> RuntimeError {
    RuntimeError::AnnotationFailed(format!("host annotator '{annotator_name}' raised: {err}"))
}

fn py_err_to_policy_failure(err: PyErr) -> RuntimeError {
    RuntimeError::PolicyInvocationFailed(format!("host policy dispatcher raised: {err}"))
}

/// Call a Python callable, preferring a named method when `callback`
/// exposes one. The old 0.3.1b1 API accepted objects with a `dispatch`
/// method; a plain callable is admitted too so hosts can use a small
/// lambda for tests.
fn call_py_method<'py>(
    py: Python<'py>,
    callback: &Py<PyAny>,
    method: &str,
    args: Vec<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let bound = callback.bind(py);
    let py_tuple = pyo3::types::PyTuple::new(py, args)?;
    if let Ok(func) = bound.getattr(method) {
        return func.call1(py_tuple);
    }
    // No named method: treat the object itself as callable. `.call1` is
    // itself an attribute lookup, so a non-callable object surfaces its
    // own error rather than a fabricated one.
    bound.call1(py_tuple)
}

/// Adapter from an `AnnotatorDispatcher` call to a Python object.
struct PyAnnotatorDispatcher {
    callback: Py<PyAny>,
}

impl AnnotatorDispatcher for PyAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &Value,
    ) -> Result<Value, RuntimeError> {
        Python::attach(|py| {
            let invocation = serde_json::to_value(annotator).map_err(|err| {
                RuntimeError::AnnotationFailed(format!(
                    "host annotator '{annotator_name}': failed to serialize invocation: {err}"
                ))
            })?;
            let invocation_py = json_to_py(py, &invocation)
                .map_err(|err| py_err_to_annotation_failure(annotator_name, err))?;
            let prelim_py = json_to_py(py, preliminary_policy_input)
                .map_err(|err| py_err_to_annotation_failure(annotator_name, err))?;
            let name_py = PyString::new(py, annotator_name).into_any();

            let result = call_py_method(
                py,
                &self.callback,
                "dispatch",
                vec![name_py, invocation_py, prelim_py],
            )
            .map_err(|err| py_err_to_annotation_failure(annotator_name, err))?;

            py_to_json(&result).map_err(|err| {
                RuntimeError::AnnotationFailed(format!(
                    "host annotator '{annotator_name}' returned a non-JSON value: {err}"
                ))
            })
        })
    }
}

/// Adapter from a `PolicyDispatcher` call to a Python object. Accepts an
/// object with `evaluate` (and optionally `warm`) or a plain callable.
struct PyPolicyDispatcher {
    callback: Py<PyAny>,
}

impl PolicyDispatcher for PyPolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<Value, RuntimeError> {
        Python::attach(|py| {
            let invocation_json = serde_json::to_value(invocation).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to serialize policy invocation for host dispatcher: {err}"
                ))
            })?;
            let invocation_py =
                json_to_py(py, &invocation_json).map_err(py_err_to_policy_failure)?;

            let result = call_py_method(py, &self.callback, "evaluate", vec![invocation_py])
                .map_err(py_err_to_policy_failure)?;

            py_to_json(&result).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "host policy dispatcher returned a non-JSON value: {err}"
                ))
            })
        })
    }

    fn warm(&self, invocation: &PreparedPolicyInvocation) -> Result<(), RuntimeError> {
        // `warm` is best-effort per the trait contract, and a host that
        // does not expose it is not obliged to. Skip silently rather than
        // charging every host with implementing an optimization hook.
        Python::attach(|py| {
            let bound = self.callback.bind(py);
            let func = match bound.getattr("warm") {
                Ok(func) => func,
                Err(_) => return Ok(()),
            };
            let invocation_json = serde_json::to_value(invocation).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to serialize policy invocation for host warm: {err}"
                ))
            })?;
            let invocation_py =
                json_to_py(py, &invocation_json).map_err(py_err_to_policy_failure)?;
            let args = pyo3::types::PyTuple::new(py, vec![invocation_py])
                .map_err(py_err_to_policy_failure)?;
            func.call1(args).map_err(py_err_to_policy_failure)?;
            Ok(())
        })
    }
}

/// Adapter from a `TelemetrySink` call to a Python object.
struct PyTelemetrySink {
    callback: Py<PyAny>,
}

impl PyTelemetrySink {
    fn event_to_py<'py>(
        &self,
        py: Python<'py>,
        event: &TelemetryEvent,
    ) -> PyResult<Bound<'py, PyAny>> {
        let dict = PyDict::new(py);
        dict.set_item("event_type", event.event_type.as_str())?;
        dict.set_item("intervention_point", event.intervention_point.as_str())?;
        dict.set_item("decision", event.decision.map(|d| d.as_str().to_string()))?;
        dict.set_item("reason_code", event.reason_code.clone())?;
        dict.set_item("error_class", event.error_class.clone())?;
        dict.set_item("policy_id", event.policy_id.clone())?;
        dict.set_item("annotators", event.annotators.clone())?;
        dict.set_item(
            "enforcement_mode",
            event.enforcement_mode.map(|m| match m {
                agent_control_spec::EnforcementMode::Enforce => "enforce".to_string(),
                agent_control_spec::EnforcementMode::EvaluateOnly => "evaluate_only".to_string(),
            }),
        )?;
        dict.set_item("duration_ms", event.duration_ms)?;
        dict.set_item("evidence_artefact", event.evidence_artefact.clone())?;
        dict.set_item(
            "evidence_verification_pointer_keys",
            event.evidence_verification_pointer_keys.clone(),
        )?;
        dict.set_item("action_identity", event.action_identity.clone())?;
        let metadata = PyDict::new(py);
        for (k, v) in &event.metadata {
            metadata.set_item(k, v)?;
        }
        dict.set_item("metadata", metadata)?;
        Ok(dict.into_any())
    }
}

impl TelemetrySink for PyTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // `emit` returns `()` in the trait, so a Python-side raise is
        // swallowed here after being converted to a printed exception:
        // telemetry is out-of-band by design and must not corrupt a
        // decision that already succeeded. The engine calls `emit` after
        // it has settled a verdict.
        Python::attach(|py| {
            let event_py = match self.event_to_py(py, &event) {
                Ok(value) => value,
                Err(err) => {
                    err.write_unraisable(py, Some(self.callback.bind(py).as_any()));
                    return;
                }
            };
            if let Err(err) = call_py_method(py, &self.callback, "emit", vec![event_py]) {
                err.write_unraisable(py, Some(self.callback.bind(py).as_any()));
            }
        });
    }

    fn shutdown(&self) {
        Python::attach(|py| {
            let bound = self.callback.bind(py);
            if let Ok(func) = bound.getattr("shutdown") {
                let args = pyo3::types::PyTuple::empty(py);
                if let Err(err) = func.call1(args) {
                    err.write_unraisable(py, Some(bound.as_any()));
                }
            }
        });
    }
}

fn parse_perf_telemetry(value: &str) -> PyResult<PerfTelemetry> {
    match value {
        "off" => Ok(PerfTelemetry::Off),
        "external" => Ok(PerfTelemetry::External),
        "full" => Ok(PerfTelemetry::Full),
        other => Err(PyValueError::new_err(format!(
            "unknown perf_telemetry level '{other}'; expected 'off', 'external', or 'full'"
        ))),
    }
}

fn resolve_annotator_dispatcher(dispatcher: Option<Py<PyAny>>) -> Arc<dyn AnnotatorDispatcher> {
    match dispatcher {
        Some(callback) => Arc::new(PyAnnotatorDispatcher { callback }),
        None => default_annotator_dispatcher(),
    }
}

fn resolve_policy_dispatcher(dispatcher: Option<Py<PyAny>>) -> Arc<dyn PolicyDispatcher> {
    match dispatcher {
        Some(callback) => Arc::new(PyPolicyDispatcher { callback }),
        None => Arc::new(BindingPolicyDispatcher::new()),
    }
}

fn resolve_telemetry_sink(sink: Option<Py<PyAny>>) -> Option<Arc<dyn TelemetrySink>> {
    sink.map(|callback| {
        let arc: Arc<dyn TelemetrySink> = Arc::new(PyTelemetrySink { callback });
        arc
    })
}

#[pyclass(frozen)]
struct RuntimeHandle {
    runtime: Runtime,
}

/// Build a runtime handle from a manifest path.
///
/// Passing no host arguments preserves the zero-config path: bundled
/// annotators, `BindingPolicyDispatcher` for Rego/Cedar/test policies,
/// no-op telemetry, `PerfTelemetry::Off`. Host-supplied callbacks and
/// a `perf_telemetry` other than "off" replace them.
#[pyfunction]
#[pyo3(signature = (
    manifest_path,
    annotator_dispatcher = None,
    policy_dispatcher = None,
    telemetry_sink = None,
    perf_telemetry = "off",
))]
fn interceptor_new(
    manifest_path: &str,
    annotator_dispatcher: Option<Py<PyAny>>,
    policy_dispatcher: Option<Py<PyAny>>,
    telemetry_sink: Option<Py<PyAny>>,
    perf_telemetry: &str,
) -> PyResult<RuntimeHandle> {
    let manifest =
        Manifest::from_path(manifest_path).map_err(|e| PyValueError::new_err(format!("{e}")))?;
    let annotations = resolve_annotator_dispatcher(annotator_dispatcher);
    let policy = resolve_policy_dispatcher(policy_dispatcher);
    let perf = parse_perf_telemetry(perf_telemetry)?;
    let telemetry = resolve_telemetry_sink(telemetry_sink);
    let runtime = match telemetry {
        Some(sink) => Runtime::with_telemetry_and_perf(manifest, annotations, policy, sink, perf)
            .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?,
        None => Runtime::with_perf_telemetry(manifest, annotations, policy, perf)
            .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?,
    };
    Ok(RuntimeHandle { runtime })
}

/// Evaluate one agent context (JSON object per AGENT-HOOKS-0.1 §4) and
/// return the verdict as wire JSON.
#[pyfunction]
fn intercept(handle: &RuntimeHandle, context_json: &str) -> PyResult<String> {
    let snapshot: Value = serde_json::from_str(context_json)
        .map_err(|e| PyValueError::new_err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(PyValueError::new_err("context_json must be a JSON object"));
    }
    let verdict = handle.runtime.evaluate(&snapshot).verdict;
    serde_json::to_string(&verdict)
        .map_err(|e| PyRuntimeError::new_err(format!("verdict serialization failed: {e}")))
}

// Fully qualified, so the type's `__module__` is importable. A bare
// `_native` makes the class unpicklable, which breaks marshalling the
// error across a process boundary.
create_exception!(
    agent_control_spec._native,
    ManifestInvalid,
    PyValueError,
    "The engine rejected a manifest."
);

/// Validate manifest source against the grammar, without building a
/// runtime.
///
/// Authoring and migration tools need this answer before a policy is
/// runnable, and building a runtime would additionally require the
/// bundled dispatchers and, for Rego, a loadable policy bundle. Fails
/// closed with the engine's own error text.
#[pyfunction]
fn validate_manifest(source: &str) -> PyResult<()> {
    // A dedicated type, so the wrapper never has to infer whether a
    // ValueError came from the grammar or from argument conversion.
    let manifest =
        Manifest::parse_yaml_str(source).map_err(|e| ManifestInvalid::new_err(format!("{e}")))?;
    if !manifest.extends.is_empty() {
        // `validate` checks references across the merged document, so
        // judging this fragment alone would reject it for something its
        // parent defines. That is not a verdict on the manifest, so it
        // must not surface as one.
        return Err(PyValueError::new_err(
            "manifest extends other manifests; validation needs the merged \
             document. Use validate_manifest_file, which resolves the chain.",
        ));
    }
    manifest
        .validate()
        .map_err(|e| ManifestInvalid::new_err(format!("{e}")))
}

/// Validate a manifest file, resolving `extends` first.
///
/// This is the entry point for a manifest that inherits, and it reads
/// from disk and may fetch URL `extends`, exactly as loading a runtime
/// would.
#[pyfunction]
fn validate_manifest_file(path: &str) -> PyResult<()> {
    Manifest::from_path(path).map(|_| ()).map_err(|e| match e {
        // Only a grammar rejection is a verdict on the document.
        // Everything else, including a breached resource limit and any
        // variant added later, is a boundary problem.
        RuntimeError::ManifestInvalid(detail) => ManifestInvalid::new_err(detail),
        other => PyValueError::new_err(format!("{other}")),
    })
}

/// The manifest grammar versions this engine accepts.
#[pyfunction]
fn supported_manifest_versions() -> Vec<String> {
    SUPPORTED_VERSIONS
        .iter()
        .map(|v| (*v).to_string())
        .collect()
}

/// Parse a single manifest source into a JSON string representation.
///
/// Returns the manifest as JSON so a Python wrapper `json.loads` it into a
/// `dict`. `parse_manifest` neither validates nor merges: an authoring
/// tool that needs to inspect a fragment (an `extends` child, for
/// example) can do so without dragging a policy engine on-path.
///
/// A malformed manifest raises `ManifestInvalid`, exactly as
/// `validate_manifest` does, so a caller does not have to distinguish
/// grammar failures by exception class.
#[pyfunction]
fn parse_manifest(source: &str) -> PyResult<String> {
    let manifest =
        Manifest::parse_yaml_str(source).map_err(|e| ManifestInvalid::new_err(format!("{e}")))?;
    serde_json::to_string(&manifest)
        .map_err(|e| PyRuntimeError::new_err(format!("manifest serialization failed: {e}")))
}

/// Compose an ordered chain of manifests into one merged JSON document.
///
/// Later entries overlay earlier ones under the same merge grammar that
/// `extends` uses on disk, and the result is validated before it is
/// returned: a chain that would fail as an on-disk `extends` fails here.
/// Each entry must be a fully-formed manifest fragment (no chain entry
/// may itself carry unresolved `extends`).
///
/// Empty chains and chains whose entries do not parse raise
/// `ManifestInvalid`.
#[pyfunction]
fn merge_manifests(sources: Vec<String>) -> PyResult<String> {
    let refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    let manifest = Manifest::from_yaml_chain(&refs).map_err(|e| match e {
        RuntimeError::ManifestInvalid(detail) => ManifestInvalid::new_err(detail),
        other => PyValueError::new_err(format!("{other}")),
    })?;
    serde_json::to_string(&manifest)
        .map_err(|e| PyRuntimeError::new_err(format!("merged manifest serialization failed: {e}")))
}

/// Field names an authoring tool wants surfaced verbatim. The engine's
/// validation error messages contain them, so a heuristic search picks
/// the first occurrence and returns it as the diagnostic's `field`.
const DIAGNOSTIC_FIELDS: &[&str] = &[
    "agent_control_specification_version",
    "policy_target_kind",
    "policy_target",
    "tool_name_from",
    "annotations",
    "annotators",
    "intervention_points",
    "intervention point",
    "extends",
    "policies",
    "policy.id",
    "approval",
    "metadata",
    "tools",
];

fn guess_field(message: &str) -> Option<String> {
    // Longest match first: `policy_target_kind` is a superstring of
    // `policy_target`, so ordering `DIAGNOSTIC_FIELDS` by length keeps
    // `policy_target` from swallowing a `policy_target_kind` message.
    let mut ordered: Vec<&&str> = DIAGNOSTIC_FIELDS.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.len()));
    for field in ordered {
        if message.contains(*field) {
            return Some((*field).to_string());
        }
    }
    None
}

/// Structured validation diagnostics as a JSON array string.
///
/// Returned entries have shape
/// `{"reason_code": str, "message": str, "field": str | null}`. The
/// engine's validation surface reports one failure at a time, so a
/// successful validation returns `[]` and every failed one returns a
/// single-entry list. Wrapping in a list leaves room for a batch
/// validation to grow into the same shape without a breaking rename.
///
/// A manifest that uses `extends` returns a single diagnostic pointing
/// the caller at file-based validation, matching `validate_manifest`.
#[pyfunction]
fn validate_manifest_diagnostics(source: &str) -> PyResult<String> {
    fn diagnostic(reason: &str, message: &str) -> Value {
        json!({
            "reason_code": reason,
            "message": message,
            "field": guess_field(message),
        })
    }
    let parsed = match Manifest::parse_yaml_str(source) {
        Ok(manifest) => manifest,
        Err(RuntimeError::ManifestInvalid(detail)) => {
            return serde_json::to_string(&json!([diagnostic(
                "runtime_error:manifest_invalid",
                &detail
            )]))
            .map_err(|e| {
                PyRuntimeError::new_err(format!("diagnostics serialization failed: {e}"))
            });
        }
        Err(other) => {
            return Err(PyValueError::new_err(format!("{other}")));
        }
    };
    if !parsed.extends.is_empty() {
        let msg = "manifest extends other manifests; validation needs the merged document. Use \
                   validate_manifest_file or merge_manifests, both of which resolve the chain.";
        return serde_json::to_string(&json!([diagnostic("runtime_error:manifest_invalid", msg)]))
            .map_err(|e| {
                PyRuntimeError::new_err(format!("diagnostics serialization failed: {e}"))
            });
    }
    match parsed.validate() {
        Ok(()) => Ok("[]".to_string()),
        Err(RuntimeError::ManifestInvalid(detail)) => serde_json::to_string(&json!([diagnostic(
            "runtime_error:manifest_invalid",
            &detail
        )]))
        .map_err(|e| PyRuntimeError::new_err(format!("diagnostics serialization failed: {e}"))),
        Err(other) => Err(PyValueError::new_err(format!("{other}"))),
    }
}

// ---------------------------------------------------------------------
// Activated policy: one policy version, readied once, evaluated many
// times.
//
// `interceptor_new`/`intercept` answer "evaluate this agent context
// against a manifest", and ready the policy lazily on the first call. A
// host that pins a policy version and serves traffic against it wants
// the opposite split: pay for reading and compiling the bundle once, at
// a moment of its choosing, then evaluate a named intervention point
// with nothing left to set up. These entry points are that split, and
// mirror `policyActivate`/`policyEvaluate` in the Node binding and
// `acs_policy_*` in the C ABI.
// ---------------------------------------------------------------------

#[pyclass(frozen)]
struct PolicyHandle {
    policy: ActivatedPolicy,
}

/// Activate the manifest at `manifest_path`, readying every policy it
/// binds.
///
/// Passing no host arguments preserves the zero-config activation.
/// Host-supplied dispatchers replace the bundled ones; they are used
/// for readying (via `PolicyDispatcher::warm`) as well as for every
/// later evaluation, so a policy compile pays its cost here and not on
/// the first decision.
///
/// Readying is bounded by the eval timeout. A policy too slow to ready
/// inside it activates anyway and pays that cost on its first
/// evaluation instead.
#[pyfunction]
#[pyo3(signature = (
    manifest_path,
    annotator_dispatcher = None,
    policy_dispatcher = None,
))]
fn policy_activate(
    py: Python<'_>,
    manifest_path: &str,
    annotator_dispatcher: Option<Py<PyAny>>,
    policy_dispatcher: Option<Py<PyAny>>,
) -> PyResult<PolicyHandle> {
    let manifest_path = manifest_path.to_string();
    let annotations = resolve_annotator_dispatcher(annotator_dispatcher);
    let policy = resolve_policy_dispatcher(policy_dispatcher);
    // Activation is the expensive call and touches no Python object, so
    // it must not hold the GIL: a host activating a new policy version
    // in a background thread would otherwise stall every request thread
    // for the whole bundle load and compile.
    let policy = py.detach(move || {
        let manifest = Manifest::from_path(&manifest_path)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        ActivatedPolicy::activate_with(manifest, annotations, policy)
            .map_err(|e| PyRuntimeError::new_err(format!("{e}")))
    })?;
    Ok(PolicyHandle { policy })
}

/// Activate a manifest and its Rego, both supplied as values rather
/// than read from disk.
///
/// `manifest_yaml` is the manifest text. `bundles_json` is a JSON
/// object mapping a policy id declared in it to that policy's modules
/// and data documents, replacing whatever `bundle` path the manifest
/// names. A host holding both in a database activates from them
/// directly, instead of staging a temporary directory per activation.
///
/// A Rego policy left naming a relative `bundle` or data path is rejected: a
/// manifest parsed from a string has no directory of its own, so the
/// path would resolve against the process working directory.
///
/// Passing host dispatchers replaces the bundled ones, exactly as in
/// [`policy_activate`].
#[pyfunction]
#[pyo3(signature = (
    manifest_yaml,
    bundles_json,
    annotator_dispatcher = None,
    policy_dispatcher = None,
))]
fn policy_activate_from_memory(
    py: Python<'_>,
    manifest_yaml: &str,
    bundles_json: &str,
    annotator_dispatcher: Option<Py<PyAny>>,
    policy_dispatcher: Option<Py<PyAny>>,
) -> PyResult<PolicyHandle> {
    let bundles: std::collections::BTreeMap<String, InMemoryRegoBundle> =
        serde_json::from_str(bundles_json)
            .map_err(|e| PyValueError::new_err(format!("bundles do not parse: {e}")))?;
    let manifest_yaml = manifest_yaml.to_string();
    let annotations = resolve_annotator_dispatcher(annotator_dispatcher);
    let policy = resolve_policy_dispatcher(policy_dispatcher);
    // Same reason as `policy_activate`: loading and compiling touches no
    // Python object and must not stall other threads.
    let policy = py.detach(move || {
        ActivatedPolicy::activate_from_memory_with(&manifest_yaml, bundles, annotations, policy)
            .map_err(|e| match e {
                RuntimeError::ManifestInvalid(detail) => ManifestInvalid::new_err(detail),
                other => PyRuntimeError::new_err(format!("{other}")),
            })
    })?;
    Ok(PolicyHandle { policy })
}

/// Evaluate one intervention point against an activated policy and
/// return the verdict as wire JSON.
///
/// `point` is an agent-hooks intervention point name, such as ``input``
/// or ``pre_tool_call``. `context_json` is the agent context object
/// (AGENT-HOOKS-0.1 §4).
///
/// A policy that does not bind `point` does not raise: it fails closed
/// with a ``runtime_error:*`` deny, exactly as every other evaluation
/// failure does. An unknown point name is a boundary problem and
/// raises.
#[pyfunction]
fn policy_evaluate(
    py: Python<'_>,
    handle: &PolicyHandle,
    point: &str,
    context_json: &str,
) -> PyResult<String> {
    let point: InterceptionPoint = point
        .parse()
        .map_err(|_| PyValueError::new_err(format!("unknown intervention point '{point}'")))?;
    let snapshot: Value = serde_json::from_str(context_json)
        .map_err(|e| PyValueError::new_err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(PyValueError::new_err("context_json must be a JSON object"));
    }
    // Evaluation is pure Rust over data already copied out of Python, so
    // the GIL is released for it. Without this, threads calling
    // `evaluate` would serialize on the interpreter even though the
    // engine itself is `Sync` and holds no Python state.
    let policy = handle.policy.clone();
    let verdict = py.detach(move || policy.evaluate(point, snapshot).verdict);
    serde_json::to_string(&verdict)
        .map_err(|e| PyRuntimeError::new_err(format!("verdict serialization failed: {e}")))
}

/// The intervention points this policy version binds, in manifest
/// order, as agent-hooks wire names.
#[pyfunction]
fn policy_intervention_points(handle: &PolicyHandle) -> Vec<String> {
    handle
        .policy
        .intervention_points()
        .iter()
        .map(|point| point.to_string())
        .collect()
}

// ---------------------------------------------------------------------
// Streaming session: host side accounting for the incremental stream
// profile in specification section 18.1.
//
// A `StreamSession` holds no policy, performs no evaluation, and stores
// no stream text. The host drives it: reports arrived text, declares
// spans, records what its policy decided for them, and asks which
// prefix it may release. Every function here is a thin projection over
// the engine's typed accounting. Enum wire names come from the engine's
// own `as_str`/`parse` methods, so the two cannot drift.
//
// State lives behind a `Mutex` because Python threads share the handle
// and every mutating method borrows exclusively. Reads take the same
// lock, which is what the engine's `&self` methods want anyway. The
// lock is uncontended in the common single-threaded flow, and its cost
// is negligible next to the JSON conversion of a settled reason.
// ---------------------------------------------------------------------

#[pyclass(frozen)]
struct StreamSessionHandle {
    inner: Mutex<StreamSession>,
}

// A poisoned `Mutex` means a previous mutating call panicked while
// holding the lock. Nothing in the engine's session accounting panics
// on well-formed input, so this cannot arise on a healthy contract.
// The wrapper still refuses to keep operating on a session in an
// unknown state: it lifts the poisoned guard and surfaces a runtime
// error rather than pretending the session is usable.
fn locked<T>(guard: std::sync::LockResult<T>) -> PyResult<T> {
    guard.map_err(|_| PyRuntimeError::new_err("streaming session mutex was poisoned"))
}

fn parse_track(value: &str) -> PyResult<StreamTrack> {
    match value {
        "request" => Ok(StreamTrack::Request),
        "response" => Ok(StreamTrack::Response),
        other => Err(PyValueError::new_err(format!(
            "unknown stream track '{other}'"
        ))),
    }
}

fn parse_outcome(value: &str) -> PyResult<SegmentOutcome> {
    match value {
        "cleared" => Ok(SegmentOutcome::Cleared),
        "transformed" => Ok(SegmentOutcome::Transformed),
        "denied" => Ok(SegmentOutcome::Denied),
        other => Err(PyValueError::new_err(format!(
            "unknown segment outcome '{other}'"
        ))),
    }
}

// A `StreamError` from the engine is always a boundary rejection: the
// host handed a value the contract does not admit, or asked for an
// operation the session cannot honor. `ValueError` is the same mapping
// the parse-side errors above receive, so the boundary reports one
// exception class regardless of which check caught it.
fn stream_err(error: StreamError) -> PyErr {
    PyValueError::new_err(format!("{error}"))
}

fn end_reason_to_json(reason: &StreamEndReason) -> Value {
    match reason {
        StreamEndReason::Complete => json!({ "kind": "complete" }),
        StreamEndReason::Denied { track, task, range } => json!({
            "kind": "denied",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Rewritten { track, task, range } => json!({
            "kind": "rewritten",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Failed(error) => json!({
            "kind": "failed",
            "reason": error.reason(),
            "message": format!("{error}"),
        }),
    }
}

fn json_string(value: &Value) -> PyResult<String> {
    serde_json::to_string(value)
        .map_err(|e| PyRuntimeError::new_err(format!("stream JSON serialization failed: {e}")))
}

/// Open a streaming session. Field meanings mirror
/// `StreamSessionConfig` in the engine.
#[pyfunction]
#[pyo3(signature = (
    safety_level,
    request_start_rune_offset,
    response_start_rune_offset,
    request_tasks,
    response_tasks,
))]
fn stream_session_new(
    safety_level: &str,
    request_start_rune_offset: u32,
    response_start_rune_offset: u32,
    request_tasks: Vec<String>,
    response_tasks: Vec<String>,
) -> PyResult<StreamSessionHandle> {
    let safety_level = SafetyLevel::parse(safety_level).map_err(stream_err)?;
    let config = StreamSessionConfig {
        safety_level,
        request_start_rune_offset,
        response_start_rune_offset,
        request_tasks,
        response_tasks,
    };
    let session = StreamSession::new(config).map_err(stream_err)?;
    Ok(StreamSessionHandle {
        inner: Mutex::new(session),
    })
}

/// Report that `runes` more runes arrived on this role's track. Returns
/// the track's new end offset.
#[pyfunction]
fn stream_observe(handle: &StreamSessionHandle, source_type: &str, runes: u32) -> PyResult<u32> {
    let source_type = StreamSourceType::parse(source_type).map_err(stream_err)?;
    let mut session = locked(handle.inner.lock())?;
    session.observe(source_type, runes).map_err(stream_err)
}

/// Report arriving text and let the engine count its runes, so a host
/// does not reach for a length that measures UTF-16 code units or bytes.
#[pyfunction]
fn stream_observe_text(
    handle: &StreamSessionHandle,
    source_type: &str,
    text: &str,
) -> PyResult<u32> {
    let source_type = StreamSourceType::parse(source_type).map_err(stream_err)?;
    let mut session = locked(handle.inner.lock())?;
    session.observe_text(source_type, text).map_err(stream_err)
}

/// Record what a host decided for one span under one task. The span is
/// built from `source_type` and the half-open rune range
/// `[start, end)`.
#[pyfunction]
fn stream_record_outcome(
    handle: &StreamSessionHandle,
    task: &str,
    source_type: &str,
    start: u32,
    end: u32,
    outcome: &str,
) -> PyResult<()> {
    let source_type = StreamSourceType::parse(source_type).map_err(stream_err)?;
    let outcome = parse_outcome(outcome)?;
    let span = StreamSpan::new(source_type, start, end).map_err(stream_err)?;
    let mut session = locked(handle.inner.lock())?;
    session
        .record_outcome(task, &span, outcome)
        .map_err(stream_err)
}

/// Record a wire-shaped agent-hooks verdict for one span under one
/// task. The verdict text is deserialized with the same grammar the
/// runtime uses, so a shape section 5 does not admit fails closed here
/// rather than clearing the span.
#[pyfunction]
fn stream_record_verdict(
    handle: &StreamSessionHandle,
    task: &str,
    source_type: &str,
    start: u32,
    end: u32,
    verdict_json: &str,
) -> PyResult<()> {
    let source_type = StreamSourceType::parse(source_type).map_err(stream_err)?;
    let span = StreamSpan::new(source_type, start, end).map_err(stream_err)?;
    let verdict: Verdict = serde_json::from_str(verdict_json)
        .map_err(|e| PyValueError::new_err(format!("verdict_json does not parse: {e}")))?;
    let mut session = locked(handle.inner.lock())?;
    session
        .record_verdict(task, &span, &verdict)
        .map_err(stream_err)
}

/// Recompute the watermark for `track` and return the new confirmed
/// offset when it advanced.
#[pyfunction]
fn stream_advance(handle: &StreamSessionHandle, track: &str) -> PyResult<Option<u32>> {
    let track = parse_track(track)?;
    let mut session = locked(handle.inner.lock())?;
    Ok(session.advance(track))
}

/// Offset through which the host may emit this track, or `None` once
/// the session has ended.
#[pyfunction]
fn stream_safe_offset(handle: &StreamSessionHandle, track: &str) -> PyResult<Option<u32>> {
    let track = parse_track(track)?;
    let session = locked(handle.inner.lock())?;
    Ok(session.safe_offset(track))
}

/// Runes observed but not yet cleared by every task on this track.
#[pyfunction]
fn stream_pending(handle: &StreamSessionHandle, track: &str) -> PyResult<u32> {
    let track = parse_track(track)?;
    let session = locked(handle.inner.lock())?;
    Ok(session.pending(track))
}

/// Watermark snapshot for one track, as wire JSON.
#[pyfunction]
fn stream_watermark(handle: &StreamSessionHandle, track: &str) -> PyResult<String> {
    let track_kind = parse_track(track)?;
    let session = locked(handle.inner.lock())?;
    let watermark = session.watermark(track_kind);
    let tasks: Vec<&str> = watermark.tasks().collect();
    let value = json!({
        "track": track_kind.as_str(),
        "confirmed": watermark.confirmed(),
        "received": watermark.received(),
        "pending": watermark.pending(),
        "tasks": tasks,
    });
    json_string(&value)
}

/// Stop accepting payloads while outcomes are still in flight. A
/// `Deferred` host calls this at payload EOF so a classifier running
/// behind the stream can still record a denial before `finish`.
#[pyfunction]
fn stream_end_of_payloads(handle: &StreamSessionHandle) -> PyResult<()> {
    let mut session = locked(handle.inner.lock())?;
    session.end_of_payloads();
    Ok(())
}

/// Settle the session and return the wire-JSON completion:
/// `{"reason": <end_reason>, "transformed": bool, "is_clean": bool}`.
#[pyfunction]
fn stream_finish(handle: &StreamSessionHandle) -> PyResult<String> {
    let mut session = locked(handle.inner.lock())?;
    let completion = session.finish();
    let value = json!({
        "reason": end_reason_to_json(&completion.reason),
        "transformed": completion.transformed,
        "is_clean": completion.reason.is_clean(),
    });
    json_string(&value)
}

/// Whether the session has reached its terminal state.
#[pyfunction]
fn stream_is_ended(handle: &StreamSessionHandle) -> PyResult<bool> {
    let session = locked(handle.inner.lock())?;
    Ok(session.is_ended())
}

/// Whether a `transformed` outcome ended this session, meaning the host
/// emits a substitute rather than verbatim model output.
#[pyfunction]
fn stream_transformed(handle: &StreamSessionHandle) -> PyResult<bool> {
    let session = locked(handle.inner.lock())?;
    Ok(session.transformed())
}

/// Terminal reason as wire JSON, or `None` when the session has not
/// ended.
#[pyfunction]
fn stream_end_reason(handle: &StreamSessionHandle) -> PyResult<Option<String>> {
    let session = locked(handle.inner.lock())?;
    match session.end_reason() {
        Some(reason) => json_string(&end_reason_to_json(reason)).map(Some),
        None => Ok(None),
    }
}

/// Streaming parameters this session was opened with, as wire JSON.
#[pyfunction]
fn stream_config(handle: &StreamSessionHandle) -> PyResult<String> {
    let session = locked(handle.inner.lock())?;
    let config = session.config();
    let value = json!({
        "safety_level": config.safety_level.as_str(),
        "request_start_rune_offset": config.request_start_rune_offset,
        "response_start_rune_offset": config.response_start_rune_offset,
        "request_tasks": config.request_tasks,
        "response_tasks": config.response_tasks,
    });
    json_string(&value)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RuntimeHandle>()?;
    m.add_function(wrap_pyfunction!(interceptor_new, m)?)?;
    m.add_function(wrap_pyfunction!(intercept, m)?)?;
    m.add_class::<PolicyHandle>()?;
    m.add_function(wrap_pyfunction!(policy_activate, m)?)?;
    m.add_function(wrap_pyfunction!(policy_activate_from_memory, m)?)?;
    m.add_function(wrap_pyfunction!(policy_evaluate, m)?)?;
    m.add_function(wrap_pyfunction!(policy_intervention_points, m)?)?;
    m.add_class::<StreamSessionHandle>()?;
    m.add_function(wrap_pyfunction!(stream_session_new, m)?)?;
    m.add_function(wrap_pyfunction!(stream_observe, m)?)?;
    m.add_function(wrap_pyfunction!(stream_observe_text, m)?)?;
    m.add_function(wrap_pyfunction!(stream_record_outcome, m)?)?;
    m.add_function(wrap_pyfunction!(stream_record_verdict, m)?)?;
    m.add_function(wrap_pyfunction!(stream_advance, m)?)?;
    m.add_function(wrap_pyfunction!(stream_safe_offset, m)?)?;
    m.add_function(wrap_pyfunction!(stream_pending, m)?)?;
    m.add_function(wrap_pyfunction!(stream_watermark, m)?)?;
    m.add_function(wrap_pyfunction!(stream_end_of_payloads, m)?)?;
    m.add_function(wrap_pyfunction!(stream_finish, m)?)?;
    m.add_function(wrap_pyfunction!(stream_is_ended, m)?)?;
    m.add_function(wrap_pyfunction!(stream_transformed, m)?)?;
    m.add_function(wrap_pyfunction!(stream_end_reason, m)?)?;
    m.add_function(wrap_pyfunction!(stream_config, m)?)?;
    m.add("ManifestInvalid", m.py().get_type::<ManifestInvalid>())?;
    m.add_function(wrap_pyfunction!(validate_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(validate_manifest_file, m)?)?;
    m.add_function(wrap_pyfunction!(validate_manifest_diagnostics, m)?)?;
    m.add_function(wrap_pyfunction!(parse_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(merge_manifests, m)?)?;
    m.add_function(wrap_pyfunction!(supported_manifest_versions, m)?)?;
    Ok(())
}
