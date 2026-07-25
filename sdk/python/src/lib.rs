// Python native binding over the Agent Control Specification runtime.
//
// Deliberately thin, mirroring the Node binding: construct a runtime
// from a manifest (zero-config dispatchers), evaluate one context,
// return the verdict as wire JSON. Evaluation failures never surface
// as Python exceptions — the runtime normalizes them into fail-closed
// `deny` verdicts with `runtime_error:*` reasons. Exceptions on this
// boundary mean a boundary problem only (unreadable manifest,
// non-object context JSON).

use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::{Manifest, Runtime};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde_json::Value;
use std::sync::Arc;

#[pyclass(frozen)]
struct RuntimeHandle {
    runtime: Runtime,
}

/// Build a runtime handle from a manifest path using the zero-config
/// dispatchers (bundled annotators; Rego through OPA, Cedar through the
/// built-in evaluator, `test` policies through their embedded verdict).
#[pyfunction]
fn interceptor_new(manifest_path: &str) -> PyResult<RuntimeHandle> {
    let manifest =
        Manifest::from_path(manifest_path).map_err(|e| PyValueError::new_err(format!("{e}")))?;
    let runtime = Runtime::new(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;
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

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RuntimeHandle>()?;
    m.add_function(wrap_pyfunction!(interceptor_new, m)?)?;
    m.add_function(wrap_pyfunction!(intercept, m)?)?;
    Ok(())
}
