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
use agent_control_spec::{Manifest, RuntimeError, Runtime, SUPPORTED_VERSIONS};
use pyo3::create_exception;
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
    SUPPORTED_VERSIONS.iter().map(|v| (*v).to_string()).collect()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RuntimeHandle>()?;
    m.add_function(wrap_pyfunction!(interceptor_new, m)?)?;
    m.add_function(wrap_pyfunction!(intercept, m)?)?;
    m.add("ManifestInvalid", m.py().get_type::<ManifestInvalid>())?;
    m.add_function(wrap_pyfunction!(validate_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(validate_manifest_file, m)?)?;
    m.add_function(wrap_pyfunction!(supported_manifest_versions, m)?)?;
    Ok(())
}
