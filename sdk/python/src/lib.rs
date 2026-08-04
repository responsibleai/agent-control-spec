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
use agent_control_spec::{
    ActivatedPolicy, InterceptionPoint, Manifest, Runtime, RuntimeError, SUPPORTED_VERSIONS,
};
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
/// dispatchers (bundled annotators; Rego in process, Cedar through the
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
/// binds, against the zero-config dispatchers.
///
/// This is the expensive call: it reads the manifest, loads every Rego
/// module and data document, and compiles the entrypoint each
/// intervention point queries. Do it once per policy version and keep
/// the handle; `policy_evaluate` then costs no I/O and no compile.
///
/// Readying is bounded by the eval timeout. A policy too slow to ready
/// inside it activates anyway and pays that cost on its first
/// evaluation instead.
#[pyfunction]
fn policy_activate(py: Python<'_>, manifest_path: &str) -> PyResult<PolicyHandle> {
    let manifest_path = manifest_path.to_string();
    // Activation is the expensive call and touches no Python object, so
    // it must not hold the GIL: a host activating a new policy version
    // in a background thread would otherwise stall every request thread
    // for the whole bundle load and compile.
    let policy = py.detach(move || {
        let manifest = Manifest::from_path(&manifest_path)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        ActivatedPolicy::activate_with(
            manifest,
            default_annotator_dispatcher(),
            Arc::new(BindingPolicyDispatcher::new()),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("{e}")))
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

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RuntimeHandle>()?;
    m.add_function(wrap_pyfunction!(interceptor_new, m)?)?;
    m.add_function(wrap_pyfunction!(intercept, m)?)?;
    m.add_class::<PolicyHandle>()?;
    m.add_function(wrap_pyfunction!(policy_activate, m)?)?;
    m.add_function(wrap_pyfunction!(policy_evaluate, m)?)?;
    m.add_function(wrap_pyfunction!(policy_intervention_points, m)?)?;
    m.add("ManifestInvalid", m.py().get_type::<ManifestInvalid>())?;
    m.add_function(wrap_pyfunction!(validate_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(validate_manifest_file, m)?)?;
    m.add_function(wrap_pyfunction!(supported_manifest_versions, m)?)?;
    Ok(())
}
