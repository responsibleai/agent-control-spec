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
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, Manifest, Runtime, RuntimeError,
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamError, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack, Verdict, SUPPORTED_VERSIONS,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

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
    SUPPORTED_VERSIONS
        .iter()
        .map(|v| (*v).to_string())
        .collect()
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
#[pyfunction]
fn policy_activate_from_memory(
    py: Python<'_>,
    manifest_yaml: &str,
    bundles_json: &str,
) -> PyResult<PolicyHandle> {
    let bundles: std::collections::BTreeMap<String, InMemoryRegoBundle> =
        serde_json::from_str(bundles_json)
            .map_err(|e| PyValueError::new_err(format!("bundles do not parse: {e}")))?;
    let manifest_yaml = manifest_yaml.to_string();
    // Same reason as `policy_activate`: loading and compiling touches no
    // Python object and must not stall other threads.
    let policy = py.detach(move || {
        ActivatedPolicy::activate_from_memory(&manifest_yaml, bundles).map_err(|e| match e {
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
    m.add_function(wrap_pyfunction!(supported_manifest_versions, m)?)?;
    Ok(())
}
