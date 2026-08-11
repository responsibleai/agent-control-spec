// Node native binding over the Agent Control Specification runtime.
//
// The binding is deliberately thin: construct a runtime from a
// manifest (zero-config dispatchers), evaluate one context, return the
// verdict as wire JSON. Evaluation failures never surface as JS
// exceptions — the runtime normalizes them into fail-closed `deny`
// verdicts with `runtime_error:*` reasons. Exceptions on this boundary
// mean a boundary problem only (unreadable manifest, non-object
// context JSON).

use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::Verdict;
use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, Manifest, Runtime, RuntimeError,
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamError, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack, SUPPORTED_VERSIONS,
};
use napi::bindgen_prelude::{External, Utf16String};
use napi_derive::napi;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub struct Handle {
    runtime: Runtime,
}

/// Handle to one activated policy version.
///
/// Separate from [`Handle`] on purpose: an interceptor handle answers
/// "evaluate this agent context against a manifest" and readies the
/// policy lazily, while this one has already paid for reading and
/// compiling the bundle.
pub struct PolicyHandle {
    policy: ActivatedPolicy,
}

fn err(message: String) -> napi::Error {
    napi::Error::from_reason(message)
}

/// Decode a JS string without losing anything.
///
/// napi's `String` conversion goes through `napi_get_value_string_utf8`,
/// which silently replaces an unpaired surrogate with U+FFFD. That would
/// have the engine judge or evaluate content the caller never supplied,
/// and `binding.js` is published, so a consumer can reach these entry
/// points without the wrapper's guard. Taking UTF-16 code units and
/// converting here makes invalid encoding an explicit error on every
/// path into the engine, matching the C ABI.
///
/// UTF-16 rather than a byte array on purpose: a `Uint8Array` may be
/// backed by a `SharedArrayBuffer`, which another worker can mutate
/// while the engine reads it.
fn decode(what: &str, value: &Utf16String) -> napi::Result<String> {
    String::from_utf16(value).map_err(|_| err(format!("{what} contains an unpaired surrogate")))
}

/// Build a runtime handle from a manifest path using the zero-config
/// dispatchers (bundled annotators; Rego in process, Cedar through the
/// built-in evaluator, `test` policies through their embedded verdict).
#[napi]
pub fn interceptor_new(manifest_path: Utf16String) -> napi::Result<External<Handle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let runtime = Runtime::new(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(Handle { runtime }))
}

/// Evaluate one agent context (JSON object per AGENT-HOOKS-0.1 §4) and
/// return the verdict as wire JSON.
#[napi]
pub fn intercept(handle: &External<Handle>, context_json: Utf16String) -> napi::Result<String> {
    let context_json = decode("context_json", &context_json)?;
    let snapshot: Value = serde_json::from_str(&context_json)
        .map_err(|e| err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(err("context_json must be a JSON object".to_string()));
    }
    let verdict = handle.runtime.evaluate(&snapshot).verdict;
    serde_json::to_string(&verdict).map_err(|e| err(format!("verdict serialization failed: {e}")))
}

// ---------------------------------------------------------------------
// Activated policy: one policy version, readied once, evaluated many
// times.
//
// `interceptorNew`/`intercept` answer "evaluate this agent context
// against a manifest", and ready the policy lazily on the first call. A
// host that pins a policy version and serves traffic against it wants
// the opposite split: pay for reading and compiling the bundle once, at
// a moment of its choosing, then evaluate a named intervention point
// with nothing left to set up. These entry points are that split, and
// mirror `acs_policy_*` in the C ABI.
// ---------------------------------------------------------------------

/// Activate the manifest at `manifest_path`, readying every policy it
/// binds, against the zero-config dispatchers.
///
/// This is the expensive call: it reads the manifest, loads every Rego
/// module and data document, and compiles the entrypoint each
/// intervention point queries. Do it once per policy version and keep
/// the handle; `policyEvaluate` then costs no I/O and no compile.
///
/// Readying is bounded by the eval timeout. A policy too slow to ready
/// inside it activates anyway and pays that cost on its first
/// evaluation instead.
#[napi]
pub fn policy_activate(manifest_path: Utf16String) -> napi::Result<External<PolicyHandle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let policy = ActivatedPolicy::activate_with(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(PolicyHandle { policy }))
}

/// Activate a manifest and its Rego, both supplied as values rather
/// than read from disk.
///
/// `manifest_yaml` is the manifest text. `bundles_json` is a JSON
/// object mapping a policy id declared in that manifest to
/// `{"modules": {name: source}, "data": [{"mount": [..], "document":
/// {..}}]}`, replacing whatever `bundle` path the manifest names. A
/// service holding manifests and Rego in a database activates from them
/// directly rather than staging a temporary directory per activation.
///
/// Throws when the manifest does not parse, when a key of `bundles_json`
/// names a policy the manifest does not declare as Rego, and when a Rego
/// policy is left naming a relative `bundle` or data path: that path would
/// resolve against the process working directory, since a manifest
/// parsed from a string has no directory of its own. An absolute path is
/// left as written.
#[napi]
pub fn policy_activate_from_memory(
    manifest_yaml: Utf16String,
    bundles_json: Utf16String,
) -> napi::Result<External<PolicyHandle>> {
    let manifest_yaml = decode("manifest_yaml", &manifest_yaml)?;
    let bundles_json = decode("bundles_json", &bundles_json)?;
    let bundles: BTreeMap<String, InMemoryRegoBundle> = serde_json::from_str(&bundles_json)
        .map_err(|e| err(format!("bundles_json does not parse: {e}")))?;
    let policy = ActivatedPolicy::activate_from_memory_with(
        &manifest_yaml,
        bundles,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(PolicyHandle { policy }))
}

/// Evaluate one intervention point against an activated policy and
/// return the verdict as wire JSON.
///
/// `point` is an agent-hooks intervention point name, such as `input`
/// or `pre_tool_call`. `context_json` is the agent context object
/// (AGENT-HOOKS-0.1 §4).
///
/// A policy that does not bind `point` is not thrown at: it fails
/// closed with a `runtime_error:*` deny, exactly as every other
/// evaluation failure does. An unknown point name is a boundary problem
/// and throws.
#[napi]
pub fn policy_evaluate(
    handle: &External<PolicyHandle>,
    point: Utf16String,
    context_json: Utf16String,
) -> napi::Result<String> {
    let point_raw = decode("point", &point)?;
    let point: InterceptionPoint = point_raw
        .parse()
        .map_err(|_| err(format!("unknown intervention point '{point_raw}'")))?;
    let context_json = decode("context_json", &context_json)?;
    let snapshot: Value = serde_json::from_str(&context_json)
        .map_err(|e| err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(err("context_json must be a JSON object".to_string()));
    }
    let verdict = handle.policy.evaluate(point, snapshot).verdict;
    serde_json::to_string(&verdict).map_err(|e| err(format!("verdict serialization failed: {e}")))
}

/// The intervention points this policy version binds, in manifest
/// order, as agent-hooks wire names.
#[napi]
pub fn policy_intervention_points(handle: &External<PolicyHandle>) -> Vec<String> {
    handle
        .policy
        .intervention_points()
        .iter()
        .map(|point| point.to_string())
        .collect()
}

/// Validate manifest source against the grammar, without building a
/// runtime.
///
/// Authoring and migration tools need this answer before a policy is
/// runnable, and building a runtime would additionally require the
/// bundled dispatchers and, for Rego, a loadable policy bundle.
///
/// A rejected manifest comes back as `Some(message)` rather than being
/// thrown, so a thrown error from this function always means the call
/// itself failed and never that the manifest is bad. The wrapper relies
/// on that split so it does not relabel boundary failures as grammar
/// failures.
#[napi]
pub fn validate_manifest(source: Utf16String) -> napi::Result<Option<String>> {
    let source = decode("source", &source)?;
    let manifest = match Manifest::parse_yaml_str(&source) {
        Ok(m) => m,
        Err(e) => return Ok(Some(format!("{e}"))),
    };
    if !manifest.extends.is_empty() {
        // Validation checks references across the merged document, so
        // judging this fragment alone would reject it for something its
        // parent defines. Not a verdict, so it is thrown rather than
        // returned as a rejection.
        return Err(err(
            "manifest extends other manifests; validation needs the merged document. \
             Use validateManifestFile, which resolves the chain."
                .to_string(),
        ));
    }
    Ok(manifest.validate().err().map(|e| format!("{e}")))
}

/// Validate a manifest file, resolving `extends` first.
///
/// The entry point for a manifest that inherits. Reads from disk and may
/// fetch URL `extends`, exactly as loading a runtime would.
#[napi]
pub fn validate_manifest_file(path: Utf16String) -> napi::Result<Option<String>> {
    let path = decode("path", &path)?;
    match Manifest::from_path(&path) {
        Ok(_) => Ok(None),
        // Only a grammar rejection is returned as a rejection.
        // Everything else, including a breached resource limit and any
        // variant added later, is thrown as a boundary failure.
        Err(RuntimeError::ManifestInvalid(detail)) => Ok(Some(detail)),
        Err(other) => Err(err(format!("{other}"))),
    }
}

/// The manifest grammar versions this engine accepts.
#[napi]
pub fn supported_manifest_versions() -> Vec<String> {
    SUPPORTED_VERSIONS
        .iter()
        .map(|v| (*v).to_string())
        .collect()
}

// ---------------------------------------------------------------------
// Streaming: incremental release accounting for stream-shaped tracks
// (spec §18.1). A session holds no policy and no text; the host drives
// it: report arriving text, declare the spans its segmenter produced,
// evaluate those spans with the ordinary runtime, feed the outcomes
// back, and ask which prefix is safe to release. Mirrors
// `acs_stream_session_*` in the C ABI and the Python `StreamSession`.
// ---------------------------------------------------------------------

/// One live streaming session.
///
/// The session is `&mut` on every meaningful call, so the handle wraps
/// a `Mutex`. Napi may invoke bindings from any worker thread, and a
/// session is cheap to lock: no policy runs behind it.
pub struct StreamHandle {
    session: Mutex<StreamSession>,
}

fn parse_track_wire(raw: &str) -> napi::Result<StreamTrack> {
    match raw {
        "request" => Ok(StreamTrack::Request),
        "response" => Ok(StreamTrack::Response),
        other => Err(err(format!("unknown stream track '{other}'"))),
    }
}

fn parse_outcome_wire(raw: &str) -> napi::Result<SegmentOutcome> {
    match raw {
        "cleared" => Ok(SegmentOutcome::Cleared),
        "transformed" => Ok(SegmentOutcome::Transformed),
        "denied" => Ok(SegmentOutcome::Denied),
        other => Err(err(format!("unknown segment outcome '{other}'"))),
    }
}

fn parse_source_wire(raw: &str) -> napi::Result<StreamSourceType> {
    StreamSourceType::parse(raw).map_err(|e| err(format!("{e}")))
}

fn end_reason_json(reason: &StreamEndReason) -> Value {
    match reason {
        StreamEndReason::Complete => serde_json::json!({ "kind": "complete" }),
        StreamEndReason::Denied { track, task, range } => serde_json::json!({
            "kind": "denied",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Rewritten { track, task, range } => serde_json::json!({
            "kind": "rewritten",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Failed(error) => serde_json::json!({
            "kind": "failed",
            "reason": error.reason(),
            "message": error.to_string(),
        }),
    }
}

fn stream_err(e: StreamError) -> napi::Error {
    err(format!("{e}"))
}

fn read_offset(parsed: &Value, key: &str) -> napi::Result<u32> {
    match parsed.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| err(format!("{key} must be a rune offset within u32"))),
    }
}

fn read_tasks(parsed: &Value, key: &str) -> napi::Result<Vec<String>> {
    match parsed.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| err(format!("{key} must contain only task name strings")))
            })
            .collect(),
        Some(_) => Err(err(format!("{key} must be an array of task names"))),
    }
}

/// Open a session from a config JSON object.
///
/// Matches `acs_stream_session_new`: takes `safety_level` (`blocking`,
/// `complete` or `deferred`), the per-track start offsets
/// `request_start_rune_offset` and `response_start_rune_offset`, and
/// the task name arrays `request_tasks` and `response_tasks`. An empty
/// task array means that track is unmediated; payload on it fails
/// closed. A configuration mediating neither track is refused.
///
/// The wrapper takes a JSON string rather than a napi object so the
/// config surface is identical to the other language SDKs and offset
/// coercion happens in one place.
#[napi]
pub fn stream_session_new(config_json: Utf16String) -> napi::Result<External<StreamHandle>> {
    let config_json = decode("config_json", &config_json)?;
    let parsed: Value = serde_json::from_str(&config_json)
        .map_err(|e| err(format!("config_json does not parse: {e}")))?;
    if !parsed.is_object() {
        return Err(err("config_json must be a JSON object".to_string()));
    }
    let level_raw = parsed
        .get("safety_level")
        .and_then(Value::as_str)
        .unwrap_or("blocking");
    let safety_level = SafetyLevel::parse(level_raw).map_err(|e| err(format!("{e}")))?;
    let request_start_rune_offset = read_offset(&parsed, "request_start_rune_offset")?;
    let response_start_rune_offset = read_offset(&parsed, "response_start_rune_offset")?;
    let request_tasks = read_tasks(&parsed, "request_tasks")?;
    let response_tasks = read_tasks(&parsed, "response_tasks")?;
    let config = StreamSessionConfig {
        safety_level,
        request_start_rune_offset,
        response_start_rune_offset,
        request_tasks,
        response_tasks,
    };
    let session = StreamSession::new(config).map_err(stream_err)?;
    Ok(External::new(StreamHandle {
        session: Mutex::new(session),
    }))
}

fn lock<'a>(
    handle: &'a External<StreamHandle>,
) -> napi::Result<std::sync::MutexGuard<'a, StreamSession>> {
    handle
        .session
        .lock()
        .map_err(|_| err("stream session mutex was poisoned".to_string()))
}

/// Report that `runes` more runes of `source_type` arrived and return
/// the track's new end offset. Boundary failures throw; a streaming
/// accounting failure throws with the engine's message and puts the
/// session into its terminal state.
#[napi]
pub fn stream_session_observe(
    handle: &External<StreamHandle>,
    source_type: Utf16String,
    runes: u32,
) -> napi::Result<u32> {
    let raw = decode("source_type", &source_type)?;
    let source = parse_source_wire(&raw)?;
    let mut session = lock(handle)?;
    session.observe(source, runes).map_err(stream_err)
}

/// Report arriving `text` on `source_type`, counting Unicode scalars so
/// a host does not have to. Returns the track's new end offset.
///
/// The engine counts runes, not UTF-16 code units. `Utf16String` yields
/// UTF-16, so the binding decodes to a `String` before delegating to
/// the engine and rune counting stays consistent with every other SDK.
/// An astral-plane character is one rune here even though it is two
/// UTF-16 code units.
#[napi]
pub fn stream_session_observe_text(
    handle: &External<StreamHandle>,
    source_type: Utf16String,
    text: Utf16String,
) -> napi::Result<u32> {
    let source_raw = decode("source_type", &source_type)?;
    let source = parse_source_wire(&source_raw)?;
    let body = decode("text", &text)?;
    let mut session = lock(handle)?;
    session.observe_text(source, &body).map_err(stream_err)
}

/// Record what `task` decided about the span `[start, end)` of
/// `source_type`. `outcome` is `cleared`, `transformed` or `denied`.
#[napi]
pub fn stream_session_record_outcome(
    handle: &External<StreamHandle>,
    task: Utf16String,
    source_type: Utf16String,
    start: u32,
    end: u32,
    outcome: Utf16String,
) -> napi::Result<()> {
    let task = decode("task", &task)?;
    let source_raw = decode("source_type", &source_type)?;
    let source = parse_source_wire(&source_raw)?;
    let outcome_raw = decode("outcome", &outcome)?;
    let outcome = parse_outcome_wire(&outcome_raw)?;
    let span = StreamSpan::new(source, start, end).map_err(stream_err)?;
    let mut session = lock(handle)?;
    session
        .record_outcome(&task, &span, outcome)
        .map_err(stream_err)
}

/// Record an ACS verdict against the span `[start, end)` of
/// `source_type`, mapping its decision onto an outcome. A host feeds
/// the JSON returned by `policyEvaluate` straight back without
/// translating it.
#[napi]
pub fn stream_session_record_verdict(
    handle: &External<StreamHandle>,
    task: Utf16String,
    source_type: Utf16String,
    start: u32,
    end: u32,
    verdict_json: Utf16String,
) -> napi::Result<()> {
    let task = decode("task", &task)?;
    let source_raw = decode("source_type", &source_type)?;
    let source = parse_source_wire(&source_raw)?;
    let raw = decode("verdict_json", &verdict_json)?;
    let verdict: Verdict =
        serde_json::from_str(&raw).map_err(|e| err(format!("verdict_json does not parse: {e}")))?;
    let span = StreamSpan::new(source, start, end).map_err(stream_err)?;
    let mut session = lock(handle)?;
    session
        .record_verdict(&task, &span, &verdict)
        .map_err(stream_err)
}

/// Recompute `track`'s watermark. Returns the new offset when the
/// watermark advanced, `null` when it did not or the session has ended
/// (matching the Rust `Option<u32>`).
#[napi]
pub fn stream_session_advance(
    handle: &External<StreamHandle>,
    track: Utf16String,
) -> napi::Result<Option<u32>> {
    let raw = decode("track", &track)?;
    let track = parse_track_wire(&raw)?;
    let mut session = lock(handle)?;
    Ok(session.advance(track))
}

/// Offset of `track` the host may release through, or `null` once the
/// session has ended. A settled session has no safe offset, which is
/// not an error: it means release nothing further.
#[napi]
pub fn stream_session_safe_offset(
    handle: &External<StreamHandle>,
    track: Utf16String,
) -> napi::Result<Option<u32>> {
    let raw = decode("track", &track)?;
    let track = parse_track_wire(&raw)?;
    let session = lock(handle)?;
    Ok(session.safe_offset(track))
}

/// Runes on `track` observed but not yet released.
#[napi]
pub fn stream_session_pending(
    handle: &External<StreamHandle>,
    track: Utf16String,
) -> napi::Result<u32> {
    let raw = decode("track", &track)?;
    let track = parse_track_wire(&raw)?;
    let session = lock(handle)?;
    Ok(session.pending(track))
}

/// `track`'s watermark as JSON, carrying `track`, `confirmed`,
/// `received`, `pending` and the `tasks` that must clear it. The
/// confirmed offset stays readable after settlement, so an audit
/// record can still say how far the stream got.
#[napi]
pub fn stream_session_watermark(
    handle: &External<StreamHandle>,
    track: Utf16String,
) -> napi::Result<String> {
    let raw = decode("track", &track)?;
    let track = parse_track_wire(&raw)?;
    let session = lock(handle)?;
    let watermark = session.watermark(track);
    let payload = serde_json::json!({
        "track": track.as_str(),
        "confirmed": watermark.confirmed(),
        "received": watermark.received(),
        "pending": watermark.pending(),
        "tasks": watermark.tasks().collect::<Vec<_>>(),
    });
    serde_json::to_string(&payload).map_err(|e| err(format!("watermark serialization failed: {e}")))
}

/// Session state as JSON: `is_ended`, `transformed`, `end_reason`
/// (null while live) and the effective `config`.
#[napi]
pub fn stream_session_state(handle: &External<StreamHandle>) -> napi::Result<String> {
    let session = lock(handle)?;
    let config = session.config();
    let payload = serde_json::json!({
        "is_ended": session.is_ended(),
        "transformed": session.transformed(),
        "end_reason": session.end_reason().map(end_reason_json),
        "config": {
            "safety_level": config.safety_level.as_str(),
            "request_start_rune_offset": config.request_start_rune_offset,
            "response_start_rune_offset": config.response_start_rune_offset,
            "request_tasks": config.request_tasks,
            "response_tasks": config.response_tasks,
        },
    });
    serde_json::to_string(&payload).map_err(|e| err(format!("state serialization failed: {e}")))
}

/// Declare that no further payload will arrive. Idempotent.
#[napi]
pub fn stream_session_end_of_payloads(handle: &External<StreamHandle>) -> napi::Result<()> {
    let mut session = lock(handle)?;
    session.end_of_payloads();
    Ok(())
}

/// Settle the session and return the completion as JSON, carrying
/// `reason`, `transformed` and `is_clean`. Settling twice returns the
/// same completion.
#[napi]
pub fn stream_session_finish(handle: &External<StreamHandle>) -> napi::Result<String> {
    let mut session = lock(handle)?;
    let completion = session.finish();
    let payload = serde_json::json!({
        "reason": end_reason_json(&completion.reason),
        "transformed": completion.transformed,
        "is_clean": completion.reason.is_clean(),
    });
    serde_json::to_string(&payload)
        .map_err(|e| err(format!("completion serialization failed: {e}")))
}
