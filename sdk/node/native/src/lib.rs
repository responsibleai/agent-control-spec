// Node native binding over the Agent Control Specification runtime.
//
// The binding is deliberately thin: construct a runtime from a
// manifest (zero-config dispatchers), evaluate one context, return the
// verdict as wire JSON. Evaluation failures never surface as JS
// exceptions — the runtime normalizes them into fail-closed `deny`
// verdicts with `runtime_error:*` reasons. Exceptions on this boundary
// mean a boundary problem only (unreadable manifest, non-object
// context JSON).

use agent_control_spec::annotation::{AnnotatorDispatcher, AnnotatorInvocation};
use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::runtime::PolicyDispatcher;
use agent_control_spec::telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetrySink};
use agent_control_spec::Verdict;
use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, JsonValue, Manifest, PerfTelemetry,
    PreparedPolicyInvocation, Runtime, RuntimeError, SafetyLevel, SegmentOutcome, StreamEndReason,
    StreamError, StreamSession, StreamSessionConfig, StreamSourceType, StreamSpan, StreamTrack,
    SUPPORTED_VERSIONS,
};
use napi::bindgen_prelude::{External, FnArgs, FunctionRef, Utf16String};
use napi::Env;
use napi_derive::napi;
use serde_json::Value;
use std::cell::Cell;
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

// ---------------------------------------------------------------------
// Host dispatcher plumbing (annotator, policy, telemetry).
//
// The engine calls a dispatcher SYNCHRONOUSLY from inside its
// evaluation, on whichever thread called into it. Every napi entry
// point that drives evaluation (`intercept`, `policy_evaluate`) runs
// on the JS thread, so a callback fired inside the engine is on the
// same JS thread as the caller and can call the JS function directly
// through a `Function` handle. That handle is scope-bound, so we hold a
// `FunctionRef` (Send + Sync) and `borrow_back` it against the current
// napi `Env` when the engine asks. The env is stored in a thread-local
// set by each entry point for the duration of the call, so a dispatcher
// invoked from a different thread errors out rather than reaching into
// V8 off-thread.
//
// A ThreadsafeFunction would be wrong here: it dispatches ASYNCHRONOUSLY
// to the JS thread, which deadlocks when the JS thread is already
// blocked in the engine call that produced the callback.
// ---------------------------------------------------------------------

thread_local! {
    // Set only while a napi entry point that drives engine evaluation
    // is on the stack. A dispatcher invoked with no env available is
    // treated as a host failure so the engine fails closed.
    static CURRENT_ENV: Cell<napi::sys::napi_env> =
        const { Cell::new(std::ptr::null_mut()) };
}

/// RAII guard binding a napi `Env` to the current thread for the
/// duration of an engine call. Nesting is not expected (napi calls
/// don't reenter), but the guard is nesting-safe: it saves the previous
/// value and restores it on drop.
struct EnvScope {
    previous: napi::sys::napi_env,
}

impl EnvScope {
    fn enter(env: &Env) -> Self {
        let raw = env.raw();
        let previous = CURRENT_ENV.with(|c| c.replace(raw));
        Self { previous }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        let previous = self.previous;
        CURRENT_ENV.with(|c| c.set(previous));
    }
}

fn with_current_env<T>(
    what: &str,
    kind: fn(String) -> RuntimeError,
    f: impl FnOnce(&Env) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let raw = CURRENT_ENV.with(|c| c.get());
    if raw.is_null() {
        return Err(kind(format!(
            "host {what} was invoked without a live napi env; this dispatcher can only be \
             called from a napi entry point on the JS thread"
        )));
    }
    // SAFETY: `raw` was captured by `EnvScope::enter` from the napi
    // entry point currently on the stack, on this same JS thread.
    let env = Env::from_raw(raw);
    f(&env)
}

struct NodeAnnotatorDispatcher {
    func: FunctionRef<FnArgs<(String, String, String)>, String>,
}

impl AnnotatorDispatcher for NodeAnnotatorDispatcher {
    fn dispatch(
        &self,
        annotator_name: &str,
        annotator: &AnnotatorInvocation,
        preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        let invocation_json = serde_json::to_string(annotator).map_err(|e| {
            RuntimeError::AnnotationFailed(format!("serialize annotator invocation: {e}"))
        })?;
        let policy_input_json = serde_json::to_string(preliminary_policy_input).map_err(|e| {
            RuntimeError::AnnotationFailed(format!("serialize preliminary policy input: {e}"))
        })?;
        with_current_env(
            "annotator dispatcher",
            RuntimeError::AnnotationFailed,
            |env| {
                let func = self.func.borrow_back(env).map_err(|e| {
                    RuntimeError::AnnotationFailed(format!("reacquire annotator function: {e}"))
                })?;
                let raw = func
                    .call(FnArgs {
                        data: (
                            annotator_name.to_string(),
                            invocation_json,
                            policy_input_json,
                        ),
                    })
                    .map_err(|e| {
                        RuntimeError::AnnotationFailed(format!(
                            "host annotator dispatcher threw: {e}"
                        ))
                    })?;
                serde_json::from_str::<JsonValue>(&raw).map_err(|e| {
                    RuntimeError::AnnotationFailed(format!(
                        "host annotator dispatcher returned non-JSON: {e}"
                    ))
                })
            },
        )
    }
}

struct NodePolicyDispatcher {
    func: FunctionRef<FnArgs<(String,)>, String>,
}

impl PolicyDispatcher for NodePolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let invocation_json = serde_json::to_string(invocation).map_err(|e| {
            RuntimeError::PolicyInvocationFailed(format!("serialize policy invocation: {e}"))
        })?;
        with_current_env(
            "policy dispatcher",
            RuntimeError::PolicyInvocationFailed,
            |env| {
                let func = self.func.borrow_back(env).map_err(|e| {
                    RuntimeError::PolicyInvocationFailed(format!("reacquire policy function: {e}"))
                })?;
                let raw = func
                    .call(FnArgs {
                        data: (invocation_json,),
                    })
                    .map_err(|e| {
                        RuntimeError::PolicyInvocationFailed(format!(
                            "host policy dispatcher threw: {e}"
                        ))
                    })?;
                serde_json::from_str::<JsonValue>(&raw).map_err(|e| {
                    RuntimeError::PolicyInvocationFailed(format!(
                        "host policy dispatcher returned non-JSON: {e}"
                    ))
                })
            },
        )
    }
}

struct NodeTelemetrySink {
    func: FunctionRef<FnArgs<(String,)>, ()>,
}

impl TelemetrySink for NodeTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // TelemetryEvent is not Serialize, so the wire shape is owned
        // here (matches the FFI binding). A sink cannot fail an
        // evaluation, so every step drops on error rather than
        // propagating.
        let payload = serde_json::json!({
            "event_type": event.event_type.as_str(),
            "intervention_point": event.intervention_point.as_str(),
            "decision": event.decision.map(|d| format!("{d:?}").to_lowercase()),
            "reason_code": event.reason_code,
            "error_class": event.error_class,
            "policy_id": event.policy_id,
            "annotators": event.annotators,
            "enforcement_mode": event
                .enforcement_mode
                .map(|m| format!("{m:?}").to_lowercase()),
            "duration_ms": event.duration_ms,
            "evidence_artefact": event.evidence_artefact,
            "evidence_verification_pointer_keys": event.evidence_verification_pointer_keys,
            "action_identity": event.action_identity,
            "metadata": event.metadata,
        });
        let Ok(json) = serde_json::to_string(&payload) else {
            return;
        };
        let raw = CURRENT_ENV.with(|c| c.get());
        if raw.is_null() {
            return;
        }
        // SAFETY: same as `with_current_env`; the sink is called from
        // engine code that is itself running inside a napi entry point.
        let env = Env::from_raw(raw);
        let Ok(func) = self.func.borrow_back(&env) else {
            return;
        };
        let _: napi::Result<()> = func.call(FnArgs { data: (json,) });
    }
}

fn parse_perf(value: Option<Utf16String>) -> napi::Result<PerfTelemetry> {
    let Some(value) = value else {
        return Ok(PerfTelemetry::Off);
    };
    let raw = decode("perfTelemetry", &value)?;
    match raw.as_str() {
        "off" => Ok(PerfTelemetry::Off),
        "external" => Ok(PerfTelemetry::External),
        "full" => Ok(PerfTelemetry::Full),
        other => Err(err(format!("unknown perf telemetry level '{other}'"))),
    }
}

// Type aliases for the FunctionRef signatures the JS↔Rust wire uses.
// Kept private so they never leak into the TS declaration; napi-derive
// still sees the expanded types on the entry points that take them as
// arguments (aliases are not expanded through the `#[napi]` macro).
type NodeAnnotatorFn = FunctionRef<FnArgs<(String, String, String)>, String>;
type NodePolicyFn = FunctionRef<FnArgs<(String,)>, String>;
type NodeTelemetryFn = FunctionRef<FnArgs<(String,)>, ()>;

fn build_annotator(dispatcher: Option<NodeAnnotatorFn>) -> Arc<dyn AnnotatorDispatcher> {
    match dispatcher {
        Some(func) => Arc::new(NodeAnnotatorDispatcher { func }),
        None => default_annotator_dispatcher(),
    }
}

fn build_policy(dispatcher: Option<NodePolicyFn>) -> Arc<dyn PolicyDispatcher> {
    match dispatcher {
        Some(func) => Arc::new(NodePolicyDispatcher { func }),
        None => Arc::new(BindingPolicyDispatcher::new()),
    }
}

fn build_telemetry(sink: Option<NodeTelemetryFn>) -> Arc<dyn TelemetrySink> {
    match sink {
        Some(func) => Arc::new(NodeTelemetrySink { func }),
        None => Arc::new(NoopTelemetrySink),
    }
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

/// Build a runtime handle from a manifest path, optionally overriding
/// the annotator dispatcher, policy dispatcher, telemetry sink, and
/// perf telemetry level.
///
/// Every callback is optional: absent means keep the zero-config
/// default for that slot. Callbacks cross the boundary as JSON strings,
/// mirroring the FFI hook contract, so a host that already sits behind
/// a JSON schema does not re-model its wire shape for this SDK.
///
/// Callbacks are called SYNCHRONOUSLY on the JS thread from inside the
/// engine's evaluation. A callback that throws surfaces as a fail-closed
/// `runtime_error:*` deny (annotator → `annotation_failed`, policy →
/// `policy_invocation_failed`) rather than silently reading as "no
/// annotation".
#[napi]
#[allow(clippy::type_complexity)]
pub fn interceptor_new_with_hooks(
    manifest_path: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, String>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, String>>,
    telemetry_sink: Option<FunctionRef<FnArgs<(String,)>, ()>>,
    perf_telemetry: Option<Utf16String>,
) -> napi::Result<External<Handle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let perf = parse_perf(perf_telemetry)?;
    let annotations = build_annotator(annotator_dispatcher);
    let policy = build_policy(policy_dispatcher);
    let telemetry = build_telemetry(telemetry_sink);
    let runtime = Runtime::with_telemetry_and_perf(manifest, annotations, policy, telemetry, perf)
        .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(Handle { runtime }))
}

/// Evaluate one agent context (JSON object per AGENT-HOOKS-0.1 §4) and
/// return the verdict as wire JSON.
#[napi]
pub fn intercept(
    env: Env,
    handle: &External<Handle>,
    context_json: Utf16String,
) -> napi::Result<String> {
    let context_json = decode("context_json", &context_json)?;
    let snapshot: Value = serde_json::from_str(&context_json)
        .map_err(|e| err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(err("context_json must be a JSON object".to_string()));
    }
    // The engine may call a host dispatcher synchronously from inside
    // `evaluate`; the scope publishes the current napi env for that
    // callback and is torn down before we return.
    let _scope = EnvScope::enter(&env);
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

/// Activate the manifest at `manifest_path` against host-supplied
/// dispatchers. See `interceptor_new_with_hooks` for the callback
/// contract.
#[napi]
#[allow(clippy::type_complexity)]
pub fn policy_activate_with_hooks(
    manifest_path: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, String>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, String>>,
) -> napi::Result<External<PolicyHandle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let annotations = build_annotator(annotator_dispatcher);
    let policy = build_policy(policy_dispatcher);
    let handle = ActivatedPolicy::activate_with(manifest, annotations, policy)
        .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(PolicyHandle { policy: handle }))
}

/// Activate a manifest and its Rego from memory against host-supplied
/// dispatchers.
#[napi]
#[allow(clippy::type_complexity)]
pub fn policy_activate_from_memory_with_hooks(
    manifest_yaml: Utf16String,
    bundles_json: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, String>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, String>>,
) -> napi::Result<External<PolicyHandle>> {
    let manifest_yaml = decode("manifest_yaml", &manifest_yaml)?;
    let bundles_json = decode("bundles_json", &bundles_json)?;
    let bundles: BTreeMap<String, InMemoryRegoBundle> = serde_json::from_str(&bundles_json)
        .map_err(|e| err(format!("bundles_json does not parse: {e}")))?;
    let annotations = build_annotator(annotator_dispatcher);
    let policy = build_policy(policy_dispatcher);
    let handle =
        ActivatedPolicy::activate_from_memory_with(&manifest_yaml, bundles, annotations, policy)
            .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(PolicyHandle { policy: handle }))
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
    env: Env,
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
    let _scope = EnvScope::enter(&env);
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
// Manifest tooling: parse, chain, structured diagnostics.
//
// The engine ships these as first-party APIs on `Manifest`; the wrapper
// exposes them here so authoring, migration, and CI tooling can build
// on the same surface across languages. Every entry point takes YAML
// text, so a caller can drive them without staging a file on disk.
// ---------------------------------------------------------------------

/// Parse manifest YAML into an object (JSON encoded) without
/// validating cross-references.
///
/// The document is deserialized as-written: a manifest with an
/// unresolved `extends` chain parses fine, and returning it lets an
/// authoring tool see the fragment. Use `validate_manifest` or
/// `validate_manifest_detailed` to judge whether the fragment is
/// runnable.
#[napi]
pub fn parse_manifest(source: Utf16String) -> napi::Result<String> {
    let source = decode("source", &source)?;
    let manifest = Manifest::parse_yaml_str(&source).map_err(|e| err(format!("{e}")))?;
    serde_json::to_string(&manifest).map_err(|e| err(format!("manifest serialization failed: {e}")))
}

/// Compose a chain of manifest YAML documents (outermost base first)
/// into one merged manifest, returned as JSON.
///
/// This is the overlay case: a base policy plus deltas an environment
/// layers on it, resolved the same way the engine resolves `extends`.
#[napi]
pub fn merge_manifests(sources_json: Utf16String) -> napi::Result<String> {
    let raw = decode("sources_json", &sources_json)?;
    let sources: Vec<String> = serde_json::from_str(&raw).map_err(|e| {
        err(format!(
            "sources_json must be a JSON array of manifest sources: {e}"
        ))
    })?;
    if sources.is_empty() {
        return Err(err("sources_json must name at least one source".to_string()));
    }
    let borrowed: Vec<&str> = sources.iter().map(String::as_str).collect();
    let manifest = Manifest::from_yaml_chain(&borrowed).map_err(|e| err(format!("{e}")))?;
    serde_json::to_string(&manifest).map_err(|e| err(format!("manifest serialization failed: {e}")))
}

/// Validate manifest source and return findings as a JSON array.
///
/// An empty array means the manifest is valid. Each entry carries
/// `code` (`runtime_error:*`), `message` (engine detail), `severity`,
/// and a best-effort `field` extracted from the message. This is the
/// shape an authoring tool or CI linter needs; `validate_manifest`
/// answers yes/no with a single message and cannot be rendered
/// per-field.
#[napi]
pub fn validate_manifest_detailed(source: Utf16String) -> napi::Result<String> {
    let source = decode("source", &source)?;
    let findings = match Manifest::parse_yaml_str(&source) {
        Ok(manifest) => {
            if !manifest.extends.is_empty() {
                // A fragment cannot be judged against itself: its
                // parent may define the annotator or policy this
                // document references. Report that as a single
                // finding rather than silently blaming references
                // the fragment does not own.
                vec![diagnostic_json(&RuntimeError::ManifestInvalid(
                    "manifest extends other manifests; validation needs the merged document. \
                     Use validate_manifest_file, which resolves the chain."
                        .to_string(),
                ))]
            } else {
                match manifest.validate() {
                    Ok(()) => Vec::new(),
                    Err(e) => vec![diagnostic_json(&e)],
                }
            }
        }
        Err(e) => vec![diagnostic_json(&e)],
    };
    serde_json::to_string(&findings)
        .map_err(|e| err(format!("diagnostics serialization failed: {e}")))
}

fn diagnostic_json(error: &RuntimeError) -> Value {
    let detail = error.detail();
    let field = extract_field(detail);
    serde_json::json!({
        "code": error.reason(),
        "message": detail,
        "severity": "error",
        "field": field,
    })
}

/// Wire shape for artifact diagnostics: `code`, `message`, `severity`.
///
/// Mirrors the C ABI's `acs_artifact_diagnostics` byte-for-byte.
/// Unlike [`diagnostic_json`] this omits the best-effort `field`
/// pointer: `validate_artifacts_detailed` surfaces activation-half
/// failures whose message is the Rego compiler's own diagnostic, not
/// a manifest field, and inventing a field for it would mislead a
/// tool trying to render the pointer inline.
fn artifact_diagnostic_json(error: &RuntimeError) -> Value {
    serde_json::json!({
        "code": error.reason(),
        "message": error.detail(),
        "severity": "error",
    })
}

/// Validate a manifest together with the Rego it names, and return
/// findings as a JSON array.
///
/// An empty array means both halves are sound. Each entry has wire
/// shape `{"code": str, "message": str, "severity": "error"}`, matching
/// the C ABI's `acs_artifact_diagnostics`.
///
/// `validate_manifest_detailed` answers only for the document: a
/// manifest can name a bundle, satisfy the grammar, and still fail at
/// activation because the Rego does not compile. Compilation happens
/// at activation, so this activates against the supplied bundles in
/// memory and reports what that surfaced, which moves the failure from
/// a host's first agent action to its CI.
///
/// `bundles_json` maps policy id to an in-memory bundle, the same
/// shape `policy_activate_from_memory` takes. An empty document means
/// the manifest names no Rego, and the answer then equals what
/// `validate_manifest_detailed` reports for the manifest half.
#[napi]
pub fn validate_artifacts_detailed(
    manifest_yaml: Utf16String,
    bundles_json: Utf16String,
) -> napi::Result<String> {
    let manifest_yaml = decode("manifest_yaml", &manifest_yaml)?;
    let bundles_json = decode("bundles_json", &bundles_json)?;
    let bundles: BTreeMap<String, InMemoryRegoBundle> = if bundles_json.trim().is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_str(&bundles_json)
            .map_err(|e| err(format!("bundles_json does not parse: {e}")))?
    };
    // Mirror the C ABI's ordering exactly: parse first, validate
    // second, activate third. Each step's failure short-circuits so a
    // manifest that does not parse is never reported as an activation
    // failure — that would name the wrong half.
    let findings = match Manifest::from_yaml_str(&manifest_yaml) {
        Err(e) => vec![artifact_diagnostic_json(&e)],
        Ok(manifest) => match manifest.validate() {
            Err(e) => vec![artifact_diagnostic_json(&e)],
            Ok(()) => match ActivatedPolicy::activate_from_memory(&manifest_yaml, bundles) {
                Ok(_) => Vec::new(),
                Err(e) => vec![artifact_diagnostic_json(&e)],
            },
        },
    };
    serde_json::to_string(&findings)
        .map_err(|e| err(format!("diagnostics serialization failed: {e}")))
}

/// Best-effort extraction of the offending field name from a
/// RuntimeError detail. Returns `None` when the message does not name a
/// field the caller can point at, so the wrapper reports the raw
/// message and the field slot stays absent (not empty).
fn extract_field(detail: &str) -> Option<String> {
    // serde_yaml: "missing field `X` at line ..." or
    //             "unknown field `X`, expected ..."
    if let Some(start) = detail.find("field `") {
        let after = &detail[start + "field `".len()..];
        if let Some(end) = after.find('`') {
            let name = after[..end].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    // Engine: "unsupported agent_control_specification_version '...'"
    if let Some(rest) = detail.strip_prefix("unsupported ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    // Engine: "X is required"
    if let Some((head, _)) = detail.split_once(" is required") {
        let name = head.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    None
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
