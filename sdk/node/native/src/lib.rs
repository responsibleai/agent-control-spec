// Copyright (c) Microsoft. All rights reserved.

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
use agent_control_spec::dispatchers::{
    default_annotator_dispatcher, default_annotator_dispatcher_with_limits, BindingPolicyDispatcher,
};
use agent_control_spec::runtime::PolicyDispatcher;
use agent_control_spec::telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetrySink};
use agent_control_spec::wire;
use agent_control_spec::Verdict;
use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, JsonValue, Limits, Manifest,
    PreparedPolicyInvocation, Runtime, RuntimeError, SegmentOutcome, StreamError, StreamSession,
    StreamSourceType, StreamSpan, StreamTrack, SUPPORTED_VERSIONS,
};
use napi::bindgen_prelude::{
    CallbackContext, External, FnArgs, FunctionRef, JsValuesTupleIntoVec, Null, Object, PromiseRaw,
    Unknown, Utf16String,
};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, JsValue, Status};
use napi_derive::napi;
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::{mpsc, Arc, Mutex};

/// Handle to one runtime.
///
/// The runtime is shared, not owned: every `intercept_async` call clones
/// the `Arc` into its task, so an evaluation still running on a worker
/// keeps the engine alive after JS has dropped the handle.
pub struct Handle {
    runtime: Arc<Runtime>,
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
// The engine calls a dispatcher synchronously from inside its
// evaluation, on whichever thread runs the evaluation. On the JS
// thread (`intercept`, `policy_evaluate`) the entry point publishes its
// napi `Env` in a thread-local and the dispatcher calls the JS function
// directly; a ThreadsafeFunction cannot serve that path, since it
// queues the call for the JS thread, which is blocked inside the
// engine. On an evaluation thread (`intercept_async`) no env exists, so
// the dispatcher posts the call through a ThreadsafeFunction and blocks
// on a channel until the JS thread, which is free, answers. One
// dispatcher serves both entry points; the published env decides.
// ---------------------------------------------------------------------

thread_local! {
    // Set only while a napi entry point that drives engine evaluation
    // on the JS thread is on the stack. Null on an evaluation thread,
    // which sends a host function call through its threadsafe path.
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

/// What a host function answered: the UTF-16 code units of its string
/// result, or the text of the failure. The surrogate check and the JSON
/// parse stay with the dispatcher that knows which `runtime_error:*`
/// kind the failure maps to.
type HostAnswer = Result<Utf16String, String>;

/// A host JS function the engine can reach from either thread it runs on.
struct HostFunction<Args: JsValuesTupleIntoVec + 'static> {
    /// Borrowed back against the published env on the JS thread.
    direct: FunctionRef<Args, Unknown<'static>>,
    /// Posted to the JS thread from an evaluation thread. Weak, so
    /// holding a handle does not keep the Node process alive; the
    /// pending promise already keeps the loop alive while an evaluation
    /// is in flight.
    threadsafe: ThreadsafeFunction<Args, Unknown<'static>, Args, Status, false, true>,
    /// The JS thread, recorded at construction. A call that reaches this
    /// function on that thread with no env published cannot be posted:
    /// the thread would wait on itself. It fails closed instead.
    js_thread: std::thread::ThreadId,
}

impl<Args: JsValuesTupleIntoVec + 'static> HostFunction<Args> {
    fn new(env: &Env, direct: FunctionRef<Args, Unknown<'static>>) -> napi::Result<Self> {
        let threadsafe = direct
            .borrow_back(env)?
            .build_threadsafe_function::<Args>()
            .weak::<true>()
            .build()?;
        Ok(Self {
            direct,
            threadsafe,
            js_thread: std::thread::current().id(),
        })
    }

    /// Call the function with `args` and wait for its string result.
    /// `what` names the function in failure text.
    fn call(&self, what: &str, args: Args) -> HostAnswer {
        let raw = CURRENT_ENV.with(|c| c.get());
        if raw.is_null() {
            if std::thread::current().id() == self.js_thread {
                return Err(format!(
                    "host {what} was reached on the JS thread outside an evaluation entry point"
                ));
            }
            return self.call_from_worker(what, args);
        }
        // SAFETY: `raw` was captured by `EnvScope::enter` from the napi
        // entry point currently on the stack, on this same JS thread.
        let env = Env::from_raw(raw);
        self.call_on_js_thread(what, &env, args)
    }

    fn call_on_js_thread(&self, what: &str, env: &Env, args: Args) -> HostAnswer {
        let func = self
            .direct
            .borrow_back(env)
            .map_err(|e| format!("reacquire host {what}: {e}"))?;
        let value = func
            .call(args)
            .map_err(|e| format!("host {what} threw: {e}"))?;
        // The JS thread is inside the engine call; nothing could run a
        // Promise's continuation before the engine needs the answer.
        if value
            .is_promise()
            .map_err(|e| format!("host {what} result: {e}"))?
        {
            return Err(format!(
                "host {what} returned a Promise on the synchronous path; an async dispatcher \
                 needs intercept(), not interceptSync() or evaluate()"
            ));
        }
        string_answer(what, &value)
    }

    fn call_from_worker(&self, what: &str, args: Args) -> HostAnswer {
        let (tx, rx) = mpsc::channel::<HostAnswer>();
        let name = what.to_string();
        let status = self.threadsafe.call_with_return_value(
            args,
            ThreadsafeFunctionCallMode::NonBlocking,
            move |returned, _env| {
                deliver(&name, returned, tx);
                Ok(())
            },
        );
        if status != Status::Ok {
            // `Closing`: the env is tearing down and no JS will run again.
            return Err(format!(
                "host {what} could not be posted to the JS thread: {status:?}"
            ));
        }
        // Blocks this thread until the JS thread answers. Nothing here
        // can bound that wait: a host function that never returns or
        // never settles holds the thread, as it would hold the JS thread
        // on the synchronous path.
        rx.recv()
            .map_err(|_| format!("host {what} went away before it answered"))?
    }
}

/// Runs on the JS thread once a posted host function has returned. Sends
/// the answer to the waiting worker now, or when a returned Promise
/// settles. Every path sends exactly once or drops every sender, so the
/// worker never waits on a call that already finished.
fn deliver(what: &str, returned: napi::Result<Unknown<'static>>, tx: mpsc::Sender<HostAnswer>) {
    let value = match returned {
        Ok(value) => value,
        Err(e) => {
            let _ = tx.send(Err(format!("host {what} threw: {e}")));
            return;
        }
    };
    match value.is_promise() {
        Ok(true) => {}
        Ok(false) => {
            let _ = tx.send(string_answer(what, &value));
            return;
        }
        Err(e) => {
            let _ = tx.send(Err(format!("host {what} result: {e}")));
            return;
        }
    }
    // SAFETY: `is_promise` held, and `PromiseRaw` only wraps the value.
    let promise = match unsafe { value.cast::<PromiseRaw<Utf16String>>() } {
        Ok(promise) => promise,
        Err(e) => {
            let _ = tx.send(Err(format!("host {what} result: {e}")));
            return;
        }
    };
    let on_rejected = tx.clone();
    let on_failure = tx.clone();
    let fulfilled_name = what.to_string();
    let rejected_name = what.to_string();
    // `then` converts the settled value to a string; a non-string makes
    // the chained promise reject, so the `catch` below sees it too.
    let attached = promise
        .then(move |settled: CallbackContext<Utf16String>| {
            let _ = tx.send(Ok(settled.value));
            Ok(Null)
        })
        .and_then(|chained| {
            chained.catch(move |rejection: CallbackContext<Unknown<'_>>| {
                let _ = on_rejected.send(Err(format!(
                    "host {rejected_name} rejected: {}",
                    describe(rejection.value)
                )));
                Ok(Null)
            })
        });
    if let Err(e) = attached {
        let _ = on_failure.send(Err(format!(
            "host {fulfilled_name} returned a Promise that could not be awaited: {e}"
        )));
    }
}

/// Text for a value JS threw or rejected with: an Error's message, else
/// the value coerced to a string, else its kind.
fn describe(value: Unknown<'_>) -> String {
    let reason = napi::Error::from_unknown_without_coercion(value).reason;
    if !reason.is_empty() {
        return reason;
    }
    value
        .coerce_to_string()
        .and_then(|text| text.into_utf8())
        .and_then(|text| text.into_owned())
        .unwrap_or_else(|_| "a value with no message".to_string())
}

/// Read a host function's return value as the UTF-16 code units of its
/// string result. A non-string fails closed.
fn string_answer(what: &str, value: &Unknown<'_>) -> HostAnswer {
    // SAFETY: the conversion checks the value's type and fails for a
    // non-string instead of reading it as one.
    unsafe { value.cast::<Utf16String>() }
        .map_err(|e| format!("host {what} returned a non-string: {e}"))
}

struct NodeAnnotatorDispatcher {
    func: HostFunction<FnArgs<(String, String, String)>>,
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
        let raw = self
            .func
            .call(
                "annotator dispatcher",
                FnArgs {
                    data: (
                        annotator_name.to_string(),
                        invocation_json,
                        policy_input_json,
                    ),
                },
            )
            .map_err(RuntimeError::AnnotationFailed)?;
        // Strict: an unpaired surrogate in the result fails the
        // dispatch closed instead of becoming U+FFFD.
        let raw = decode("host annotator dispatcher result", &raw)
            .map_err(|e| RuntimeError::AnnotationFailed(e.reason))?;
        serde_json::from_str::<JsonValue>(&raw).map_err(|e| {
            RuntimeError::AnnotationFailed(format!(
                "host annotator dispatcher returned non-JSON: {e}"
            ))
        })
    }
}

struct NodePolicyDispatcher {
    func: HostFunction<FnArgs<(String,)>>,
}

impl PolicyDispatcher for NodePolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let invocation_json = serde_json::to_string(invocation).map_err(|e| {
            RuntimeError::PolicyInvocationFailed(format!("serialize policy invocation: {e}"))
        })?;
        let raw = self
            .func
            .call(
                "policy dispatcher",
                FnArgs {
                    data: (invocation_json,),
                },
            )
            .map_err(RuntimeError::PolicyInvocationFailed)?;
        let raw = decode("host policy dispatcher result", &raw)
            .map_err(|e| RuntimeError::PolicyInvocationFailed(e.reason))?;
        serde_json::from_str::<JsonValue>(&raw).map_err(|e| {
            RuntimeError::PolicyInvocationFailed(format!(
                "host policy dispatcher returned non-JSON: {e}"
            ))
        })
    }
}

struct NodeTelemetrySink {
    func: HostFunction<FnArgs<(String,)>>,
}

impl TelemetrySink for NodeTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // TelemetryEvent is not Serialize, so the wire shape lives in
        // `wire::telemetry_event_json`. Every binding then hands the
        // sink the same JSON, and a sink written for one language reads
        // the same fields in another. A sink cannot fail an
        // evaluation, so whatever it returns or throws is dropped. The
        // call still waits for the sink on both paths, so the decision
        // event reaches the host before the verdict does.
        let payload = wire::telemetry_event_json(&event);
        let Ok(json) = serde_json::to_string(&payload) else {
            return;
        };
        let _ = self.func.call("telemetry sink", FnArgs { data: (json,) });
    }
}

fn parse_perf(value: Option<Utf16String>) -> napi::Result<agent_control_spec::PerfTelemetry> {
    let Some(value) = value else {
        return Ok(agent_control_spec::PerfTelemetry::Off);
    };
    let raw = decode("perfTelemetry", &value)?;
    // The engine owns what a level name means; this boundary only
    // decodes UTF-16 and reshapes the error for napi.
    wire::parse_perf_telemetry(&raw).map_err(|e| err(format!("{e}")))
}

/// Read a limits override.
///
/// - Absent / null / empty means keep every default.
/// - Each field is individually optional; an absent field keeps its own
///   default, so a host raising one cap does not restate the others.
/// - A field present but not a non-negative integer is a hard ERROR, not
///   a silently-kept default. A host that asked for a smaller bound and
///   got the larger one would believe it was protected when it was not.
/// - An unknown/misspelled field is refused rather than silently
///   ignored, so a typo cannot mask a bound the host believes it set
///   but did not set.
///
/// Field-by-field acceptance and the misspelled-key refusal live in
/// [`wire::limits_from_json`]; this boundary only decodes UTF-16,
/// parses the JSON, and reshapes the error into a napi error.
fn parse_limits(value: Option<Utf16String>) -> napi::Result<Limits> {
    let Some(value) = value else {
        return Ok(Limits::default());
    };
    let raw = decode("limits", &value)?;
    if raw.trim().is_empty() {
        return Ok(Limits::default());
    }
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|e| err(format!("limits does not parse: {e}")))?;
    wire::limits_from_json(&parsed).map_err(|e| err(format!("{e}")))
}

/// The engine's default resource caps as a JSON object string. A host
/// that raises one cap reads this to see what it is overriding, so a
/// shipping change to another default cannot be silently absorbed by a
/// stale mapping.
#[napi]
pub fn default_limits() -> napi::Result<String> {
    serde_json::to_string(&wire::limits_json(&Limits::default())).map_err(|e| err(format!("{e}")))
}

// Type aliases for the FunctionRef signatures the JS↔Rust wire uses.
// Kept private so they never leak into the TS declaration; napi-derive
// still sees the expanded types on the entry points that take them as
// arguments (aliases are not expanded through the `#[napi]` macro).
// The return type is `Unknown` because a callback may answer with a
// string or, on the worker path, a Promise of one; the host function
// reads it either way.
type NodeAnnotatorFn = FunctionRef<FnArgs<(String, String, String)>, Unknown<'static>>;
type NodePolicyFn = FunctionRef<FnArgs<(String,)>, Unknown<'static>>;
type NodeTelemetryFn = FunctionRef<FnArgs<(String,)>, Unknown<'static>>;

fn build_annotator(
    env: &Env,
    dispatcher: Option<NodeAnnotatorFn>,
) -> napi::Result<Arc<dyn AnnotatorDispatcher>> {
    build_annotator_with_limits(env, dispatcher, Limits::default())
}

fn build_annotator_with_limits(
    env: &Env,
    dispatcher: Option<NodeAnnotatorFn>,
    limits: Limits,
) -> napi::Result<Arc<dyn AnnotatorDispatcher>> {
    Ok(match dispatcher {
        Some(func) => Arc::new(NodeAnnotatorDispatcher {
            func: HostFunction::new(env, func)?,
        }),
        None => default_annotator_dispatcher_with_limits(limits),
    })
}

fn build_policy(
    env: &Env,
    dispatcher: Option<NodePolicyFn>,
) -> napi::Result<Arc<dyn PolicyDispatcher>> {
    build_policy_with_limits(env, dispatcher, Limits::default())
}

fn build_policy_with_limits(
    env: &Env,
    dispatcher: Option<NodePolicyFn>,
    limits: Limits,
) -> napi::Result<Arc<dyn PolicyDispatcher>> {
    Ok(match dispatcher {
        Some(func) => Arc::new(NodePolicyDispatcher {
            func: HostFunction::new(env, func)?,
        }),
        None => Arc::new(BindingPolicyDispatcher::with_limits(limits)),
    })
}

fn build_telemetry(
    env: &Env,
    sink: Option<NodeTelemetryFn>,
) -> napi::Result<Arc<dyn TelemetrySink>> {
    Ok(match sink {
        Some(func) => Arc::new(NodeTelemetrySink {
            func: HostFunction::new(env, func)?,
        }),
        None => Arc::new(NoopTelemetrySink),
    })
}

/// Decode `context_json` and require a JSON object. Runs on the JS
/// thread for every evaluation entry point, so a boundary problem throws
/// synchronously whichever one the caller used.
fn context_snapshot(context_json: &Utf16String) -> napi::Result<Value> {
    let context_json = decode("context_json", context_json)?;
    let snapshot: Value = serde_json::from_str(&context_json)
        .map_err(|e| err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(err("context_json must be a JSON object".to_string()));
    }
    Ok(snapshot)
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
    Ok(External::new(Handle {
        runtime: Arc::new(runtime),
    }))
}

/// Build a runtime handle from a manifest path, optionally overriding
/// the annotator dispatcher, policy dispatcher, telemetry sink, perf
/// telemetry level, and resource caps.
///
/// Every callback is optional: absent means keep the zero-config
/// default for that slot. Callbacks cross the boundary as JSON strings,
/// mirroring the FFI hook contract, so a host that already sits behind
/// a JSON schema does not re-model its wire shape for this SDK.
///
/// `limits_json` is a JSON object of resource caps overriding the
/// engine's defaults field by field. Null or empty means keep every
/// default; each field is individually optional, so a host raising one
/// cap does not restate the others. A host feeding large payloads
/// raises `max_snapshot_bytes`; one hardening against a hostile
/// manifest lowers `max_extends_depth` or `manifest_url_timeout_ms`.
/// The caps bound manifest loading (the `extends` chain), evaluation
/// and the bundled dispatchers alike. A field present but not a
/// non-negative integer is a hard ERROR, not a silently-kept default.
///
/// Callbacks run on the JS thread. Under `intercept` and
/// `policy_evaluate` the engine calls them synchronously from inside
/// the evaluation and they must return a string. Under
/// `intercept_async` the evaluation runs on a thread of its own, the
/// call is posted to the JS thread, and a callback may return a string
/// or a Promise of one. A callback that throws, rejects, or returns a
/// Promise on the synchronous path surfaces as a fail-closed
/// `runtime_error:*` deny (annotator → `annotation_failed`, policy →
/// `policy_invocation_failed`) rather than silently reading as "no
/// annotation".
#[napi]
#[allow(clippy::type_complexity)]
pub fn interceptor_new_with_hooks(
    env: Env,
    manifest_path: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, Unknown<'static>>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, Unknown<'static>>>,
    telemetry_sink: Option<FunctionRef<FnArgs<(String,)>, Unknown<'static>>>,
    perf_telemetry: Option<Utf16String>,
    limits_json: Option<Utf16String>,
) -> napi::Result<External<Handle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let perf = parse_perf(perf_telemetry)?;
    let limits = parse_limits(limits_json)?;
    // The host's caps bound manifest loading too: `max_extends_depth`
    // and the URL caps apply while the `extends` chain is resolved.
    let manifest =
        Manifest::from_path_with_limits(&manifest_path, limits).map_err(|e| err(format!("{e}")))?;
    let annotations = build_annotator_with_limits(&env, annotator_dispatcher, limits)?;
    let policy = build_policy_with_limits(&env, policy_dispatcher, limits)?;
    let telemetry = build_telemetry(&env, telemetry_sink)?;
    // Construction runs on the JS thread; should the engine ever reach a
    // host callback while building, the direct path is the right one.
    let _scope = EnvScope::enter(&env);
    let runtime = Runtime::with_telemetry_perf_and_limits(
        manifest,
        annotations,
        policy,
        telemetry,
        perf,
        limits,
    )
    .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(Handle {
        runtime: Arc::new(runtime),
    }))
}

/// Evaluate one agent context (JSON object per AGENT-HOOKS-0.1 §4) on
/// the calling JS thread and return the verdict as wire JSON.
///
/// The call blocks the JS thread until the engine returns, so no timer
/// can preempt it. `intercept_async` is the preemptable entry point.
#[napi]
pub fn intercept(
    env: Env,
    handle: &External<Handle>,
    context_json: Utf16String,
) -> napi::Result<String> {
    let snapshot = context_snapshot(&context_json)?;
    // The engine may call a host dispatcher synchronously from inside
    // `evaluate`; the scope publishes the current napi env for that
    // callback and is torn down before we return.
    let _scope = EnvScope::enter(&env);
    let verdict = handle.runtime.evaluate(&snapshot).verdict;
    serde_json::to_string(&verdict).map_err(|e| err(format!("verdict serialization failed: {e}")))
}

/// Evaluate one agent context on a thread of its own and resolve the
/// verdict as wire JSON.
///
/// The context is decoded and checked here, on the JS thread, so a
/// boundary problem throws synchronously as it does for `intercept`.
/// Evaluation then runs off the JS thread, which stays free to run
/// timers and host callbacks, so an agent-hooks emitter timeout can
/// preempt a slow evaluation. The promise rejects only if the engine
/// panics or no thread could be started; every evaluation failure is a
/// fail-closed `deny` verdict.
///
/// The thread is the binding's own, not a libuv worker. A hung
/// dispatcher then holds one thread rather than a share of the pool
/// that fs, dns and zlib use, and `process.exit()` does not wait for
/// it, as it would for a worker. Abandoning the promise does not stop
/// the evaluation; the pending promise keeps the process alive until
/// the engine returns.
#[napi(ts_return_type = "Promise<string>")]
pub fn intercept_async<'env>(
    env: &'env Env,
    handle: &External<Handle>,
    context_json: Utf16String,
) -> napi::Result<Object<'env>> {
    let snapshot = context_snapshot(&context_json)?;
    let (deferred, promise) = env.create_deferred::<String, _>()?;
    let runtime = Arc::clone(&handle.runtime);
    // Clones of a deferred share one promise: the first to settle wins
    // and the other is a no-op. This clone settles it if no thread
    // could be started, since the closure, and the deferred inside it,
    // are dropped unsettled in that case.
    let unstarted = deferred.clone();
    let spawned = std::thread::Builder::new()
        .name("acs-evaluation".to_string())
        .spawn(move || {
            // No napi env is published on this thread, so host
            // dispatchers take their threadsafe path. The engine turns
            // every evaluation failure, including a panicking
            // dispatcher, into a fail-closed deny; a panic that still
            // escapes rejects the promise, which the emitter records as
            // `host_error:interceptor_failed`.
            let outcome =
                std::panic::catch_unwind(AssertUnwindSafe(|| runtime.evaluate(&snapshot).verdict))
                    .map_err(|_| err("engine panicked during evaluation".to_string()))
                    .and_then(|verdict| {
                        serde_json::to_string(&verdict)
                            .map_err(|e| err(format!("verdict serialization failed: {e}")))
                    });
            match outcome {
                Ok(wire) => deferred.resolve(move |_env: Env| Ok(wire)),
                Err(error) => deferred.reject(error),
            }
        });
    if let Err(e) = spawned {
        unstarted.reject(err(format!("could not start an evaluation thread: {e}")));
    }
    Ok(promise)
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
/// contract; `policy_evaluate` is the synchronous path, so these
/// callbacks must return a string.
#[napi]
#[allow(clippy::type_complexity)]
pub fn policy_activate_with_hooks(
    env: Env,
    manifest_path: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, Unknown<'static>>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, Unknown<'static>>>,
) -> napi::Result<External<PolicyHandle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let annotations = build_annotator(&env, annotator_dispatcher)?;
    let policy = build_policy(&env, policy_dispatcher)?;
    // Activation warms policies on the JS thread; a dispatcher reached
    // while warming takes the direct path.
    let _scope = EnvScope::enter(&env);
    let handle = ActivatedPolicy::activate_with(manifest, annotations, policy)
        .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(PolicyHandle { policy: handle }))
}

/// Activate a manifest and its Rego from memory against host-supplied
/// dispatchers.
#[napi]
#[allow(clippy::type_complexity)]
pub fn policy_activate_from_memory_with_hooks(
    env: Env,
    manifest_yaml: Utf16String,
    bundles_json: Utf16String,
    annotator_dispatcher: Option<FunctionRef<FnArgs<(String, String, String)>, Unknown<'static>>>,
    policy_dispatcher: Option<FunctionRef<FnArgs<(String,)>, Unknown<'static>>>,
) -> napi::Result<External<PolicyHandle>> {
    let manifest_yaml = decode("manifest_yaml", &manifest_yaml)?;
    let bundles_json = decode("bundles_json", &bundles_json)?;
    let bundles: BTreeMap<String, InMemoryRegoBundle> = serde_json::from_str(&bundles_json)
        .map_err(|e| err(format!("bundles_json does not parse: {e}")))?;
    let annotations = build_annotator(&env, annotator_dispatcher)?;
    let policy = build_policy(&env, policy_dispatcher)?;
    let _scope = EnvScope::enter(&env);
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
    let snapshot = context_snapshot(&context_json)?;
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
pub fn validate_manifest(
    source: Utf16String,
    limits_json: Option<Utf16String>,
) -> napi::Result<Option<String>> {
    let source = decode("source", &source)?;
    let manifest = match Manifest::parse_yaml_str_with_limits(&source, parse_limits(limits_json)?) {
        Ok(m) => m,
        Err(error @ RuntimeError::ManifestInvalid(_)) => return Ok(Some(format!("{error}"))),
        Err(other) => return Err(err(format!("{other}"))),
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
pub fn validate_manifest_file(
    path: Utf16String,
    limits_json: Option<Utf16String>,
) -> napi::Result<Option<String>> {
    let path = decode("path", &path)?;
    match Manifest::from_path_with_limits(&path, parse_limits(limits_json)?) {
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
pub fn parse_manifest(
    source: Utf16String,
    limits_json: Option<Utf16String>,
) -> napi::Result<String> {
    let source = decode("source", &source)?;
    let manifest = Manifest::parse_yaml_str_with_limits(&source, parse_limits(limits_json)?)
        .map_err(|e| err(format!("{e}")))?;
    serde_json::to_string(&manifest).map_err(|e| err(format!("manifest serialization failed: {e}")))
}

/// Compose a chain of manifest YAML documents (outermost base first)
/// into one merged manifest, returned as JSON.
///
/// This is the overlay case: a base policy plus deltas an environment
/// layers on it, resolved the same way the engine resolves `extends`.
#[napi]
pub fn merge_manifests(
    sources_json: Utf16String,
    limits_json: Option<Utf16String>,
) -> napi::Result<String> {
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
    let manifest = Manifest::from_yaml_chain_with_limits(&borrowed, parse_limits(limits_json)?)
        .map_err(|e| err(format!("{e}")))?;
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
pub fn validate_manifest_detailed(
    source: Utf16String,
    limits_json: Option<Utf16String>,
) -> napi::Result<String> {
    let source = decode("source", &source)?;
    let findings = match Manifest::parse_yaml_str_with_limits(&source, parse_limits(limits_json)?) {
        Ok(manifest) => {
            if !manifest.extends.is_empty() {
                // A fragment cannot be judged against itself: its
                // parent may define the annotator or policy this
                // document references. Report that as a single
                // finding rather than silently blaming references
                // the fragment does not own.
                vec![wire::diagnostic_json(&RuntimeError::ManifestInvalid(
                    "manifest extends other manifests; validation needs the merged document. \
                     Use validate_manifest_file, which resolves the chain."
                        .to_string(),
                ))]
            } else {
                match manifest.validate() {
                    Ok(()) => Vec::new(),
                    Err(e @ RuntimeError::ManifestInvalid(_)) => vec![wire::diagnostic_json(&e)],
                    Err(other) => return Err(err(format!("{other}"))),
                }
            }
        }
        Err(e @ RuntimeError::ManifestInvalid(_)) => vec![wire::diagnostic_json(&e)],
        Err(other) => return Err(err(format!("{other}"))),
    };
    serde_json::to_string(&findings)
        .map_err(|e| err(format!("diagnostics serialization failed: {e}")))
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
    // failure — that would name the wrong half. The diagnostic shape
    // is owned by the core so every binding renders artifact findings
    // the same way.
    let findings = match Manifest::from_yaml_str(&manifest_yaml) {
        Err(e @ RuntimeError::ManifestInvalid(_)) => vec![wire::diagnostic_json(&e)],
        Err(other) => return Err(err(format!("{other}"))),
        Ok(manifest) => match manifest.validate() {
            Err(e) => vec![wire::diagnostic_json(&e)],
            Ok(()) => match ActivatedPolicy::activate_from_memory(&manifest_yaml, bundles) {
                Ok(_) => Vec::new(),
                Err(e) => vec![wire::diagnostic_json(&e)],
            },
        },
    };
    serde_json::to_string(&findings)
        .map_err(|e| err(format!("diagnostics serialization failed: {e}")))
}

// Note: the field pointer that used to be built here now lives with the
// diagnostic shape in `wire::diagnostic_field`, so a manifest diagnostic
// reads the same across the FFI, the Python binding, and this binding.

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
    // Like the FFI's `wire_track`: the core owns what the wire name
    // means; this boundary only reshapes the error for napi.
    StreamTrack::parse(raw).map_err(stream_err)
}

fn parse_outcome_wire(raw: &str) -> napi::Result<SegmentOutcome> {
    SegmentOutcome::parse(raw).map_err(stream_err)
}

fn parse_source_wire(raw: &str) -> napi::Result<StreamSourceType> {
    StreamSourceType::parse(raw).map_err(stream_err)
}

fn stream_err(e: StreamError) -> napi::Error {
    err(format!("{e}"))
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
    // Field acceptance, absent-field defaults and the safety-level
    // vocabulary live in the core so every binding builds the same
    // configuration from the same JSON.
    let config = wire::stream_config_from_json(&parsed).map_err(stream_err)?;
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
    let payload = wire::watermark_json(track, watermark);
    serde_json::to_string(&payload).map_err(|e| err(format!("watermark serialization failed: {e}")))
}

/// Session state as JSON: `is_ended`, `transformed`, `end_reason`
/// (null while live) and the effective `config`.
#[napi]
pub fn stream_session_state(handle: &External<StreamHandle>) -> napi::Result<String> {
    let session = lock(handle)?;
    let payload = wire::stream_session_state_json(&session);
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
    let payload = wire::completion_json(&completion);
    serde_json::to_string(&payload)
        .map_err(|e| err(format!("completion serialization failed: {e}")))
}
