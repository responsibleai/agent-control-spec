// Copyright (c) Microsoft. All rights reserved.

//! The agent-hooks emitter bounds an interceptor with `tokio::time::timeout`,
//! which can only fire when the interceptor's future yields. With the
//! `tokio` feature the ACS interceptor evaluates on `spawn_blocking`, so a
//! dispatcher that blocks past the deadline costs a worker thread, not the
//! emission: the emitter records `host_error:interceptor_timeout` on time
//! and the system fails closed.
//!
//! Without the feature this file compiles to nothing, like the streaming
//! suites. CI runs with `--all-features`.

#![cfg(feature = "tokio")]

use agent_control_spec::{
    AcsInterceptor, ActivatedPolicy, AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Manifest,
    PolicyDispatcher, PreparedPolicyInvocation, Runtime, RuntimeError,
};
use agent_hooks::{
    AgentContext, AgentContextBuilder, Decision, EnforcementMode, InterceptionEmitter, Interceptor,
};
use serde_json::json;
use std::{
    sync::{mpsc, Arc, Mutex},
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

/// The emitter deadline under test.
const DEADLINE: Duration = Duration::from_millis(50);

/// How long a gated dispatcher waits for release before returning on its
/// own. Long enough that an emission which waited for it is unmistakable,
/// short enough that a broken yield fails the test instead of hanging it.
const BACKSTOP: Duration = Duration::from_secs(5);

/// An emission that took this long waited for the dispatcher.
const TOO_SLOW: Duration = Duration::from_secs(1);

/// A policy dispatcher that blocks until the test releases it, or until
/// the backstop passes, then allows. It reports the thread it ran on, so
/// a test can tell the worker path from the inline one, and the report
/// doubles as proof that an abandoned evaluation still ran to the end.
struct GatedDispatcher {
    gate: Mutex<mpsc::Receiver<()>>,
    finished: mpsc::Sender<ThreadId>,
}

impl GatedDispatcher {
    fn new() -> (Arc<Self>, mpsc::Sender<()>, mpsc::Receiver<ThreadId>) {
        let (release, gate) = mpsc::channel();
        let (finished, ran_on) = mpsc::channel();
        let dispatcher = Arc::new(Self {
            gate: Mutex::new(gate),
            finished,
        });
        (dispatcher, release, ran_on)
    }
}

impl PolicyDispatcher for GatedDispatcher {
    fn evaluate(&self, _invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        // A release or a dropped sender both end the wait. Only the
        // backstop is a timeout, and the verdict still returns after it.
        let _ = self.gate.lock().unwrap().recv_timeout(BACKSTOP);
        let _ = self.finished.send(thread::current().id());
        Ok(json!({"decision": "allow"}))
    }
}

struct NoAnnotators;

impl AnnotatorDispatcher for NoAnnotators {
    fn dispatch(
        &self,
        _annotator_name: &str,
        _annotator: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Ok(json!({}))
    }
}

/// A host-supplied policy: the one kind of dispatcher the engine cannot
/// bound itself.
const MANIFEST: &str = r#"
agent_control_specification_version: 0.4.0-alpha.1
policies:
  gated:
    type: custom
    adapter: gated
intervention_points:
  pre_tool_call:
    policy:
      id: gated
    policy_target: $snap.tool_call.args
"#;

fn runtime(dispatcher: Arc<GatedDispatcher>) -> Runtime {
    let manifest = Manifest::from_yaml_str(MANIFEST).expect("manifest");
    Runtime::new(manifest, Arc::new(NoAnnotators), dispatcher).expect("runtime")
}

/// A well-formed envelope: the emitter validates it before any
/// interceptor runs, so a bare object would be denied as
/// `host_error:context_invalid` before the dispatcher is reached.
fn context() -> AgentContext {
    AgentContextBuilder::new("demo-agent", "acs-tests", "session-1").pre_tool_call(
        "tc-1",
        "wire_transfer",
        json!({"amount": 1}),
    )
}

fn bounded_emitter(interceptor: AcsInterceptor) -> InterceptionEmitter {
    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.set_timeout(DEADLINE);
    emitter.register(Box::new(interceptor));
    emitter
}

/// Asserts the emission failed closed on the emitter's deadline, then
/// releases the worker and checks the abandoned evaluation still ran to
/// the end, on another thread.
fn assert_timed_out(
    record: &agent_hooks::InterceptionRecord,
    elapsed: Duration,
    release: &mpsc::Sender<()>,
    ran_on: &mpsc::Receiver<ThreadId>,
) {
    let _ = release.send(());
    assert_eq!(record.verdict.decision, Decision::Deny);
    assert_eq!(
        record.verdict.reason.as_deref(),
        Some("host_error:interceptor_timeout")
    );
    assert!(
        elapsed < TOO_SLOW,
        "the emission waited for the dispatcher instead of timing out: {elapsed:?}"
    );
    let worker = ran_on
        .recv_timeout(BACKSTOP)
        .expect("the abandoned evaluation runs to completion");
    assert_ne!(
        worker,
        thread::current().id(),
        "the evaluation ran on the calling thread"
    );
}

/// On a current-thread runtime this proves the yield: an inline
/// evaluation would hold the only thread, and the timer could not run
/// until the dispatcher returned.
#[tokio::test]
async fn emitter_timeout_fires_while_the_dispatcher_blocks() {
    let (dispatcher, release, ran_on) = GatedDispatcher::new();
    let mut emitter = bounded_emitter(AcsInterceptor::new(runtime(dispatcher)));

    let mut ctx = context();
    let started = Instant::now();
    let record = emitter.emit_unchecked(&mut ctx).await;
    let elapsed = started.elapsed();

    assert_timed_out(&record, elapsed, &release, &ran_on);
}

/// An interceptor over an activated policy shares the activation, and
/// must take the same worker path.
#[tokio::test]
async fn activated_policy_interceptor_yields_to_the_emitter_timeout() {
    let (dispatcher, release, ran_on) = GatedDispatcher::new();
    let policy = ActivatedPolicy::activate(runtime(dispatcher)).expect("activation");
    let mut emitter = bounded_emitter(policy.interceptor());

    let mut ctx = context();
    let started = Instant::now();
    let record = emitter.emit_unchecked(&mut ctx).await;
    let elapsed = started.elapsed();

    assert_timed_out(&record, elapsed, &release, &ran_on);
}

/// A host that calls the interceptor itself gets the same yield, so its
/// own `tokio::time::timeout` works too.
#[tokio::test]
async fn a_direct_caller_can_bound_intercept_with_a_timeout() {
    let (dispatcher, release, ran_on) = GatedDispatcher::new();
    let interceptor = AcsInterceptor::new(runtime(dispatcher));
    let ctx = context();

    let started = Instant::now();
    let outcome = tokio::time::timeout(DEADLINE, interceptor.intercept(&ctx)).await;
    let elapsed = started.elapsed();
    let _ = release.send(());

    assert!(outcome.is_err(), "the timeout did not fire: {outcome:?}");
    assert!(
        elapsed < TOO_SLOW,
        "the call waited for the dispatcher instead of timing out: {elapsed:?}"
    );
    let worker = ran_on
        .recv_timeout(BACKSTOP)
        .expect("the abandoned evaluation runs to completion");
    assert_ne!(worker, thread::current().id());
}

/// With no deadline the worker path must return the dispatcher's own
/// verdict, and must have run it on another thread.
#[tokio::test]
async fn evaluation_runs_on_a_worker_and_returns_the_dispatcher_verdict() {
    let (dispatcher, release, ran_on) = GatedDispatcher::new();
    release.send(()).expect("the dispatcher holds the gate");
    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.register(Box::new(AcsInterceptor::new(runtime(dispatcher))));

    let mut ctx = context();
    let record = emitter.emit_unchecked(&mut ctx).await;

    assert_eq!(record.verdict.decision, Decision::Allow);
    assert_eq!(record.verdict.reason, None);
    let worker = ran_on.try_recv().expect("the dispatcher ran");
    assert_ne!(worker, thread::current().id());
}

/// Outside a tokio runtime there is no worker to hand the call to, so
/// the interceptor evaluates inline on the calling thread and still
/// returns the dispatcher's verdict. This is what a host on another
/// executor gets, and what every engine test that drives the interceptor
/// without `#[tokio::test]` relies on.
#[test]
fn without_a_runtime_evaluation_runs_inline() {
    let (dispatcher, release, ran_on) = GatedDispatcher::new();
    release.send(()).expect("the dispatcher holds the gate");
    let interceptor = AcsInterceptor::new(runtime(dispatcher));
    let ctx = context();

    let verdict = block_on(interceptor.intercept(&ctx));

    assert_eq!(verdict.decision, Decision::Allow);
    assert_eq!(
        ran_on.try_recv().expect("the dispatcher ran"),
        thread::current().id(),
        "with no runtime on the thread the evaluation must stay inline"
    );
}

/// Minimal executor, as in `activation.rs`: enough to drive the one async
/// surface here with no runtime on the thread.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::yield_now(),
        }
    }
}
