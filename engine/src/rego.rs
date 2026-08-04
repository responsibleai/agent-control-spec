//! In-process Rego policy dispatcher backed by [`regorus`].
//!
//! This is the bundled zero-config Rego execution path. It supersedes the
//! legacy `opa` CLI dispatcher, which stays available behind the opt-in
//! `opa` feature. The reason is latency: a decision here costs no process
//! spawn and no pipe round trip, and with the optional policy cache it
//! does not re-parse the bundle.
//!
//! The manifest surface does not change. A `rego` policy still declares
//! an optional `bundle` and optional `data` / `data_paths` entries, and
//! the runtime still hands the dispatcher a [`RegoPolicyInvocation`]
//! carrying the query and the canonical policy input. The verdict shape
//! also matches: like the `opa` CLI dispatcher, this one returns the
//! single expression value the query resolved to.
//!
//! Verdicts agree with `opa eval` for the policy language `regorus`
//! covers. They are NOT guaranteed to agree for every bundle; the
//! divergences are enumerated below, and a host porting a bundle written
//! against the `opa` CLI should read them.
//!
//! # Differences from the `opa` CLI dispatcher
//!
//! Data and policy loading follow `opa eval`: inside a `bundle` root only
//! `data.json` / `data.yaml` / `data.yml` documents are data, mounted
//! under the `data` path their directory implies; a `data_paths` root
//! additionally accepts any `.json` / `.yaml` / `.yml` file, and a single
//! file mounts at the `data` root. What remains different:
//!
//! * A `bundle` MUST be a directory or a single policy/data file. OPA's
//!   packaged `.tar.gz` bundles are not read; the error message says so.
//! * Rego parses as v1 by default. A bundle written for OPA 0.x without
//!   `import rego.v1` needs [`RegorusRegoRunner::with_rego_v0`] or
//!   `ACS_REGO_V0=1`.
//! * `regorus` implements most but not all OPA builtins. Notably absent
//!   or inert: `crypto.*`, `io.jwt.*`, `json.patch`, `regex.globs_match`,
//!   GraphQL, and AWS signing. Calling an absent builtin is an
//!   evaluation error, so the verdict fails closed and the divergence is
//!   loud. `http.send` is the exception and the dangerous one: it is
//!   registered but always undefined, so a deny rule gated on it silently
//!   does not fire. Policies for this runtime are meant to be pure and
//!   offline, so `http.send` should not appear in one; check a ported
//!   bundle before relying on this dispatcher.
//! * Numeric precision differs, and this one can flip a verdict.
//!   `regorus` holds integers exactly while they fit in `i64`/`u64` and
//!   falls back to `f64` beyond that; every non-integer is `f64`. OPA
//!   carries numbers as decimal text and computes on them at higher
//!   precision. So integer counts and thresholds, which is what most
//!   policy arithmetic is, agree exactly. Decimal arithmetic need not:
//!   `sum([0.1, 0.2])` is `0.3` under OPA and `0.30000000000000004`
//!   here, so a budget policy comparing that sum against a cap of `0.3`
//!   allows under OPA and denies here. Comparing decimals straight out
//!   of the policy input is unaffected at realistic precision; doing
//!   arithmetic on them first is where the two engines part. Upstream
//!   tracks the decimal case as microsoft/regorus#202, open since 2024
//!   and deliberately accepted there as a performance tradeoff.
//!
//!   Integers past `u64` also arrive as `f64` here, though `regorus`
//!   computes them exactly. That one is this crate's own doing: carrying
//!   them through would mean enabling `serde_json/arbitrary_precision`,
//!   which is a global feature, and it makes canonicalization
//!   non-idempotent: `0.5` and `5e-1` canonicalize to different strings
//!   under it, so equal values would hash differently in
//!   [`crate::canonical_json`]. Exact integers past `u64` are not worth
//!   an unsound content hash.
//! * The dispatcher enforces the eval timeout twice. `regorus` checks a
//!   cooperative deadline as it evaluates, and the evaluation, including
//!   loading the bundle, runs on a worker thread the dispatcher abandons
//!   once the deadline passes, so a caller's deadline holds even when one
//!   builtin call runs long. An abandoned thread cannot be killed, so a
//!   runner stops starting new evaluations once [`MAX_ABANDONED_WORKERS`]
//!   are outstanding, so the backlog converges instead of growing without
//!   bound.

use crate::{
    policy::rego_adapter_data_paths, runtime::PolicyDispatcher, JsonValue,
    PreparedPolicyInvocation, RegoPolicyInvocation, RuntimeError,
};
use std::{
    collections::BTreeMap,
    env, fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

/// Eval timeout override, in milliseconds. Shared with the legacy `opa`
/// CLI dispatcher so hosts that already tune it keep their configuration.
pub const REGO_TIMEOUT_ENV: &str = "ACS_OPA_TIMEOUT_MS";
const DEFAULT_REGO_TIMEOUT: Duration = Duration::from_secs(5);

/// How many units of interpreter work pass between cooperative deadline
/// checks. Small enough that a runaway comprehension is cut off promptly,
/// large enough that the clock read does not dominate evaluation.
const TIMER_CHECK_INTERVAL: u32 = 32;

/// How deep a `bundle` or data directory is walked before the dispatcher
/// gives up. Guards against symlink cycles in a host supplied bundle.
const MAX_BUNDLE_DEPTH: usize = 32;

/// How many evaluations may be abandoned past their deadline before the
/// dispatcher refuses to start another.
///
/// An abandoned worker cannot be killed: `regorus` has no cancellation
/// point inside a builtin call, so the thread runs until its evaluation
/// finishes on its own. Without this gate a policy that reliably times
/// out spawns a fresh thread per decision and the host grows without
/// bound; past it the dispatcher fails closed instead.
///
/// This gates STARTING work, so it is a convergence bound rather than a
/// hard ceiling on live threads. A burst of callers already in flight
/// when the limit is crossed all go on to be abandoned, so the peak is
/// this many plus the host's own concurrency. What it guarantees is that
/// the count stops growing: no further threads are created while the
/// backlog is over the limit. Read the current value with
/// [`RegorusRegoRunner::abandoned_evaluations`].
///
/// Only abandoned evaluations count against it. Work a caller is still
/// waiting on is bounded by the host's concurrency already, and counting
/// that would turn ordinary parallel load into fail-closed denials.
pub const MAX_ABANDONED_WORKERS: usize = 32;

/// How many idle evaluation threads a runner keeps parked between calls.
/// Evaluation runs on a worker thread so a deadline can be enforced even
/// when `regorus` cannot interrupt itself; reusing the thread keeps that
/// guarantee from costing a thread spawn on every evaluation, which would
/// otherwise dominate the per-call cost of a cached policy.
const MAX_IDLE_WORKERS: usize = 16;

/// Upper bound on distinct policy sets held in the optional cache. A
/// manifest names a fixed set of bundles, so this is headroom rather than
/// a working limit; it keeps a host that synthesizes bundle paths from
/// growing the cache without bound. Past the cap, evaluation still works,
/// it just stops being cached.
const MAX_CACHED_POLICY_SETS: usize = 64;

const REGO_EXTENSION: &str = "rego";
const DATA_EXTENSIONS: [&str; 3] = ["json", "yaml", "yml"];

type PolicyCache = Arc<Mutex<BTreeMap<CacheKey, Arc<regorus::Engine>>>>;

/// Identifies a prepared [`regorus::Engine`]: the same bundle and the same
/// data paths always produce the same loaded engine, so the parse can be
/// shared across evaluations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    bundle: Option<String>,
    data_paths: Vec<PathBuf>,
    strict_builtin_errors: bool,
    rego_v0: bool,
}

/// Loads Rego policies and evaluates queries in process.
#[derive(Debug, Clone)]
pub struct RegorusRegoRunner {
    data_paths: Vec<PathBuf>,
    eval_timeout: Duration,
    strict_builtin_errors: bool,
    rego_v0: bool,
    hard_deadline: bool,
    cache: Option<PolicyCache>,
    workers: Arc<WorkerPool>,
    /// Warming runs here rather than on `workers`, so a slow policy
    /// readied at activation cannot spend the budget that keeps
    /// evaluation from failing closed.
    warm_workers: Arc<WorkerPool>,
}

impl RegorusRegoRunner {
    /// A runner with no extra data paths, the default eval timeout, and no
    /// policy cache.
    pub fn new() -> Self {
        Self {
            data_paths: Vec::new(),
            eval_timeout: DEFAULT_REGO_TIMEOUT,
            strict_builtin_errors: false,
            rego_v0: false,
            hard_deadline: true,
            cache: None,
            workers: Arc::new(WorkerPool::default()),
            warm_workers: Arc::new(WorkerPool::default()),
        }
    }

    /// A runner configured from the process environment. Reads
    /// [`REGO_TIMEOUT_ENV`]; every other setting keeps its default.
    pub fn from_environment() -> Self {
        let mut runner = Self::new();
        if let Some(timeout) = eval_timeout_from_environment() {
            runner = runner.with_eval_timeout(timeout);
        }
        if rego_v0_from_environment() {
            runner = runner.with_rego_v0(true);
        }
        runner
    }

    pub fn with_eval_timeout(mut self, timeout: Duration) -> Self {
        self.eval_timeout = timeout;
        self
    }

    pub fn eval_timeout(&self) -> Duration {
        self.eval_timeout
    }

    pub fn with_data_path(mut self, data_path: impl Into<PathBuf>) -> Self {
        self.data_paths.push(data_path.into());
        self
    }

    pub fn with_data_paths<I, P>(mut self, data_paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.data_paths
            .extend(data_paths.into_iter().map(Into::into));
        self
    }

    pub fn data_paths(&self) -> &[PathBuf] {
        &self.data_paths
    }

    /// Whether a builtin that errors fails the query (`true`) or leaves the
    /// rule undefined (`false`). Defaults to `false`, matching `opa eval`.
    /// Either way an unresolved query fails closed at the runtime boundary.
    pub fn with_strict_builtin_errors(mut self, strict: bool) -> Self {
        self.strict_builtin_errors = strict;
        self
    }

    pub fn strict_builtin_errors(&self) -> bool {
        self.strict_builtin_errors
    }

    /// Selects the Rego v0 dialect. Off by default, so policies parse as
    /// v1, the `import rego.v1` dialect this repository's own policy
    /// library uses and the default since OPA 1.0.
    ///
    /// A bundle written for OPA 0.x without `import rego.v1` uses the v0
    /// grammar, where rule bodies need no `if` and partial sets need no
    /// `contains`. Such a bundle fails to load under v1, so a host
    /// carrying pre-1.0 policy needs this until it migrates.
    pub fn with_rego_v0(mut self, rego_v0: bool) -> Self {
        self.rego_v0 = rego_v0;
        self
    }

    pub fn rego_v0(&self) -> bool {
        self.rego_v0
    }

    /// Whether the eval timeout is a hard wall-clock deadline. On by
    /// default.
    ///
    /// A hard deadline runs the evaluation on a pooled worker thread that
    /// the dispatcher abandons once the timeout passes, so the caller
    /// returns on time even in the one case `regorus` cannot interrupt: a
    /// single long-running builtin call. The guarantee costs a
    /// cross-thread round trip on every call, which is a large share of
    /// the total once policies are cached. A host that trusts its policy
    /// set, or that already imposes a deadline of its own around the
    /// interceptor, can turn this off and evaluate inline, keeping only
    /// the cooperative deadline `regorus` checks while it interprets
    /// Rego.
    pub fn with_hard_deadline(mut self, hard_deadline: bool) -> Self {
        self.hard_deadline = hard_deadline;
        self
    }

    pub fn hard_deadline(&self) -> bool {
        self.hard_deadline
    }

    /// Enables the compiled policy cache. Off by default.
    ///
    /// With the cache on, the first evaluation for a given bundle and data
    /// path set parses the policies and every later evaluation reuses that
    /// parse, which is where most of the remaining per call cost lives. The
    /// trade is staleness: policy files edited on disk are not re-read for
    /// the life of the runner, so hosts that hot-reload policy should leave
    /// the cache off or build a new runner after a reload.
    pub fn with_policy_cache(mut self, enabled: bool) -> Self {
        self.cache = enabled.then(|| Arc::new(Mutex::new(BTreeMap::new())));
        self
    }

    /// Whether the compiled policy cache is enabled.
    pub fn policy_cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    /// Drops every cached engine, forcing the next evaluation to re-read
    /// policies from disk. A no-op when the cache is disabled.
    pub fn clear_policy_cache(&self) {
        if let Some(cache) = &self.cache {
            if let Ok(mut cache) = cache.lock() {
                cache.clear();
            }
        }
    }

    /// How many evaluations are still running past their deadline.
    ///
    /// These threads cannot be stopped, so they are the runner's one
    /// unbounded resource and worth watching: a value that sits near
    /// [`MAX_ABANDONED_WORKERS`] means policies are not terminating, and
    /// at the ceiling the runner starts failing closed.
    pub fn abandoned_evaluations(&self) -> usize {
        self.workers.counters.abandoned.load(Ordering::Acquire)
    }

    /// Always available: unlike the `opa` CLI dispatcher there is no
    /// external binary that could be missing.
    pub fn is_available(&self) -> bool {
        true
    }

    /// Loads and compiles the policy this invocation names, then keeps it,
    /// so that a later [`Self::evaluate`] neither reads the bundle nor
    /// compiles it.
    ///
    /// Compilation matters as much as parsing here: `regorus` compiles on
    /// the first `eval_query` of an engine, and the per-evaluation clone
    /// inherits that state, so an engine cached cold pays compilation on
    /// every single decision. Warming runs the real query once against an
    /// empty input to move that cost to activation time.
    ///
    /// Bounded by the same deadline and the same worker pool as
    /// [`Self::evaluate`]. A policy whose entrypoint does input
    /// independent work would otherwise run unbounded on the caller's
    /// thread, which for a host is worse than a slow first decision: it
    /// is an activation that never returns.
    ///
    /// Exceeding the deadline is not an activation failure. Warming is an
    /// optimization, so a policy too slow to warm is left cached but
    /// uncompiled and evaluated normally later, where the deadline
    /// applies again and a runaway policy fails closed. A bundle that
    /// cannot be READ is a different matter and is reported.
    ///
    /// Only meaningful with the policy cache enabled; without it there is
    /// nowhere to keep the result and this is a no-op.
    pub fn warm(&self, invocation: &RegoPolicyInvocation) -> Result<(), RuntimeError> {
        if self.cache.is_none() {
            return Ok(());
        }
        let key = self.cache_key(invocation)?;
        let query = invocation.query.clone();
        let timeout = self.eval_timeout;
        let loader = self.clone();

        let work = move || -> Result<JsonValue, RuntimeError> {
            // Inside the deadline, because reading and parsing a bundle
            // is unbounded disk work on a path a host may not control.
            let engine = loader.prepared_engine(key.clone())?;
            let mut warmed = (*engine).clone();
            warmed.set_execution_timer_config(regorus::utils::limits::ExecutionTimerConfig {
                limit: timeout,
                check_interval: NonZeroU32::new(TIMER_CHECK_INTERVAL).unwrap_or(NonZeroU32::MIN),
            });
            warmed.set_input_json("{}").map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to set Rego warm-up input: {err}"
                ))
            })?;
            // The verdict is irrelevant. An undefined result, or a policy
            // that needs real input, still leaves the engine compiled,
            // which is the whole point.
            let _ = warmed.eval_query(query, false);
            loader.store_warmed(key, warmed);
            Ok(JsonValue::Null)
        };

        if !self.hard_deadline {
            return work().map(|_| ());
        }
        // A separate pool from evaluation. A warm that blows its deadline
        // abandons a thread, and charging that against the budget
        // evaluation fails closed on would let activating one slow policy
        // deny traffic for every other policy sharing the runner.
        match self.warm_workers.run_with_deadline(timeout, work) {
            DeadlineOutcome::Completed(outcome) => outcome.map(|_| ()),
            // Too slow to warm: the bundle may already be cached
            // unwarmed, and evaluation will apply the deadline again.
            DeadlineOutcome::TimedOut => Ok(()),
            // No warming capacity is not a policy failure either.
            DeadlineOutcome::Unavailable(_) => Ok(()),
        }
    }

    /// Keeps a compiled engine for later evaluations, under the same cap
    /// [`Self::prepared_engine`] respects: activation is exactly the path
    /// a host could otherwise use to grow the cache without bound.
    fn store_warmed(&self, key: CacheKey, engine: regorus::Engine) {
        let Some(cache) = &self.cache else {
            return;
        };
        if let Ok(mut cache) = cache.lock() {
            // Replacing a key already present is not growth, so it stays
            // allowed at the cap: that is the cold-to-warm upgrade.
            if cache.len() < MAX_CACHED_POLICY_SETS || cache.contains_key(&key) {
                cache.insert(key, Arc::new(engine));
            }
        }
    }

    pub fn evaluate(&self, invocation: &RegoPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let key = self.cache_key(invocation)?;
        let query = invocation.query.clone();
        let input = invocation.canonical_input.clone();
        let timeout = self.eval_timeout;
        // Cloned rather than borrowed so that loading the bundle happens
        // INSIDE the deadline: reading and parsing a policy set is disk
        // work that can outlast the timeout on its own, and on a cache
        // miss it runs on every call.
        let loader = self.clone();

        let evaluate = move || {
            let mut engine = (*loader.prepared_engine(key)?).clone();
            engine.set_execution_timer_config(regorus::utils::limits::ExecutionTimerConfig {
                limit: timeout,
                check_interval: NonZeroU32::new(TIMER_CHECK_INTERVAL).unwrap_or(NonZeroU32::MIN),
            });
            engine.set_input_json(&input).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to set Rego policy input: {err}"
                ))
            })?;
            let results = engine
                .eval_query(query, false)
                .map_err(|err| eval_error(&err))?;
            single_expression_value(&results)
        };

        if !self.hard_deadline {
            return evaluate();
        }
        match self.workers.run_with_deadline(timeout, evaluate) {
            DeadlineOutcome::Completed(outcome) => outcome,
            DeadlineOutcome::TimedOut => Err(RuntimeError::PolicyInvocationFailed(format!(
                "Rego eval exceeded timeout of {} ms",
                timeout.as_millis()
            ))),
            DeadlineOutcome::Unavailable(error) => Err(error),
        }
    }

    fn cache_key(&self, invocation: &RegoPolicyInvocation) -> Result<CacheKey, RuntimeError> {
        let mut data_paths = self.data_paths.clone();
        data_paths.extend(rego_adapter_data_paths(&invocation.adapter_config)?);
        Ok(CacheKey {
            bundle: invocation.bundle.clone(),
            data_paths,
            strict_builtin_errors: self.strict_builtin_errors,
            rego_v0: self.rego_v0,
        })
    }

    fn prepared_engine(&self, key: CacheKey) -> Result<Arc<regorus::Engine>, RuntimeError> {
        let Some(cache) = &self.cache else {
            return Ok(Arc::new(build_engine(&key)?));
        };
        if let Ok(cache) = cache.lock() {
            if let Some(engine) = cache.get(&key) {
                return Ok(Arc::clone(engine));
            }
        }
        let engine = Arc::new(build_engine(&key)?);
        if let Ok(mut cache) = cache.lock() {
            if cache.len() < MAX_CACHED_POLICY_SETS {
                cache.insert(key, Arc::clone(&engine));
            }
        }
        Ok(engine)
    }
}

impl Default for RegorusRegoRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for RegorusRegoRunner {
    /// Compares configuration, not cache contents: two runners configured
    /// the same way evaluate the same way regardless of what either has
    /// already parsed.
    fn eq(&self, other: &Self) -> bool {
        self.data_paths == other.data_paths
            && self.eval_timeout == other.eval_timeout
            && self.strict_builtin_errors == other.strict_builtin_errors
            && self.rego_v0 == other.rego_v0
            && self.hard_deadline == other.hard_deadline
            && self.policy_cache_enabled() == other.policy_cache_enabled()
    }
}

impl Eq for RegorusRegoRunner {}

/// The bundled in-process Rego [`PolicyDispatcher`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegorusPolicyDispatcher {
    runner: RegorusRegoRunner,
}

impl RegorusPolicyDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runner(runner: RegorusRegoRunner) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &RegorusRegoRunner {
        &self.runner
    }
}

impl PolicyDispatcher for RegorusPolicyDispatcher {
    fn warm(&self, invocation: &PreparedPolicyInvocation) -> Result<(), RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Rego(invocation) => self.runner.warm(invocation),
            // Another engine's policy is not this dispatcher's to prepare.
            _ => Ok(()),
        }
    }

    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Rego(invocation) => self.runner.evaluate(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "Rego policy dispatcher only supports Rego invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

/// Opt into the Rego v0 dialect without a code change, for hosts whose
/// bundle predates OPA 1.0.
pub const REGO_V0_ENV: &str = "ACS_REGO_V0";

fn rego_v0_from_environment() -> bool {
    matches!(
        env::var(REGO_V0_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

fn eval_timeout_from_environment() -> Option<Duration> {
    let value = env::var(REGO_TIMEOUT_ENV).ok()?;
    let millis = value.parse::<u64>().ok()?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

/// Runs `work` on a pooled worker thread and gives up on that thread once
/// `timeout` elapses.
///
/// `regorus` checks its own cooperative deadline, which unwinds runaway
/// Rego, but a single long running builtin call is not interruptible. A
/// worker that blows the deadline is therefore abandoned rather than
/// returned to the pool: it exits on its own once its evaluation ends and
/// it finds nobody listening. This preserves the hard deadline the `opa`
/// CLI dispatcher got from killing its child process, while the common
/// case reuses a parked thread instead of paying a spawn.
#[derive(Debug, Default)]
struct WorkerPool {
    idle: Mutex<Vec<Worker>>,
    counters: Arc<WorkerPoolCounters>,
}

#[derive(Debug, Default)]
struct WorkerPoolCounters {
    /// Threads still running an evaluation nobody is waiting for.
    ///
    /// Counted exactly rather than inferred from live/idle/in-flight
    /// arithmetic: those three move independently, and the windows
    /// between them read as phantom abandonment, which denies healthy
    /// load.
    abandoned: AtomicUsize,
}

/// Lifecycle of one worker thread, owned jointly by the thread and by
/// whichever caller currently holds it.
///
/// A worker leaves `Running` exactly once, and the two racing parties
/// resolve that transition by compare-exchange: the caller claims
/// `Abandoned` when its deadline passes, the thread claims `Finished`
/// when it exits. Whoever loses the race does nothing, so the abandoned
/// count stays balanced even when a worker finishes in the same instant
/// its caller gives up on it.
const WORKER_RUNNING: u8 = 0;
const WORKER_ABANDONED: u8 = 1;
const WORKER_FINISHED: u8 = 2;

#[derive(Debug)]
struct WorkerState {
    state: AtomicU8,
    counters: Arc<WorkerPoolCounters>,
}

impl WorkerState {
    /// Called by a caller that has stopped waiting.
    fn abandon(&self) {
        let claimed = self
            .state
            .compare_exchange(
                WORKER_RUNNING,
                WORKER_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if claimed {
            self.counters.abandoned.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Held by the worker thread for its whole life, so the thread settles
/// its own accounting however it leaves, panic included.
#[derive(Debug)]
struct LiveCount {
    state: Arc<WorkerState>,
}

impl Drop for LiveCount {
    fn drop(&mut self) {
        if self
            .state
            .state
            .compare_exchange(
                WORKER_RUNNING,
                WORKER_FINISHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // A caller got there first, so this thread was charged
            // against the abandoned budget. Give the slot back.
            self.state.counters.abandoned.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

type EvalJob = Box<dyn FnOnce() -> Result<JsonValue, RuntimeError> + Send>;
type EvalOutcome = Result<JsonValue, RuntimeError>;

/// Why a deadline-bounded run ended.
///
/// Carried out of band rather than inferred from an error message: a
/// load failure quotes the bundle path and the offending Rego source, so
/// matching on text would classify a policy in `timeout-rules/`, or one
/// whose broken line mentions `timeout`, as a timeout and silently
/// discard a real failure.
#[derive(Debug)]
enum DeadlineOutcome {
    /// The work ran to completion, successfully or not.
    Completed(EvalOutcome),
    /// The deadline passed and the worker was abandoned.
    TimedOut,
    /// No worker could be obtained, so the work never started.
    Unavailable(RuntimeError),
}

#[derive(Debug)]
struct Worker {
    jobs: mpsc::Sender<EvalJob>,
    outcomes: mpsc::Receiver<EvalOutcome>,
    state: Arc<WorkerState>,
}

impl Worker {
    /// Spawns a worker. The thread holds a [`LiveCount`] for its whole
    /// life so it settles its own accounting however it exits.
    fn spawn(counters: Arc<WorkerPoolCounters>) -> Result<Self, RuntimeError> {
        let (job_sender, job_receiver) = mpsc::channel::<EvalJob>();
        let (outcome_sender, outcome_receiver) = mpsc::channel::<EvalOutcome>();
        let state = Arc::new(WorkerState {
            state: AtomicU8::new(WORKER_RUNNING),
            counters,
        });
        let thread_state = Arc::clone(&state);
        thread::Builder::new()
            .name("acs-rego-eval".to_string())
            .spawn(move || {
                let _slot = LiveCount {
                    state: thread_state,
                };
                while let Ok(job) = job_receiver.recv() {
                    // A closed outcome channel means the caller timed out
                    // and abandoned this worker, so it has no more work.
                    if outcome_sender.send(job()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to start Rego evaluation thread: {err}"
                ))
            })?;
        Ok(Self {
            jobs: job_sender,
            outcomes: outcome_receiver,
            state,
        })
    }
}

impl WorkerPool {
    fn run_with_deadline<F>(&self, timeout: Duration, work: F) -> DeadlineOutcome
    where
        F: FnOnce() -> Result<JsonValue, RuntimeError> + Send + 'static,
    {
        let worker = match self.take_idle() {
            Some(worker) => worker,
            None => match self.spawn_worker() {
                Ok(worker) => worker,
                Err(error) => return DeadlineOutcome::Unavailable(error),
            },
        };
        if worker.jobs.send(Box::new(work)).is_err() {
            return DeadlineOutcome::Unavailable(RuntimeError::PolicyInvocationFailed(
                "Rego evaluation thread ended before it accepted the query".to_string(),
            ));
        }

        match worker.outcomes.recv_timeout(timeout) {
            Ok(outcome) => {
                self.release(worker);
                DeadlineOutcome::Completed(outcome)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The thread cannot be stopped, so charge it against the
                // abandoned budget until it finishes on its own.
                worker.state.abandon();
                DeadlineOutcome::TimedOut
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                DeadlineOutcome::Completed(Err(RuntimeError::PolicyInvocationFailed(
                    "Rego evaluation thread ended without producing a verdict".to_string(),
                )))
            }
        }
    }

    fn take_idle(&self) -> Option<Worker> {
        self.idle.lock().ok()?.pop()
    }

    /// Spawns a worker, or fails closed when too many earlier evaluations
    /// have been abandoned past their deadline.
    fn spawn_worker(&self) -> Result<Worker, RuntimeError> {
        let abandoned = self.counters.abandoned.load(Ordering::Acquire);
        if abandoned >= MAX_ABANDONED_WORKERS {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "{abandoned} Rego evaluations are still running past their timeout and cannot be \
                 interrupted, at the limit of {MAX_ABANDONED_WORKERS}; refusing to start another. \
                 Raise ACS_OPA_TIMEOUT_MS, or fix the policy that is not terminating"
            )));
        }
        Worker::spawn(Arc::clone(&self.counters))
    }

    fn release(&self, worker: Worker) {
        if let Ok(mut idle) = self.idle.lock() {
            if idle.len() < MAX_IDLE_WORKERS {
                idle.push(worker);
            }
        }
    }
}

fn build_engine(key: &CacheKey) -> Result<regorus::Engine, RuntimeError> {
    let mut engine = regorus::Engine::new();
    engine.set_strict_builtin_errors(key.strict_builtin_errors);
    engine.set_rego_v0(key.rego_v0);
    // Capture `print` output instead of letting it reach the host's
    // stderr. A policy may print its input, and the policy input carries
    // user content; the CLI dispatcher kept it inside the child process,
    // so surfacing it in host logs would be a new disclosure path.
    engine.set_gather_prints(true);
    if let Some(bundle) = &key.bundle {
        load_path(&mut engine, Path::new(bundle), "bundle", DataScope::Bundle)?;
    }
    for data_path in &key.data_paths {
        load_path(&mut engine, data_path, "data path", DataScope::DataPath)?;
    }
    Ok(engine)
}

/// Which OPA loading rule applies to a root, because `opa eval` treats a
/// `--bundle` root and a `--data` root differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataScope {
    /// `--bundle`: only files named `data.json` / `data.yaml` / `data.yml`
    /// are data. Every other `.json` / `.yaml` file is ignored.
    Bundle,
    /// `--data`: every `.json` / `.yaml` file is data whatever its name.
    DataPath,
}

impl DataScope {
    fn accepts_data_file(self, path: &Path) -> bool {
        match self {
            Self::Bundle => path.file_stem().is_some_and(|stem| stem == "data"),
            Self::DataPath => true,
        }
    }
}

/// Loads a bundle or data root.
///
/// A directory contributes every `.rego` file beneath it, plus the data
/// documents `scope` accepts, each mounted under the `data` path its
/// parent directory implies relative to this root. A single file
/// contributes itself, mounted at the `data` root, which is what
/// `opa eval --data <file>` does.
fn load_path(
    engine: &mut regorus::Engine,
    path: &Path,
    label: &str,
    scope: DataScope,
) -> Result<(), RuntimeError> {
    let metadata = fs::metadata(path).map_err(|err| {
        if is_packaged_bundle(path) {
            return RuntimeError::PolicyInvocationFailed(format!(
                "Rego {label} '{}' looks like a packaged OPA bundle archive; the in-process Rego \
                 dispatcher reads a directory or a single .rego/.json/.yaml file. Unpack the \
                 bundle, or register the opt-in OpaPolicyDispatcher instead",
                path.display()
            ));
        }
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to read Rego {label} '{}': {err}",
            path.display()
        ))
    })?;
    if metadata.is_dir() {
        let mut loaded = 0usize;
        load_directory(engine, path, path, label, scope, 0, &mut loaded)?;
        if loaded == 0 {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "Rego {label} '{}' contains no .rego, .json, .yaml, or .yml files",
                path.display()
            )));
        }
        Ok(())
    } else if is_packaged_bundle(path) {
        Err(RuntimeError::PolicyInvocationFailed(format!(
            "Rego {label} '{}' is a packaged OPA bundle archive; the in-process Rego dispatcher \
             reads a directory or a single .rego/.json/.yaml file. Unpack the bundle, or register \
             the opt-in OpaPolicyDispatcher instead",
            path.display()
        )))
    } else {
        load_file(engine, path, label, &[])
    }
}

#[allow(clippy::too_many_arguments)]
fn load_directory(
    engine: &mut regorus::Engine,
    root: &Path,
    dir: &Path,
    label: &str,
    scope: DataScope,
    depth: usize,
    loaded: &mut usize,
) -> Result<(), RuntimeError> {
    if depth > MAX_BUNDLE_DEPTH {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "Rego {label} '{}' nests deeper than {MAX_BUNDLE_DEPTH} directories",
            dir.display()
        )));
    }
    let entries = fs::read_dir(dir).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to list Rego {label} directory '{}': {err}",
            dir.display()
        ))
    })?;
    // Sorted so a policy set loads identically on every platform and every
    // run, keeping evaluation deterministic.
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "failed to list Rego {label} directory '{}': {err}",
                dir.display()
            ))
        })?;
        paths.push(entry.path());
    }
    paths.sort();

    for path in paths {
        if path.is_dir() {
            load_directory(engine, root, &path, label, scope, depth + 1, loaded)?;
        } else if is_rego_file(&path) {
            load_file(engine, &path, label, &[])?;
            *loaded += 1;
        } else if is_data_file(&path) && scope.accepts_data_file(&path) {
            let mount = data_mount_path(root, &path);
            load_file(engine, &path, label, &mount)?;
            *loaded += 1;
        }
    }
    Ok(())
}

/// The `data` path a document mounts under: the components of its parent
/// directory relative to the loaded root. `opa eval` derives the mount
/// point from the directory, never from the file name, so
/// `<root>/nested/limits.json` and `<root>/nested/data.json` both land on
/// `data.nested`.
fn data_mount_path(root: &Path, file: &Path) -> Vec<String> {
    let Some(parent) = file.parent() else {
        return Vec::new();
    };
    let Ok(relative) = parent.strip_prefix(root) else {
        return Vec::new();
    };
    relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Wraps `value` so that adding it to the engine mounts it at
/// `data.<mount[0]>.<mount[1]>...` rather than at the `data` root.
fn mount_data(value: regorus::Value, mount: &[String]) -> Result<regorus::Value, RuntimeError> {
    if mount.is_empty() {
        return Ok(value);
    }
    // Built through JSON so the nesting uses regorus' own object
    // representation rather than reaching for an internal mutator.
    let mut json = serde_json::to_value(&value).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to prepare Rego data for mounting: {err}"
        ))
    })?;
    for key in mount.iter().rev() {
        json = serde_json::Value::Object(
            [(key.clone(), json)]
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    }
    regorus::Value::from_json_str(&json.to_string()).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!("failed to mount Rego data: {err}"))
    })
}

fn load_file(
    engine: &mut regorus::Engine,
    path: &Path,
    label: &str,
    mount: &[String],
) -> Result<(), RuntimeError> {
    let contents = fs::read_to_string(path).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to read Rego {label} file '{}': {err}",
            path.display()
        ))
    })?;
    let display = path.display().to_string();
    match extension(path).as_deref() {
        Some(REGO_EXTENSION) => engine
            .add_policy(display.clone(), contents)
            .map(|_| ())
            .map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to load Rego policy '{display}': {err}"
                ))
            }),
        Some("json") => {
            let value = regorus::Value::from_json_str(&contents).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to parse Rego data file '{display}': {err}"
                ))
            })?;
            add_data(engine, mount_data(value, mount)?, &display)
        }
        Some("yaml") | Some("yml") => {
            let value = regorus::Value::from_yaml_str(&contents).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to parse Rego data file '{display}': {err}"
                ))
            })?;
            add_data(engine, mount_data(value, mount)?, &display)
        }
        _ => Err(RuntimeError::PolicyInvocationFailed(format!(
            "Rego {label} file '{display}' must be a .rego, .json, .yaml, or .yml file"
        ))),
    }
}

fn add_data(
    engine: &mut regorus::Engine,
    value: regorus::Value,
    display: &str,
) -> Result<(), RuntimeError> {
    engine.add_data(value).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to load Rego data file '{display}': {err}"
        ))
    })
}

/// The file extension exactly as written. `opa` matches these case
/// sensitively, so `p.REGO` is not a policy and `data.YAML` is not a data
/// document; lowercasing here would load files OPA ignores.
fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|extension| extension.to_string_lossy().into_owned())
}

fn is_rego_file(path: &Path) -> bool {
    extension(path).as_deref() == Some(REGO_EXTENSION)
}

fn is_data_file(path: &Path) -> bool {
    match extension(path) {
        Some(extension) => DATA_EXTENSIONS.contains(&extension.as_str()),
        None => false,
    }
}

fn is_packaged_bundle(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".tar")
}

fn eval_error(err: &impl std::fmt::Display) -> RuntimeError {
    let detail = err.to_string();
    if detail.contains("execution exceeded time limit") {
        return RuntimeError::PolicyInvocationFailed(format!(
            "Rego eval exceeded timeout: {detail}"
        ));
    }
    RuntimeError::PolicyInvocationFailed(format!("Rego eval failed: {detail}"))
}

/// Projects a query result onto the single verdict value the runtime
/// expects, mirroring how the `opa` CLI dispatcher reads
/// `result[0].expressions[0].value`.
fn single_expression_value(results: &regorus::QueryResults) -> Result<JsonValue, RuntimeError> {
    let result =
        match results.result.as_slice() {
            [] => {
                return Err(RuntimeError::PolicyInvocationFailed(
                    "Rego query returned no result".to_string(),
                ))
            }
            [result] => result,
            _ => return Err(RuntimeError::PolicyInvocationFailed(
                "Rego query returned multiple results; policy query must resolve to one verdict"
                    .to_string(),
            )),
        };

    match result.expressions.as_slice() {
        [expression] => serde_json::to_value(&expression.value).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "failed to convert Rego query result to JSON: {err}"
            ))
        }),
        [] => Err(RuntimeError::PolicyInvocationFailed(
            "Rego query returned a result with no expression value".to_string(),
        )),
        _ => Err(RuntimeError::PolicyInvocationFailed(
            "Rego query returned multiple expression values; policy query must resolve to one verdict"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_bundle_archives_are_recognized() {
        assert!(is_packaged_bundle(Path::new("/tmp/policy.tar.gz")));
        assert!(is_packaged_bundle(Path::new("/tmp/policy.TGZ")));
        assert!(is_packaged_bundle(Path::new("/tmp/policy.tar")));
        assert!(!is_packaged_bundle(Path::new("/tmp/policy")));
        assert!(!is_packaged_bundle(Path::new("/tmp/policy.rego")));
    }

    #[test]
    fn loadable_extensions_cover_policies_and_data_only() {
        assert!(is_rego_file(Path::new("a.rego")));
        assert!(!is_rego_file(Path::new("a.json")));
        assert!(is_data_file(Path::new("a.json")));
        assert!(is_data_file(Path::new("a.yaml")));
        assert!(is_data_file(Path::new("a.yml")));
        assert!(!is_data_file(Path::new("a.md")));
        assert!(!is_data_file(Path::new(".manifest")));
        // `opa` matches extensions case sensitively.
        assert!(!is_rego_file(Path::new("a.REGO")));
        assert!(!is_data_file(Path::new("a.JSON")));
    }

    /// `opa eval --bundle` treats only `data.json` / `data.yaml` as data.
    #[test]
    fn bundle_scope_accepts_only_data_named_documents() {
        assert!(DataScope::Bundle.accepts_data_file(Path::new("/b/data.json")));
        assert!(!DataScope::Bundle.accepts_data_file(Path::new("/b/DATA.yaml")));
        assert!(!DataScope::Bundle.accepts_data_file(Path::new("/b/limits.json")));
        // A name that merely starts with "data" is not a data document.
        assert!(!DataScope::Bundle.accepts_data_file(Path::new("/b/database.json")));
        assert!(DataScope::DataPath.accepts_data_file(Path::new("/b/limits.json")));
    }

    #[test]
    fn data_mount_path_follows_the_directory_not_the_file_name() {
        let root = Path::new("/b");
        assert_eq!(
            data_mount_path(root, Path::new("/b/data.json")),
            Vec::<String>::new()
        );
        assert_eq!(
            data_mount_path(root, Path::new("/b/nested/limits.json")),
            vec!["nested".to_string()]
        );
        assert_eq!(
            data_mount_path(root, Path::new("/b/a/b/data.yaml")),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn runner_equality_ignores_cache_contents() {
        let plain = RegorusRegoRunner::new();
        assert_eq!(plain, RegorusRegoRunner::new());
        assert_ne!(plain, RegorusRegoRunner::new().with_policy_cache(true));
        assert_eq!(
            RegorusRegoRunner::new().with_policy_cache(true),
            RegorusRegoRunner::new().with_policy_cache(true)
        );
    }
}
