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
//! # Differences from the `opa` CLI dispatcher
//!
//! * A `bundle` MUST be a directory or a single policy/data file. OPA's
//!   packaged `.tar.gz` bundles are not read; the error message says so.
//! * Rego is parsed as v1, the `import rego.v1` dialect every bundled
//!   policy in this repository already uses.
//! * The dispatcher enforces the eval timeout twice. `regorus` checks a
//!   cooperative deadline as it evaluates, and the evaluation itself runs
//!   on a worker thread the dispatcher abandons once the deadline passes,
//!   so a caller's deadline holds even when one builtin call runs long.

use crate::{
    policy::rego_adapter_data_paths, runtime::PolicyDispatcher, JsonValue,
    PreparedPolicyInvocation, RegoPolicyInvocation, RuntimeError,
};
use std::{
    collections::BTreeMap,
    env, fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
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
}

/// Loads Rego policies and evaluates queries in process.
#[derive(Debug, Clone)]
pub struct RegorusRegoRunner {
    data_paths: Vec<PathBuf>,
    eval_timeout: Duration,
    strict_builtin_errors: bool,
    hard_deadline: bool,
    cache: Option<PolicyCache>,
    workers: Arc<WorkerPool>,
}

impl RegorusRegoRunner {
    /// A runner with no extra data paths, the default eval timeout, and no
    /// policy cache.
    pub fn new() -> Self {
        Self {
            data_paths: Vec::new(),
            eval_timeout: DEFAULT_REGO_TIMEOUT,
            strict_builtin_errors: false,
            hard_deadline: true,
            cache: None,
            workers: Arc::new(WorkerPool::default()),
        }
    }

    /// A runner configured from the process environment. Reads
    /// [`REGO_TIMEOUT_ENV`]; every other setting keeps its default.
    pub fn from_environment() -> Self {
        let mut runner = Self::new();
        if let Some(timeout) = eval_timeout_from_environment() {
            runner = runner.with_eval_timeout(timeout);
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

    /// Always available: unlike the `opa` CLI dispatcher there is no
    /// external binary that could be missing.
    pub fn is_available(&self) -> bool {
        true
    }

    pub fn evaluate(&self, invocation: &RegoPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let key = self.cache_key(invocation)?;
        let engine = self.prepared_engine(key)?;
        let query = invocation.query.clone();
        let input = invocation.canonical_input.clone();
        let timeout = self.eval_timeout;

        let evaluate = move || {
            let mut engine = (*engine).clone();
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

        if self.hard_deadline {
            self.workers.run_with_deadline(timeout, evaluate)
        } else {
            evaluate()
        }
    }

    fn cache_key(&self, invocation: &RegoPolicyInvocation) -> Result<CacheKey, RuntimeError> {
        let mut data_paths = self.data_paths.clone();
        data_paths.extend(rego_adapter_data_paths(&invocation.adapter_config)?);
        Ok(CacheKey {
            bundle: invocation.bundle.clone(),
            data_paths,
            strict_builtin_errors: self.strict_builtin_errors,
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
}

type EvalJob = Box<dyn FnOnce() -> Result<JsonValue, RuntimeError> + Send>;
type EvalOutcome = Result<JsonValue, RuntimeError>;

#[derive(Debug)]
struct Worker {
    jobs: mpsc::Sender<EvalJob>,
    outcomes: mpsc::Receiver<EvalOutcome>,
}

impl Worker {
    fn spawn() -> Result<Self, RuntimeError> {
        let (job_sender, job_receiver) = mpsc::channel::<EvalJob>();
        let (outcome_sender, outcome_receiver) = mpsc::channel::<EvalOutcome>();
        thread::Builder::new()
            .name("acs-rego-eval".to_string())
            .spawn(move || {
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
        })
    }
}

impl WorkerPool {
    fn run_with_deadline<F>(&self, timeout: Duration, work: F) -> Result<JsonValue, RuntimeError>
    where
        F: FnOnce() -> Result<JsonValue, RuntimeError> + Send + 'static,
    {
        let worker = self.take_idle().map_or_else(Worker::spawn, Ok)?;
        if worker.jobs.send(Box::new(work)).is_err() {
            return Err(RuntimeError::PolicyInvocationFailed(
                "Rego evaluation thread ended before it accepted the query".to_string(),
            ));
        }

        match worker.outcomes.recv_timeout(timeout) {
            Ok(outcome) => {
                self.release(worker);
                outcome
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::PolicyInvocationFailed(
                format!("Rego eval exceeded timeout of {} ms", timeout.as_millis()),
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(RuntimeError::PolicyInvocationFailed(
                "Rego evaluation thread ended without producing a verdict".to_string(),
            )),
        }
    }

    fn take_idle(&self) -> Option<Worker> {
        self.idle.lock().ok()?.pop()
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
    if let Some(bundle) = &key.bundle {
        load_path(&mut engine, Path::new(bundle), "bundle")?;
    }
    for data_path in &key.data_paths {
        load_path(&mut engine, data_path, "data path")?;
    }
    Ok(engine)
}

/// Loads a bundle or data path: a directory contributes every `.rego`,
/// `.json`, `.yaml`, and `.yml` file beneath it; a file contributes itself.
fn load_path(engine: &mut regorus::Engine, path: &Path, label: &str) -> Result<(), RuntimeError> {
    if is_packaged_bundle(path) {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "Rego {label} '{}' is a packaged OPA bundle archive; the in-process Rego dispatcher \
             reads a directory or a single .rego/.json/.yaml file. Unpack the bundle, or register \
             the opt-in OpaPolicyDispatcher instead",
            path.display()
        )));
    }
    let metadata = fs::metadata(path).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to read Rego {label} '{}': {err}",
            path.display()
        ))
    })?;
    if metadata.is_dir() {
        let mut loaded = 0usize;
        load_directory(engine, path, label, 0, &mut loaded)?;
        if loaded == 0 {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "Rego {label} '{}' contains no .rego, .json, .yaml, or .yml files",
                path.display()
            )));
        }
        Ok(())
    } else {
        load_file(engine, path, label)
    }
}

fn load_directory(
    engine: &mut regorus::Engine,
    dir: &Path,
    label: &str,
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
            load_directory(engine, &path, label, depth + 1, loaded)?;
        } else if has_loadable_extension(&path) {
            load_file(engine, &path, label)?;
            *loaded += 1;
        }
    }
    Ok(())
}

fn load_file(engine: &mut regorus::Engine, path: &Path, label: &str) -> Result<(), RuntimeError> {
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
            add_data(engine, value, &display)
        }
        Some("yaml") | Some("yml") => {
            let value = regorus::Value::from_yaml_str(&contents).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "failed to parse Rego data file '{display}': {err}"
                ))
            })?;
            add_data(engine, value, &display)
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

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
}

fn has_loadable_extension(path: &Path) -> bool {
    match extension(path) {
        Some(extension) => {
            extension == REGO_EXTENSION || DATA_EXTENSIONS.contains(&extension.as_str())
        }
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
        assert!(has_loadable_extension(Path::new("a.rego")));
        assert!(has_loadable_extension(Path::new("a.REGO")));
        assert!(has_loadable_extension(Path::new("a.json")));
        assert!(has_loadable_extension(Path::new("a.yaml")));
        assert!(has_loadable_extension(Path::new("a.yml")));
        assert!(!has_loadable_extension(Path::new("a.md")));
        assert!(!has_loadable_extension(Path::new(".manifest")));
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
