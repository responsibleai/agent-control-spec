//! Policy evaluation benchmark for the Rust core.
//!
//! Reports what a host sizing this runtime needs to know: what
//! activating a policy version costs, what the first decision after it
//! costs, what a steady-state decision costs at the tail rather than
//! the mean, and what happens when decisions arrive in parallel.
//!
//! Run with:
//!
//! ```text
//! cargo run --release -p agent-control-spec --all-features --example benchmark
//! ```
//!
//! Every number is measured in this process on the machine that runs
//! it. Absolute values are hardware-specific; the ratio between the
//! cold and warm rows is the portable part.

use agent_control_spec::{
    ActivatedPolicy, InterceptionPoint, JsonValue, Manifest, Runtime, RuntimeError,
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

/// Iterations per warm measurement. Large enough that the percentiles
/// mean something, small enough that the whole run stays quick.
const WARM_ITERATIONS: usize = 2_000;
/// Discarded before measuring, so allocator warmup does not land in the
/// reported distribution.
const WARMUP_ITERATIONS: usize = 200;
const CONCURRENCY: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workload = Workload::bank_agent()?;

    println!("Agent Control Specification: policy evaluation benchmark");
    println!("workload: {}", workload.name);
    println!(
        "warm iterations: {WARM_ITERATIONS}, discarded warmup: {WARMUP_ITERATIONS}, concurrency: {CONCURRENCY}\n"
    );

    let activation = measure_activation(&workload)?;
    let policy = ActivatedPolicy::activate_manifest(workload.manifest()?)?;

    println!("== Activation, once per policy version ==");
    row("activate() cold", activation.activate);
    row("first evaluate after activate", activation.first_evaluate);
    row(
        "activate() + first evaluate",
        activation.activate + activation.first_evaluate,
    );
    println!();

    println!("== Lazy runtime, for comparison: same work, readied on first use ==");
    row("Runtime::new()", activation.lazy_construct);
    row(
        "first evaluate (pays the load and compile)",
        activation.lazy_first_evaluate,
    );
    println!();

    println!("== Warm evaluation, per intervention point ==");
    println!(
        "{:<26} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "point", "p50", "p95", "p99", "max", "per second"
    );
    for point in policy.intervention_points() {
        let Some(snapshot) = workload.snapshot_for(*point) else {
            continue;
        };
        let stats = measure_warm(&policy, *point, snapshot);
        println!(
            "{:<26} {:>10} {:>10} {:>10} {:>10} {:>12.0}",
            point.to_string(),
            micros(stats.p50),
            micros(stats.p95),
            micros(stats.p99),
            micros(stats.max),
            1.0 / stats.p50.as_secs_f64()
        );
    }
    println!();

    let (point, snapshot) = workload.busiest_point();
    let cores = std::thread::available_parallelism()
        .map(|cores| cores.get())
        .unwrap_or(0);
    println!("== Concurrency, all threads on '{point}' ({cores} logical cores) ==");
    println!(
        "{:<26} {:>14} {:>16} {:>12}",
        "threads", "throughput/s", "mean latency", "vs 1 thread"
    );
    let mut baseline = 0.0;
    for threads in [1, 8, CONCURRENCY] {
        let parallel = measure_concurrent(&policy, point, snapshot, threads);
        if threads == 1 {
            baseline = parallel.throughput;
        }
        println!(
            "{:<26} {:>14.0} {:>16} {:>11.2}x",
            threads,
            parallel.throughput,
            micros(parallel.mean_latency),
            parallel.throughput / baseline
        );
    }
    if CONCURRENCY > cores && cores > 0 {
        println!(
            "\nNote: {CONCURRENCY} threads oversubscribes {cores} cores, so the last row is a \
             queueing measurement rather than a scaling one."
        );
    }
    println!();

    println!("== Cold versus warm, the number that decides whether to cache ==");
    let cold = activation.activate + activation.first_evaluate;
    let warm = measure_warm(&policy, point, snapshot).p50;
    row("cold: activate + first decision", cold);
    row("warm: subsequent decision (p50)", warm);
    let ratio = cold.as_secs_f64() / warm.as_secs_f64();
    println!("{:<44} {ratio:>12.0}x", "cold / warm");
    println!(
        "\nActivation pays for itself after {} decisions on this policy version.",
        ratio.ceil() as u64
    );
    Ok(())
}

struct Activation {
    activate: Duration,
    first_evaluate: Duration,
    lazy_construct: Duration,
    lazy_first_evaluate: Duration,
}

fn measure_activation(workload: &Workload) -> Result<Activation, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let policy = ActivatedPolicy::activate_manifest(workload.manifest()?)?;
    let activate = started.elapsed();

    let (point, snapshot) = workload.busiest_point();
    let started = Instant::now();
    policy.evaluate(point, snapshot.clone());
    let first_evaluate = started.elapsed();

    let manifest = workload.manifest()?;
    let started = Instant::now();
    let runtime = Runtime::new(
        manifest.clone(),
        agent_control_spec::dispatchers::default_annotator_dispatcher(),
        agent_control_spec::dispatchers::default_policy_dispatcher(&manifest)?,
    )?;
    let lazy_construct = started.elapsed();
    let started = Instant::now();
    runtime.evaluate_point(point, snapshot.clone());
    let lazy_first_evaluate = started.elapsed();

    Ok(Activation {
        activate,
        first_evaluate,
        lazy_construct,
        lazy_first_evaluate,
    })
}

struct WarmStats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

fn measure_warm(
    policy: &ActivatedPolicy,
    point: InterceptionPoint,
    snapshot: &JsonValue,
) -> WarmStats {
    for _ in 0..WARMUP_ITERATIONS {
        policy.evaluate(point, snapshot.clone());
    }
    let mut samples = Vec::with_capacity(WARM_ITERATIONS);
    for _ in 0..WARM_ITERATIONS {
        let started = Instant::now();
        policy.evaluate(point, snapshot.clone());
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    WarmStats {
        p50: percentile(&samples, 50.0),
        p95: percentile(&samples, 95.0),
        p99: percentile(&samples, 99.0),
        max: *samples.last().expect("at least one sample"),
    }
}

struct ConcurrentStats {
    throughput: f64,
    mean_latency: Duration,
}

fn measure_concurrent(
    policy: &ActivatedPolicy,
    point: InterceptionPoint,
    snapshot: &JsonValue,
    threads: usize,
) -> ConcurrentStats {
    let per_thread = WARM_ITERATIONS / threads;
    let barrier = Arc::new(Barrier::new(threads));
    let started = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            // Cloning shares the activated policy rather than copying
            // it: this is the pattern a server would use.
            let policy = policy.clone();
            let barrier = Arc::clone(&barrier);
            let snapshot = snapshot.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let thread_started = Instant::now();
                for _ in 0..per_thread {
                    policy.evaluate(point, snapshot.clone());
                }
                thread_started.elapsed()
            })
        })
        .collect();
    let total: Duration = handles.into_iter().map(|h| h.join().expect("worker")).sum();
    let wall = started.elapsed();
    let evaluations = per_thread * threads;
    ConcurrentStats {
        throughput: evaluations as f64 / wall.as_secs_f64(),
        mean_latency: total / evaluations as u32,
    }
}

struct Workload {
    name: &'static str,
    dir: PathBuf,
    snapshots: Vec<(InterceptionPoint, JsonValue)>,
}

impl Workload {
    fn bank_agent() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/bank_agent")
            .canonicalize()?;
        let mut snapshots = Vec::new();
        for entry in std::fs::read_dir(dir.join("snapshots"))? {
            let path = entry?.path();
            let stem = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            let Some(point) = point_for(&stem) else {
                continue;
            };
            let snapshot: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            snapshots.push((point, snapshot));
        }
        snapshots.sort_by_key(|(point, _)| point.to_string());
        Ok(Self {
            name: "examples/bank_agent",
            dir,
            snapshots,
        })
    }

    fn manifest(&self) -> Result<Manifest, RuntimeError> {
        Manifest::from_path(self.dir.join("manifest.yaml"))
    }

    fn snapshot_for(&self, point: InterceptionPoint) -> Option<&JsonValue> {
        self.snapshots
            .iter()
            .find(|(candidate, _)| *candidate == point)
            .map(|(_, snapshot)| snapshot)
    }

    /// The point a host evaluates most, and so the one worth reporting
    /// concurrency and cold/warm against.
    fn busiest_point(&self) -> (InterceptionPoint, &JsonValue) {
        self.snapshot_for(InterceptionPoint::Input)
            .map(|snapshot| (InterceptionPoint::Input, snapshot))
            .unwrap_or_else(|| {
                let (point, snapshot) = &self.snapshots[0];
                (*point, snapshot)
            })
    }
}

fn point_for(stem: &str) -> Option<InterceptionPoint> {
    Some(match stem {
        "agent_startup" => InterceptionPoint::AgentStartup,
        "input" => InterceptionPoint::Input,
        "pre_model_call" => InterceptionPoint::PreModelCall,
        "post_model_call" => InterceptionPoint::PostModelCall,
        "output" => InterceptionPoint::Output,
        "agent_shutdown" => InterceptionPoint::AgentShutdown,
        other if other.starts_with("pre_tool_call") => InterceptionPoint::PreToolCall,
        other if other.starts_with("post_tool_call") => InterceptionPoint::PostToolCall,
        _ => return None,
    })
}

/// Nearest-rank percentile over a sorted sample.
fn percentile(sorted: &[Duration], percentile: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = (percentile / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn micros(duration: Duration) -> String {
    format!("{:.1}us", duration.as_secs_f64() * 1e6)
}

fn row(label: &str, duration: Duration) {
    println!("{label:<44} {:>12}", micros(duration));
}
