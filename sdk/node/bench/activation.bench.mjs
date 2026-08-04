// Activation benchmark for the Node binding.
//
//   cd sdk/node && npm run bench
//
// Workload: examples/bank_agent — the real Rego bundle, the committed
// snapshots, all eight intervention points. It runs against
// `manifest.bench.yaml`, the annotator-free variant of the example
// manifest: every annotator type calls an HTTP endpoint, which a
// zero-config binding cannot serve, so under `manifest.yaml` every
// evaluation would fail closed at annotation and this would time the
// error path instead of the engine. See that file's header.
//
// A manifest names its bundle relative to itself, so an absolute
// manifest path is enough and the working directory does not matter —
// the same assumption sdk/dotnet/bench makes.
//
// Every number below is measured in this process. Warmup iterations are
// excluded from every reported statistic.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, "..", "dist", "index.js");
const BANK_AGENT = path.resolve(HERE, "..", "..", "..", "examples", "bank_agent");
const MANIFEST = path.join(BANK_AGENT, "manifest.bench.yaml");

// Fixed, not adaptive: a benchmark whose iteration count moves with the
// machine cannot be compared across runs.
const REPEAT_ACTIVATIONS = 10;
const WARMUP_EVALUATIONS = 2_000;
const TIMED_EVALUATIONS = 20_000;
const CONCURRENCY = 32;
const EVALUATIONS_PER_WORKER = 2_000;

const POINTS = [
  "agent_startup",
  "input",
  "pre_model_call",
  "post_model_call",
  "pre_tool_call",
  "post_tool_call",
  "output",
  "agent_shutdown",
];

const { ActivatedPolicy } = require(DIST);
const SNAPSHOTS = POINTS.map((point) =>
  JSON.parse(fs.readFileSync(path.join(BANK_AGENT, "snapshots", `${point}.json`), "utf8")),
);

const ms = (ns) => Number(ns) / 1e6;
const us = (ns) => Number(ns) / 1e3;
const ascending = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function time(fn) {
  const started = process.hrtime.bigint();
  const value = fn();
  return { ns: process.hrtime.bigint() - started, value };
}

function percentile(sortedNs, p) {
  // Nearest-rank, so every reported quantile is an observation that
  // actually happened rather than an interpolation between two.
  const rank = Math.ceil((p / 100) * sortedNs.length);
  return sortedNs[Math.min(rank, sortedNs.length) - 1];
}

function table(title, rows) {
  const width = Math.max(...rows.map(([label]) => label.length));
  console.log(`\n${title}`);
  console.log("-".repeat(title.length));
  for (const [label, value] of rows) {
    console.log(`  ${label.padEnd(width)}  ${value}`);
  }
}

// --- construction: cold activation, then the first evaluation --------
// Refuses to report numbers for work that never reached the policy. An
// evaluation that fails closed before Rego runs, most easily by failing
// annotation, costs about a tenth of a real decision, and this benchmark
// family has already once timed exactly that while printing plausible
// figures.
{
  const probe = ActivatedPolicy.activate(MANIFEST);
  for (let k = 0; k < POINTS.length; k += 1) {
    const { reason } = probe.evaluate(POINTS[k], SNAPSHOTS[k]);
    if (typeof reason === "string" && reason.startsWith("runtime_error")) {
      console.error(
        `${POINTS[k]} fails closed with '${reason}' before reaching the policy; ` +
          "timing it would measure the error path.",
      );
      process.exit(1);
    }
  }
}

const cold = time(() => ActivatedPolicy.activate(MANIFEST));
const policy = cold.value;
const firstEvaluate = time(() => policy.evaluate(POINTS[1], SNAPSHOTS[1]));

// --- repeat activation -----------------------------------------------
// The compiled-policy cache lives inside an activation, so a repeat
// activation re-reads and re-compiles the bundle; only the OS page cache
// is warm. Reported to make that explicit rather than to imply a
// cross-activation cache the runtime does not have.
const repeatActivations = [];
for (let i = 0; i < REPEAT_ACTIVATIONS; i += 1) {
  repeatActivations.push(time(() => ActivatedPolicy.activate(MANIFEST)).ns);
}
repeatActivations.sort(ascending);

// --- warm evaluation latency ------------------------------------------
for (let i = 0; i < WARMUP_EVALUATIONS; i += 1) {
  const k = i % POINTS.length;
  policy.evaluate(POINTS[k], SNAPSHOTS[k]);
}

const samples = new Array(TIMED_EVALUATIONS);
for (let i = 0; i < TIMED_EVALUATIONS; i += 1) {
  const k = i % POINTS.length;
  const started = process.hrtime.bigint();
  policy.evaluate(POINTS[k], SNAPSHOTS[k]);
  samples[i] = process.hrtime.bigint() - started;
}
const sorted = [...samples].sort(ascending);
const totalNs = samples.reduce((a, b) => a + b, 0n);

// --- throughput: one thread, then 32 -----------------------------------
const serialStarted = process.hrtime.bigint();
for (let i = 0; i < EVALUATIONS_PER_WORKER; i += 1) {
  const k = i % POINTS.length;
  policy.evaluate(POINTS[k], SNAPSHOTS[k]);
}
const serialNs = process.hrtime.bigint() - serialStarted;
const serialThroughput = (EVALUATIONS_PER_WORKER / Number(serialNs)) * 1e9;

// A native handle cannot cross a worker boundary, so each worker
// activates its own policy version — which is how a host would shard
// anyway. Every worker activates and reports ready before the barrier,
// so the measured window contains evaluation only.
async function concurrentThroughput() {
  const workers = Array.from(
    { length: CONCURRENCY },
    () =>
      new Worker(new URL("./evaluate-worker.mjs", import.meta.url), {
        workerData: {
          bankAgent: BANK_AGENT,
          manifest: MANIFEST,
          dist: DIST,
          points: POINTS,
          iterations: EVALUATIONS_PER_WORKER,
        },
      }),
  );

  const message = (worker) =>
    new Promise((resolve, reject) => {
      worker.once("message", (m) => (m.error ? reject(new Error(m.error)) : resolve(m)));
      worker.once("error", reject);
    });

  const ready = workers.map(message);
  await Promise.all(ready);

  const done = workers.map(message);
  const started = process.hrtime.bigint();
  for (const worker of workers) worker.postMessage("go");
  const results = await Promise.all(done);
  const wallNs = process.hrtime.bigint() - started;
  await Promise.all(workers.map((worker) => worker.terminate()));
  return {
    wallNs,
    evaluations: results.reduce((total, r) => total + r.iterations, 0),
    activationMs: results.map((r) => r.activationMs).sort((a, b) => a - b),
  };
}

const concurrent = await concurrentThroughput();
const concurrentPerSec = (concurrent.evaluations / Number(concurrent.wallNs)) * 1e9;

// --- report ------------------------------------------------------------
console.log("Agent Control Specification — Node activation benchmark");
console.log(
  `workload   examples/bank_agent (${path.basename(MANIFEST)}), ${POINTS.length} intervention points, round-robin`,
);
console.log(`runtime    node ${process.version} on ${process.platform}-${process.arch}, ${os.cpus().length} CPUs`);

table("construction + first call", [
  ["cold activation (after the reachability probe)", `${ms(cold.ns).toFixed(2)} ms`],
  ["first evaluate after activation", `${us(firstEvaluate.ns).toFixed(1)} µs`],
]);

table("cold activation vs warm cache hit", [
  ["cold activation", `${ms(cold.ns).toFixed(2)} ms`],
  [
    `repeat activation p50 of ${REPEAT_ACTIVATIONS} (re-read and re-compiled; only the page cache is warm)`,
    `${ms(percentile(repeatActivations, 50)).toFixed(2)} ms`,
  ],
  ["first evaluate after activation (warm cache hit)", `${us(firstEvaluate.ns).toFixed(1)} µs`],
  ["warm evaluate p50 (warm cache hit)", `${us(percentile(sorted, 50)).toFixed(1)} µs`],
  [
    "cold activation costs, in warm evaluations",
    `${Math.round(Number(cold.ns) / Number(percentile(sorted, 50))).toLocaleString("en-US")}`,
  ],
]);

table(
  `warm evaluate latency (${TIMED_EVALUATIONS.toLocaleString("en-US")} iterations, ${WARMUP_EVALUATIONS.toLocaleString("en-US")} warmup excluded)`,
  [
    ["p50", `${us(percentile(sorted, 50)).toFixed(1)} µs`],
    ["p95", `${us(percentile(sorted, 95)).toFixed(1)} µs`],
    ["p99", `${us(percentile(sorted, 99)).toFixed(1)} µs`],
    ["mean", `${(Number(totalNs) / TIMED_EVALUATIONS / 1e3).toFixed(1)} µs`],
    ["max", `${us(sorted[sorted.length - 1]).toFixed(1)} µs`],
  ],
);

table("throughput", [
  ["1 thread", `${Math.round(serialThroughput).toLocaleString("en-US")} evaluations/s`],
  [
    `${CONCURRENCY} worker threads (${EVALUATIONS_PER_WORKER.toLocaleString("en-US")} each, one activation per worker)`,
    `${Math.round(concurrentPerSec).toLocaleString("en-US")} evaluations/s`,
  ],
  ["scaling", `${(concurrentPerSec / serialThroughput).toFixed(1)}x`],
  [
    "per-worker activation p50 (excluded from the throughput window)",
    `${concurrent.activationMs[Math.floor(concurrent.activationMs.length / 2)].toFixed(2)} ms`,
  ],
]);

console.log(
  `\nEvaluation is a synchronous native call, so concurrency here means worker\n` +
    `threads: awaiting the same handle from one event loop would serialize. The\n` +
    `binding holds no interpreter lock and the engine is Sync, so the ${CONCURRENCY} workers run\n` +
    `genuinely in parallel, bounded by the ${os.cpus().length} CPUs on this machine.`,
);
