// One thread of the concurrency-32 leg of activation.bench.mjs.
//
// Each worker activates its own policy version: a native handle is not
// transferable across a worker boundary, and sharding activations is how
// a host would run this anyway. Activation happens before the parent's
// go signal, so it stays outside the measured window.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { parentPort, workerData } from "node:worker_threads";

const require = createRequire(import.meta.url);
const { bankAgent, manifest, dist, points, iterations } = workerData;

try {
  const { ActivatedPolicy } = require(dist);
  const snapshots = points.map((point) =>
    JSON.parse(fs.readFileSync(path.join(bankAgent, "snapshots", `${point}.json`), "utf8")),
  );

  const activationStarted = process.hrtime.bigint();
  const policy = ActivatedPolicy.activate(manifest);
  const activationMs = Number(process.hrtime.bigint() - activationStarted) / 1e6;

  // Warm this thread's own code paths, so the measured window is steady
  // state on every worker rather than JIT warmup on some of them.
  for (let i = 0; i < 200; i += 1) {
    const k = i % points.length;
    policy.evaluate(points[k], snapshots[k]);
  }

  parentPort.postMessage({ ready: true, activationMs });
  parentPort.once("message", () => {
    for (let i = 0; i < iterations; i += 1) {
      const k = i % points.length;
      policy.evaluate(points[k], snapshots[k]);
    }
    parentPort.postMessage({ iterations, activationMs });
  });
} catch (error) {
  parentPort.postMessage({ error: String(error && error.stack ? error.stack : error) });
}
