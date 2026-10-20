// Copyright (c) Microsoft. All rights reserved.

// The wrapper contract: manifest-bound evaluation surfaces as
// agent-hooks verdicts, fail-closed on every failure path, and the
// interceptor registers cleanly with an agent-hooks emitter. `intercept`
// evaluates on a thread of its own and returns a Promise, so the
// emitter's timeout can preempt it; `interceptSync` evaluates inline on
// the JS thread and the two agree on every verdict.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import fs from "node:fs";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const { AcsInterceptor } = require("../dist/index.js");
const { AgentContextBuilder, InterceptionEmitter, EnforcementMode } = require(
  "@responsibleai/agent-hooks",
);

const here = path.dirname(fileURLToPath(import.meta.url));
const manifest = path.join(here, "fixtures", "manifest.yaml");

const builder = () =>
  new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A promise the test resolves by hand. A dispatcher that awaits it is a
// hung dispatcher until the test says otherwise, with no sleep to tune.
function gate() {
  let open;
  const opened = new Promise((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

const workdir = fs.mkdtempSync(path.join(here, ".interceptor-"));
test.after(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

// A custom policy a host dispatcher answers, so the dispatcher decides
// how long an evaluation takes.
function writeCustomPolicyManifest(name) {
  const src = `agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: ${name}
policies:
  gate:
    type: custom
    adapter: host_gate
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
`;
  const p = path.join(workdir, `${name}.yaml`);
  fs.writeFileSync(p, src, "utf8");
  return p;
}

// A bundled HTTP annotator pointed at a local server, so the engine
// itself blocks inside a native call with no JS callback involved.
function writeEndpointManifest(port) {
  const src = `agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: node-endpoint-annotator
policies:
  allow_all:
    type: test
    verdict:
      decision: allow
annotators:
  probe:
    type: endpoint
    endpoint: "http://127.0.0.1:${port}"
    timeout_ms: 5000
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    annotations:
      probe:
        from: "$target.content"
    policy:
      id: allow_all
`;
  const p = path.join(workdir, "endpoint-annotator.yaml");
  fs.writeFileSync(p, src, "utf8");
  return p;
}

test("allow policy permits input", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = await acs.intercept(builder().input("hello"));
  assert.equal(verdict.decision, "allow");
});

test("deny policy blocks a tool call with its reason", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = await acs.intercept(builder().preToolCall("t1", "search", { q: "x" }));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "blocked_by_policy");
  assert.equal(verdict.approval, undefined);
});

test("approval-carrying deny is liftable", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = await acs.intercept(builder().output("final answer"));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "requires_human");
  assert.deepEqual(verdict.approval, {});
});

test("engine failure fails closed as runtime_error deny", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const b = builder();
  b.preToolCall("t1", "search", { q: "x" });
  const verdict = await acs.intercept(b.postToolCall("t1", "search", { q: "x" }, "r"));
  assert.equal(verdict.decision, "deny");
  assert.match(verdict.reason, /^runtime_error:/);
});

test("intercept and interceptSync agree", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  for (const ctx of [
    builder().input("hello"),
    builder().preToolCall("t1", "search", { q: "x" }),
    builder().output("final answer"),
  ]) {
    assert.deepEqual(await acs.intercept(ctx), acs.interceptSync(ctx));
  }
});

test("a non-object context is a boundary problem on both paths", async () => {
  const acs = AcsInterceptor.fromPath(manifest);
  // The async path reports it as a rejection, never as a verdict.
  await assert.rejects(acs.intercept("not an object"), /JSON object/);
  assert.throws(() => acs.interceptSync("not an object"), /JSON object/);
});

test("unreadable manifest is a construction error", () => {
  assert.throws(() => AcsInterceptor.fromPath("/nonexistent/manifest.yaml"), /manifest/);
});

test("maxConcurrency must be a positive integer", () => {
  for (const bad of [0, -1, 1.5, "4", NaN]) {
    assert.throws(
      () => AcsInterceptor.fromPath(manifest, { maxConcurrency: bad }),
      RangeError,
      `maxConcurrency ${String(bad)} was accepted`,
    );
  }
});

test("registers with an agent-hooks emitter end to end", async () => {
  const emitter = new InterceptionEmitter(EnforcementMode.Enforce);
  emitter.register(AcsInterceptor.fromPath(manifest), "acs");
  const b = builder();

  const allowed = await emitter.emitUnchecked(b.input("hello"));
  assert.equal(allowed.verdict.decision, "allow");

  const denied = await emitter.emitUnchecked(b.preToolCall("t1", "search", { q: "x" }));
  assert.equal(denied.verdict.decision, "deny");
  assert.equal(denied.verdict.reason, "blocked_by_policy");
  // Attribution pins the wiring (fields available in the published
  // agent-hooks 0.1.0-alpha.2; newer record fields arrive with its
  // next release).
  assert.equal(denied.decided_by, 0);
  assert.equal(denied.identity_provider, "jcs-sha256");
});

// ---------------------------------------------------------------------
// The point of the async path: a dispatcher that never answers cannot
// hold the emission past the emitter's deadline. The emitter records its
// own `host_error:interceptor_timeout` deny on time, and the event loop
// keeps turning while the evaluation is stuck, which is what lets the
// timer fire at all.
// ---------------------------------------------------------------------

test("the emitter timeout preempts a hung host dispatcher", async () => {
  const hang = gate();
  const acs = AcsInterceptor.fromPath(writeCustomPolicyManifest("hung-dispatcher"), {
    policyDispatcher: async () => {
      await hang.opened;
      return { decision: "allow" };
    },
  });
  const emitter = new InterceptionEmitter(EnforcementMode.Enforce, null, 100);
  emitter.register(acs, "acs");

  let ticked = false;
  setTimeout(() => {
    ticked = true;
  }, 20);
  const started = Date.now();
  const record = await emitter.emitUnchecked(builder().input("hello"));
  const elapsed = Date.now() - started;

  assert.equal(record.verdict.decision, "deny");
  assert.equal(record.verdict.reason, "host_error:interceptor_timeout");
  assert.ok(elapsed < 1500, `timeout deny took ${elapsed} ms`);
  assert.equal(ticked, true, "a timer must fire while the evaluation is blocked");

  // The timeout stopped the wait, not the evaluation. Let it finish so
  // the evaluation thread returns.
  hang.open();
});

test("the emitter timeout preempts a blocked bundled annotator", async () => {
  // The server holds every request open, so the engine blocks inside
  // its own HTTP call on the evaluation thread. No JS callback is involved:
  // this proves the native evaluation itself left the JS thread.
  const held = [];
  const server = createServer((_request, response) => {
    held.push(response);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const acs = AcsInterceptor.fromPath(writeEndpointManifest(server.address().port));
  const emitter = new InterceptionEmitter(EnforcementMode.Enforce, null, 100);
  emitter.register(acs, "acs");

  const started = Date.now();
  const record = await emitter.emitUnchecked(builder().input("hello"));
  const elapsed = Date.now() - started;

  assert.equal(record.verdict.decision, "deny");
  assert.equal(record.verdict.reason, "host_error:interceptor_timeout");
  assert.ok(elapsed < 1500, `timeout deny took ${elapsed} ms`);
  // The JS thread accepted the engine's request while the engine waited
  // on it, so the loop was free the whole time.
  for (let i = 0; held.length === 0 && i < 50; i += 1) {
    await sleep(10);
  }
  assert.equal(held.length, 1, "the engine's request must reach the server");

  // Answer the held request so the evaluation thread returns, then shut
  // down.
  for (const response of held) {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ severity: 1 }));
  }
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

test("process.exit() does not wait for a dispatcher that never settles", async () => {
  // Evaluation threads are the binding's own, not libuv workers. A libuv
  // worker stuck waiting on a host Promise is joined by process.exit(),
  // which then never returns; a thread of the binding's own is not. The
  // child times the hung evaluation out, prints the deny and exits.
  const script = path.join(workdir, "exit-after-timeout.mjs");
  fs.writeFileSync(
    script,
    `import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { AcsInterceptor } = require(${JSON.stringify(path.join(here, "..", "dist", "index.js"))});
const { AgentContextBuilder, InterceptionEmitter, EnforcementMode } = require("@responsibleai/agent-hooks");
const acs = AcsInterceptor.fromPath(${JSON.stringify(writeCustomPolicyManifest("never-settles"))}, {
  policyDispatcher: () => new Promise(() => {}),
});
const emitter = new InterceptionEmitter(EnforcementMode.Enforce, null, 100);
emitter.register(acs, "acs");
const ctx = new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" }).input("hello");
const record = await emitter.emitUnchecked(ctx);
console.log(record.verdict.reason);
process.exit(0);
`,
    "utf8",
  );
  const child = spawnSync(process.execPath, [script], { encoding: "utf8", timeout: 10_000 });
  assert.equal(child.signal, null, `the child had to be killed: ${child.stderr}`);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), "host_error:interceptor_timeout");
});

test("hung evaluations leave the libuv pool to fs, dns and zlib", async () => {
  // More evaluations than libuv's default pool of four, every one stuck
  // in its dispatcher. On that pool a readFile would queue behind them
  // until the dispatcher answered; on the binding's own threads it does
  // not wait.
  const hang = gate();
  const acs = AcsInterceptor.fromPath(writeCustomPolicyManifest("pool-free"), {
    policyDispatcher: async () => {
      await hang.opened;
      return { decision: "allow" };
    },
  });
  const stuck = Array.from({ length: 6 }, (_, i) => acs.intercept(builder().input(`stuck ${i}`)));
  await sleep(50);

  const started = Date.now();
  await fs.promises.readFile(manifest, "utf8");
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 1000, `readFile waited ${elapsed} ms behind hung evaluations`);

  hang.open();
  for (const verdict of await Promise.all(stuck)) {
    assert.equal(verdict.decision, "allow");
  }
});

test("the concurrency cap denies with acs_async_capacity_exceeded", async () => {
  const hang = gate();
  const acs = AcsInterceptor.fromPath(writeCustomPolicyManifest("capped"), {
    maxConcurrency: 1,
    policyDispatcher: async () => {
      await hang.opened;
      return { decision: "allow" };
    },
  });

  const first = acs.intercept(builder().input("one"));
  const second = await acs.intercept(builder().input("two"));
  assert.equal(second.decision, "deny");
  assert.equal(second.reason, "runtime_error:acs_async_capacity_exceeded");
  assert.match(second.message, /maxConcurrency/);

  hang.open();
  assert.equal((await first).decision, "allow");
  // Capacity comes back once the evaluation settles.
  assert.equal((await acs.intercept(builder().input("three"))).decision, "allow");
});

test("the cap deny passes the emitter's verdict gate as written", async () => {
  // The reason is registered in spec/reserved-reasons.json for the ACS
  // async adapter, so the §5 gate must keep it rather than rewrite it
  // as a host error.
  const hang = gate();
  const acs = AcsInterceptor.fromPath(writeCustomPolicyManifest("capped-emitter"), {
    maxConcurrency: 1,
    policyDispatcher: async () => {
      await hang.opened;
      return { decision: "allow" };
    },
  });
  const emitter = new InterceptionEmitter(EnforcementMode.Enforce);
  emitter.register(acs, "acs");

  const both = Promise.all([
    emitter.emitUnchecked(builder().input("one")),
    emitter.emitUnchecked(builder().input("two")),
  ]);
  await sleep(20);
  hang.open();
  const reasons = (await both).map((record) => [record.verdict.decision, record.verdict.reason ?? null]);
  assert.deepEqual(reasons.sort(), [
    ["allow", null],
    ["deny", "runtime_error:acs_async_capacity_exceeded"],
  ]);
});
