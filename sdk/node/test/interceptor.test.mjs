// The wrapper contract: manifest-bound evaluation surfaces as
// agent-hooks verdicts, fail-closed on every failure path, and the
// interceptor registers cleanly with an agent-hooks emitter.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const { AcsInterceptor } = require("../dist/index.js");
const { AgentContextBuilder, InterceptionEmitter, EnforcementMode } = require(
  "@responsibleai/agent-hooks",
);

const manifest = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "manifest.yaml",
);

const builder = () =>
  new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" });

test("allow policy permits input", () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = acs.intercept(builder().input("hello"));
  assert.equal(verdict.decision, "allow");
});

test("deny policy blocks a tool call with its reason", () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = acs.intercept(builder().preToolCall("t1", "search", { q: "x" }));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "blocked_by_policy");
  assert.equal(verdict.approval, undefined);
});

test("approval-carrying deny is liftable", () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const verdict = acs.intercept(builder().output("final answer"));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "requires_human");
  assert.deepEqual(verdict.approval, {});
});

test("engine failure fails closed as runtime_error deny", () => {
  const acs = AcsInterceptor.fromPath(manifest);
  const b = builder();
  b.preToolCall("t1", "search", { q: "x" });
  const verdict = acs.intercept(b.postToolCall("t1", "search", { q: "x" }, "r"));
  assert.equal(verdict.decision, "deny");
  assert.match(verdict.reason, /^runtime_error:/);
});

test("unreadable manifest is a construction error", () => {
  assert.throws(() => AcsInterceptor.fromPath("/nonexistent/manifest.yaml"), /manifest/);
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
