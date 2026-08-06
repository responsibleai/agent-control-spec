// The activation contract: one policy version readied once, evaluated
// many times, fail-closed on every failure path, and boundary problems
// thrown rather than returned as verdicts.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const { ActivatedPolicy } = require("../dist/index.js");
const { AgentContextBuilder } = require("@responsibleai/agent-hooks");

const manifest = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "manifest.yaml",
);

const builder = () =>
  new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" });

test("activate then evaluate a bound point", () => {
  const policy = ActivatedPolicy.activate(manifest);
  const verdict = policy.evaluate("input", builder().input("hello"));
  assert.equal(verdict.decision, "allow");
});

test("one activation serves every bound point", () => {
  const policy = ActivatedPolicy.activate(manifest);
  const denied = policy.evaluate(
    "pre_tool_call",
    builder().preToolCall("t1", "search", { q: "x" }),
  );
  assert.equal(denied.decision, "deny");
  assert.equal(denied.reason, "blocked_by_policy");

  const escalated = policy.evaluate("output", builder().output("final answer"));
  assert.equal(escalated.decision, "deny");
  assert.equal(escalated.reason, "requires_human");
  assert.deepEqual(escalated.approval, {});
});

test("intervention points report what the version governs", () => {
  const policy = ActivatedPolicy.activate(manifest);
  const points = policy.interventionPoints();
  assert.deepEqual(
    [...points].sort(),
    ["input", "output", "post_tool_call", "pre_tool_call"],
  );
  assert.equal(policy.governs("input"), true);
  assert.equal(policy.governs("pre_model_call"), false);
  // Frozen, so a caller cannot edit the activated version's view of
  // itself.
  assert.throws(() => points.push("agent_startup"), TypeError);
});

test("a point the policy does not bind fails closed rather than throwing", () => {
  const policy = ActivatedPolicy.activate(manifest);
  const verdict = policy.evaluate("pre_model_call", builder().input("hello"));
  assert.equal(verdict.decision, "deny");
  assert.match(verdict.reason, /^runtime_error:/);
});

test("an unknown point name is a boundary error", () => {
  const policy = ActivatedPolicy.activate(manifest);
  assert.throws(
    () => policy.evaluate("not_a_point", builder().input("hello")),
    /unknown intervention point/,
  );
});

test("engine failure fails closed as runtime_error deny", () => {
  const policy = ActivatedPolicy.activate(manifest);
  const b = builder();
  b.preToolCall("t1", "search", { q: "x" });
  const verdict = policy.evaluate(
    "post_tool_call",
    b.postToolCall("t1", "search", { q: "x" }, "r"),
  );
  assert.equal(verdict.decision, "deny");
  assert.match(verdict.reason, /^runtime_error:/);
});

test("an unreadable manifest is an activation error", () => {
  assert.throws(() => ActivatedPolicy.activate("/nonexistent/manifest.yaml"), /manifest/);
});

test("concurrent evaluation shares one activation", async () => {
  const policy = ActivatedPolicy.activate(manifest);
  const cases = [
    ["input", builder().input("hello"), "allow"],
    ["pre_tool_call", builder().preToolCall("t1", "search", { q: "x" }), "deny"],
    ["output", builder().output("final answer"), "deny"],
  ];
  const verdicts = await Promise.all(
    Array.from({ length: 128 }, async (_, i) => {
      const [point, context, expected] = cases[i % cases.length];
      // Yield first, so the evaluations interleave rather than running
      // as one synchronous run.
      await Promise.resolve();
      return [policy.evaluate(point, context), expected];
    }),
  );
  for (const [verdict, expected] of verdicts) {
    assert.equal(verdict.decision, expected);
  }
});
