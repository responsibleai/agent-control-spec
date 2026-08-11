// Streaming mediation surface (spec §18.1).
//
// The engine is stateless everywhere else, so a rune-addressable
// track a host emits incrementally cannot ride the ordinary
// interceptor pipeline. `StreamSession` is the accounting layer that
// makes both a mid-stream deny and a cleared-prefix release possible.
// These tests pin the wire contract other language SDKs also
// implement, and the correctness traps a Node-only implementation is
// most likely to fall into: UTF-16 rune-counting drift and a settled
// session leaking a released offset.
import assert from "node:assert/strict";
import { test } from "node:test";

const require = (await import("node:module")).createRequire(import.meta.url);
const { StreamSession } = require("../dist/index.js");

test("happy path clears, advances, and finishes clean", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["pii"],
  });

  assert.equal(s.observeText("model_generated", "hello"), 5);
  // Nothing has cleared yet, so the safe offset stays at the start.
  assert.equal(s.safeOffset("response"), 0);
  assert.equal(s.pending("response"), 5);

  s.recordOutcome("pii", "model_generated", 0, 5, "cleared");
  assert.equal(s.advance("response"), 5);
  assert.equal(s.safeOffset("response"), 5);

  const mark = s.watermark("response");
  assert.equal(mark.track, "response");
  assert.equal(mark.confirmed, 5);
  assert.equal(mark.received, 5);
  assert.equal(mark.pending, 0);
  assert.deepEqual(mark.tasks, ["pii"]);

  const completion = s.finish();
  assert.equal(completion.reason.kind, "complete");
  assert.equal(completion.isClean, true);
  assert.equal(completion.transformed, false);
  // A settled session releases nothing further. `null` says that in
  // the type: the caller cannot read it as an offset by accident.
  assert.equal(s.safeOffset("response"), null);
  assert.equal(s.advance("response"), null);
});

test("a deny ends the session and safeOffset becomes null, but watermark still shows how far it got", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
  });

  s.observeText("model_generated", "cleared prefix");
  s.recordOutcome("safety", "model_generated", 0, 7, "cleared");
  s.advance("response");
  assert.equal(s.safeOffset("response"), 7);

  s.observeText("model_generated", "!!!DANGER!!!");
  s.recordOutcome("safety", "model_generated", 14, 26, "denied");

  // Every rune the host has not already emitted must be withheld,
  // including runes a task had cleared. The type says that.
  assert.equal(s.safeOffset("response"), null);
  assert.equal(s.advance("response"), null);

  // The audit path stays open: the watermark still says how far the
  // track got before the deny.
  const mark = s.watermark("response");
  assert.equal(mark.confirmed, 7);
  assert.equal(mark.received, 26);

  const reason = s.endReason();
  assert.equal(reason.kind, "denied");
  assert.equal(reason.track, "response");
  assert.equal(reason.task, "safety");
  assert.equal(reason.start, 14);
  assert.equal(reason.end, 26);

  const completion = s.finish();
  assert.equal(completion.reason.kind, "denied");
  assert.equal(completion.isClean, false);
  assert.equal(completion.transformed, false);
});

test("a span needs every task to clear before the watermark advances", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["pii", "safety"],
  });

  s.observeText("model_generated", "hello world");
  s.recordOutcome("pii", "model_generated", 0, 11, "cleared");
  // One task cleared, the other has not, so the confirmed offset must
  // not move: releasing the prefix would skip `safety`.
  assert.equal(s.advance("response"), null);
  assert.equal(s.safeOffset("response"), 0);

  s.recordOutcome("safety", "model_generated", 0, 11, "cleared");
  assert.equal(s.advance("response"), 11);
  assert.equal(s.safeOffset("response"), 11);

  const mark = s.watermark("response");
  assert.deepEqual(mark.tasks, ["pii", "safety"]);
  assert.equal(mark.confirmed, 11);
});

test("observeText counts runes, not UTF-16 code units", () => {
  // 🙂 is one Unicode scalar (U+1F642) but two UTF-16 code units in a
  // JS string. If observeText leaked the JS length instead of the
  // engine's rune count, the received offset would come back as 2 and
  // every downstream offset would slide by one for every emoji.
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["pii"],
  });

  const text = "🙂";
  assert.equal(text.length, 2, "JS string length reports UTF-16 code units");
  assert.equal(s.observeText("model_generated", text), 1);
  assert.equal(s.watermark("response").received, 1);

  // Recording an outcome over the UTF-16 length (2) would be past the
  // observed end of the track. It must be past the end here.
  assert.throws(
    () => s.recordOutcome("pii", "model_generated", 0, 2, "cleared"),
    /past end|OffsetPastEnd|offset/i,
  );

  // But the actual rune span clears fine.
  const s2 = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["pii"],
  });
  s2.observeText("model_generated", "🙂");
  s2.recordOutcome("pii", "model_generated", 0, 1, "cleared");
  assert.equal(s2.advance("response"), 1);
  assert.equal(s2.finish().isClean, true);
});

test("an unmediated track releases without evaluation", () => {
  // Empty response task set: the response track is not mediated at
  // all, so text on it fails closed while the request track releases
  // as usual. This is the ordinary shape for a host guarding only the
  // user prompt.
  const s = new StreamSession({
    safetyLevel: "blocking",
    requestTasks: ["moderation"],
    responseTasks: [],
  });

  s.observeText("user_request", "hello");
  s.recordOutcome("moderation", "user_request", 0, 5, "cleared");
  assert.equal(s.advance("request"), 5);
  assert.equal(s.safeOffset("request"), 5);

  // Payload on the unmediated response track fails closed, because
  // nothing would gate it.
  assert.throws(() => s.observeText("model_generated", "reply"), /NoTasks|not mediated|response/i);

  // The failed observe put the session into its terminal state.
  const reason = s.endReason();
  assert.equal(reason.kind, "failed");
  assert.match(reason.reason, /^host_error:/);
});

test("unknown safety level and unknown track throw with the engine's message", () => {
  assert.throws(
    () => new StreamSession({ safetyLevel: "permissive", responseTasks: ["t"] }),
    /permissive|unknown/i,
  );

  const s = new StreamSession({ safetyLevel: "blocking", responseTasks: ["t"] });
  assert.throws(() => s.safeOffset("nope"), /nope|unknown/i);
  assert.throws(() => s.advance("nope"), /nope|unknown/i);
  assert.throws(() => s.watermark("nope"), /nope|unknown/i);
  assert.throws(() => s.pending("nope"), /nope|unknown/i);

  assert.throws(
    () => new StreamSession({ safetyLevel: "blocking" }),
    /NoTracksMediated|neither|no tasks/i,
  );
});

test("request and response tracks carry independent offsets", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    requestTasks: ["moderation"],
    responseTasks: ["safety"],
  });

  s.observeText("user_request", "user prompt");
  s.observeText("model_generated", "model reply");

  // Each track has its own confirmed and received frontier.
  assert.equal(s.watermark("request").received, 11);
  assert.equal(s.watermark("response").received, 11);
  assert.equal(s.watermark("request").confirmed, 0);
  assert.equal(s.watermark("response").confirmed, 0);

  // Clearing the request must not release the response.
  s.recordOutcome("moderation", "user_request", 0, 11, "cleared");
  s.advance("request");
  assert.equal(s.safeOffset("request"), 11);
  assert.equal(s.safeOffset("response"), 0);
  assert.equal(s.pending("response"), 11);

  // Clearing the response then releases only that track.
  s.recordOutcome("safety", "model_generated", 0, 11, "cleared");
  s.advance("response");
  assert.equal(s.safeOffset("response"), 11);
  assert.equal(s.finish().isClean, true);
});

test("resume offsets keep offsets comparable across a retry", () => {
  // A retry that re-sends the prompt and resumes the response reports
  // its resume point through `responseStartRuneOffset`. The received
  // frontier starts at that offset, so an outcome over the resumed
  // range clears without releasing the gap.
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
    responseStartRuneOffset: 12,
  });

  const mark = s.watermark("response");
  assert.equal(mark.confirmed, 12);
  assert.equal(mark.received, 12);

  s.observeText("model_generated", "continued");
  s.recordOutcome("safety", "model_generated", 12, 21, "cleared");
  s.advance("response");
  assert.equal(s.safeOffset("response"), 21);
  assert.equal(s.finish().isClean, true);
});

test("recordVerdict routes an allow verdict as a clear", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
  });
  s.observeText("model_generated", "hello");
  s.recordVerdict("safety", "model_generated", 0, 5, {
    decision: "allow",
    warnings: [],
    result_labels: [],
  });
  assert.equal(s.advance("response"), 5);
  assert.equal(s.finish().isClean, true);
});

test("recordVerdict deny ends the session with the engine's terminal reason", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
  });
  s.observeText("model_generated", "hello");
  s.recordVerdict("safety", "model_generated", 0, 5, {
    decision: "deny",
    reason: "policy_blocked",
    warnings: [],
    result_labels: [],
  });
  const completion = s.finish();
  assert.equal(completion.reason.kind, "denied");
  assert.equal(completion.reason.task, "safety");
  assert.equal(completion.isClean, false);
});

test("transform before any release ends the session rewritten under a withholding level", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
  });
  s.observeText("model_generated", "raw");
  s.recordOutcome("safety", "model_generated", 0, 3, "transformed");
  assert.equal(s.isTransformed(), true);
  const completion = s.finish();
  assert.equal(completion.reason.kind, "rewritten");
  assert.equal(completion.transformed, true);
  assert.equal(completion.isClean, false);
});

test("finish twice returns the same completion", () => {
  const s = new StreamSession({
    safetyLevel: "blocking",
    responseTasks: ["safety"],
  });
  s.observeText("model_generated", "ok");
  s.recordOutcome("safety", "model_generated", 0, 2, "cleared");
  const first = s.finish();
  const second = s.finish();
  assert.deepEqual(first, second);
});
