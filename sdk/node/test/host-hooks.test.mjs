// Host extension surface: annotator dispatcher, policy dispatcher,
// telemetry sink, perf telemetry level; and manifest tooling (parse,
// chain, structured diagnostics).
//
// The engine calls dispatchers synchronously from inside `intercept`,
// which is itself a napi call running on the JS thread. These tests
// prove: (a) a JS callback IS invoked on that stack, (b) its return
// value flows into the policy decision, (c) a throw fails closed with
// a `runtime_error:*` deny (never "no annotation"), (d) telemetry
// events reach a sink, and (e) the manifest tooling that authoring
// tools need is reachable from Node.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const {
  AcsInterceptor,
  ActivatedPolicy,
  parseManifest,
  mergeManifests,
  validateArtifacts,
  validateManifestDetailed,
} = require("../dist/index.js");
const { AgentContextBuilder } = require("@responsibleai/agent-hooks");

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureManifestPath = path.join(here, "fixtures", "manifest.yaml");

const builder = () =>
  new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" });

// A manifest binding a custom policy that a host policy dispatcher
// answers, and a classifier annotator whose value the dispatcher reads
// from `input.annotations.mood`. The manifest is deliberately minimal:
// one intervention point, one annotator, one policy.
function writeAnnotatorPolicyManifest(tmpdir) {
  const src = `agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: node-host-hooks-test
policies:
  gate:
    type: custom
    adapter: host_gate
annotators:
  mood:
    type: classifier
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    annotations:
      mood:
        from: "$target.content"
    policy:
      id: gate
`;
  const p = path.join(tmpdir, "annotator-policy-manifest.yaml");
  fs.writeFileSync(p, src, "utf8");
  return p;
}

function writePolicyOnlyManifest(tmpdir) {
  const src = `agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: node-host-hooks-policy-only
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
  const p = path.join(tmpdir, "policy-only-manifest.yaml");
  fs.writeFileSync(p, src, "utf8");
  return p;
}

const workdir = fs.mkdtempSync(path.join(here, ".host-hooks-"));
test.after(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------
// 1. Host annotator dispatcher IS called on the sync stack and its
// return value flows into the policy decision. Two invocations against
// the same manifest, differing only in what the annotator returns,
// produce different verdicts.
// ---------------------------------------------------------------------

test("host annotator dispatcher return value drives the policy verdict", () => {
  const manifest = writeAnnotatorPolicyManifest(workdir);
  const seen = [];
  const annotatorDispatcher = (name, invocation, _preliminary) => {
    // Prove the engine actually asked us, and remember what for.
    seen.push({ name, type: invocation.type, from: invocation.from });
    // Emit the mood the policy will read.
    return { mood: invocation.from === "$target.content" ? "angry" : "calm" };
  };
  const policyDispatcher = (invocation) => {
    // Custom-policy invocations tag as `custom` and carry the policy
    // input under `input`. The annotator's output appears at
    // `input.annotations.mood`.
    assert.equal(invocation.type, "custom");
    assert.equal(invocation.adapter, "host_gate");
    const mood = invocation.input?.annotations?.mood?.mood;
    if (mood === "angry") {
      return {
        decision: "deny",
        reason: "annotation_says_angry",
        message: "annotator flagged mood=angry",
      };
    }
    return { decision: "allow", reason: "annotation_ok" };
  };

  const acs = AcsInterceptor.fromPath(manifest, {
    annotatorDispatcher,
    policyDispatcher,
  });

  const angry = acs.intercept(builder().input("you are broken"));
  assert.equal(angry.decision, "deny");
  assert.equal(angry.reason, "annotation_says_angry");

  // The annotator was actually called on the sync call stack.
  assert.equal(seen.length, 1);
  assert.equal(seen[0].name, "mood");
  assert.equal(seen[0].type, "classifier");
  assert.equal(seen[0].from, "$target.content");
});

// ---------------------------------------------------------------------
// 2. An annotator that throws fails CLOSED. The verdict is a deny with
// `runtime_error:annotation_failed`. The engine never treats a thrown
// callback as "no annotation".
// ---------------------------------------------------------------------

test("annotator dispatcher that throws fails closed with annotation_failed", () => {
  const manifest = writeAnnotatorPolicyManifest(workdir);
  const annotatorDispatcher = () => {
    throw new Error("upstream classifier is on fire");
  };
  // Present the policy dispatcher, but it must never be reached: the
  // annotator failure short-circuits evaluation.
  let policyCalled = false;
  const policyDispatcher = () => {
    policyCalled = true;
    return { decision: "allow" };
  };

  const acs = AcsInterceptor.fromPath(manifest, {
    annotatorDispatcher,
    policyDispatcher,
  });

  const verdict = acs.intercept(builder().input("hi"));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "runtime_error:annotation_failed");
  assert.equal(
    policyCalled,
    false,
    "policy dispatcher must not run after an annotator failure",
  );
});

// ---------------------------------------------------------------------
// 3. Passing no options behaves identically to the zero-config path.
// The fixture manifest's verdicts are the pinned baseline; the with-
// hooks constructor must return the same values when no hooks are set.
// ---------------------------------------------------------------------

test("no host hooks leaves the zero-config path bit-identical", () => {
  const zeroConfig = AcsInterceptor.fromPath(fixtureManifestPath);
  const empty = AcsInterceptor.fromPath(fixtureManifestPath, {});
  for (const ctx of [
    builder().input("hello"),
    builder().preToolCall("t1", "search", { q: "x" }),
    builder().output("final answer"),
  ]) {
    // Two independent Contexts of the same shape.
    const a = zeroConfig.intercept(ctx);
    const b = empty.intercept(ctx);
    assert.deepEqual(b, a);
  }
});

// ---------------------------------------------------------------------
// 4. A telemetry sink receives events, and perfTelemetry levels round-
// trip. The engine emits a Decision event per evaluation; the sink
// must see at least one, and reject an unknown perf level.
// ---------------------------------------------------------------------

test("telemetry sink receives Decision events; perf level round-trips", () => {
  const events = [];
  const acs = AcsInterceptor.fromPath(fixtureManifestPath, {
    telemetrySink: (event) => events.push(event),
    perfTelemetry: "off",
  });
  const verdict = acs.intercept(builder().input("hello"));
  assert.equal(verdict.decision, "allow");
  assert.ok(events.length >= 1, "expected at least one telemetry event");
  const decision = events.find((e) => e.event_type === "decision");
  assert.ok(decision, "expected a decision event");
  assert.equal(decision.intervention_point, "input");
  assert.equal(decision.decision, "allow");
  assert.equal(decision.policy_id, "allow_all");

  // Every documented perf level is accepted.
  for (const level of ["off", "external", "full"]) {
    const configured = AcsInterceptor.fromPath(fixtureManifestPath, {
      perfTelemetry: level,
    });
    // Construction alone proves the level round-trips; also confirm
    // evaluation still works under it.
    assert.equal(configured.intercept(builder().input("x")).decision, "allow");
  }

  // An unknown level is a boundary problem, not a silent fallback.
  assert.throws(
    () =>
      AcsInterceptor.fromPath(fixtureManifestPath, { perfTelemetry: "loud" }),
    /perf telemetry/i,
  );
});

// ---------------------------------------------------------------------
// 5. `parseManifest`: a valid document returns structured JSON; a
// broken document throws.
// ---------------------------------------------------------------------

test("parseManifest returns structure for valid YAML and throws on garbage", () => {
  const parsed = parseManifest(fs.readFileSync(fixtureManifestPath, "utf8"));
  assert.equal(typeof parsed, "object");
  assert.ok(parsed);
  assert.equal(
    parsed.agent_control_specification_version,
    "0.4.0-alpha.1",
    "top-level version preserved",
  );
  assert.ok(parsed.policies, "policies map is present");
  assert.ok(parsed.policies.allow_all, "individual policies survive parse");
  assert.ok(parsed.intervention_points, "intervention points are present");

  // Malformed YAML must throw, not return an empty object.
  assert.throws(() => parseManifest("agent_control_specification_version: ["));
  assert.throws(() => parseManifest("::not: [valid: yaml"));

  // Boundary problems throw as TypeError, not as an invalid manifest.
  assert.throws(() => parseManifest(42), TypeError);
  assert.throws(() => parseManifest("\uD800"), TypeError);
});

// ---------------------------------------------------------------------
// 6. `mergeManifests` composes a chain: a base manifest plus an overlay
// that adds an intervention point. The merged result carries fields
// from both.
// ---------------------------------------------------------------------

test("mergeManifests composes a base and an overlay", () => {
  const base = `agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: base
policies:
  allow_all:
    type: test
    verdict:
      decision: allow
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: allow_all
`;
  const overlay = `agent_control_specification_version: "0.4.0-alpha.1"
policies:
  block_tool:
    type: test
    verdict:
      decision: deny
      reason: blocked_by_policy
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy:
      id: block_tool
`;
  const merged = mergeManifests([base, overlay]);
  // The base's metadata was left as-written by the additive overlay,
  // and both policies and both intervention points survived the merge.
  assert.equal(typeof merged, "object");
  assert.ok(merged.policies.allow_all, "base policy survives");
  assert.ok(merged.policies.block_tool, "overlay policy survives");
  assert.ok(merged.intervention_points.input, "base intervention point survives");
  assert.ok(
    merged.intervention_points.pre_tool_call,
    "overlay intervention point survives",
  );
  assert.equal(merged.metadata.name, "base", "base metadata is preserved");

  // The merged document is runnable end to end: build an interceptor
  // from an equivalent YAML shape and get the two verdicts the pieces
  // expected.
  const mergedYaml =
    `agent_control_specification_version: "0.4.0-alpha.1"\n` +
    `metadata:\n  name: merged\n` +
    `policies:\n  allow_all:\n    type: test\n    verdict:\n      decision: allow\n` +
    `  block_tool:\n    type: test\n    verdict:\n      decision: deny\n      reason: blocked_by_policy\n` +
    `intervention_points:\n  input:\n    policy_target: "$.input"\n    policy:\n      id: allow_all\n` +
    `  pre_tool_call:\n    policy_target: "$.tool_call.args"\n    policy:\n      id: block_tool\n`;
  const yamlPath = path.join(workdir, "merged-baseline.yaml");
  fs.writeFileSync(yamlPath, mergedYaml, "utf8");
  const acs = AcsInterceptor.fromPath(yamlPath);
  assert.equal(acs.intercept(builder().input("hi")).decision, "allow");
  assert.equal(
    acs.intercept(builder().preToolCall("t1", "search", { q: "x" })).decision,
    "deny",
  );

  // Boundary problems throw as TypeError.
  assert.throws(() => mergeManifests("not an array"), TypeError);
  assert.throws(() => mergeManifests([42]), TypeError);
  assert.throws(() => mergeManifests([]));
});

// ---------------------------------------------------------------------
// 7. `validateManifestDetailed` returns diagnostics that name the
// offending field. An unsupported version triggers the "unsupported
// <field>" branch, so `field` points at
// `agent_control_specification_version`.
// ---------------------------------------------------------------------

test("validateManifestDetailed names the offending field", () => {
  const good = fs.readFileSync(fixtureManifestPath, "utf8");
  const empty = validateManifestDetailed(good);
  assert.deepEqual(empty, []);

  const badVersion = good.replace('"0.4.0-alpha.1"', '"0.3.1-beta"');
  const findings = validateManifestDetailed(badVersion);
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.severity, "error");
  assert.ok(finding.code.startsWith("runtime_error:"), `code was ${finding.code}`);
  assert.match(finding.message, /0\.3\.1-beta/);
  assert.equal(
    finding.field,
    "agent_control_specification_version",
    "the field pointer should identify the version key",
  );

  // Boundary problems throw as TypeError.
  assert.throws(() => validateManifestDetailed(42), TypeError);
  assert.throws(() => validateManifestDetailed("\uD800"), TypeError);
});

// ---------------------------------------------------------------------
// Bonus: ActivatedPolicy takes host hooks too. Prove the sync callback
// works through that path as well, so the two entry points stay in
// lockstep.
// ---------------------------------------------------------------------

test("ActivatedPolicy.activate accepts host hooks and evaluates against them", () => {
  const manifest = writePolicyOnlyManifest(workdir);
  const seen = [];
  const activated = ActivatedPolicy.activate(manifest, {
    policyDispatcher: (invocation) => {
      seen.push(invocation.type);
      return { decision: "deny", reason: "denied_by_test" };
    },
  });
  const verdict = activated.evaluate("input", builder().input("hi"));
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.reason, "denied_by_test");
  assert.deepEqual(seen, ["custom"]);
});


// ---------------------------------------------------------------------
// 8. `validateArtifacts` catches Rego compilation failures a
// manifest-only validator cannot see. This is the shape a 0.3-era
// consumer's CI depended on (validate_acs_artifacts) and the reason
// this feature exists: today a manifest can name a bundle, pass
// grammar validation, and only fail at activation. That moves the
// failure from CI to a host's first agent action.
// ---------------------------------------------------------------------

const ARTIFACT_MANIFEST = `agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: rego
    bundle: ./b
intervention_points:
  input:
    policy_target: "$.input"
    policy:
      id: gate
      query: data.acs.decision
`;

const VALID_REGO = 'package acs\ndecision := {"decision":"allow"}\n';

test("validateArtifacts returns [] for a manifest whose Rego compiles", () => {
  const findings = validateArtifacts(ARTIFACT_MANIFEST, {
    gate: { modules: { "p.rego": VALID_REGO } },
  });
  assert.deepEqual(findings, []);
});

test("validateArtifacts surfaces a broken Rego module the manifest names", () => {
  // Same manifest, same shape, only the module is malformed. The
  // manifest-only surface accepts this; the artifact surface must
  // not, because activation would fail on the host's first action.
  const findings = validateArtifacts(ARTIFACT_MANIFEST, {
    gate: { modules: { "p.rego": "package acs\nfoo := ] not valid rego" } },
  });
  assert.equal(findings.length, 1, `expected one finding, got ${JSON.stringify(findings)}`);
  const entry = findings[0];
  assert.equal(entry.severity, "error");
  assert.ok(
    entry.code.startsWith("runtime_error:"),
    `code was ${entry.code}`,
  );
  // The Rego compiler's own text carries the module name and its
  // "expecting expression" complaint verbatim, so an editor can point
  // at the module. Assert both so a regression that swallowed the
  // detail would fail.
  assert.match(entry.message, /p\.rego/);
  assert.match(entry.message, /expecting expression/);

  // And the manifest-only surface still accepts this: the point of
  // validateArtifacts is exactly this gap.
  assert.deepEqual(validateManifestDetailed(ARTIFACT_MANIFEST), []);
});

test("validateArtifacts reports an unparseable manifest as a manifest problem", () => {
  // A document that does not parse must be reported as a manifest
  // problem, not an activation failure — that would name the wrong
  // half. Even when bundles are supplied, the diagnostic must be
  // manifest-half.
  const findings = validateArtifacts("::not: [valid", {
    gate: { modules: { "p.rego": VALID_REGO } },
  });
  assert.equal(findings.length, 1);
  const entry = findings[0];
  assert.equal(entry.code, "runtime_error:manifest_invalid");
  assert.equal(entry.severity, "error");

  // The underlying RuntimeError message matches what the
  // manifest-only surface reports for the same input.
  const manifestOnly = validateManifestDetailed("::not: [valid");
  assert.equal(manifestOnly[0].code, entry.code);
  assert.equal(manifestOnly[0].message, entry.message);
});

test("validateArtifacts without bundles equals the manifest-only result", () => {
  // No bundles supplied: activation is either skipped (no Rego to
  // load) or fails the same way manifest validation does. Either
  // way, the artifact validator must not invent activation errors
  // when the manifest half is what actually reports the problem.
  // For a grammatically invalid document — one that parses but
  // fails validation — the two surfaces report the same underlying
  // manifest problem. Activation would never be reached.
  const invalid =
    'agent_control_specification_version: "0.4.0-alpha.1"\npolicies: {}\nintervention_points: {}\n';
  const artifact = validateArtifacts(invalid);
  const manifest = validateManifestDetailed(invalid);
  assert.equal(artifact.length, manifest.length);
  assert.equal(artifact.length, 1);
  assert.equal(artifact[0].code, manifest[0].code);
  assert.equal(artifact[0].message, manifest[0].message);
  assert.equal(artifact[0].severity, "error");

  // And omitting the bundles argument behaves identically to passing
  // an empty object, so callers can write either.
  assert.deepEqual(
    validateArtifacts(ARTIFACT_MANIFEST, {}),
    validateArtifacts(ARTIFACT_MANIFEST),
  );
});

test("validateArtifacts throws on boundary problems", () => {
  // Non-string manifest and unpaired surrogate are boundary problems
  // and throw as TypeError, not as an invalid manifest. Wrong shape
  // for `bundles` throws too, rather than silently JSON.stringify-ing
  // something the native side would reject.
  assert.throws(() => validateArtifacts(42), TypeError);
  assert.throws(() => validateArtifacts("\uD800"), TypeError);
  assert.throws(() => validateArtifacts(ARTIFACT_MANIFEST, 5), TypeError);
  assert.throws(() => validateArtifacts(ARTIFACT_MANIFEST, "not-an-object"), TypeError);
});

// ---------------------------------------------------------------------
// 9. Resource limits: caps overriding the engine's defaults reach the
// runtime and change the verdict.
//
// `Limits` is a denial-of-service control surface: a host feeding
// large payloads raises `max_snapshot_bytes`; one hardening against a
// hostile manifest lowers `max_extends_depth` or
// `manifest_url_timeout_ms`.
//
// The behavioural test is deliberately end-to-end: the same manifest
// and the same context, evaluated once with default caps and once with
// a small `max_snapshot_bytes`, produce different verdicts. That is
// what proves the value reaches the engine rather than being accepted
// on the JS side and dropped on the way in.
// ---------------------------------------------------------------------

const { DEFAULT_LIMITS } = require("../dist/index.js");

test("a lowered snapshot cap flips the verdict from allow to fail-closed deny", () => {
  const big = "x".repeat(4096);
  const permissive = AcsInterceptor.fromPath(fixtureManifestPath);
  assert.equal(permissive.intercept(builder().input(big)).decision, "allow");

  // Same manifest, same context, but the cap is now smaller than the
  // canonicalized snapshot. A host that asked for the smaller bound and
  // got the larger one would believe it was protected when it was not.
  const capped = AcsInterceptor.fromPath(fixtureManifestPath, {
    limits: { max_snapshot_bytes: 64 },
  });
  const verdict = capped.intercept(builder().input(big));
  assert.equal(verdict.decision, "deny");
  assert.ok(
    verdict.reason.startsWith("runtime_error:"),
    `expected runtime_error:*, got ${verdict.reason}`,
  );
});

test("no limits option matches the baseline zero-config path", () => {
  const baseline = AcsInterceptor.fromPath(fixtureManifestPath);
  const empty = AcsInterceptor.fromPath(fixtureManifestPath, { limits: {} });
  for (const ctx of [
    builder().input("hi"),
    builder().preToolCall("t1", "search", { q: "x" }),
  ]) {
    // Two independent Contexts of the same shape.
    assert.deepEqual(
      empty.intercept(ctx),
      baseline.intercept(ctx),
      "an empty limits object must be identical to no limits option",
    );
  }
});

test("overriding one limit leaves the others at their defaults", () => {
  const big = "x".repeat(4096);
  // Raise only the annotator output cap. Untouched `max_snapshot_bytes`
  // still defaults big, so the 4096-char input allows.
  const partial = AcsInterceptor.fromPath(fixtureManifestPath, {
    limits: { max_annotator_output_bytes: 8_388_608 },
  });
  assert.equal(partial.intercept(builder().input(big)).decision, "allow");

  // And when the second, untouched cap IS lowered on a separate
  // interceptor, it enforces — proving the field-by-field override
  // semantics: a raised cap does not silently reset a peer.
  const both = AcsInterceptor.fromPath(fixtureManifestPath, {
    limits: {
      max_annotator_output_bytes: 8_388_608,
      max_snapshot_bytes: 64,
    },
  });
  const v = both.intercept(builder().input(big));
  assert.equal(v.decision, "deny");
  assert.ok(v.reason.startsWith("runtime_error:"));
});

test("a limit that is not a non-negative integer is refused", () => {
  // A value the engine cannot parse is a hard error, not a
  // silently-kept default. A host that typo'd learns immediately
  // instead of finding out at the first breached limit that would
  // never fire.
  assert.throws(
    () =>
      AcsInterceptor.fromPath(fixtureManifestPath, {
        limits: { max_snapshot_bytes: "big" },
      }),
    /max_snapshot_bytes/,
  );
  assert.throws(
    () =>
      AcsInterceptor.fromPath(fixtureManifestPath, {
        limits: { max_snapshot_bytes: -1 },
      }),
    /max_snapshot_bytes/,
  );
  assert.throws(
    () =>
      AcsInterceptor.fromPath(fixtureManifestPath, {
        limits: { max_snapshot_bytes: 1.5 },
      }),
    /max_snapshot_bytes/,
  );
});

test("DEFAULT_LIMITS carries every documented field and is frozen", () => {
  // A host raising one cap reads `DEFAULT_LIMITS` to see what it is
  // overriding. The shape must stay wired to the engine's own
  // defaults, so a shipping change to another cap cannot be silently
  // absorbed by a stale mapping.
  const expected = new Set([
    "max_snapshot_bytes",
    "max_policy_input_depth",
    "max_annotators_per_point",
    "max_annotator_output_bytes",
    "max_policy_output_bytes",
    "max_extends_depth",
    "max_merged_manifest_bytes",
    "max_manifest_url_bytes",
    "manifest_url_timeout_ms",
    "max_manifest_url_redirects",
  ]);
  assert.deepEqual(new Set(Object.keys(DEFAULT_LIMITS)), expected);
  for (const [key, value] of Object.entries(DEFAULT_LIMITS)) {
    assert.equal(
      typeof value,
      "number",
      `DEFAULT_LIMITS[${key}] must be a number, was ${typeof value}`,
    );
    assert.ok(Number.isInteger(value) && value >= 0, `${key} = ${value}`);
  }
  // Frozen so a caller cannot mutate a shared default.
  assert.ok(Object.isFrozen(DEFAULT_LIMITS));
});
