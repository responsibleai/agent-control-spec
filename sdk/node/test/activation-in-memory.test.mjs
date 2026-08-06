// Activating a policy whose manifest and Rego are held in memory.
//
// A host that keeps both in a database has no directory to point a
// manifest at, so these pin that a bundle supplied as values evaluates,
// that two such bundles stay apart in the policy cache, and that the
// same policy activated from disk and from memory decides alike.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const { ActivatedPolicy } = require("../dist/index.js");
const { AgentContextBuilder } = require("@responsibleai/agent-hooks");

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "rego");
const manifestPath = path.join(fixtures, "manifest.yaml");
const manifestYaml = fs.readFileSync(manifestPath, "utf8");

const context = () =>
  new AgentContextBuilder({ agentId: "a", framework: "test", sessionId: "s" }).input("hello");

const module = (allow) => `package gate

verdict := {"decision": "${allow ? "allow" : "deny"}", "reason": "${allow ? "permitted" : "refused"}"}
`;

const activate = (bundle) => ActivatedPolicy.activateFromMemory(manifestYaml, { gate: bundle });

// A fail-closed deny would otherwise pass an assertion that only looks
// at the reason.
const verdict = (policy) => {
  const decided = policy.evaluate("input", context());
  assert.doesNotMatch(
    decided.reason ?? "",
    /^runtime_error:/,
    `policy failed rather than decided: ${JSON.stringify(decided)}`,
  );
  return decided;
};

test("a bundle held only in memory decides", () => {
  const policy = activate({ modules: { "gate.rego": module(true) } });

  assert.deepEqual(verdict(policy), { decision: "allow", reason: "permitted" });
});

test("data documents mount where the caller puts them", () => {
  const policy = activate({
    modules: {
      "gate.rego": `package gate

verdict := {
    "decision": "allow",
    "reason": sprintf("limit=%v root=%v", [data.limits.daily, data.at_root]),
}
`,
    },
    data: [
      { mount: ["limits"], document: { daily: 42 } },
      { document: { at_root: "yes" } },
    ],
  });

  assert.equal(verdict(policy).reason, "limit=42 root=yes");
});

// The policy cache is keyed on a bundle path, and an in-memory bundle
// has none. Two of them must still be told apart, or the second
// activation would be served the first one's engine and decide as it.
test("two in-memory bundles do not share a cache entry", () => {
  const permissive = activate({ modules: { "gate.rego": module(true) } });
  const restrictive = activate({ modules: { "gate.rego": module(false) } });

  assert.equal(verdict(permissive).reason, "permitted");
  assert.equal(verdict(restrictive).reason, "refused");

  // Both directions, so an ordering that happens to work once is not
  // mistaken for keys that separate.
  const permissiveAgain = activate({ modules: { "gate.rego": module(true) } });
  assert.equal(verdict(permissiveAgain).reason, "permitted");
  assert.equal(verdict(restrictive).reason, "refused");
});

// The same policy from either source must decide identically, or the
// in-memory path is a second implementation rather than the same one
// without the read.
test("a policy decides the same from disk and from memory", () => {
  const fromDisk = ActivatedPolicy.activate(manifestPath);
  // The same two files as the bundle directory holds. `data.json` sits
  // at its root, which mounts at the data root, so the mount is empty.
  const fromMemory = activate({
    modules: {
      "gate.rego": fs.readFileSync(path.join(fixtures, "policy", "gate.rego"), "utf8"),
    },
    data: [
      {
        mount: [],
        document: JSON.parse(fs.readFileSync(path.join(fixtures, "policy", "data.json"), "utf8")),
      },
    ],
  });

  assert.deepEqual(verdict(fromDisk), verdict(fromMemory));
  assert.deepEqual(verdict(fromDisk), { decision: "allow", reason: "tier=gold" });
});

// A manifest parsed from a string has no directory of its own, so a
// leftover relative path would resolve against the working directory
// and read a policy nobody chose.
test("a leftover relative bundle path is refused", () => {
  assert.throws(
    () => ActivatedPolicy.activateFromMemory(manifestYaml, {}),
    /relative bundle or data path/,
  );
});

test("supplying modules for an undeclared policy is refused", () => {
  assert.throws(
    () =>
      ActivatedPolicy.activateFromMemory(manifestYaml, {
        gate: { modules: { "gate.rego": module(true) } },
        absent: { modules: { "gate.rego": module(true) } },
      }),
    /no such policy/,
  );
});

test("an in-memory activation reports the points it binds", () => {
  const policy = activate({ modules: { "gate.rego": module(true) } });

  assert.deepEqual([...policy.interventionPoints()], ["input"]);
  assert.equal(policy.governs("input"), true);
});
