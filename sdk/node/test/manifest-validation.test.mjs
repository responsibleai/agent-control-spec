// Grammar checks are reachable without building a runtime.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import path from "node:path";

const require = (await import("node:module")).createRequire(import.meta.url);
const { validateManifest, validateManifestFile, supportedManifestVersions, ManifestInvalidError,
  parseManifest, mergeManifests, validateManifestDetailed, validateArtifacts } =
  require("../dist/index.js");

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const valid = fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "manifest.yaml"),
  "utf8",
);

test("a valid manifest is accepted", () => {
  assert.equal(validateManifest(valid), undefined);
});

test("text resource limits stay boundary errors and can be configured", () => {
  const source = valid + "\n# " + "x".repeat(1_048_576);
  for (const operation of [
    validateManifest, parseManifest, validateManifestDetailed,
    (text, limits) => mergeManifests([text], limits),
  ]) {
    assert.throws(() => operation(source), (error) => {
      assert.ok(!(error instanceof ManifestInvalidError));
      assert.match(error.message, /runtime_error:resource_limit_exceeded/);
      return true;
    });
    operation(source, { max_merged_manifest_bytes: 2_097_152 });
    assert.throws(() => operation(valid, { max_manifest_nodes: 1 }),
      /runtime_error:resource_limit_exceeded/);
    operation(valid, { max_policy_input_depth: 0 });
  }
});

test("an unsupported version is rejected with the engine message", () => {
  const source = valid.replace('"0.4.0-alpha.1"', '"0.3.1-beta"');
  assert.throws(() => validateManifest(source), (error) => {
    assert.ok(error instanceof ManifestInvalidError);
    assert.match(error.message, /0\.3\.1-beta/);
    return true;
  });
});

test("diagnostics throw resource failures instead of returning findings", () => {
  for (const operation of [validateManifestDetailed, validateArtifacts]) {
    for (const source of [
      valid + "\n# " + "x".repeat(1_048_576),
      "agent_control_specification_version: 0.4.0-alpha.1\nmetadata:\n  v: " + "[".repeat(65) + "0" + "]".repeat(65),
    ]) {
      assert.throws(() => operation(source), (error) => {
        assert.ok(!(error instanceof ManifestInvalidError));
        assert.match(error.message, /^runtime_error:resource_limit_exceeded:/);
        return true;
      });
    }
    assert.equal(operation("x: [")[0].code, "runtime_error:manifest_invalid");
  }
});

test("parse and validation failures keep the runtime reason prefix", () => {
  for (const operation of [validateManifest, parseManifest, (source) => mergeManifests([source])]) {
    assert.throws(() => operation("x: ["), (error) => {
      assert.match(error.message, /^runtime_error:manifest_invalid:/);
      return true;
    });
  }
  for (const operation of [validateManifest, (source) => mergeManifests([source])]) {
    assert.throws(() => operation(valid.replace('"0.4.0-alpha.1"', '"0.3.1-beta"')), (error) => {
      assert.match(error.message, /^runtime_error:manifest_invalid:/);
      return true;
    });
  }
});

test("the retired $policy_target root is rejected", () => {
  const source = valid.replace('"$.input"', '"$policy_target.input"');
  assert.throws(() => validateManifest(source), ManifestInvalidError);
});

test("malformed yaml is rejected", () => {
  assert.throws(() => validateManifest("agent_control_specification_version: ["), ManifestInvalidError);
});

test("a non-string argument is not relabelled as a bad manifest", () => {
  // The manifest was never parsed, so calling it invalid would be a lie.
  for (const bad of [42, null, undefined, {}]) {
    assert.throws(() => validateManifest(bad), (error) => {
      assert.ok(!(error instanceof ManifestInvalidError), `${typeof bad} misreported`);
      assert.ok(error instanceof TypeError);
      return true;
    });
  }
});

test("a lone surrogate is a boundary failure, not a bad manifest", () => {
  // Lossy UTF-8 encoding would substitute U+FFFD, so the engine would
  // report on text the caller never wrote.
  const supplied = valid.replace('"0.4.0-alpha.1"', '"0.3.1-bet\ud800"');
  for (const bad of ["\ud800", supplied]) {
    assert.throws(() => validateManifest(bad), (error) => {
      assert.ok(!(error instanceof ManifestInvalidError));
      assert.ok(error instanceof TypeError);
      return true;
    });
  }
});

test("the published native binding cannot be fed lossy input either", () => {
  // binding.js ships in the package and a consumer can require it
  // directly, bypassing the wrapper. Enforcement lives in the native
  // layer so that path cannot silently validate altered text.
  const native = require("../binding.js");
  // every published entry point taking text decodes strictly
  assert.throws(() => native.validateManifest("\ud800"), /unpaired surrogate/);
  assert.throws(() => native.validateManifestFile("\ud800"), /unpaired surrogate/);
  assert.throws(() => native.interceptorNew("\ud800"), /unpaired surrogate/);
  // a well-formed manifest still works through the raw binding
  assert.equal(native.validateManifest(valid), null);
});

test("extends is not reported as an invalid manifest", () => {
  // The runtime loads this file fine; judging the child alone would
  // blame it for an annotator its parent defines.
  const child = path.join(repoRoot, "examples", "coding_agent", "manifest.yaml");
  const source = fs.readFileSync(child, "utf8");
  assert.throws(() => validateManifest(source), (error) => {
    assert.ok(!(error instanceof ManifestInvalidError));
    assert.match(error.message, /extends/);
    return true;
  });
  assert.equal(validateManifestFile(child), undefined);
});

test("an unreadable path is not reported as an invalid manifest", () => {
  // The document was never read, so its content was never judged.
  for (const p of ["/nonexistent/typo.yaml", path.dirname(fileURLToPath(import.meta.url))]) {
    assert.throws(() => validateManifestFile(p), (error) => {
      assert.ok(!(error instanceof ManifestInvalidError), p);
      return true;
    });
  }
});

test("supported versions are reported rather than hardcoded", () => {
  const versions = supportedManifestVersions();
  assert.ok(versions.length > 0);
  assert.ok(versions.some((v) => valid.includes(v)));
});
