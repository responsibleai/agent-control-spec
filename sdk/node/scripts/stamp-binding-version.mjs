#!/usr/bin/env node
// Stamp the loader version into the napi-generated version checks of a
// binding.js file (argument, default ../binding.js).
//
// `napi build` embeds the loader's package.json version into every
// platform branch of binding.js ("Native binding package version
// mismatch" under NAPI_RS_ENFORCE_VERSION_CHECK), which made the
// committed file a bump-coupled artifact: a version bump that did not
// regenerate it tripped the CI drift check (#29, #31). Instead the
// version is injected at publish time (release.yml) from package.json,
// the node-side version source, and the CI drift check compares the
// regenerated and committed files with both sides stamped, so only
// real generator-output changes can fail it.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(
  readFileSync(join(here, "..", "package.json"), "utf8"),
);
const file = process.argv[2] ?? join(here, "..", "binding.js");

const source = readFileSync(file, "utf8");
let stamped = 0;
const result = source
  .replace(/(bindingPackageVersion !== ')[^']+(')/g, (_, head, tail) => {
    stamped += 1;
    return head + version + tail;
  })
  .replace(/(expected )\S+( but got)/g, (_, head, tail) => {
    stamped += 1;
    return head + version + tail;
  });

if (stamped === 0) {
  console.error(
    `${file}: no napi version-check strings matched; the napi-rs ` +
      "template has changed shape — update stamp-binding-version.mjs " +
      "or the published loader will carry a stale version check",
  );
  process.exit(1);
}

writeFileSync(file, result);
console.log(`${file}: stamped ${stamped} version-check strings to ${version}`);
