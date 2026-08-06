# Agent Control Specification — Node wrapper

`@responsibleai/agent-control-spec` wraps the ACS policy decision
engine as an [agent-hooks](https://github.com/responsibleai/agent-hooks)
interceptor. A host registers `AcsInterceptor` with its agent-hooks
emitter; every failure path is fail-closed (`runtime_error:*` deny).

```ts
import { AcsInterceptor } from "@responsibleai/agent-control-spec";
import { AgentContextBuilder, InterceptionEmitter } from "@responsibleai/agent-hooks";

const emitter = new InterceptionEmitter();
emitter.register(AcsInterceptor.fromPath("manifest.yaml"), "acs");
```

Zero-config construction: bundled annotators; Rego policies through the
in-process Rego evaluator, Cedar through the built-in evaluator, `test`
policies through their embedded verdict. Custom policies require a host
dispatcher and fail closed under this construction.

## Activating a policy version

A host that pins a policy version and serves traffic against it wants
the expensive work done once, at a moment of its choosing.
`ActivatedPolicy.activate` reads the manifest, loads every Rego module
and data document, and compiles the entrypoint each intervention point
queries; every later `evaluate` costs no I/O and no compile.

Compiling is bounded by the eval timeout. A policy too slow to compile in
that window activates anyway, not necessarily fully readied, and pays compilation
on its first decision instead.


```ts
import { ActivatedPolicy } from "@responsibleai/agent-control-spec";

const policy = ActivatedPolicy.activate("manifest.yaml"); // once per version
const verdict = policy.evaluate("input", context);        // many times, hot path
policy.interventionPoints();                              // what this version governs
```

The instance is immutable and safe to use from concurrent evaluations. A
policy edit on disk needs a new activation: the host decides when a
version changes. Evaluation stays fail-closed, including for a point the
version does not bind; only boundary problems (an unknown point name, a
non-object context) throw.

### Activating from memory

A service that keeps manifests and Rego in a database has no directory to
point a manifest at. `ActivatedPolicy.activateFromMemory` takes both as
values, so nothing is staged to a temporary directory per activation:

```ts
const policy = ActivatedPolicy.activateFromMemory(manifestYaml, {
  gate: {
    modules: { "gate.rego": moduleSource },
    data: [{ mount: ["limits"], document: { daily: 42 } }],
  },
});
```

Each key names a Rego policy the manifest declares, and the bundle
replaces whatever `bundle` path that policy names. A data document
mounts at `data.<mount[0]>.<mount[1]>...`; an omitted or empty `mount`
puts it at the data root. Activation is refused when a Rego policy is
left naming a relative `bundle` or data path, since a manifest parsed from a
string has no directory to resolve it against. Absolute paths are left
alone, so a manifest can mix policy from the database with policy from a
known location on disk.

Manifests can also be checked on their own, without building a runtime
or resolving a policy bundle. Useful when generating or migrating manifests:

```ts
import { validateManifest, ManifestInvalidError } from "@responsibleai/agent-control-spec";

try {
  validateManifest(source);
} catch (error) {
  if (error instanceof ManifestInvalidError) console.error(error.message);
}
```

A manifest that uses `extends` cannot be judged from its own source,
because validation checks references across the merged document. Pass a
path instead and the chain is resolved first:

```ts
import { validateManifestFile } from "@responsibleai/agent-control-spec";

validateManifestFile("manifest.yaml");
```

`supportedManifestVersions()` reports the grammar versions this engine
accepts. Read it rather than hardcoding the set.

Build/test: `npm ci && npm test` (compiles the native engine binding —
Rust toolchain required).

Benchmark: `npm run bench` runs `bench/activation.bench.mjs` against
`examples/bank_agent`, reporting activation cost, first-evaluate cost,
warm p50/p95/p99, and throughput at concurrency 32.
