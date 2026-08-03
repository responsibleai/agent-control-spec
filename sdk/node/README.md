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
