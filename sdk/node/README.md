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

Zero-config construction: bundled annotators; Rego policies through a
local `opa` binary, Cedar through the built-in evaluator, `test`
policies through their embedded verdict. Custom policies require a host
dispatcher and fail closed under this construction.

Build/test: `npm ci && npm test` (compiles the native engine binding —
Rust toolchain required).
