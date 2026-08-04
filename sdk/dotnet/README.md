# Agent Control Specification — .NET wrapper

`ResponsibleAI.AgentControlSpec` wraps the ACS policy decision engine
as an [agent-hooks](https://github.com/responsibleai/agent-hooks)
interceptor (`AcsInterceptor : IInterceptor`). Every failure path is
fail-closed (`runtime_error:*` deny).

```csharp
using var acs = AcsInterceptor.FromPath("manifest.yaml", name: "acs");
var emitter = new InterceptionEmitter(EnforcementMode.Enforce);
emitter.Register(acs, "acs");
```

Manifests can also be checked on their own, without building a runtime
or having `opa` on PATH. Useful when generating or migrating manifests:

```csharp
try
{
    AcsManifest.Validate(source);
}
catch (ManifestInvalidException error)
{
    Console.Error.WriteLine(error.Message); // names the offending field
}
```

A manifest that uses `extends` cannot be judged from its own source,
because validation checks references across the merged document. Pass a
path instead and the chain is resolved first:

```csharp
AcsManifest.ValidateFile("manifest.yaml");
```

`AcsManifest.SupportedVersions()` reports the grammar versions this
engine accepts. Read it rather than hardcoding the set.

## Activating a policy version

`AcsInterceptor` readies a policy lazily, on the first emission. A host
that pins a policy version and serves traffic against it wants the
opposite split — pay to read and compile the bundle once, at a moment of
its choosing, then evaluate a named intervention point with nothing left
to set up:

```csharp
using var policy = AcsPolicy.Activate("manifest.yaml");   // once per policy version
policy.Evaluate(InterceptionPoint.Input, contextJson);
policy.Evaluate(InterceptionPoint.PreToolCall, contextJson);
```

`ActivatedPolicy` is immutable and safe to evaluate from any number of
threads at once; keep one per policy version rather than one per
request. `InterventionPoints` reports the points the manifest binds, so
a host can skip emitting where the policy does not govern:

```csharp
if (policy.Governs(InterceptionPoint.PostToolCall))
    policy.Evaluate(InterceptionPoint.PostToolCall, contextJson);
```

Disposal is deterministic, safe to repeat, and safe against evaluations
already in flight. Evaluating an unbound point is not an exception; like
every other failure it is a fail-closed deny, here with reason
`runtime_error:intervention_point_unknown`.

A manifest names its policy bundle relative to itself, so the manifest
path is the only one that has to be right; the host's working directory
does not matter.

`bench/` measures this surface — activation cost, warm p50/p95/p99, and
throughput at concurrency 32. See [bench/README.md](bench/README.md).

Native libraries: this wrapper loads `agent_control_spec_ffi` (built
with `cargo build --release -p agent-control-spec-ffi`), and the
agent-hooks package separately loads `agent_hooks_ffi`; both resolve
from the platform loader path (`LD_LIBRARY_PATH` on Linux).

Build/test: `dotnet restore && dotnet test` from `sdk/dotnet` with
`LD_LIBRARY_PATH` pointing at `target/release`.
