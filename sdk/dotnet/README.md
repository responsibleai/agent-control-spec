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

Native libraries: this wrapper loads `agent_control_spec_ffi` (built
with `cargo build --release -p agent-control-spec-ffi`), and the
agent-hooks package separately loads `agent_hooks_ffi`; both resolve
from the platform loader path (`LD_LIBRARY_PATH` on Linux).

Build/test: `dotnet restore && dotnet test` from `sdk/dotnet` with
`LD_LIBRARY_PATH` pointing at `target/release`.
