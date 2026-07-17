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

Native libraries: this wrapper loads `agent_control_spec_ffi` (built
with `cargo build --release -p agent-control-spec-ffi`), and the
agent-hooks package separately loads `agent_hooks_ffi`; both resolve
from the platform loader path (`LD_LIBRARY_PATH` on Linux).

Build/test: `dotnet restore && dotnet test` from `sdk/dotnet` with
`LD_LIBRARY_PATH` pointing at `target/release`.
