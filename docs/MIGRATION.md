# Migrating from agent-control-specification 0.3

0.4 is a re-layering, not only a rewrite. The control contract and the
host obligations moved to [agent-hooks]; ACS kept the policy decision and
nothing else. So most of what 0.3 exported did not disappear, it moved
down a layer.

Two mechanical facts first. The Python distribution was renamed from
`agent-control-specification` to `agent-control-spec`, and
`InterventionPoint` was renamed to `InterceptionPoint`. Between them
those account for a large share of the import errors a 0.3 codebase hits
first.

## Where each thing went

### The control contract now comes from agent-hooks

`Decision`, `Verdict`, `EnforcementMode`, `Transform`, `Evidence`,
`ApprovalOutcome`, `ApprovalResolution`, `ApprovalResolver`.

```python
# 0.3
from agent_control_specification import Decision, EnforcementMode

# 0.4
from agent_hooks import Decision, EnforcementMode
```

`InterventionPoint` is `agent_hooks.InterceptionPoint`.

ACS does not re-export these. Two packages defining one contract is the
ambiguity the re-layering removed.

### Orchestration is agent-hooks' InterceptionEmitter

`AgentControl` was "host-owned async orchestration around a stateless
runtime client". That is now `InterceptionEmitter`, which implements
sections 6 through 10 of the control contract once so that adapters do
not each reimplement them.

```python
# 0.3
control = AgentControl.from_native(manifest)
result = await control.enforce(point, snapshot, EnforcementMode.ENFORCE)

# 0.4
from agent_hooks import InterceptionEmitter, EnforcementMode
from agent_control_spec import AcsInterceptor

emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
emitter.register(AcsInterceptor("manifest.yaml"), name="acs")
outcome = await emitter.emit(context)
```

| 0.3 | 0.4 |
| --- | --- |
| `AgentControl` | `agent_hooks.InterceptionEmitter` |
| `AgentControlBlocked` | `agent_hooks.InterceptionBlocked` |
| `AgentControlSuspended` | `agent_hooks.InterceptionSuspended` |
| `RunResult`, `ToolRunResult`, `ModelCallResult` | `agent_hooks.EmitOutcome` |
| `InterventionPointRequest` | `agent_hooks.AgentContext` |
| `action_identity` | `agent_hooks.context_identity` |
| `RuntimeClient`, `NativeRuntimeClient` | the `agent_hooks.Interceptor` protocol, which `AcsInterceptor` implements |

### Audit records replaced the telemetry sinks

`JsonStdoutTelemetrySink` and `InMemoryTelemetrySink` recorded what was
decided. That is a host obligation, so it moved to the emitter:
`set_record_sink`, `take_records`, `set_max_records` and
`InterceptionRecord`.

ACS still exposes engine-level telemetry, which is a different thing: it
reports how the engine spent its time, not what it decided. See host
hooks below.

### Host extension points stayed in ACS

`AnnotatorDispatcher` and `PolicyDispatcher` are ACS concerns by
definition and are still supported. The keyword survives:

```python
# 0.3
control = AgentControl.from_native(manifest, annotator_dispatcher=MyClassifier())

# 0.4
interceptor = AcsInterceptor("manifest.yaml", annotator_dispatcher=MyClassifier())
```

A dispatcher is any object with the matching method, or a plain callable,
so a 0.3 dispatcher class usually ports unchanged. A dispatcher that
raises fails the evaluation closed: a classifier that could not be
reached must not read as a classifier that found nothing.

### Manifest tooling

| 0.3 | 0.4 |
| --- | --- |
| `validate_manifest` | `validate_manifest` |
| `validate_acs_manifest` | `validate_manifest` |
| `parse_manifest` | `parse_manifest` |
| `validate_manifest_overlay` | `merge_manifests` |
| `ValidationDiagnostic`, `ArtifactValidationResult` | `validate_manifest_detailed` |

### Framework adapters have no successor yet

The 18 `guard_*` functions, `FullCoverageAgentAdapter`,
`LiteLLMProxyMiddleware`, `mcp_approval_resolver` and the rest are not in
0.4 and are not in agent-hooks.

They wrap nine frameworks, so they do not belong in a policy decision
runtime that would then version-lock to all of them. Where they should
live is an open question. Until it is answered, a host that used one
writes the equivalent against `InterceptionEmitter` directly, which is
what the adapters did internally.

## Things that will look like ACS breaking but are not

**Checking for the `opa` binary.** 0.3 evaluated Rego by shelling out to
OPA. 0.4 evaluates it in process with regorus and needs no external
binary. A startup check for `opa` on PATH will reject a working 0.4
install. Delete the check.

**`intervention_points` in a manifest.** The manifest grammar keeps the
older spelling. Only the Python symbol was renamed.

## A worked port

0.3:

```python
from agent_control_specification import (
    AgentControl, AgentControlBlocked, EnforcementMode,
)

control = AgentControl.from_native(manifest, annotator_dispatcher=ContentSafety())

async def guarded(text):
    try:
        return await control.enforce("input", {"input": text}, EnforcementMode.ENFORCE)
    except AgentControlBlocked:
        return "refused"
```

0.4:

```python
from agent_hooks import (
    AgentContextBuilder, EnforcementMode, InterceptionBlocked, InterceptionEmitter,
)
from agent_control_spec import AcsInterceptor

emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
emitter.register(
    AcsInterceptor("manifest.yaml", annotator_dispatcher=ContentSafety()),
    name="acs",
)

async def guarded(text):
    ctx = AgentContextBuilder(
        agent_id="a", framework="custom", session_id="s"
    ).input(content=text)
    try:
        return await emitter.emit(ctx)
    except InterceptionBlocked:
        return "refused"
```

`ContentSafety` is unchanged.

[agent-hooks]: https://github.com/responsibleai/agent-hooks
