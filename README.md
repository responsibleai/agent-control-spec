# Agent Control Specification

The Agent Control Specification (ACS) is a stateless, deterministic
**policy decision runtime** for agent security, built on the
[agent-hooks](https://github.com/responsibleai/agent-hooks) control
contract.

The layering:

- agent-hooks defines the control contract: eight interception
  points, the `AgentContext` payload, the three-verdict model
  (`allow` / `deny` / `transform`, with warnings and liftable denies),
  host obligations, composition, and the conformance test kit.
- ACS, this repository, is a conformant interceptor: a host framework
  emits interception points through an agent-hooks emitter, and ACS
  evaluates the bound policy (manifest binding, Cedar, Rego or custom
  dispatchers, annotators, information-flow labels) and returns an
  agent-hooks verdict.
- Hosts and frameworks integrate agent-hooks once and gain ACS (or any
  other interceptor) without bespoke glue.

ACS decisions are deterministic: the same manifest, the same context,
the same annotations and the same dispatcher results give the same
verdict. A dispatcher is the host-trusted code that runs an annotator
or a policy, so a dispatcher that reads a clock or the network breaks
replay. The bundled Rego dispatcher blocks `http.send`, and it blocks
the clock and random builtins (`time.now_ns`, `rand.intn`,
`uuid.rfc4122`, `opa.runtime`), so a policy that calls one fails
closed. Escalation is expressed natively as a liftable deny (`deny` +
`approval`); warnings ride on `allow`.

ACS computes verdicts and nothing else. It does not sandbox, it does
not isolate processes, and it does not mediate a path that bypasses an
intervention point. It applies no transform, resolves no approval and
keeps no record. Enforcement is the job of the agent-hooks emitter and
the host that owns it: the emitter blocks a denied action and hands back
the transformed target the host must use. The host is fully trusted;
conformance is a test result, not a certification. The threat model is
in [specification section 21](spec/SPECIFICATION.md#21-security-considerations)
and in the [agent-hooks threat model](https://github.com/responsibleai/agent-hooks/blob/main/docs/THREAT-MODEL.md).

Security: see [SECURITY.md](SECURITY.md) for the trust model and how to
report a vulnerability.

## Layout

| Path | Contents |
| --- | --- |
| `engine/` | Rust evaluation core (`agent-control-spec` crate): manifest, dispatchers, annotators, policy-output normalization, the `AcsInterceptor` |
| `sdk/ffi/` | C ABI over the engine (`agent-control-spec-ffi`), which the .NET binding calls |
| `sdk/python/` | Python binding: `agent_control_spec` package wrapping the engine as an `agent_hooks` interceptor |
| `sdk/node/` | Node binding: `@responsibleai/agent-control-spec` |
| `sdk/dotnet/` | .NET binding: `ResponsibleAI.AgentControlSpec` |
| [`generator/`](generator/README.md) | Optional `acs-policy-gen` authoring tool. Produces draft manifests and Rego from prose, with parser checks and ACS validation |
| `spec/` | The ACS specification (policy plane) and schemas |
| `policy/` | Cedar and Rego policy libraries |
| `fixtures/` | Evaluation fixtures |
| `docs/EXTRACTION.md` | Provenance map from the previous tree |

## Status

Rust builds require Rust 1.89 or newer. See
[manifest parsing](docs/manifest-parsing.md) for YAML typing rules, host-controlled
parsing budgets and parser dependency details.

Rust: add `agent-control-spec = "0.4.0-beta.1"` to `Cargo.toml`. Cargo
does not match a pre-release from a bare version requirement, so name
the exact string while the crate is pre-release. The bundled annotator
dispatchers sit behind the `default-dispatchers` feature; the
zero-config constructor below needs it:

```toml
[dependencies]
agent-control-spec = { version = "0.4.0-beta.1", features = ["default-dispatchers"] }
agent-hooks-sdk = "0.1.0-beta.2"
serde_json = "1"
```

From a manifest to a registered interceptor:

```rust
use agent_control_spec::ActivatedPolicy;
use agent_hooks::{AgentContextBuilder, EnforcementMode, InterceptionEmitter};
use serde_json::json;

async fn guard() -> Result<(), Box<dyn std::error::Error>> {
    // Once per policy version: read the manifest, load and compile its
    // Rego, and ready every bound intervention point.
    let policy = ActivatedPolicy::activate_from_path("manifest.yaml")?;

    // Register the policy with an agent-hooks emitter. The emitter
    // applies verdicts; ACS only computes them.
    let mut emitter = InterceptionEmitter::new(EnforcementMode::Enforce, None);
    emitter.register(Box::new(policy.interceptor()));

    // Emit one pre_tool_call context. A deny returns Err; an allow or
    // transform returns the target the tool call must use.
    let mut builder = AgentContextBuilder::new("demo-agent", "my-framework", "session-1");
    let mut ctx = builder.pre_tool_call("call-1", "wire_transfer", json!({"amount": 100}));
    match emitter.emit(&mut ctx).await {
        Ok(outcome) => println!("proceed with {}", outcome.target),
        Err(blocked) => println!("blocked: {blocked}"),
    }
    Ok(())
}
```

`activate_from_path` installs the bundled dispatchers: Rego in process,
Cedar through the built-in evaluator, and the bundled annotators, which
make HTTPS calls during evaluation when the manifest declares
annotators. A host that wants its own dispatchers uses
`ActivatedPolicy::activate_with` or `Runtime::new`, and
`AcsInterceptor::new(runtime)` wraps a runtime directly.

Python: [SDK quickstart](sdk/python/README.md) and
[composing ACS controls through Agent Hooks](docs/ACS-AND-AGENT-HOOKS.md).

Node: `npm install @responsibleai/agent-control-spec`, see the
[Node wrapper](sdk/node/README.md). A plain install gets the newest
release, pre-releases included; the channel tags `alpha`, `beta` and
`rc` exist for pinning to one line.

.NET: `dotnet add package ResponsibleAI.AgentControlSpec --prerelease`,
see the [.NET wrapper](sdk/dotnet/README.md).

Current version: `0.4.0-beta.1`, the first beta of the re-based runtime.
It depends on agent-hooks `0.1.0-beta.2`.
