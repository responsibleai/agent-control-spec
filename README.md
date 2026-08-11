# Agent Control Specification

The Agent Control Specification (ACS) is a stateless, deterministic
**policy decision runtime** for agent security, built on the
[agent-hooks](https://github.com/responsibleai/agent-hooks) control
contract.

The layering:

- **agent-hooks** defines the control contract: eight interception
  points, the `AgentContext` payload, the three-verdict model
  (`allow` / `deny` / `transform`, with warnings and liftable denies),
  host obligations, composition, and the conformance test kit.
- **ACS (this repository)** is a conformant *interceptor*: a host
  framework emits interception points through an agent-hooks emitter,
  and ACS evaluates the bound policy — manifest binding, Cedar / Rego /
  custom dispatchers, annotators, information-flow labels — and
  returns an agent-hooks verdict.
- Hosts and frameworks integrate agent-hooks once and gain ACS (or any
  other interceptor) without bespoke glue.

ACS decisions are pure: same manifest, same context, same annotations →
same verdict. Escalation is expressed natively as a liftable deny
(`deny` + `approval`); warnings ride on `allow`. The engine performs no
transform application, no approval resolution, and no record keeping —
those are host obligations defined by agent-hooks.

## Layout

| Path | Contents |
| --- | --- |
| `engine/` | Rust evaluation core (`agent-control-spec` crate): manifest, dispatchers, annotators, policy-output normalization, the `AcsInterceptor` |
| `sdk/ffi/` | C ABI over the engine (`agent-control-spec-ffi`), which the .NET binding calls |
| `sdk/python/` | Python binding: `agent_control_spec` package wrapping the engine as an `agent_hooks` interceptor |
| `sdk/node/` | Node binding: `@responsibleai/agent-control-spec` |
| `sdk/dotnet/` | .NET binding: `ResponsibleAI.AgentControlSpec` |
| `spec/` | The ACS specification (policy plane) and schemas |
| `policy/` | Cedar and Rego policy libraries |
| `fixtures/` | Evaluation fixtures |
| `docs/STREAMING.md` | The incremental stream profile (section 18.1) in every language |
| `docs/MIGRATION.md` | Porting from `agent-control-specification` 0.3 |
| `docs/EXTRACTION.md` | Provenance map from the previous tree |

## Status

`0.4.0-alpha.1` — first release of the re-based runtime. Depends on
`agent-hooks-sdk 0.1.0-alpha.3`.
