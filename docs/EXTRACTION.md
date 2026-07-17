# Extraction map

This repository is the Agent Control Specification (ACS) policy
decision runtime, extracted from the `agent-policy-spec/policy-engine`
tree of the Agent Governance Toolkit and re-based on the
[agent-hooks](https://github.com/responsibleai/agent-hooks) control
contract. ACS no longer defines its own interception layer: it is a
**conformant interceptor** — a host framework emits interception
points through an agent-hooks emitter, and ACS evaluates bound
policies and returns agent-hooks verdicts.

## Source → destination

| Source (`policy-engine/`) | Destination | Notes |
| --- | --- | --- |
| `core/src/manifest.rs` | `engine/src/manifest.rs` | Policy/intervention-point binding grammar. Point names validate against the agent-hooks closed set. |
| `core/src/runtime.rs` | `engine/src/runtime.rs` | Evaluation pipeline (annotators → policy → normalization). Transform application and `evaluate_only` handling removed — those are host obligations under agent-hooks. |
| `core/src/policy.rs`, `cedar.rs`, `opa.rs`, `dispatchers/` | `engine/src/…` | Dispatcher plane, unchanged in structure. |
| `core/src/annotation.rs`, `tool_projection.rs` | `engine/src/…` | Annotator plane. |
| `core/src/paths.rs` | `engine/src/paths.rs` | `$policy_target` root renamed `$target` (agent-hooks transform grammar). `$snap` remains the manifest's name for the agent context. |
| `core/src/policy_input.rs` | `engine/src/policy_input.rs` | Builds the policy-input document from an agent-hooks `AgentContext`. Canonicalization/identity helpers removed — context identity is owned by agent-hooks (§10). |
| `core/src/error.rs` | `engine/src/error.rs` | `runtime_error:*` reserved reasons kept for the policy plane. Approval- and effects-related variants removed (approval seam and transform enforcement are host-side). |
| `core/src/limits.rs`, `telemetry.rs`, `perf_telemetry.rs`, `constants.rs` | `engine/src/…` | Unchanged in role. |
| `core/src/verdict.rs` | `engine/src/policy_output.rs` | Rewritten. The five-decision enum is gone; policy outputs normalize to agent-hooks `Verdict` values natively (`warn` intent → `allow` + `warnings[]`, `escalate` intent → `deny` + `approval{}`). Evidence uses the agent-hooks type and size bound. |
| `core/src/intervention_point.rs` | — | Superseded by `agent_hooks::InterceptionPoint` / `EnforcementMode`. |
| `core/src/effects.rs` | — | Removed (already sunset in the source; `transform` is the only value-changing decision). |
| `core/src/ffi.rs` | — (pending) | C ABI to be reintroduced with the Node/.NET SDK ports. |
| `spec/SPECIFICATION.md` | `spec/SPECIFICATION.md` | Interception-layer sections replaced by references to AGENT-HOOKS-0.1; policy-plane sections retained. |
| `spec/schema/` | `spec/schema/` | Manifest/advice schemas kept; wire verdict schema superseded by the agent-hooks verdict schema. |
| `policy/` | `policy/` | Cedar/Rego policy libraries. |
| `tests/fixtures` | `fixtures/` | Evaluation fixtures. |
| `sdk/python` | `sdk/python` | PyO3 binding; re-exports agent-hooks types and wraps the engine as an `agent_hooks` interceptor. |
| `sdk/node`, `sdk/dotnet`, `sdk/rust` | — (pending) | To be reintroduced on the same pattern. Rust consumers use the `engine` crate directly. |
| `integrations/`, `generator/`, `benchmarks/`, `deploy/`, `examples/` | — | Out of scope for the runtime repository. |
