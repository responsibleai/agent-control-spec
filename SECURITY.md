# Security

## Trust model

The Agent Control Specification runtime is a policy decision point. It
computes a verdict from the snapshot a host supplies and performs no
input or output of its own. It is not a security boundary around the
host, the dispatchers, or the agent.

| Party | Trust |
| --- | --- |
| Host (agent framework) | Fully trusted. The host assembles the snapshot, calls the runtime at each intervention point, and enforces the verdict. The runtime does not authenticate the snapshot or verify that it reflects the real agent state. A host that skips an intervention point, ignores a verdict, or feeds a false snapshot defeats every control, and nothing in the runtime detects it. |
| Dispatchers (policy and annotator) | Fully trusted by the host. They run host supplied code, receive the full snapshot and the outputs of the dependencies they name, and reach the network and other systems. The host is responsible for that code and for the endpoints it contacts. |
| Manifests and fetched documents | Trusted configuration. A manifest selects the policies and annotators that run; whoever can change it can change what the agent is allowed to do. Pins verify document bytes but do not create a separate trust class. |
| Annotations and dependency outputs | Untrusted data. An annotator observes adversarial content such as a user prompt or a tool result. A policy must treat annotation values as data and must not let them widen authority. |
| Model, tools, external inputs | Untrusted. This is the adversary the controls target. |

## What the runtime is not

- Not a sandbox. Dispatchers and tools execute with the privilege of the host process.
- Not a reference monitor. The runtime mediates the intervention points a host wires. Paths that bypass an intervention point are outside its trust boundary.
- Not a stateful enforcement point. The runtime stores no labels, propagates no taint, and keeps no state between calls. Information flow tracking is the host's job.
- Not an authentication layer for manifests, snapshots, or dispatchers.

The normative statement is [specification section 21](spec/SPECIFICATION.md#21-security-considerations). The host side trust boundary, including the approval resolver and the identity provider, is set out in agent-hooks [AGENT-HOOKS-0.1 section 1.4](https://github.com/responsibleai/agent-hooks/blob/main/spec/AGENT-HOOKS-0.1.md#14-trust-model-and-non-goals).

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/responsibleai/agent-control-spec/security/advisories/new). Do not open a public issue for an undisclosed vulnerability.

This project has one maintainer. Expect an acknowledgement within five business days. A fix ships in the next tagged release; there is no fixed deadline for that release. If you receive no reply within ten business days, open an issue that says only that you have sent a private report, without details.

## Supported versions

Pre-1.0: only the latest tagged release receives security fixes. One tag
releases every package together; see [RELEASING.md](RELEASING.md).

| Version | Status |
| --- | --- |
| `0.4.0-beta.1` | Supported. Latest tag. Package names: crates.io `agent-control-spec 0.4.0-beta.1`, PyPI `agent-control-spec 0.4.0b1`, npm `@responsibleai/agent-control-spec 0.4.0-beta.1`, NuGet `ResponsibleAI.AgentControlSpec 0.4.0-beta.1`. |
| `0.4.0-alpha.x` | No longer supported. Upgrade to the latest tag. |
| `main` | Fixes land here first and ship with the next tag. |
