# Proposal: explicit verdict for known, unbound points

Status: design for agreement, September 10, 2026. **Not implemented or
accepted grammar.** Existing manifests and default runtime behavior
remain unchanged. The Python scoped adapter does not depend on this
proposal.

## Contract

Add an optional top-level `unbound_point_verdict`, under a newly agreed
manifest grammar version. Limit its shape to:

```yaml
unbound_point_verdict:
  decision: allow
  reason: outside_this_control
```

`decision` is `allow` or `deny`. `reason` is required, nonempty, and
subject to the existing user-verdict reason rules (no reserved
`runtime_error:` or `host_error:` prefixes). Reject unknown members,
null values, transforms, approvals, warnings, labels, and evidence.
This is an auditable scope declaration, not another policy engine.

| Request | Result |
| --- | --- |
| Known point, binding exists | Evaluate its binding normally; fallback is never consulted. |
| Known point, no binding, no fallback | Existing `deny runtime_error:intervention_point_unknown`. |
| Known point, no binding, explicit fallback | Return the configured plain allow/deny and its reason. No annotation or policy dispatch. |
| Invalid/missing point name | Fail closed; never apply fallback. Preserve each binding's boundary-error representation. |
| Invalid manifest, malformed request, exceeded limits, or bound evaluation failure | Existing error behavior; never apply fallback. |

Retain snapshot validation and resource limits before returning any
fallback. `intervention_points` and `governs()` continue to describe
explicit bindings, not the fallback. Their meaning does not expand to
all eight points.

Native decision telemetry records fallback decisions and their reason,
with no policy id or annotator invocation. Agent Hooks records the
control's verdict normally. No new wire verdict fields or reserved
error namespace entries are needed. A fallback cannot override another
control's denial or the host's composition profile.

## Composition and precedence

Follow ACS's additive, conflict-rejecting `extends` merge:

- No declaration anywhere: preserve today's implicit deny.
- One declaration: inherit it into the resolved manifest.
- Multiple identical declarations: accept them.
- Conflicting declarations: reject the merge, rather than last-writer-wins.
- Absence is not a deletion or an explicit override. To disallow
  inherited fallback, remove it from the parent or use a different
  parent; a conflicting child cannot silently replace it.

Validate after resolution and retain existing version-equality checks
across the chain. Adding an allow fallback to a fragment deliberately
changes all known unbound points in the resolved artifact; review the
resolved artifact, not just the fragment.

`Scope.STRICT` on the proposed Python adapter means "evaluate all
points using the artifact's semantics"; it would therefore honor this
explicit engine fallback. `Scope.BOUND_POINTS_ONLY` remains a separate
host choice that bypasses known unbound points, even if an artifact
would deny them. Do not combine that host bypass with a requirement
to enforce artifact fallback denials.

## Version and rollout

Do not add this to the currently supported `0.4.0-alpha.1` grammar in
place. Allocate the new grammar version with the spec owners; the
package release version is a separate decision. A package bump to the
next alpha does not itself authorize a grammar bump.

Keep accepting old manifests with their old semantics. Reject the new
key under the old grammar. Older runtimes must reject the new version,
not ignore a fallback. A manifest must opt in explicitly; no migration
tool should insert allow fallbacks automatically.

Once the contract is agreed, implement in a separate change covering
`spec/SPECIFICATION.md`, manifest schema/version validation, the Rust
manifest model and merge, runtime lookup/telemetry, binding parse and
validation outputs, and conformance vectors across Rust, Python,
Node, and the C ABI/.NET path. Do not change host emission or global
composition defaults.

## Acceptance cases

Use a pre-tool-only manifest to verify allowed startup and preserved
tool denial under explicit fallback. Also cover absent fallback,
explicit fallback deny, all known lifecycle points, invalid names,
invalid/missing fallback fields, reserved reasons, malformed contexts,
resource limits, bound annotator/policy failures, no annotator calls
on the fallback path, and another control's denial.

Pin merge behavior for absent/identical/conflicting parents and
children, resolved serialization, old/new grammar compatibility, and
the distinction between manifest fallback and host scope. Run the
same vectors through every binding, including telemetry and the real
Agent Hooks emitter where available.

## Decision requested

Agree on the field name and restricted verdict shape, inheritance
rules, new-grammar gate, and scope precedence before changing the
grammar. The local async adapter can proceed independently.
