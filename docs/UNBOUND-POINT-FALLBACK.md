# Proposal: declare known points intentionally outside an ACS control

Status: revised design for agreement, September 24, 2026. **Not implemented or
accepted grammar.** Existing manifests and default runtime behavior remain
unchanged.

## Problem

Today a known intervention point without a binding is an evaluation error and
fails closed as `deny runtime_error:intervention_point_unknown`. Specification
sections 1.1, 6, 16, 20, and 21 require that result and forbid a manifest-level
fail-open path.

Some controls intentionally govern only a declared subset of an Agent Hooks
surface. That scope must be explicit in the resolved artifact and in every
interception record. It must not turn an evaluation error into a configurable
allow.

## Contract

Under a newly allocated manifest grammar version, add a root-only
`ungoverned_points` list:

```yaml
intervention_points:
  pre_tool_call:
    policy:
      type: rego
      path: policy/tool.rego

ungoverned_points:
  - agent_startup
  - agent_shutdown
```

The list contains known Agent Hooks point names that this ACS control
intentionally does not govern. It is a scope declaration evaluated before the
unbound-point error, not a policy verdict and not a general fallback.

Validation rules:

- `intervention_points` remains nonempty. A manifest cannot express an
  allow-all control using only `ungoverned_points`.
- A point cannot appear in both `intervention_points` and
  `ungoverned_points`; overlap is `runtime_error:manifest_invalid`.
- Unknown names, duplicates, null, an empty list, and unknown members are
  `runtime_error:manifest_invalid`.
- A fetched `extends` document cannot declare `ungoverned_points`, even when
  pinned. The declaration must be present in the host-authored root document.
  This matches the source-sensitive validation used for `approval` and prevents
  a remote fragment from widening scope.
- `ungoverned_points` is not inherited or merged. A declaration in any
  non-root document is invalid, so the resolved scope is visible in one place.
- Existing manifest and policy-input limits run before returning the scope
  verdict.

| Request | Result |
| --- | --- |
| Known point with a binding | Evaluate the binding normally. |
| Known point listed in `ungoverned_points` | Return `allow scope:unbound_point`; perform no annotation or policy dispatch. |
| Known point in neither collection | Preserve `deny runtime_error:intervention_point_unknown`. |
| Invalid or missing point name | Preserve the existing boundary error; never consult the scope declaration. |
| Invalid manifest, malformed request, exceeded limit, or bound evaluation failure | Preserve existing fail-closed behavior. |

`scope:unbound_point` is a new spec-reserved permit-class reason. Policy output
cannot use the `scope:` prefix, just as it cannot imitate `runtime_error:` or
`host_error:` reasons. The author cannot replace this reason. Human explanation
belongs in manifest metadata or documentation rather than in the verdict.

## Introspection and records

`intervention_points()` and `governs()` continue to describe bindings.
Implementations add equivalent read-only introspection for
`ungoverned_points`, and resolved-manifest serialization retains the list. A
host can therefore distinguish bound, intentionally ungoverned, and erroneous
points without inferring scope from a verdict.

Native decision telemetry marks this path with
`decision_source: ungoverned_point_declaration`, includes the point and the
verbatim `scope:unbound_point` reason, and carries no policy id or annotator
invocation. The Agent Hooks bridge returns the same fixed reason. Because policy
output cannot use the reserved `scope:` prefix, the per-interceptor
`verdicts[]` entry differs from a policy allow.

Agent Hooks composition may replace the combined top-level allow reason, and
`verdicts[]` is optional in some profiles. The ACS-native telemetry source
marker is therefore the authoritative audit signal for this declaration. This
proposal does not claim that the declaration is recoverable from every generic
Agent Hooks record.

## Host-side scope

The Python async adapter proposed in #68 has a separate host choice:
`Scope.BOUND_POINTS_ONLY`. A host using that mode never calls ACS for known
unbound points, so this manifest declaration is not consulted. Such a bypass
returns the fixed host reason `host_scope:bound_points_only`, which is reserved
from policy output and distinguishable from both a bound policy allow and
`scope:unbound_point`.

`Scope.STRICT`, the default, calls ACS for every point and therefore honors
`ungoverned_points`. Only Python has this host-side switch today. The manifest
declaration is the cross-language mechanism for Rust, Python, Node, FFI, and
.NET. A deployment that requires manifest scope to be enforced uses strict host
scope.

## Version and rollout

Do not add this key to `0.4.0-alpha.1`. Target `0.6.0-alpha.1` if #78 allocates
`0.5.0-alpha.1` first; otherwise the spec owners must reallocate the next minor
grammar version before implementation.

The model needs a post-parse version rule, and the schema needs an `if`/`then`
constraint or a version-specific schema, so the new key is rejected under old
grammar. `SUPPORTED` retains `0.4.0-alpha.1` and intervening versions throughout
the alpha line; removing one requires a separate breaking-change proposal.
Existing chain version equality remains. A shared base must be re-versioned
before children can adopt the new grammar, and mixed-version chains remain
`runtime_error:manifest_invalid`.

Implementation is a separate change spanning:

- `spec/SPECIFICATION.md`, `spec/README.md`, the manifest schema, and
  `spec/reserved-reasons.json`;
- the Rust manifest model, per-document source validation, resolved
  serialization, activation introspection, runtime lookup, and telemetry;
- the unconditional unbound-point promises in the Python, Node, .NET, and FFI
  public documentation and API comments;
- conformance vectors and binding parity across Rust, Python, Node, FFI, and
  .NET.

The affected existing surfaces include `sdk/python/README.md`,
`sdk/python/agent_control_spec/__init__.py`, `sdk/node/README.md`,
`sdk/node/binding.d.ts`, `sdk/dotnet/README.md`,
`sdk/dotnet/src/AgentControlSpec/AcsPolicy.cs`, `sdk/ffi/src/lib.rs`, and the
`intervention_points()` contract in `engine/src/activation.rs`.

## Acceptance cases

Add cases proving:

- absent declaration preserves `runtime_error:intervention_point_unknown`;
- one listed lifecycle point returns the fixed allow reason and source marker;
- a policy cannot emit `scope:` or `host_scope:` reasons;
- a listed point and a bound point remain behaviorally distinct;
- overlap, unknown names, duplicates, empty lists, empty
  `intervention_points`, and old-version use fail manifest validation;
- fetched or non-root declarations fail, including pinned URLs;
- local root declarations survive resolved serialization;
- mixed-version chains fail and same-version chains remain unchanged;
- limits run before the scope verdict and no annotator or policy runs on that
  path;
- another control's denial still wins under the configured Agent Hooks
  composition profile;
- strict and `BOUND_POINTS_ONLY` host scope produce their respective reserved
  reasons.

Keep the existing `spec-08-intervention-points.case-07.json` and the
`intervention-point-unknown` case in
`tests/conformance/fail_closed_error_parity.json` as the absent-declaration
baseline.

The Agent Hooks CTK cannot observe this ACS-specific distinction because its
harness registers scripted interceptors rather than exercising ACS manifest
resolution. ACS conformance cases and native telemetry tests are the automated
contract for this feature.

## Decision requested

Agree on the explicit coverage-set shape, fixed reserved reasons, root-only
authorship, telemetry source marker, host-scope interaction, and grammar
allocation before implementation.
