# agent-hooks contract feedback

Living log of items this consumer surfaces against the agent-hooks
contract while building on it. Open items are candidates for the next
agent-hooks release; resolved items record what shipped and how this
repository adopted it.

## Open

None.

## Resolved

Resolved in agent-hooks `0.1.0-alpha.3` (surfaced against
`0.1.0-alpha.2`):

1. **`ctk::Harness` is not implementable outside the crate.** The
   trait's `run()` returned `ctk::RunRecord`, which was private.
   Resolved: `RunRecord`, `VectorResult`, and `IdentityPair` are
   exported from `agent_hooks::ctk` (with `async_trait` re-exported).
   Adopted here: `engine/tests/agent_hooks_conformance.rs` implements
   the trait directly and runs the corpus under the adapter name
   `agent-control-spec-reference-host`.
2. **`InterceptionPoint` lacks `Ord` and `Display`.** Deterministic
   ordered maps keyed by interception point and human-readable
   diagnostics both need them. Resolved: upstream derives `Ord`
   (lifecycle declaration order, documented) and implements `Display`
   (wire name). Adopted here: the local `PointKey` wrapper in
   `engine/src/point_ext.rs` is gone; manifests key
   `intervention_points` on `InterceptionPoint` directly.
3. **Doc gap: `EvaluationResult`-style consumers.** The crate-level
   docs described hosts and interceptors but not decision runtimes
   that sit behind an interceptor. Resolved: documentation covers the
   `runtime_error:*` vs `host_error:*` namespace split for
   engine-internal failures.

Positive signal worth keeping: the vendored 47-vector corpus ran green
against the emitter loop on the first complete attempt after the
engine's native adoption — the §5 validation surface (`approval` only
on deny, warnings shape, transform grammar parity via
`parse_transform_path`) caught every malformed policy output in tests
before it could reach a host.
