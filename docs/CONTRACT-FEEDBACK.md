# agent-hooks contract feedback

Items this consumer surfaced against agent-hooks `0.1.0-alpha.2` while
rebuilding on the contract. Candidates for the next agent-hooks
release; none are worked around here beyond what is noted.

1. **`ctk::Harness` is not implementable outside the crate.** The
   trait's `run()` returns `ctk::RunRecord`, which is private — a
   third-party Rust host cannot implement the trait to run the corpus
   under its own adapter name. This repository runs the corpus through
   the SDK's `ReferenceHarness` directly and names the claim in its
   report instead. Fix: export `RunRecord` (and any other types the
   trait signatures reference) from `agent_hooks::ctk`.
2. **`InterceptionPoint` lacks `Ord` and `Display`.** Deterministic
   ordered maps keyed by interception point and human-readable
   diagnostics both need them; `engine/src/point_ext.rs` carries a
   local `PointKey` wrapper ordering by wire name. Fix: derive `Ord`
   (wire-name order documented) and implement `Display` upstream.
3. **Doc gap: `EvaluationResult`-style consumers.** The crate-level
   docs describe hosts and interceptors; a section for decision
   runtimes that sit behind an interceptor (what to return for
   engine-internal failures — the `runtime_error:*` vs `host_error:*`
   namespace split this repository uses) would prevent every consumer
   re-deriving the convention. Documentation-only.

Positive signal worth keeping: the vendored 47-vector corpus ran green
against the emitter loop on the first complete attempt after the
engine's native adoption — the §5 validation surface (`approval` only
on deny, warnings shape, transform grammar parity via
`parse_transform_path`) caught every malformed policy output in tests
before it could reach a host.
