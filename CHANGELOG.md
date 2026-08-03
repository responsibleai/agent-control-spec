# Changelog

## Unreleased

- Incremental stream mediation, specification section 18.1. A host that must
  release model output before the whole response exists can now drive
  `StreamSession`, which tracks how far each configured task has cleared a
  stream and reports the prefix that is safe to emit. The watermark for a track
  is the minimum across its tasks, clearance is contiguous so a span starting
  past a task's frontier fails closed rather than confirming an unevaluated gap,
  and any rune no task cleared fails the stream at settlement. The session holds
  no stream text and performs no segmentation: the host declares the rune range
  it evaluated, because two accounts of what was evaluated over the same runes
  cannot both be authoritative. The runtime is untouched and stays stateless.
  The module sits behind the new `streaming` cargo feature, off by default, so
  the crate's default surface stays free of per stream state.
- The profile applies to text streams only. A structured streaming surface whose
  deltas carry fragments a policy cannot read until reassembly, such as a chat
  completion stream splitting tool call arguments across chunks, still buffers.
  `tests/conformance/streaming` is that path and is unchanged.
- Streaming failures now report the agent-hooks reason
  `host_error:streaming_unsupported` rather than the SDK layer
  `runtime_error:streaming_unsupported`, per the section 16 rule that new code
  uses the agent-hooks reserved set. The older reason stays reserved for
  compatibility while the language SDKs are rebuilt.
- A verdict the section 5 contract does not admit, such as a `transform` with no
  substitution body or one whose path leaves `$target`, fails the stream closed
  with `host_error:verdict_invalid` before it clears anything. A `deny` carrying a
  `host_error:` reason is exempt from that check, since the contract rejects one
  only to stop an interceptor forging a host error over the wire and the host
  that drives this profile owns that namespace. No other decision is exempt, and no
  `warnings` entry is exempt under any decision, since a reason reporting that
  the host's own evaluation failed cannot justify releasing or rewriting text
  and a warning is never the host reporting its own failure. The typed contract
  check covers the top level reason only, so the warning rule is applied here
  rather than depending on which path a host used. It covers both reserved
  prefixes: `runtime_error:` belongs to the runtime, and the policy output
  normalizer screens a policy's top level reason for it but not a warning's. A liftable `deny`, meaning one carrying an
  `approval` block, is taken at its word and denies. Resolving it is a host
  obligation under section 9, which a session cannot discharge because it cannot
  hold its connection open across an out of band approval, so withholding the
  text is the conservative reading.
- A `transform` is honored only while nothing on its track has been released.
  Under `deferred` that means never, since the payload was emitted on arrival. A
  transform names a node of the policy target rather than a rune range, and the
  session holds no text, so it cannot bound how far below the span the rewritten
  value reaches. A host evaluating the accumulated prefix has a target covering
  every rune of the track, and a session resuming a partially delivered stream
  starts above zero precisely because that prefix already reached the caller, so
  it can never transform.

- Manifest grammar validation is reachable from every binding, not just
  the Rust crate: `validate_manifest` (Python), `validateManifest`
  (Node), `AcsManifest.Validate` (.NET), over the new C ABI entry point
  `acs_validate_manifest`. Validation builds no runtime and needs no
  policy engine on PATH, so generators and migration tools can check a
  manifest before any policy is runnable.
- Manifests that use `extends` are validated through a path-taking
  variant (`validate_manifest_file`, `validateManifestFile`,
  `AcsManifest.ValidateFile`, `acs_validate_manifest_file`), which
  resolves the chain first. Validating such a manifest from source alone
  reports a boundary error rather than a grammar rejection, because the
  cross-reference checks only hold once the documents are merged.
- New reserved reason `runtime_error:manifest_unreadable`, returned when
  a manifest could not be obtained at all: the named manifest is absent
  or unreadable, a permission denial anywhere in the chain, or a failed
  fetch of a URL `extends`. Previously these arrived as
  `runtime_error:manifest_invalid`, which said the document was bad when
  it had never been read. A missing `extends` target stays
  `runtime_error:manifest_invalid`, since the including document was read
  and names a file that is not there. The validation entry points map
  `manifest_unreadable` to a boundary failure rather than a verdict.
- `acs_interceptor_new_ex` takes a manifest path as a pointer and a
  length. `acs_interceptor_new` is kept for existing consumers but
  truncates at an interior NUL, which loads a different manifest than the
  caller named.
- `RuntimeError` is `#[non_exhaustive]`, so a future reserved reason does
  not break a downstream exhaustive match.
- The accepted grammar versions are published as
  `manifest::SUPPORTED_VERSIONS` and through each binding, so consumers
  no longer have to hardcode a copy that drifts from the engine.

## 0.4.0-alpha.1

First public release.

- Policy decision runtime extracted from the governance toolkit's
  policy engine, adopting the agent-hooks contract natively: the
  engine evaluates manifest-bound policies (Rego through OPA, Cedar
  through the built-in evaluator, `test` doubles) and returns
  three-verdict wire shapes; engine failures normalize into
  fail-closed `deny` verdicts with `runtime_error:*` reasons.
- `AcsInterceptor` wrappers for Rust, Python, Node, and .NET register
  with any agent-hooks host emitter.
- Conformance: the AGENT-HOOKS-0.1 corpus passes under this
  repository's first-party harness (46 of 47 vectors; one
  capability-gated skip). Report under `conformance/agent-hooks/`.
- Distribution: crates.io `agent-control-spec`, PyPI
  `agent-control-spec`, npm `@responsibleai/agent-control-spec` (+
  platform packages), NuGet `ResponsibleAI.AgentControlSpec`.
