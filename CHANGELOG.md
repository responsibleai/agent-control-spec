# Changelog

## Unreleased

- Section 18's requirement that a host assemble streamed model output before
  `post_model_call` now carries an exception for a host adopting section 18.1.
  The requirement to assemble streamed final output before `output` is unchanged
  and has no exception. The sentence excluding enforcement below the snapshot
  level now excludes the token level only. It previously excluded the chunk
  level too, which was ambiguous once this profile existed: a transport chunk
  is what the wire delivers, while the unit this profile evaluates is a span
  the host chooses, and the two need not coincide.
- A `transform` is terminal for the session and no watermark is reported for a
  track that records one. The substitution replaces the policy target with a new
  whole value: its runes are not the ones the session counted, so an offset over
  it names a position in a sequence that no longer exists, and no task evaluated
  it, so no clearance against the original authorizes releasing it. Settlement
  reports `StreamEndReason::Rewritten` with the track, task, and range. The host
  evaluates the replacement on the ordinary section 18 path.
- Payload arriving after the host closed the payload stream now fails the
  session rather than only being refused, since a host that ignored the refusal
  would settle clean over runes no task evaluated.
- A failing settlement no longer advances the watermark. Measuring residue is
  now independent of committing it, so `safe_offset` cannot rise as a side
  effect of failing.
- The resume offset is per track, `request_start_rune_offset` and
  `response_start_rune_offset`. The tracks are independent offset spaces and
  the ordinary retry re sends the prompt while resuming the response, which a
  single shared offset could not express.
- Payload on an unmediated track reports `NoTasks`, naming that track. A
  configuration mediating neither track is refused with `NoTracksMediated`,
  which names no track because none is at fault.
- A track declared with no tasks is not mediated rather than rejected, so a host
  guarding only the model stream no longer has to invent a request task that
  evaluates nothing. Payload on an unmediated track fails closed, and a session
  mediating neither track is refused.
- `StreamEndReason::Denied` and `StreamEndReason::Rewritten` carry the track.
  The same task name may gate both tracks, which left the audit record
  ambiguous about which one ended the session.
- The section 18.1 rule for sizing a bounded policy target is stated against
  the span's start rather than the term's length. A window merely longer than
  the longest term still misses a term that straddles a segment boundary, since
  a term overlapping a span can begin `L - 1` runes above where the span
  starts. For a suffix window of `N` runes over spans of at most `S`, the bound
  is `N >= S + L - 1`.
- `safe_offset` returns `Option<u32>` and is `None` once the session has ended.
  A denial withholds every rune the host has not already emitted, including
  cleared ones, so a terminal session has no offset anyone may emit through and
  a host that delivers lazily by polling now stops without having to remember
  to check. The offset the track reached is unaffected and stays readable
  through `watermark`, which is what an audit record needs.
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
  obligation under AGENT-HOOKS-0.1 section 9, which a session cannot discharge
  because it cannot
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
