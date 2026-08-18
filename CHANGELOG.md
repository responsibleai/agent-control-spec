# Changelog

## Unreleased

## 0.4.0-alpha.3

- Python `__version__` is read from the installed distribution instead of being
  written into `__init__.py`. The literal was a seventh version surface, covered
  by neither `scripts/check-version-consistency.py` nor RELEASING.md, so it held
  `0.4.0a1` through the 0.4.0-alpha.2 release with CI green. It was also immune
  to a search-and-replace bump, because the stale literal never contained the
  version being replaced. `sdk/python/tests/test_version.py` fails if a literal
  returns.
- Release bump only otherwise. 0.4.0-alpha.2 shipped before #39 merged, so the
  streaming, host hook, manifest tooling and artifact validation surfaces that
  change added are reachable from a registry install for the first time here.
  The .NET package also carries the native engine for five runtime identifiers;
  the published 0.4.0-alpha.2 nupkg could not run without one on the library
  path.

## 0.4.0-alpha.2

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
- A policy version can be activated once and evaluated many times.
  `ActivatedPolicy::activate` reads the manifest, loads every Rego module
  and data document, and compiles the entrypoint each intervention point
  queries, so a decision afterwards costs no I/O and no compilation. Readying is bounded by the eval
  timeout, so a policy too slow to compile inside it activates anyway,
  not necessarily fully readied, and pays compilation on its first decision. The
  handle is immutable, `Send + Sync`, and cheap to clone, so a host holds
  one per policy version and shares it across threads under its own
  versioning scheme rather than relying on the runtime to guess when a
  policy changed.
  - `PolicyDispatcher` gains a `warm` method with a default no-op, so any
    dispatcher can prepare a policy ahead of the first decision and none
    is required to.
  - Over `examples/bank_agent`, activation costs milliseconds and a
    later decision hundreds of microseconds, so activation repays itself
    in tens of decisions rather than thousands. The four benchmarks
    measured the `input` point at 166us from Rust, 200us from .NET,
    249us from Node, and 284us from Python, run back to back so they
    compare: the spread is what each binding adds around one engine
    call, not four different engines. Read the ratios rather than the
    microseconds. The same machine returned figures a third lower
    earlier in the day, so an absolute number here says as much about
    the machine as about the code; the benchmarks print their own.
  - Warming earns its keep in proportion to the policy set, and the
    benchmark takes a module count so that claim is reproducible from
    this tree rather than asserted. At 200 modules the first decision
    drops from about 17.6ms to about 6.9ms, medians of seven runs, because
    compilation is otherwise charged to it. Read those two numbers off a
    settled machine: the first runs after a build measure the page cache
    as much as the policy, and moved between 6.7ms and 17.1ms here.
  - Reachable from every binding: `AcsPolicy.Activate` (.NET),
    `policyActivate` (Node), `ActivatedPolicy` (Python), and
    `acs_policy_activate` / `acs_policy_evaluate` / `acs_policy_free`
    over the C ABI.
  - `cargo run --release -p agent-control-spec --all-features --example
    benchmark` reports activation cost, warm p50/p95/p99 per intervention
    point, and the concurrency curve.

- A policy version can be activated from a manifest and Rego held in
  memory, not only from a path. A service that keeps both in a database
  had to stage them to a temporary directory before every activation;
  `ActivatedPolicy::activate_from_memory` takes the manifest as text and
  a map from policy id to the modules and data documents that policy
  evaluates. The path-based entry points are unchanged.
  - The engine reads policy source as a string either way, so this is
    the existing load path with the read removed rather than a second
    way to load a policy. A test pins that the same policy activated
    from disk and from memory reaches the same verdict.
  - A data document carries its mount point explicitly. On disk that
    comes from the file's directory relative to the bundle root, and
    nothing implies it in memory.
  - The prepared-engine cache is keyed on a bundle path, which an
    in-memory bundle does not have, so such a bundle is keyed on a
    SHA-256 over its contents instead. Without it, two Rego policies in
    one manifest would share one cache entry, and the second would be
    served the first one's engine and fail closed on its own query.
  - A Rego policy left naming a relative `bundle` path is refused. A
    manifest parsed from text has no directory of its own, so the path
    would resolve against the process working directory and load a
    policy nobody chose. An absolute path is left as written, so one
    manifest can mix policy from a database with policy on disk.
  - The `opa` CLI dispatcher refuses an in-memory bundle rather than
    evaluating without it: it passes policy to a subprocess as paths, so
    it would otherwise return a verdict for a policy the host did not
    supply.
  - Building a bundle validates and hashes it; nothing is compiled until
    activation. It cost 0.4us at one module and 14.7us at 200 against
    1.6ms to 3.7ms to activate over the same range, four orders of
    magnitude apart, so a host gains nothing by caching a bundle
    separately from the activation it feeds. Cache the activated policy.
  - Reachable from every binding: `AcsPolicy.ActivateFromMemory` (.NET),
    `ActivatedPolicy.activateFromMemory` (Node),
    `ActivatedPolicy.from_memory` (Python), and
    `acs_policy_activate_from_memory` over the C ABI.
  - `RegoPolicyInvocation` and `RegoPolicyConfig` gain an `inline_bundle`
    field. Both have public fields, so code constructing either
    literally has to add it.

- A policy calling `http.send` now fails closed. `regorus` registers the
  builtin but leaves it permanently undefined, so a deny rule gated on it
  did not fire and the policy allowed: the one divergence in this
  dispatcher that failed open. It is shadowed by an extension that
  errors, so it behaves like every other builtin this runtime does not
  provide. Policies here are meant to be pure and offline, so no correct
  policy changes; one that reaches for the network now says so at the
  first decision.

- A manifest query naming a rule, which is the ordinary case, is read as
  a rule rather than parsed as query text on every decision. In the
  engine call alone the parse dominated, 284us against 46us; end to end
  a warm decision over `examples/bank_agent` fell about a fifth to a
  quarter, from 221us to 166us at p50 on the `input` point, medians of
  five runs interleaved with the previous commit to hold the machine
  steady. The rest of a decision is annotation, input building, and
  dispatch, which this does not touch. Queries that are not plain rule
  paths, including the expression forms the specification permits, still
  go through the general path, and a rule left undefined by its input
  still fails closed with the reason it always had.

- The bundled Rego dispatcher evaluates policy in process through
  [`regorus`](https://crates.io/crates/regorus) instead of shelling out to
  an `opa` binary on PATH. Nothing has to be installed on the host, and a
  decision no longer costs a process spawn, a pipe round trip, and a JSON
  re-parse: measured over the `examples/bank_agent` policy set, one
  intervention point drops from 26ms to 0.3ms. The new dispatcher reads
  the same single query expression value the `opa` CLI returned, and
  loads bundles and data documents by OPA's own rules, so a bundle within
  the Rego that `regorus` implements produces the same verdict. It is not
  a drop-in for every bundle: see the divergences below.
  - New default feature `rego`, exposing `RegorusRegoRunner` and
    `RegorusPolicyDispatcher`. `default_policy_dispatcher` and the
    language bindings use it.
  - The `opa` CLI dispatcher is unchanged, but its `opa` feature is no
    longer on by default. Hosts that need OPA's exact CLI semantics can
    opt back in and register `OpaPolicyDispatcher` themselves. One
    behaviour does differ: the in-process dispatcher reads a bundle
    directory or a single file, never a packaged `.tar.gz`.
  - `ACS_OPA_TIMEOUT_MS` still sets the eval timeout. The dispatcher
    enforces it twice, through a cooperative deadline inside the
    evaluator and through a pooled worker thread it abandons when the
    deadline passes, so a caller returns on time even for a policy the
    evaluator cannot interrupt. `ACS_OPA_PATH` applies only to the opt-in
    CLI dispatcher.
  - `RegorusRegoRunner::with_policy_cache(true)` reuses a parsed bundle
    across evaluations. It stays off by default on the bare runner
    because it hides on-disk policy edits until the runner is rebuilt.
    `default_policy_dispatcher` and the language bindings turn it on,
    since they hold one runtime for the life of the process and would
    otherwise re-read the whole policy set on every decision.
  - Known divergences from the `opa` CLI, for hosts porting a bundle:
    Rego parses as v1 unless `ACS_REGO_V0=1` or
    `RegorusRegoRunner::with_rego_v0(true)`; packaged `.tar.gz` bundles
    are not read; `regorus` lacks some OPA builtins (`crypto.*`,
    `io.jwt.*`, `json.patch`, GraphQL, AWS signing), where calling one is
    a loud fail-closed evaluation error, except `http.send`, which is
    registered but always undefined and so silently fails open for a deny
    rule gated on it; and numeric precision differs, which can flip a
    verdict. Integers agree exactly while they fit in `i64`/`u64`, so
    counts and integer thresholds are unaffected, but every non-integer
    is an `f64` here against OPA's higher-precision decimal arithmetic:
    `sum([0.1, 0.2])` is `0.3` under OPA and `0.30000000000000004` here,
    enough for a budget policy comparing it against a `0.3` cap to allow
    under OPA and deny here. Upstream tracks this as
    microsoft/regorus#202. Integers past `u64` likewise arrive as
    doubles, which is this crate's choice rather than a `regorus` limit:
    carrying them exactly needs `serde_json/arbitrary_precision`, a
    global feature that makes `canonical_json` non-idempotent (`0.5` and
    `5e-1` would canonicalize differently and so hash differently).
  - A host can now be told that a decision was refused rather than
    evaluated. A run abandoned at its deadline leaves a thread that
    cannot be killed, so once
    `agent_control_spec::rego::MAX_ABANDONED_WORKERS` of them are
    outstanding in a pool, that pool stops starting new work and fails
    closed with `runtime_error:policy_invocation_failed` until the
    backlog drains. A runner keeps two pools, one for evaluation and one
    for readying a policy, so the limit bounds a pool rather than a
    runner. `RegorusRegoRunner::abandoned_evaluations()` reports the sum
    across both, which is the number to watch for a leak rather than the
    number either gate compares against.
  - A policy's `print()` output is captured and discarded rather than
    reaching the host's stderr. The CLI dispatcher kept it inside the
    child process, so letting it through would have been a new way for
    policy input to land in host logs.

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
