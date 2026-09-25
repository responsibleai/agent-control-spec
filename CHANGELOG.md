# Changelog

## Unreleased

- Replace archived `serde_yaml` and its transpiled libyaml dependency with
  `serde-saphyr` (caret `1.2`, locked to `1.2.0`) and `granit-parser` `1.2.1`.
  Building the engine requires Rust 1.89, now checked in CI. Regorus YAML
  capabilities remain unchanged and may use a different YAML implementation.
- YAML manifest parsing rejects duplicate keys, unsupported tags (including
  non-specific `!`), non-finite numbers and positional sequences in place of
  structs. YAML merge keys remain ordinary keys. Typed string fields and mapping
  keys spelled like numbers, booleans or null must be quoted; an empty plain
  value is null, not an empty string. Use `policy_target: ""` to leave an overlay
  target unset. Legacy spellings such as `010`, `1_000`, `0X1F` and `tRuE` retain
  their string types, including when used as keys. Numeric fields do not coerce
  these strings or ordinary quoted strings.
- Explicit core tags determine scalar types: `!!int "1"` is numeric and
  `!!null ""` or an empty `!!null` block is null. An optional string set to an
  explicitly tagged null is absent. Parsing unsigned `-0` yields zero (fields
  requiring positive values still reject it at validation). A leading UTF-8 BOM
  and tabs separating mapping colons from values are accepted. Unknown reserved
  directives, space-then-tab indentation and tabs after sequence dashes are
  accepted; a tab starting block indentation and embedded BOMs remain invalid.
  `intervention_points: null` remains invalid, unlike an omitted or empty map.
  Diagnostics retain field paths and
  line/column locations without source snippets or parser-configuration advice.
- Manifest source and expanded scalar bytes are bounded by
  `Limits.max_merged_manifest_bytes` (1 MiB), also used for composed manifests.
  Text-chain composition intentionally checks the serialized combined size:
  individually admissible overlays can exceed the cap when merged.
  Local YAML **and JSON** reads stop after this cap plus one byte. YAML budgets
  default to depth 64 (formerly the old parser's fixed 128), 100,000 expanded
  nodes including keys, 300,000 scanned/replayed events excluding comments, 50,000 aliases and
  anchors, and 10,000 retained anchor event copies. Each is configurable through
  a dedicated `max_manifest_*` limit; manifest depth is independent of
  `max_policy_input_depth`. Every anchor retains at least one event, so the
  retained-event budget limits default anchor definitions to at most 10,000,
  even though the nominal anchor limit is 50,000.
  Alias reuse is not limited by a ratio heuristic.
  Exceeded budgets retain `runtime_error:resource_limit_exceeded`, not grammar
  rejection, across Rust, Python, Node, FFI and .NET text validation, including
  manifest and artifact diagnostics. Budget messages name the exceeded count
  and limit field with at most one location, not parser debug variants or
  repeated alias locations. Diagnostics omit unknown path segments and the
  root placeholder without stripping punctuation from actual keys.
  Python/Node parse, validate and merge exceptions consistently retain the
  `runtime_error:manifest_invalid:` prefix; findings carry a separate code.
- Specify manifest parsing among the activities that runtimes MUST bound;
  engine limit fields and defaults remain documented implementation choices.
- Fix the existing no-default-features build by making manifest Rego adapter
  path validation available without enabling Rego or OPA dispatchers.
- Add Rust `parse_yaml_str_with_limits`, `from_yaml_str_with_limits` and
  `from_yaml_chain_with_limits`; Python/Node manifest tooling accepts optional
  limits, FFI has additive `_with_limits` text functions, and .NET
  `AcsManifest.Validate` and `AcsManifestTools.Parse`/`Merge` accept a limits dictionary. Existing no-options calls
  use defaults. Rust `Limits` gains six fields; exhaustive struct literals must
  supply them or use `..Limits::default()`. See [manifest parsing](docs/manifest-parsing.md) for contracts and
  dependency evidence.
- Manifest contract `0.5.0-alpha.1` adds annotator chaining through point-binding
  `needs`: dependencies run first, and consumers can read their outputs through
  `$pi.annotations.<name>`. Legacy `0.4.0-alpha.1` semantics stay unchanged.
  Migrate an entire `extends` chain together and rename any host-specific
  `needs` setting first; see specification sections 2.1 and 10.1.
  This is an unreleased contract change, not a release or package bump;
  package versions remain `0.4.0-alpha.4`.
  The manifest schema now rejects unsupported versions rather than leaving that
  check solely to the runtime. Version validation and composition use the Unicode
  `White_Space` property when trimming surrounding characters.
  The runtime prepares dependency order and metadata once at construction and
  reuses one staged snapshot copy per evaluation. Consumers still copy their
  dependency outputs, so dispatch cost grows with the volume of those outputs.
  Staged depth checks visit only the replaced annotations member, preserving
  its depth under the policy-input root without rescanning the snapshot.
  In a local release benchmark with 50 no-op annotators, a 50,000-element
  array snapshot, and 100 measured evaluations after warmup, median chain/flat
  time fell from 2.92x to 1.45x (51.3/17.6 ms to 25.4/17.6 ms).
  Those figures describe that workload, not a general latency guarantee.
- Python adds `AsyncAcsInterceptor` over an `ActivatedPolicy`: awaitable
  interception, a dedicated bounded worker pool, reject or bounded-wait
  admission, and draining async shutdown. Emitter timeout/cancellation
  does not free capacity until native evaluation returns. Strict scope
  remains the default; `Scope.BOUND_POINTS_ONLY` explicitly skips valid
  lifecycle points outside this control without weakening bound-point
  failures or suppressing other controls. This is separate from the GIL
  fix below and does not change the manifest grammar.
  Scope bypasses carry `acs_point_unbound` in per-interceptor records;
  that allow label remains diagnostic. The three adapter admission
  denials use reserved `runtime_error:acs_async_*` reasons attributed
  to `sdk-adapter`, which policy output cannot imitate.
  `Saturation` names the admission modes, and read-only `in_flight`,
  `waiting`, and `closed` properties expose pool state. Each admitted
  call serializes the context once on the loop thread; workers receive
  an immutable string.
  WAIT admission is FIFO, reserves slots before waking callers, and
  defaults to five seconds. Cancellation or failed submission returns
  an unused reservation to the next eligible waiter.
  If the owning loop has already closed, `close()` joins workers
  synchronously; `aclose()` on a replacement loop performs that recovery
  off-loop. Cross-loop evaluation remains rejected.
  The three reserved admission reasons are an explicit, narrow draft
  contract exception to the host-error guidance, not a general namespace
  change. Specification minor-version allocation remains a release gate
  documented in `RELEASING.md`; no new grammar is allocated here.
- All Python `ActivatedPolicy` constructors now accept `telemetry_sink`,
  `perf_telemetry`, and `limits`, preserving these settings through
  async evaluation. Both file and in-memory activation apply host limits
  to bundled dispatchers. File activation also applies them to manifest
  loading. Existing calls keep their defaults.
- Regenerated the Python development lockfile from its requirements:
  it now installs the declared Agent Hooks `0.1.0a5` and maturin
  `1.15.0`, rather than the stale `0.1.0a3` / `1.8.7` pins.
- Add the optional `agent-control-spec-generator` package and `acs-policy-gen`
  command, porting AGT's natural-language authoring flow. It writes draft
  manifests, Rego and a review report without approving or activating policy.
  Conditions retain the exact source accepted by the parser; model text is
  escaped in reports and terminal output. Provider requests refuse redirects,
  bypass proxies for loopback HTTP, and use bounded response reads. Credentials
  come from the environment or a key file, not an argv value.
- Add Python-only `agent_control_spec.authoring.parse_rego_ast` and
  `REGORUS_AST_VERSION`, backed by the pinned Regorus parser with synchronous
  input-complexity bounds. No OPA executable is required for authoring.
- Prepare version `0.4.0-alpha.4` across runtime and generator metadata.
  The generator requires SDK `0.4.0a4` and shares the version consistency check,
  but remains outside the tag-driven publication workflow.
- Require root and Python Cargo lockfiles to resolve the same Regorus version.
  Generator iteration warnings cover wildcard and unbound-index lookups across
  collections. Leading unary-minus condition bodies are rejected before they can
  attach to a generated guard across a newline.
- `CedarRequest.context` replaces `CedarRequest.context_keys` and holds
  the Cedar JSON value the mapping produces. `CedarPolicyInvocation` drops
  its never populated `query` field. A cedar policy that sets `query`, or
  a cedar binding with any field other than `id`, now fails with
  `runtime_error:manifest_invalid` instead of being ignored.
- The bundled Cedar dispatcher evaluated every request with an empty
  context, mapped every `Deny` to `no_matching_policy` and ignored
  `@advice`. Every `has` guarded `forbid` in the shipped `policy/cedar-lib`
  failed open, an unguarded read failed closed, a context-gated `permit`
  never allowed, and the library's escalate, transform and warn permits
  were plain allows. The dispatcher now builds the context from the
  snapshot, `envelope` included, plus the annotations as one nested
  `annotations` record; takes the deny reason from the `@id` of the first
  contributing `forbid`; translates the `@advice` of every contributing
  `permit`, the most restrictive winning; and fails closed on an
  evaluation error in any policy. Specification 12.4 states the value
  rules: a float becomes a `decimal`, a null record member drops, a null
  set element fails closed, and a value Cedar cannot hold or a key its
  JSON format reserves fails closed with a detail that names the key and
  not the value. A schema now has to declare the context shape for each
  action; the dispatcher builds the context without the schema and checks
  it against the schema afterwards, so a schema cannot turn snapshot data
  into an entity reference. Advice with a member outside
  `cedar_advice.schema.json` fails closed with
  `runtime_error:policy_output_invalid`. Closes #83.
- A `cedar-lib` CI job runs the library's own Cedar test corpus with a
  pinned, checksum-verified `cedar-policy-cli`.
- Evidence over the AGENT-HOOKS-0.1 section 5.3 cap (10240 canonical
  bytes) no longer fails the whole verdict closed with
  `runtime_error:policy_output_invalid`. The runtime keeps the decision,
  reason, message, transform, result labels and the dispatcher's warnings
  as returned, keeps the artefact whole when it fits alone and drops it
  otherwise, keeps verification pointers in RFC 8785 member order up to
  the cap, and appends one `evidence_truncated` warning carrying the
  original size, the cap, the artefact outcome, the kept and total pointer
  counts and the sha256 of the full canonical evidence. The `decision` and
  `intervention_point.transformed` telemetry events carry
  `evidence_truncated: true` in their metadata when the marker is present,
  since their pointer keys then name only the kept pointers. The runtime
  owns that warning reason: a dispatcher warning that uses it fails closed. A
  dispatcher warning whose reason starts with the reserved `runtime_error:`
  or `host_error:` prefix fails closed too; section 18.1 forbids it and the
  agent-hooks wire decoder rejects it, but the runtime used to pass it
  through. Malformed evidence still fails closed, and an evidence member other than
  `artefact` and `verification_pointers`, which the runtime used to drop
  in silence, now fails closed too. The error detail for malformed
  evidence names the failure class and no longer repeats the dispatcher's
  pointer key. Closes #86.
- A manifest chain that fetches any `extends` URL is now URL sourced, and a
  URL sourced manifest may not read host secrets. A fetched document could
  name a host environment variable through `api_key_env` or one of the
  `aws_*_env` fields, or lean on a provider default such as `OPENAI_API_KEY`,
  while also choosing the endpoint that received the value. The loader now
  refuses, at load and with `runtime_error:manifest_invalid`, any `*_env`
  field anywhere in a chain that fetched a document, and refuses in a fetched
  document any filesystem path field (`bundle`, `data`, `data_paths`,
  `policy_path`, `entities_path`, `schema_path`), a rego `query` that is not
  a plain rule path, an `approval` section, and a rego `bundle_url` or
  annotator `system_prompt_url` unless every URL hop from the root is pinned.
  The bundled dispatchers refuse every
  host environment read for a URL sourced invocation, provider defaults
  included, and fail closed with `runtime_error:annotation_failed` before
  any request is sent. A pin vouches for the fetched bytes, not for host
  access. `Manifest::url_sourced`, `Manifest::url_sources` and the one way
  `Manifest::mark_url_sourced` expose and set the provenance for Rust hosts;
  manifests parsed from text stay host authored. `mark_url_sourced` takes
  one document parsed from text, before it is merged, and returns `Err` for
  a manifest the file loader produced, a merged manifest, or one already
  URL sourced; a host composing a chain marks each fetched document, then
  merges. The mark holds the document to the same rules as one fetched
  through `extends`, so it also returns `Err` for a `*_env` field, a
  filesystem path field, a rego `query` that is not a plain rule path, an
  `approval` section, a `bundle_url`, or a `system_prompt_url`, since the
  mark carries no pin.
  `Manifest` equality now includes provenance: a marked manifest is not
  equal to the same text unmarked. It ignores how the value was built, so a
  local manifest read from a file still equals the same text parsed. A
  binding overlays the declaration it names at dispatch, so the
  loader also records which annotator declarations and bindings only
  fetched documents supplied: a fetched binding for a host declared
  annotator may set only `from`, and a host binding for an annotator a
  fetched document declared may not carry an inline credential field
  (`api_key`, `headers`, `aws_access_key_id`, `aws_secret_access_key`,
  `aws_session_token`). Either shape would let the fetched document pick
  the endpoint that receives a host credential the host wrote inline. A
  declaration or binding the host wrote stays the host's when a fetched
  document repeats it byte for byte. `AnnotatorInvocation` gains a
  `url_sourced` field the runtime sets; it is skipped on the wire.
  `AnnotatorInvocation::from_annotation_in` builds an invocation with the
  manifest's provenance; `from_annotation` alone leaves the field false.
  Rust hosts that build the struct with a literal must add the field or
  spread `..Default::default()`. Local only chains are unchanged.
  Closes #20.
- Restore pinned remote prompt and OPA bundle downloads, and propagate host URL
  limits to bundled dispatchers. Reject invalid or conflicting sources, including
  for custom-dispatcher hosts. Existing constructor signatures remain supported;
  Regorus remains the default and rejects remote bundles.
- Python evaluation no longer holds the GIL. `intercept` and `interceptor_new`
  drop it around engine work, matching what `policy_activate` and
  `policy_evaluate` already did. A manifest with an `llm`, `endpoint` or
  `classifier` annotator performs a blocking HTTP request inside evaluation, and
  holding the lock across it stopped every thread in the process for the sum of
  those round trips. A Python host dispatcher re-acquires through
  `Python::attach`, unchanged.

## 0.4.0-alpha.3

- Python interception is synchronous in this release. `AcsInterceptor`
  holds the GIL during evaluation; `ActivatedPolicy.evaluate()` releases it.
  The GIL-release fix listed under Unreleased and the async-interceptor
  proposal [#68](https://github.com/responsibleai/agent-control-spec/pull/68)
  are not included in this release.

- Python `__version__` is read from the installed distribution instead of being
  written into `__init__.py`. The literal was a seventh version surface, covered
  by neither `scripts/check-version-consistency.py` nor RELEASING.md, so it held
  `0.4.0a1` through the 0.4.0-alpha.2 release with CI green. It was also immune
  to a search-and-replace bump, because the stale literal never contained the
  version being replaced. `sdk/python/tests/test_version.py` fails if a literal
  returns.
- `scripts/check-version-consistency.py` now also reads the Python binding's
  `agent-control-spec` dependency requirement. That crate is the only one
  pinning the engine by version as well as by path, and a stale requirement
  still resolves, because a caret requirement carrying a pre-release admits
  later pre-releases of the same triple. It had drifted to `0.4.0-alpha.2`.
- The first release reachable from a registry that carries what #39 added:
  stream mediation, host annotator and policy dispatchers, the telemetry sink,
  perf telemetry levels, resource caps, manifest parsing, chaining and overlay,
  validation findings as data, and manifest plus Rego validated together, in all
  four languages. The .NET package now carries the engine for five runtime
  identifiers; the published 0.4.0-alpha.2 nupkg could not run without one on
  the library path.
- Dependency work that ships inside these binaries rather than alongside them:
  the engine HTTP transport moved to ureq 3, and sha2 0.11, base64 0.23 and
  jsonschema 0.47 crossed majors. Bundle digests were verified byte-identical
  across the sha2 major, so no manifest or bundle identity changes. The Rust
  side now resolves `agent-hooks-sdk` 0.1.0-alpha.5, matching what the Python
  and .NET packages already required.
- Section 18.1 gates durable writes behind the watermark. Durable
  incorporation of stream text, into conversation history, a session store,
  or any record a later evaluation or run can read, follows the same rule as
  emission: a rune is eligible for a durable write when the watermark covers
  it, under every safety level, and a terminal deny or a failing settlement
  forbids persisting the withheld or uncleared runes. This restates the
  AGENT-HOOKS-0.1 section 6.1 discard obligation at the granularity the
  profile evaluates. The released prefix is already part of the caller
  visible record and may stay durable alongside the refusal that followed
  it. Mirrored as a module doc obligation on `StreamSession`.
- Section 18.1 defines the caller as any consumer outside the enforcement
  boundary. A host registered observer, a callback, a preview channel, or a
  sink fed from the raw accumulation is a caller, and withheld runes must
  not be delivered to one. The profile holds no text, so nothing structural
  separates the accumulation from a channel wired ahead of the release
  decision; the stated obligation is the whole of the protection.
- Section 18.1 states that the attempt boundary is not a clearance boundary.
  A track resuming at an offset above zero retains the last `L - 1` runes
  the earlier attempt delivered and includes them in the value it evaluates
  near the boundary, since a term can straddle the attempts and no value
  drawn from the new attempt alone can contain it. A host that no longer
  holds that tail must not resume the track under the profile. A mediation
  test covers a term straddling the resume boundary, with the host that
  dropped the tail as the negative control.
- Section 18.1 states the released text identity obligation. The runes the
  host releases are rune identical to the runes the recorded outcomes were
  evaluated against; a host side rewrite after clearance invalidates the
  clearance, and altered text belongs on the whole snapshot path or in a new
  session. Added to the `StreamSession` module doc obligations.
- Section 18.1 requires settlement of every opened session, including one
  the host abandons on disconnect, cancellation, or replacement by a retry.
  An abandoned session settles like any other, so uncleared residue is
  recorded rather than lost with the dropped session.
- Section 18.1 states the interaction with the `output` point, which section
  18 keeps on the whole snapshot path in every case. A host adopting the
  profile for caller facing egress receives that verdict after runes have
  reached the caller, so a deny there cannot recall them; the host records
  it and does not present the stream as settled clean, per the
  AGENT-HOOKS-0.1 section 6.1a record and close shape.

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
