# Changelog

## Unreleased

- A policy version can be activated once and evaluated many times.
  `ActivatedPolicy::activate` reads the manifest, loads every Rego module
  and data document, and compiles the entrypoint each intervention point
  queries, so a decision afterwards costs no I/O and no compilation. The
  handle is immutable, `Send + Sync`, and cheap to clone, so a host holds
  one per policy version and shares it across threads under its own
  versioning scheme rather than relying on the runtime to guess when a
  policy changed.
  - `PolicyDispatcher` gains a `warm` method with a default no-op, so any
    dispatcher can prepare a policy ahead of the first decision and none
    is required to.
  - Over `examples/bank_agent`, activation costs a few milliseconds and
    each later decision about 200 to 300us at p50, consistently across
    Rust, .NET, Node, and Python, so activation is repaid within roughly
    ten decisions. Absolute figures are hardware specific; run the
    benchmarks rather than trusting these.
  - Warming earns its keep in proportion to the policy set. The
    benchmark takes a module count and builds a synthetic bundle of that
    size, so the claim is reproducible from this tree: at 200 modules,
    activation moves about 18ms of load and compile off the first
    decision, which lazily is charged to it.
  - Reachable from every binding: `AcsPolicy.Activate` (.NET),
    `policyActivate` (Node), `ActivatedPolicy` (Python), and
    `acs_policy_activate` / `acs_policy_evaluate` / `acs_policy_free`
    over the C ABI.
  - `cargo run --release -p agent-control-spec --all-features --example
    benchmark` reports activation cost, warm p50/p95/p99 per intervention
    point, and the concurrency curve.

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
    evaluated. An evaluation abandoned at its deadline leaves a thread
    that cannot be killed, so once
    `agent_control_spec::rego::MAX_ABANDONED_WORKERS` of them are
    outstanding the dispatcher stops starting new ones and fails closed
    with `runtime_error:policy_invocation_failed` until the backlog
    drains. `RegorusRegoRunner::abandoned_evaluations()` reports the
    current count.
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
