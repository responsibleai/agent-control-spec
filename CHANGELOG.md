# Changelog

## Unreleased

- The bundled Rego dispatcher evaluates policy in process through
  [`regorus`](https://crates.io/crates/regorus) instead of shelling out to
  an `opa` binary on PATH. Nothing has to be installed on the host, and a
  decision no longer costs a process spawn, a pipe round trip, and a JSON
  re-parse: measured over the `examples/bank_agent` policy set, one
  intervention point drops from 26ms to 0.3ms. Verdicts do not change. The
  new dispatcher reads the same single query expression value the `opa`
  CLI returned, so the same manifest over the same bundle still produces
  the same verdict.
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
    across evaluations. It stays off by default because it hides on-disk
    policy edits until the runner is rebuilt; the language bindings turn
    it on, since they hold one runtime for the life of the process.

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
