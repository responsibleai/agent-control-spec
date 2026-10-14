# Fixture case corpus

This directory is a cross-language-ready fixture corpus for Agent Control Specification SDKs. Each `cases/*.json` file is declarative: it contains a YAML manifest, optional mock annotation/policy responses, intervention point snapshots, and expected verdicts/policy inputs/invocations.

Additional frozen contract artifacts:

- `manifests/*.yaml` — canonical example manifests for the refactored stateless model.
- `extends/` — path-loader fixtures for ordered, relative, duplicate-identical, conflict, cycle, missing-file, and unsupported URL scheme `extends` behavior.

The Rust integration test `tests/fixture_cases.rs` loads every case and validates it against the current core so future SDK fixtures cannot drift. The schema in `fixture-case.schema.json` documents the case shape.

Invariants encoded by the corpus:

- Closed intervention points only: `agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output`, `agent_shutdown`.
- `extends` is an ordered array resolved by file-based loaders before final manifest validation. Entries can be path strings, HTTPS URL strings, or HTTPS URL objects with optional SHA-256 pins. Policies are declared at top level, annotators are top-level `classifier | llm | endpoint`, and annotations are configured per intervention point.
- No state/endpoint hooks, hooks block, variables, lifetimes, event bus, resolvers, expression language, guard-policy merging, auto-resolution, durable runtime state, or manifest fail-open in valid manifests.
- Runtime failures deny with reserved `runtime_error:*` reasons.
- A `transform` verdict carries one `{path, value}` replacement rooted at `$target`. The runtime validates it and returns it unapplied in both modes; the host applies it.
- Tool calls are evaluated per invocation; streaming fixtures use aggregated outputs only.
