# Vendored conformance vectors

The vectors under `vectors/` are the AGENT-HOOKS-0.1 Conformance Test
Kit corpus, vendored verbatim from agent-hooks `0.1.0-alpha.5`
(https://github.com/responsibleai/agent-hooks). They are consumed by
`engine/tests/agent_hooks_conformance.rs`, which runs the full corpus
against this repository's reference host and is the source of the
conformance report in `conformance/agent-hooks/REPORT.md`.

This release matches the `agent-hooks-sdk` version the engine
resolves (`engine/Cargo.toml`, `Cargo.lock`), so the runner and the
corpus come from the same release.

Source of the current copy:

- Tag: `v0.1.0-alpha.5`
- Commit: `61952932e52d5dab091a64677f19272daae619f8`
- Files: 47 (`AH-CTK-001` through `AH-CTK-105`)
- Digest: `ee86aadddb26ff1fd6f26318c68decc504c1020ae150f30ef075176af2558c6f`

The digest is computed from inside `vectors/` with:

```sh
LC_ALL=C sha256sum AH-CTK-*.json | LC_ALL=C sort | sha256sum
```

Refresh procedure: copy `conformance/vectors/AH-CTK-*.json` from the
agent-hooks release being claimed against, update the version, tag,
commit, file count and digest above, bump the `agent-hooks-sdk`
requirement in `engine/Cargo.toml` to the same release, and re-run
the conformance suite:

```sh
cargo test -p agent-control-spec --test agent_hooks_conformance
```

The test rewrites `REPORT.md`; commit the regenerated file.
