# Vendored conformance vectors

The vectors under `vectors/` are the AGENT-HOOKS-0.1 Conformance Test
Kit corpus, vendored verbatim from agent-hooks `0.1.0-beta.2`
(https://github.com/responsibleai/agent-hooks). They are consumed by
`engine/tests/agent_hooks_conformance.rs`, which runs the full corpus
against this repository's reference host and is the source of the
conformance report in `conformance/agent-hooks/REPORT.md`.

This release matches the `agent-hooks-sdk` version the engine
resolves (`engine/Cargo.toml`, `Cargo.lock`), so the runner and the
corpus come from the same release.

Source of the current copy:

- Tag: `v0.1.0-beta.2`
- Commit: `064173e31b02be4cdea1342dc16d739e451846bb`
- Files: 73 (`AH-CTK-001` through `AH-CTK-141`)
- Digest: `ace2c33cf5b0134ddd98200e19f1645b7745aa745f694186eaa8422d43a2eb8d`

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
