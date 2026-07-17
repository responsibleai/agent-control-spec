# Vendored conformance vectors

The vectors under `vectors/` are the AGENT-HOOKS-0.1 Conformance Test
Kit corpus, vendored verbatim from agent-hooks `0.1.0-alpha.2`
(https://github.com/responsibleai/agent-hooks). They are consumed by
`engine/tests/agent_hooks_conformance.rs`, which runs the full corpus
against this repository's reference host and is the source of the
conformance report in `conformance/agent-hooks/REPORT.md`.

Refresh procedure: copy `conformance/vectors/AH-CTK-*.json` from the
agent-hooks release being claimed against, update the version above,
and re-run the conformance suite.
