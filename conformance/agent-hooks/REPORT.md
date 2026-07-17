# AGENT-HOOKS-0.1 conformance report

Host adapter: `agent-control-spec-reference-host` (agent-hooks
emitter loop; see `engine/tests/agent_hooks_conformance.rs`).
Corpus: vendored per `PROVENANCE.md`.

| Part | Passed | Failed |
| --- | --- | --- |
| approval_seam | 8 | 0 |
| composition/parallel_strictest | 3 | 0 |
| composition/parallel_unanimous | 2 | 0 |
| composition/sequential_first_deny | 2 | 0 |
| composition/sequential_run_all | 5 | 0 |
| enforcement/evaluate_only | 1 | 0 |
| enforcement/isolation | 1 | 0 |
| enforcement/post_action_deny | 1 | 0 |
| fail_closed/verdict_gate | 1 | 0 |
| identity_provider | 4 | 0 |
| record/decided_by | 1 | 0 |
| record/projection | 1 | 0 |
| unspecified | 15 | 0 |
| verdict/warnings | 1 | 0 |

Total: 46 passed, 0 failed, 1 skipped (capability-gated) of 47.
