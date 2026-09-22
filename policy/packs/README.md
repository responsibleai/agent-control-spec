# Policy packs

Twelve configurable ACS controls, with native runtime tests and an offline host
example. These are source artifacts, not a new SDK or a separately published
package. Keep the `policy/packs/` and `policy/lib/` directory structure together.
Existing stock libraries, AGT policies and examples are not replaced or renamed.

## Choose controls

| Pack | Purpose | Integration status |
| --- | --- | --- |
| [Content safety](content-safety/README.md) | Gate harmful input and generated/retrieved content | Runnable decision, **classifier integration required** |
| [Prompt injection](prompt-injection/README.md) | Gate suspicious user/retrieved instructions | Runnable decision, **classifier integration required** |
| [Credentials](credentials/README.md) | Block recognizable plaintext credentials in nested JSON | Runs offline without extra host metadata |
| [PII](pii/README.md) | Deny or redact configured text patterns | Runs offline, host must apply transforms |
| [Tool permissions](tool-permissions/README.md) | Restrict tools by authenticated role | Runnable decision, **identity integration required** |
| [Destinations](destinations/README.md) | Permit only configured HTTP origins and methods | Runnable decision, **HTTP transport integration required** |
| [Human approval](human-approval/README.md) | Hold sensitive actions and large refunds for review | Blocks offline, **resolver required to approve** |
| [Budgets](budgets/README.md) | Bound planned tool/model usage | Runnable decision, **atomic accounting required** |
| [Information flow](information-flow/README.md) | Prevent writing higher-sensitivity data to a lower-clearance sink | Runnable decision, **provenance tracking required** |
| [Model routing](model-routing/README.md) | Restrict the actual provider/deployment/region tuple | Runnable decision, **model router integration required** |
| [Tool integrity](tool-integrity/README.md) | Pin the executed tool artifact | Runnable decision, **digest collection and pins required** |
| [Resource access](resource-access/README.md) | Check subject, tenant, operation and resource ACL | Runnable decision, **identity/resource catalog required** |

**Runnable decision** means the supplied manifest and Rego execute in ACS.
It does not mean that an integration, identity provider, classifier, ledger,
approval UI, transport or provenance tracker is supplied. Host-dependent packs
are integration templates until those prerequisites are wired and tested.
No real classifier calls or protection deployments are demonstrated here.

See [COVERAGE.md](COVERAGE.md) for the existing-library inventory, ownership,
reuse decisions, coverage gaps and tests.

## Install and run

From the root of a checkout containing this library:

```sh
python3 -m venv .venv-packs
. .venv-packs/bin/activate
python -m pip install -r policy/packs/requirements.txt -r policy/packs/requirements-test.txt
python policy/packs/demo.py
python -m pytest policy/packs/tests -q
```

The consumer pin is ACS `0.4.0a3`, which depends on Agent Hooks `0.1.0a5`.
Manifest version `0.4.0-alpha.1` is deliberately different. Python 3.11+
and the platform's native ACS/Agent Hooks artifacts are required. These tests
use Regorus inside ACS, not an OPA executable, a policy stub or a model.
`pytest` is only a test dependency. No API keys are required.

Expected demo output:

```text
search: allowed
approval: blocked
safe-output: allowed
pii-output: blocked
credential-output: blocked
policy packs demo: PASS
```

The example never runs a real tool. It uses `InterceptionEmitter.emit`, which
raises before a blocked action can run. Approval stays blocked because there
is deliberately no demo auto-approver. It makes no network calls and writes
no application data. Remove the example virtual environment when finished.

To test the checkout runtime instead of the consumer wheel, install the
repository SDK into a development environment following `sdk/python/README.md`,
then install only `requirements-test.txt` and run the same tests. CI exercises
both paths. Advance the consumer pin only after a compatible release exists.

Pack policies use fully qualified cross-module function calls such as
`data.acs.packs.common.natural(value)`. The pinned `0.4.0a3` wheel fails
policy invocation for imported-function aliases such as `c.natural(value)`,
even though the source-built runtime accepts them. Do not shorten those
calls without running the consumer tests. Imported constants remain usable.

## Bind the operation you actually execute

All manifests select `$.target`. The raw snapshot is an Agent Hooks context,
not AGT's older `envelope/input.body` shape:

```json
{
  "spec": "agent-hooks/0.1",
  "interception_point": "pre_tool_call",
  "timestamp": "2026-09-22T00:00:00Z",
  "sequence": 0,
  "agent": {"id": "support", "framework": "your-host"},
  "session": {"id": "session-1"},
  "target": {"query": "returns"},
  "tool_call": {"id": "call-1", "name": "search", "args": {"query": "returns"}},
  "extensions": {
    "policy_packs": {"subject": "alice", "roles": ["reader"]}
  }
}
```

ACS builds `input.policy_target.value` from `target`, retains the raw context
as `input.snapshot`, projects catalog metadata as `input.tool` when requested,
and supplies dispatcher outputs under `input.annotations`. The policy input
is not a schema the caller should forge directly.

Construct the envelope through your Agent Hooks SDK. The host must set the
real tool/model identity and bind all extension metadata to **this exact
operation and effective target**. Use the post-emission target when executing.
Do not let model-generated arguments replace `extensions.policy_packs`, the
tool catalog, classifier results or configuration. The extension name is only
a convention. ACS does not authenticate its provenance.

At input/output the builder's target is usually `{"content": ...}`. At a
pre-tool gate it is the argument object, and at a post-tool gate it is the
result value, not a `{value, is_error}` wrapper. Pre-model targets carry the
request. Each pack documents the types it actually handles. In particular,
the PII pack requires text or a content object. It can redact `content`,
but denies matches in other fields rather than pretending to sanitize them.

`agent_startup` and `agent_shutdown` are not configured because these packs
gate content and concrete operations. Evaluating an unbound point returns
`runtime_error:intervention_point_unknown`. Register a pack only where it
governs. Never turn a missing required field into "pack not applicable."

## Configure and compose

Edit each pack's `config.json` and/or manifest catalog in a host-controlled
copy. Configuration is Rego data under `data.pack`, never input from the
agent. Reactivate after changing files. Treat the loaded artifact version as
immutable while serving requests. Empty/malformed required configuration
denies, except fields not used at the current point. Tool integrity ships
with no invented trusted hashes and therefore denies until configured.

Use a separate ACS instance for each pack, then compose instances through
Agent Hooks as in `demo.py`. Each pack intentionally has its own `gate`
policy ID and `data.pack` configuration namespace. **Do not concatenate these
bundles or merge their manifests with `extends`.** The same interception
point cannot bind different policies through additive manifest merging.
Configuration overlap is harmless only while instances remain separate.

The demonstrated composition profile is `sequential/run_all`. Hard denies
remain hard denies even if another pack requests approval. Avoid
`parallel/unanimous` with approval-on-disagreement for mandatory controls.
Register disclosure checks before redactors if the original content must
never be accepted. Register them after redactors if checking sanitized output
is the intended policy. Tests cover both transformation forwarding and
deny/approval precedence. A transform failure can stop even `run_all`, so
inspect the per-interceptor records before treating a control as consulted.

## Host enforcement requirements

- Use enforce mode. `ActivatedPolicy.evaluate` only returns a verdict.
  `AcsInterceptor` needs a host such as the Agent Hooks emitter to enforce it.
- Stop on a deny or evaluation failure. A deny with an approval block must
  remain blocked until a trusted resolver approves the current identity.
  Preserve ordinary CLI/framework permission prompts as an additional gate.
- Apply a transform to the target and execute only that effective value.
  Fail closed if a transform cannot be applied. Do not reuse stale arguments.
- Assemble streams before scanning or releasing them. Post-tool and post-model
  gates cannot undo side effects or disclosure that already happened.
- Bind destinations, hashes, ACLs, labels and accounting to immutable action
  data. Reevaluate after any relevant mutation or redirection. Prevent alternate
  unmediated execution paths.
- Bound payloads, classifier deadlines, evaluation cost and audit retention.
  These packs do not replace ACS resource limits or transport/network isolation.
  Policy reasons are fixed identifiers, not copies of sensitive target data.

No pack proves regulatory compliance. Regexes and classifiers have false
positives and false negatives. Review defaults against legitimate workloads
before enabling enforcement. Stateless decisions cannot provide session-wide
guarantees without a stateful, trusted host.
