# Policies for agent operations

Start with the operation you need to control, then select the rules it needs. The policies here are source artifacts for ACS, not a security product or a list of controls every agent should enable. A rule's simplicity is useful only if you can supply its inputs correctly and enforce its result.

## Start with a workflow

| Your operation | Policy family | What you can run here |
| --- | --- | --- |
| Read or update customer/team documents | Authorization | [Document service](recipes/README.md#document-service) loads tenant and ACL data from SQLite. Tool roles and resource access both have to permit the operation |
| Make an HTTP request or select a model destination | Egress and routing | [HTTP client](recipes/README.md#http-client) derives the destination from the URL it sends, checks each redirect and does not follow a denied hop |
| Release text or send data to a tool/model | Disclosure | Credentials and configurable PII patterns scan JSON string values. The [document response](recipes/README.md#disclosure) example delivers a redacted value rather than the original |
| Bound operations or model resource consumption | Budgets | The document service checks and commits a persisted operation counter under a transaction. Tests cover competing calls and restart |
| Require review before an irreversible action | Approval | The document service holds writes for identity-bound approval. Rules support explicit review, allow, or a threshold on a configured argument path |
| Classify harmful input or retrieved instructions | Classifier decisions | [Azure Content Safety adapter](recipes/README.md#azure-content-safety) calls the text and Prompt Shields REST operations. Tests verify actual loopback HTTP requests, response validation and fail-closed handling |

`python policy/packs/demo.py` runs the document, disclosure, HTTP and quota workflows with real local side effects. It creates a temporary SQLite database and a loopback HTTP server, then cleans them up. It neither calls a model nor contacts a remote classifier.

The [coverage inventory](COVERAGE.md) maps these families to existing ACS/AGT libraries and identifies what is still host-specific. The existing control directories remain available as implementation components. Their count is not a claim that you need that many independent protections.

## Install and run

Run from a checkout containing this library:

```sh
python3 -m venv .venv-packs
. .venv-packs/bin/activate
python -m pip install -r policy/packs/requirements.txt -r policy/packs/requirements-test.txt
python policy/packs/demo.py
python -m pytest policy/packs/tests -q
```

Keep `policy/packs/` and `policy/lib/` together if you copy them into an application. No package release or separate SDK is introduced. The recipes use the Python standard library and the pinned ACS `0.4.0a3` / Agent Hooks `0.1.0a5` packages. Python 3.11+ and supported native artifacts are required. Runtime evaluation does not need an OPA executable.

To validate a checkout build, follow `sdk/python/README.md`, install `requirements-test.txt`, then run the same tests. CI also runs them against the published consumer wheel. Fully qualified Rego function calls are intentional: the pinned wheel fails imported-function aliases that work in the source build.

## Select the rules, not every directory

| Family | Components | Important limit |
| --- | --- | --- |
| Authorization | [tool-permissions](tool-permissions/README.md), [resource-access](resource-access/README.md) | The application authenticates the caller. A claimed role in tool arguments is not identity |
| Egress and routing | [destinations](destinations/README.md), [model-routing](model-routing/README.md) | HTTP has a supplied reference client. Model routing still needs a real deployment registry and dispatcher |
| Disclosure | [credentials](credentials/README.md), [pii](pii/README.md) | These detect configured plaintext patterns. They do not replace a secret scanner or a full DLP service |
| Budgets | [budgets](budgets/README.md) | The local recipe implements an operation counter. Token/cost reservations and distributed ledgers remain application work |
| Approval | [human-approval](human-approval/README.md) | The host provides the reviewer and durable approval process. No production auto-approver is supplied |
| Classifier decisions | [content-safety](content-safety/README.md), [prompt-injection](prompt-injection/README.md) | A real REST adapter is supplied. Service provisioning, credentials, accuracy and workload calibration still need validation |

Two components are **specialist integration templates**, not suggested defaults: [information-flow](information-flow/README.md) needs a host that tracks and propagates labels across every relevant data path, and [tool-integrity](tool-integrity/README.md) needs a trustworthy artifact measurement/pinning process. A metadata fixture is not an implementation of either system. Their decision tests are retained, but they are not advertised as part of the directly adoptable workflows.

## Context and trust

All policies select `$.target` from a real Agent Hooks context. At input/output this is usually a content object, before a tool call it is the arguments, after a tool call it is the result value, and before a model call it is the message list. A tool-only model response may have null content and nonempty tool calls. The disclosure rules handle these ordinary JSON shapes without treating absence of prose as an error.

ACS projects `input.policy_target.value`, the raw `input.snapshot`, dispatcher `input.annotations` and optional catalog `input.tool`. Do not manufacture this policy input yourself. Use the SDK builder and populate the host data described by each selected rule.

Host attributes live under `extensions.policy_packs`. The name confers no trust. The document recipe obtains resource/tenant/ACL facts from its database and counters from the same transaction. The HTTP recipe obtains its origin from the URL it actually dispatches. Identity must still come from your authentication layer, and model routes from the configuration of your actual model dispatcher. Never accept these attributes from model-generated arguments.

## Composition and execution

Activate each component separately. Its `data.pack` configuration and `gate` policy ID belong to that runtime instance. Do not merge all manifests with `extends` or concatenate the bundles. `recipes/profiles.py` shows application-controlled assembly using the public ACS APIs. It is example code, not a new supported SDK interface.

For pure decision controls, the examples use `sequential/run_all` so a hard authorization denial is not lifted by another control's approval request. For the classifier pipeline, they use **`sequential/first_deny` with credential screening first**. Classifier dispatch itself sends data over the network, so a later classifier must not run after a disclosure denial. A run-all verdict that eventually denies is not enough to prevent that disclosure.

Use `InterceptionEmitter.emit` in enforce mode. It raises when the action cannot proceed. Use the returned effective target for the operation. The document and HTTP recipes refuse transforms of action identity instead of executing a URL or resource that was not authorized. Text output redaction uses the transformed target directly.

Keep ordinary framework/CLI permission prompts. Treat missing required data and adapter failures as failures, not as reasons to skip a policy. Evaluate every concrete operation, assemble streamed output before releasing it, and mediate redirects/retries/fallbacks that change the selected resource. Post-action gates cannot undo an already completed effect.

## What the evidence establishes

The unit cases test native policy decisions. The adoption cases in `tests/test_workflows.py` additionally read and write SQLite, persist/reload quotas, issue real loopback HTTP requests, reject redirect hops before sending them, and exercise the supplied Content Safety adapter through wire-shaped HTTP responses. Provider responses are scripted fixtures, not a measurement of classifier quality.

These examples do not implement distributed accounting, production authentication, durable approval queues, a model registry, provenance tracking or artifact attestation. They also do not claim regulatory compliance, full PII detection, SQL authorization, sandbox containment, DNS rebinding defense or protection against execution paths that bypass the host.
