# Policy coverage and prior art

Inventory checked September 22, 2026. ACS base revision
`a830ed5e82a267a7431010c0f51be3a2fb19d219`, live repository
`responsibleai/agent-control-spec`. AGT reference revision
`8be4268824c40ccc4b51cbbc5590a4e3e037c9ca`, repository
`microsoft/agent-governance-toolkit`. This is a source inventory, not a claim
that all historical runners work with today's SDK.

## Ownership and compatibility

ACS owns the current manifest/runtime contract, `ActivatedPolicy`,
`AcsInterceptor`, the shared Rego/Cedar libraries and the examples ported out
of AGT. AGT still owns its product profiles, framework integrations and
legacy `agent_control_specification` host surface. Agent Hooks owns
composition, identity binding, transforms and approval enforcement.

Therefore these framework-neutral artifacts belong next to ACS's existing
`policy/lib/`, not in a new AGT Python package or a copied runtime. They do
not change either repository's older names, policy behavior or snapshot
conventions. Existing consumers are not migrated implicitly. AGT hosts may
use them only after adapting their snapshot and enforcing the documented
Agent Hooks contract.

## Existing inventory

| Existing surface | Scenarios represented | Status and treatment |
| --- | --- | --- |
| ACS `policy/lib/` | Default aggregate, approval, budgets, confidence, content hash, drift, egress, IFC, patterns and redaction | Preserved. Packs reuse `patterns`, `redact`, `approval`, and IFC's explicit-argument helpers |
| ACS `policy/cedar-lib/` | Corresponding Cedar helpers and aggregate | Preserved. New packs are Rego, not untested claims of Cedar parity |
| ACS `examples/{bank_agent,coding_agent,ifc_agent,records_agent,research_agent,support_agent}` | Finance, workspace/shell operations, label flow, medical records, web research, refunds/support | Scenario references retained without replacing their manifests or legacy hosts |
| ACS `examples/from_agentshield/agents/` | `bank-manager`, `document-dlp` | Both manifests have obsolete `annotator:` binding members rejected by the current runtime |
| ACS `examples/from_agentshield/moderation/` | Azure Content Safety, OpenAI moderation, Perspective, Llama Guard, Lakera | Provider-oriented references. New packs require normalized trusted annotations, not fake provider equivalence |
| ACS `examples/from_agentshield/channel-governance/` | Discord, Google Chat, iMessage, Signal, Slack, Telegram, WhatsApp and combined channels | Existing restrictions preserved. Their destination/identity needs map to the new reusable gates |
| ACS `examples/from_agentshield/policies/` | Endpoint governance, IFC email, SQL delegate/regex, WorkIQ collaboration DLP | Preserved. SQL regexes are not promoted to authorization boundaries |
| ACS `examples/from_agentshield/quickstarts/` | AutoGen team, CrewAI invoice, LangChain | Preserved as framework integration references, not rewritten |
| ACS `examples/from_agentshield/negative_fixtures/` | Resolver transport trust and verification requirements | Remain host obligations rather than alleged manifest protections |
| AGT `examples/policies/production/` | Minimal, enterprise, healthcare, financial, strict | Existing profiles retained in AGT. Not renamed as new packs or certified for their named sectors |
| AGT `examples/policies/{african-regulatory,india-regulatory,uk-regulatory}/` | National/regional data protection, routing, transactions, approval and PII | Source references only. No legal accuracy or compliance certification asserted here |
| Other AGT `examples/policies/` files | ADK manifest, ATR, CLI, conversations, living-off-the-land, MCP, PII, injection, sandbox, semantic and SQL policies | Product/legacy integration surfaces, not universally interchangeable ACS manifests |

The ACS example inventory contains 31 manifest files. Twenty-eight validate
directly as strings. `coding_agent/manifest.yaml` also validates through the
file loader, which resolves its `extends`. The remaining two are the obsolete
annotation bindings above. This check says nothing about running their demo
applications. Existing Python demos import `agent_control_specification` and
`AgentControl`, whereas the live SDK exports `agent_control_spec` and
`ActivatedPolicy`/`AcsInterceptor`. They are not used as the runtime oracle.

Consumer compatibility testing also found that the pinned ACS `0.4.0a3`
wheel accepts a manifest but fails policy invocation when a Rego
cross-module function is called through an import alias. The source-built
base does not exhibit that failure. These packs therefore call imported
functions by fully qualified `data.*` paths. This is an artifact
compatibility adaptation, not a runtime or stock-library modification.

## Decision components behind the workflow families

All rows have native ACS allow, deny, boundary, missing-data and composition
tests. `tests/test_adoption.py` covers ordinary application shapes and generic
configuration. `tests/test_workflows.py` exercises the supplied database,
HTTP and classifier recipes. The [library index](README.md) groups the rules by
operation instead of treating their directory count as a product requirement.

| Area | Delivered control and boundary | Reused component / deliberate difference | Remaining prerequisite |
| --- | --- | --- | --- |
| Input/output safety | `content-safety`, configured severity threshold, all categories required | Azure text-analysis REST adapter supplies actual normalization | Service provisioning, live validation, calibration, unsupported modalities |
| Indirect/direct injection | `prompt-injection`, score threshold at input and retrieved results | Azure Prompt Shields REST adapter distinguishes user prompt from retrieved documents | Classifier accuracy, instruction/data separation |
| Credential disclosure | `credentials`, string-leaf and structured key/value scanning at six points | `agt.patterns.matches_any`; classifier pipeline stops before I/O on denial | Plaintext only, host-controlled credential injection must occur separately |
| PII | `pii`, JSON pattern scanning and conservative string/content redaction | `agt.patterns`, `agt.redact.apply_patterns`; normal tool-only responses permit when clean | Domain-specific detector coverage, arbitrary structured/multimodal sanitization |
| Tool authorization | `tool-permissions`, known catalog plus authenticated role | ACS catalog projection | Complete inventory, trustworthy roles and actual tool binding |
| Destinations | `destinations`, exact normalized origin/method match | Reference GET client parses the dispatched URL and mediates redirects | Production transport, DNS/address isolation and authenticated clients |
| Approval | `human-approval`, domain-neutral per-tool allow/review/argument-threshold rules | `agt.approval.escalate_if`; actual SQLite updates wait for approval | Authenticated reviewer, durable suspension, replay prevention |
| Resources/budgets | `budgets`, used + reserved <= limit, integer counters | Local recipe commits an operation counter with its database action | Distributed/token/cost accounting, upper-bound reservations and runtime limits |
| Label flow | `information-flow`, no write down and propagated join labels | Existing IFC lattice/helpers, explicit host extension path | Provenance, label union across inputs, persistent propagation |
| Model routing | `model-routing`, exact provider/deployment/region tuple | Separates routing from prompt claims and model-name-only checks | Bind to actual endpoint/configuration, control fallback routes |
| Tool supply chain | `tool-integrity`, pinned SHA-256 per tool | Same goal as stock content-hash, without old AGT snapshot path | Real immutable artifact measurement and trust distribution |
| Record/resource access | `resource-access`, subject ACL, tenant and operation | Document recipe reads fresh tenant/ACL metadata from the same database transaction as the action | Production authentication/resource catalog integration |

## Not delivered as protection

SQL authorization, shell containment, filesystem traversal/symlink defense,
sandboxing, DNS rebinding defense, trusted execution, cryptographic signature
verification, classifier quality and jurisdiction-specific compliance cannot
be obtained merely by adding regexes or manifest fields. Their host/transport
integrations are outside this library. Application-specific amount/currency,
recipient and resource constraints remain application policy.

Confidence and behavioral drift helpers already exist in both stock
libraries. They remain available rather than being repackaged into arbitrary
"security" controls. A model's own confidence is not permission. There is no
new stateful detector, learned risk model or content fingerprint database.
The stock aggregate remains available for consumers of its older snapshot
convention.

## Adoption evidence and verification

`tests/test_packs.py` activates on-disk manifests in the native engine and uses
native in-memory bundles for configuration variations. It exercises all
declared points, rejects missing targets, checks malformed annotations and
regexes, tests exact approval/resource thresholds and preserves legitimate
use. Agent Hooks composition tests check every pack with a credential deny
and with a legitimate allow, plus effective-target redaction and
identity-bound approvals. Configuration and reason assertions distinguish
policy denials from accidental runtime errors.

The workflow suite goes beyond verdict checks. It observes SQLite contents
after approved/rejected/cancelled writes, persists quotas across reopen,
revokes an ACL in the database, and races callers for the last quota slot.
Its HTTP listener records requests, including the absence of a request to
a denied redirect destination. The provider tests inspect real POST
requests and feed documented service response shapes through the supplied
adapter. Credentials denied before classification produce no provider requests.

CI runs these cases against the source-built SDK and the pinned published
wheel, plus `demo.py`. All inputs and provider replies are synthetic, but
database and loopback HTTP effects are real. No paid model campaign, live
classifier accuracy measurement, package publication or production deployment
is part of this work.

## Adoption boundary

Authorization, quotas and approval are demonstrated together in a serialized
document service. Egress is demonstrated in a bounded HTTP client. Disclosure
is exercised on values actually returned to callers. Classifier rules have a
concrete text/Prompt Shields adapter. These are reusable reference integrations,
not replacements for production services' identity, transaction or transport
systems.

Model routing still needs the application's real model registry/dispatcher.
IFC and tool-integrity remain specialist templates because this change supplies
neither full provenance tracking nor trustworthy artifact measurement. They
remain available without being counted as required controls for every agent.

The document example holds its transaction while awaiting approval and therefore
is unsuitable for long-lived approval queues or high concurrency. That tradeoff
is explicit. Distributed accounting and durable human approval are outside it.
Known pattern-filter limitations and unsupported modalities are likewise not
made safe by passing a test or documenting them.
