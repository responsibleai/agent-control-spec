# Adoption recipes

These are reference host integrations around the policy artifacts, not a new SDK. Use them to see where the inputs come from and where an operation must stop. `demo.py` runs local workflows. `tests/test_workflows.py` tests the real database and network boundaries, including failures. Existing framework authentication, permission prompts and operational controls still apply.

## Document service

`document_service.py` reads a document's tenant and ACL from SQLite, checks the authenticated principal's tool roles, evaluates an operation quota and requires review for writes. `profiles.document_emitters` selects the rules. Reads and approved updates use parameterized SQL. The operation and its counter commit together. Denial, failed approval and cancellation roll the transaction back.

```python
from policy.packs.recipes.document_service import DocumentService
from policy.packs.recipes.profiles import document_emitters

read, write = document_emitters(resolver=your_authenticated_reviewer, max_operations=50)
service = DocumentService("documents.sqlite", read_emitter=read, write_emitter=write)
try:
    result = await service.execute(
        authenticated_principal,
        "read_document",
        {"document_id": requested_document},
    )
finally:
    service.close()
```

Run/import these snippets from the checkout root with the pinned environment, inside your asynchronous application. `authenticated_principal` contains the subject, tenant and roles established by your host, never fields copied from tool arguments. `seed` is for preparing the local example database, not an agent tool.

The reference deliberately serializes operations with an async lock and an SQLite write transaction. The lock is held through approval. This keeps the example's accounting/ACL/action relationship inspectable, but limits throughput and makes long approval waits unsuitable. A production service should integrate its existing authorization transaction or versioned reservation/approval mechanism. This is a persisted per-database operation limit, not a distributed billing ledger or a monthly quota system.

Tests observe database contents after approved, rejected and cancelled writes, reject forged identities in arguments, reload counters after closing the service, refresh revoked ACLs, and run competing requests against the last quota slot.

## HTTP client

`http_client.get` is a bounded GET-only HTTP tool. It parses the actual URL, normalizes its origin, emits the destination/credential gates, then dispatches the same request using `http.client`. It does not follow redirects automatically. Each Location gets a new decision, and denied hops never open a connection.

```python
from policy.packs.recipes.http_client import get
from policy.packs.recipes.profiles import http_emitter

response = await get(
    requested_url,
    emitter=http_emitter(["https://api.example.com:443"]),
    builder=your_context_builder,
)
```

Replace the illustrative origin with the service you authorize. The client rejects URL userinfo through policy, fragments/controls/backslashes through input validation, and request-identity transforms instead of sending stale arguments. It limits redirects and response size, uses a five-second socket timeout and verifies TLS through the standard HTTPS client. It sends no application credentials. Add authenticated transport through your existing client rather than putting credentials into the agent's URL.

This is not general SSRF containment. DNS/address policy, proxies, path/resource permissions, strict end-to-end deadlines and high-throughput asynchronous I/O remain host concerns. Tests use a real loopback listener and verify both received requests and destinations that were never contacted.

## Disclosure

`profiles.disclosure_emitter(redact=True)` composes credential denial before configurable PII replacement. The example reads a record containing an email address and passes the result through `builder.output(content=record_body)`. The caller delivers the returned `outcome.target`, not the raw record body.

Pure decision controls use `sequential/run_all`. A transform cannot erase an earlier mandatory credential denial. Structured tool-only responses and safe record objects remain usable. Unredactable matching fields block instead of producing partially sanitized objects.

## Azure Content Safety

`azure_safety.AzureSafety` is a supplied ACS annotator dispatcher for the [text analysis](https://learn.microsoft.com/en-us/rest/api/contentsafety/text-operations/analyze-text?view=rest-contentsafety-2024-09-01) and [Prompt Shields](https://learn.microsoft.com/en-us/rest/api/contentsafety/text-operations/shield-prompt?view=rest-contentsafety-2024-09-01) REST operations. It uses a host-configured HTTPS origin and API key. No SDK dependency beyond ACS/Agent Hooks is needed.

```python
import os

from policy.packs.recipes.azure_safety import AzureSafety
from policy.packs.recipes.profiles import content_emitter

backend = AzureSafety(
    os.environ["CONTENT_SAFETY_ENDPOINT"],
    os.environ["CONTENT_SAFETY_KEY"],
)
gate = content_emitter(backend, point="input")
outcome = await gate.emit(your_context_builder.input(content=user_message))
```

Running this with a real endpoint sends data to that service and may incur charges. The repository does not provision or call it during validation. Never put real keys in manifests or source files.

For retrieved content use `point="post_tool_call"` and put the original user prompt at `extensions.policy_packs.user_prompt`. The adapter sends the governed result as one document and validates that the response analyzed it. It does not reuse a model-supplied "safe" flag. Input prompts and retrieved documents are different API fields.

Text analysis requests all four categories with `EightSeverityLevels` and maps their 0..7 severities into the policy's category names. Prompt Shields supplies boolean attack flags, which the adapter maps to 0 or 1 for the policy score contract. This mapping is not a calibrated probability. Malformed, incomplete, oversized and error responses raise, causing ACS to deny. Redirects are not followed and the credential is not forwarded to another origin.

The default text limit is 10,000 characters including serialized JSON structure. Oversized targets fail rather than being truncated. Recognized image/audio/file blocks fail because this is a text adapter. It does not fetch URLs, decode arbitrary documents or classify hidden media. The timeout is a socket-operation timeout, not a strict total deadline. Production retries, latency isolation and data-handling approval belong in your host.

`content_emitter` screens credentials before any remote annotation and stops on denial. The test suite proves that a denied credential-bearing input causes **zero provider requests**. Do not switch this pipeline to run-all simply because that profile is appropriate for pure authorization rules.

Tests send real loopback HTTP through this adapter and validate paths, headers, payloads, normalization and failures using documented service-shaped responses. They do not establish detection quality or live-service compatibility beyond that wire contract. Validate those with your own resource and representative workload before enforcement.
