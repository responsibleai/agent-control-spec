# Remote policy download contract v1

**Unreleased optional Python package.** Install `agent-control-spec-remote-policy`
separately from the base SDK; its import namespace is
`agent_control_spec_remote_policy`. This is a new provider-neutral distribution
contract, not an existing cloud provider's management API.
Policy creation, updates, inheritance, authorization, and storage remain the
backend's responsibility. The SDK only downloads complete artifacts and caches
them **in memory**, independently for each configured agent.

## Configuration and lifecycle

```yaml
remote_policy:
  endpoint: https://policies.example.net
  credential_ref: policy-reader
  poll_interval_seconds: 300
  request_timeout_seconds: 10
  agents:
    - agent_id: agent-1
      tenant_id: tenant-1
      policy_id: policy-1
    - agent_id: agent-2
      tenant_id: tenant-1
      policy_id: policy-2
```

`tenant_id` and `policy_id` are flat, opaque backend selectors. The SDK does not
interpret them as cloud resource paths or logical policy keys inside an ACS
manifest. There is one selection per agent in v1; up to 32 agents, including
agents sharing a selection.
Shared selections have independent cache state and are not coalesced.

`PollerConfig.from_yaml` accepts only the `remote_policy` root. Backend-specific
configuration belongs to the host's `PolicySource`, not the SDK schema.
No source implementation is imported or selected by the core from YAML.
Reusable example YAML files contain only generic `remote_policy` settings;
deployment values belong in private host configuration. Logical artifact
keys come from the downloaded manifest and cannot be renamed independently of
its pinned bytes. The generic HTTP path needs no local Rego-key mapping.

IDs must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. YAML IDs are strings, without
coercion; quote names such as `"no"` or `"010"`. Unknown fields, duplicates,
anchors, aliases, tags, merge keys and multiple documents are rejected. YAML
is capped at 64 KiB, 32 levels and 10,000 events. YAML intervals are 5-3,600
seconds; an explicit constructor override may be shorter for tests. Timeouts
are positive, at most 120 seconds, and below the interval.

- `PolicyPoller(config, source)` has no background work until `await start()`.
- Startup downloads **all** required agents or raises `StartupError` and closes.
- Refreshes run at a fixed-rate **300-second default**, skipping missed periods.
- `await refresh(agent_id)` forces a shared, single-flight refresh.
- `get_policy(agent_id)` returns a current immutable `PolicySnapshot`, or raises
  `PolicyUnavailable`. `bundles()` returns a fresh copy, not mutable cache data.
- `status(agent_id)` exposes revision, state, last success and a safe error kind.
- After actual local evaluation, call `assert_current(agent_id, snapshot)`
  **immediately before the effect**, without an intervening await.
- Use `async with` or `await aclose()`. APIs are loop-affine and single-use.
  The poller owns/closes the supplied source; do not share it between pollers.

At most four source fetches run concurrently. Each agent's request timeout
includes waiting for a fetch slot, credential acquisition and I/O; it is not
a fresh timeout after admission. For startup, budget at least
`ceil(agent_count / 4) * slowest_fetch_seconds`, plus scheduling headroom.
Decoding is bounded by the artifact limits and runs synchronously on the event
loop. More agents or a slower backend may require increasing the default
10-second timeout, within the limits above.

The core accepts a host-supplied `PolicySource` with async
`fetch(selection: AgentPolicy, if_none_match: str | None) -> Changed | NotModified`
and `aclose()`. `Changed(body: bytes, etag: str)` preserves the exact wire bytes;
`NotModified(etag: str)` contains no new lease. A custom source need not use
HTTP or a particular cloud provider, but must export this complete ACS/Rego
envelope.

## HTTP request and response

```http
GET {endpoint}/v1/tenants/{tenant_id}/policies/{policy_id}
Authorization: <host-provided value>
Accept: application/json
Accept-Encoding: identity
If-None-Match: "<previous-sha256>"
```

Send `If-None-Match` **only while an active, unexpired snapshot exists**. Recovery
after expiration or an authorization fence uses an unconditional GET.

`200` requires `Content-Type: application/json` (optional `charset=utf-8`) and a
strong `ETag` consisting of the quoted, lowercase SHA256 of the **exact response
bytes**. No compression or `Content-Encoding`, weak ETag, redirect, or delta.

| JSON field | Required meaning |
|---|---|
| `schema_version` | Integer `1` |
| `tenant_id`, `policy_id` | Exact requested selectors |
| `revision` | Monotonic integer, 1 through 2^63-1 |
| `issued_at`, `expires_at` | UTC `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` |
| `manifest` | Complete ACS YAML string |
| `bundles` | Logical manifest Rego key -> `modules`, optional inline `data` |

The [golden envelope](../sdk/python_remote_policy/tests/fixtures/remote_policy_v1.json) is shared
by contract tests and the reference server. For example, `bundles.gate.modules`
maps a basename such as `limits.rego` to Rego source. Optional `data` is a list
of `{mount: ["logical", "path"], document: <JSON>}` objects, not filesystem paths.
The ACS Rego input uses the existing engine envelope: the example reads
`input.policy_target.value.amount`, not `input.amount`.

Reject duplicate/unknown JSON fields, bool revisions, NaN/Infinity, invalid
Unicode, and nesting beyond 32. Body limit: 1 MiB. Module limit: 64 total,
64 KiB each; basename IDs with `.rego` suffix, no separators. Passive admission
mirrors native authoring limits: nesting 12, 1,024 structural tokens, 262,144
depth-weighted byte units. Admission is **not** code compilation.

## Restricted ACS profile

The SDK validates the exact original manifest with the native parser, not a
re-serialized PyYAML interpretation. Allowed:

- supported `agent_control_specification_version`;
- opaque `metadata` (never interpreted as identity or logged);
- nonempty `policies` containing only `type: rego` and a rule-path `query`;
- nonempty `intervention_points`, simple `policy: {id, query?}` bindings,
  `policy_target`, `policy_target_kind`, and `tool_name_from`;
- optional tool declarations containing only `type: Tool` and `id`;
- complete embedded bundles for every declared logical Rego key.

Queries are ASCII paths such as `data.refund_limits.verdict`, at most 256
characters. No expression, indexing or call. Reject disk/URL bundles, adapter
`data`/`data_paths`, annotators, approvals, inheritance, custom/Cedar/test engines
and unknown binding fields. Native empty defaults for `extends`, `annotators`,
and point `annotations` are harmless and allowed; nonempty values are rejected.

**A downloaded snapshot is not an activated or prepared policy.** Do not feed
untrusted Rego into host in-process `ActivatedPolicy.from_memory`. Use a reviewed
isolation/evaluation adapter and fail closed on errors. The
[reference example](../examples/remote_policy/README.md) evaluates the actual
ACS engine in a bounded child process; it is not a production OS sandbox or a
high-throughput hot-swap interceptor.

## Freshness, failures and ownership

Lease duration must be at least `2 * interval + timeout`, at most 24 hours.
Recommend **15-minute leases**. The service must publish renewal with a greater
revision before expiration. Changing any bytes, including expiration, requires
a larger revision.

`304` must echo the requested ETag and contain no body. It **never extends the
lease**. An identical `200` body and ETag skip repeat artifact decoding and
preserve active snapshot identity; an ETag match alone cannot hide changed bytes.
After a
fence it can reinstall identical still-valid artifacts. Lower revisions or
changed bytes at the same revision are rejected, even after eviction. A
delete/recreate at a lower revision needs an explicit trusted operator restart.

| Condition | SDK behavior |
|---|---|
| `401/403/404/410` | Fence that agent immediately; no automatic token retry |
| `429/5xx`, transport timeout | Surface error; retain only still-valid previous artifacts |
| Malformed/scope-mismatched candidate | Reject candidate; never replace a valid snapshot |
| Expired, absent, changed-during-evaluation | Raise; host must not execute |
| Unexpected scheduler failure/cancellation | Fence access |
| Close/drain failure | Raise `PolicyCloseError`, not successful shutdown |

Revocation is visible on the next successful poll, or lease expiration under
partition, not instantly. The initial host UTC clock is **trusted**; synchronize
it. Future `issued_at` beyond 60 seconds is rejected, but aged documents cannot
prove clock synchronization. Monotonic deadlines prevent **later** wall-clock
rollback or unchanged-response replay from extending a captured lease.

At most four requests and one retained fetch per agent. Cancellation-resistant
custom sources retain their slot and cannot install late results or accumulate
retries. Close waits up to five seconds per drain phase, retains unfinished
references, and reports failure. Such sources must be repaired; they are not
treated as closed. Credentials remain caller-owned. SDK audit events contain
configured IDs, revision, ETag, absolute expiry, request ID and safe error kind.
INFO messages include those safe policy summaries for ordinary log formatters.
They never include token, response,
manifest, module, metadata, or evaluation context.

## Authentication and provider configuration

`credential_ref` resolves against a **host-owned** mapping of
providers. Existing injected `AuthorizationProvider.authorization() -> str`
objects remain supported. To construct a provider from trusted configuration,
declare it under `remote_policy.credentials`:

```yaml
credential_ref: policy-reader
credentials:
  policy-reader:
    provider: custom_platform
    options: {}
```

These fields belong inside `remote_policy`, alongside the endpoint and agents.
`CredentialProviderRegistry.open(config)` opens only the selected named factory
and supplies a read-only reference-to-provider mapping for
`HttpPolicySource.from_config`. Register `custom_platform` in trusted host code;
it is an example registry key, not a built-in provider. An explicit host registry
is the complete allow-list of trusted factories. Unknown references/kinds fail
without fallback. YAML never names executable modules, commands or arbitrary
classes. See the [custom-provider example](../examples/remote_policy/README.md#custom-providers).

Definitions and their scalar options are immutable, hidden from representations
and defensively copied. There are at most 32 definitions and 32 option keys per
definition; option JSON is at most 16 KiB within the existing 64 KiB YAML bound.
Nested objects/arrays and non-finite numbers are rejected in this v1 option
schema. No raw credential, password, private key or bearer token belongs in YAML.

For request-dependent authentication, implement
`RequestAuthenticator.authenticate(AuthenticationRequest) -> Mapping[str, str]`.
The frozen context contains the exact final normalized method, URL/query,
lower-case pre-auth headers and empty GET body. Return only new auth headers.
The shared HTTPX adapter supports `httpx.AsyncClient` with buffered requests
(the supplied sources use empty-body GETs). Synchronous clients and unread
streaming bodies fail closed. It authenticates once and yields once: it never conceals a
401 with an auth retry or lets a provider change the request destination.

Header names are RFC 9110 ASCII tokens, 1-128 bytes. At most 32 headers, each
value 1-16384 ASCII SP/VCHAR bytes with no leading/trailing whitespace, and at
most 32768 name/value bytes in total. CR/LF, tabs, other controls, non-ASCII values,
empty output and case-insensitive duplicates fail. Interior spaces support
multi-part request signatures. The single-header interface uses its
original stricter scheme/token validation.

Every existing pre-auth header is reserved, even if returned unchanged.
Additionally forbidden: `Host`, `Connection`, `Keep-Alive`, `content-*`,
`Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Expect`, `proxy-*`, `Cookie`,
`Set-Cookie`, `Forwarded`, `x-forwarded-*`, `Via`, `Max-Forwards`, `Range`, `if-*`,
`X-HTTP-Method-Override`, `X-Original-URL` and `X-Rewrite-URL`. Providers therefore
cannot replace scope, correlation or ETag metadata. Bearer, custom-header and
request-signature schemes are supported; query-token/presigned-URL changes,
cookie sessions and mutual-TLS client configuration are outside this interface.

Provider exceptions are redacted and become transient credential failures,
not authoritative service denials; cancellation remains cancellation. Service
401/403/404/410 responses still fence immediately. Authentication executes even
for unchanged resources and stays within the existing complete fetch deadline.
Credential audit records use fixed reason codes, bounded exception class names
and non-secret configuration labels, never exception messages or option values.
Factory open/close events identify the selected credential reference and provider.
`current_policy_request_id()` exposes the current source-call ID for diagnostics
only; it is task-local, resets after refresh and returns `None` outside that scope.
The HTTP adapters join it to their request IDs without adding authentication or
identity claims. Last verified policy expiry remains in terminal audit events
after the usable snapshot is fenced, expired or closed.

The registry owns one selected factory context per source and closes it after
the poller/source. Caller-injected providers remain caller-owned. Entry and
cleanup have separate request-timeout budgets; cleanup uses bounded
non-propagating wait/cancel/drain phases. A failed cleanup raises
`CredentialCloseError`, or is safely noted/audited while preserving an existing
startup, source-close or cancellation failure.
Cancellation received during successful cleanup is propagated even
when the body had another error. An already-primary cancellation retains its
identity; if cleanup itself also fails, the existing primary error still wins
with safe diagnostic notes. Retained work is bounded and
observed, and the failed registry rejects further opens. Aggregate normal
shutdown is the poller's two drain phases plus one credential-cleanup budget.
Factories enter/exit in one structured owner task; their ContextVars do not
become authentication-call state. Providers must be re-entrant for up to four
concurrent requests and own their refresh synchronization.

HTTPS is required; TLS verification stays on and redirects are disabled.
HTTP proxy environment variables are ignored (`trust_env=False`). Authorization
is explicit; response cookies are neither retained nor forwarded between agents.
Only an explicit anonymous literal-loopback HTTP example is allowed; never send
credentials over HTTP.

The policy API owner supplies the accepted authentication scheme and read grants.
Backend selectors are not authenticated identity claims. The server must validate
the credential and independently authorize each requested tenant/policy;
authentication alone is insufficient. Token-based backends must validate issuer,
audience and expiry.

The SDK assumes neither a provider-specific token audience nor a provider-specific
route. Backend integration and inheritance resolution are outside this first
flat-selector slice.

### Optional Azure credential adapter

`AzureAuthorizationProvider` explicitly implements the shared
`AuthorizationProvider` interface. Other token providers can implement that same
interface; request-signing providers implement `RequestAuthenticator` instead.
Both are supported by the provider-neutral HTTP source.

The default credential registry supplies only the optional `azure_cli` factory.
Selecting it explicitly requires the polling package's `azure` dependency extra:

```yaml
credential_ref: policy-reader
credentials:
  policy-reader:
    provider: azure_cli
    options:
      scope: api://YOUR-POLICY-API-APP-ID/.default
      process_timeout_seconds: 5
```

Alternatively, inject
`AzureAuthorizationProvider(async_credential, api_scope)` and choose Azure CLI,
managed identity, or workload identity explicitly. The SDK does not search a
default credential chain. The API owner supplies its accepted audience/scope;
the backend's `tenant_id` is independent of the credential's directory tenant.

The configured Azure CLI factory validates `scope` and optional integer
`process_timeout_seconds` (1-120, default 5); other options fail. Azure libraries
are loaded only when needed. A custom registry does not need the Azure extra.
The Azure provider keeps one in-memory token per instance and synchronizes
refresh across concurrent requests. It refreshes with a 60-second expiry margin
and rejects newly acquired tokens with too little remaining lifetime. It owns
no background refresh worker and does not close caller-injected credentials.
Azure acquisition failures log only a fixed event and one of the two known
vendor exception classes, never a vendor message or traceback.
The cache is not invalidated by a service 401/403; those responses still fence
the policy immediately. After changing the CLI identity, role assignments or
credentials, reopen the source's registry context for a YAML-selected provider,
or construct a new `AzureAuthorizationProvider` for a host-injected provider.
This does not bypass the CLI's own token cache or service permission propagation.
The configured CLI process budget must fit inside the whole-fetch timeout,
which includes authentication and the HTTP request; setting the two budgets
equal does not reserve time for HTTP.
