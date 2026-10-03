# Proposal: call annotators from Rego when needed

Status: draft design for discussion. This document does not change the manifest
schema, runtime, or SDKs. The property and function names below are illustrative.
A new manifest contract version would be required.

Let policy authors mark an annotation binding as on demand, then call it from
Rego when the policy needs its result. The host would still implement the
annotator and own its credentials and external I/O.

For example, a refund policy might need an eligibility lookup only for refunds
of at least 10,000 cents. Today, binding that annotator means it runs before
Rego, including for smaller refunds. With an on-demand binding, the policy could
compute a condition, call the annotator, and use its answer in one evaluation:

```rego
# Proposed function, not available in the current dispatcher.
# This example assumes the host has validated the request's amount.
required := input.policy_target.value.amount_cents >= 10000
eligibility := acs.annotate("eligibility", required)
```

On false, the function returns `{"status": "not_required"}` without contacting
the provider. On true, it resolves the annotation and returns
`{"status": "completed", "value": ...}`. The remaining Rego decides whether to
allow, deny, or transform the action. A skipped lookup is not itself an allow.

The [worked example](on-demand-annotators-example.md) includes the binding,
complete policy, provider result, and failure paths.

## What would change

An execution mode would live on the intervention-point annotation binding:

```yaml
# Proposed binding fragment. It is not an opt-in under an existing version.
annotations:
  eligibility:
    from: $target
    execution: on_demand
```

An omitted mode would remain eager. Putting it on the binding lets the same
annotator declaration run eagerly at one point and on demand at another.

The first version would expose an operation with this shape:

```text
acs.annotate(bound_annotation_name, required_boolean)
    -> {status: "not_required"}
     | {status: "completed", value: ProviderOutput}
```

The name must identify an on-demand annotation bound at the current point.
Its existing `from` path and the host's approved projection determine the
provider request. The function would not accept arbitrary URLs, credentials,
or request bodies from Rego.

The resolver constructs the result envelope. The provider supplies only its
typed data. A negative business answer, such as `eligible: false`, is a
completed result. Timeouts and malformed responses are errors, not successful
data for the policy to interpret.

### Why pass the condition to the function?

I would make the zero-call guarantee explicit rather than promise that any
false condition in a Rego rule prevents a call elsewhere in that rule.

A local probe against Regorus 0.12.0 showed the distinction. These fragments
show the same rule structure with an unguarded probe function:

```rego
# With a false amount condition, this probe made no provider call.
checked if {
    input.amount >= 10000
    result := probe.lookup("eligibility")
    result.value.eligible
}

# Moving the condition after the call still made a provider call,
# even though the rule did not match.
checked_later if {
    result := probe.lookup("eligibility")
    result.value.eligible
    input.amount >= 10000
}
```

Those observations are not a scheduling guarantee for every expression or
backend. Passing a boolean lets the host check it before resolving dependencies,
credentials, a result cache, or the provider. A false argument always means
zero external work for that demand. A function the evaluator never reaches
also does no work.

There is an important limit: Regorus does not call an extension when an argument
is undefined, even with strict built-in errors enabled. The function cannot
turn an argument it never receives into an error.

The authoring contract therefore needs validated input, a condition that returns
a boolean for every admitted input, and default-deny policy logic that never
treats a missing result as success. Null or non-boolean arguments that do reach
the function are errors. Admission must restrict guards to supported forms or
explicitly approve the policy's totality obligation. The extension API alone
does not prove that arbitrary Rego has a total guard.

## One evaluation, with a request-local resolver

The proposed execution sequence is:

1. Activate an approved manifest and policy bundle. Validate on-demand support,
   provider registrations, schemas, and dependency rules. Preparation makes no
   provider calls.
2. The host captures the action context. ACS validates it, selects the target
   and tool, and collects eager annotations in their existing order.
3. ACS builds the immutable five-root policy input and a fresh resolution
   context for this evaluation.
4. The policy dispatcher evaluates Rego with the callable function connected
   to that context.
5. A false demand returns `not_required`. A true demand returns an already
   completed result or resolves the binding's dependencies and provider.
6. The resolver validates and records the result. Rego uses the returned value
   and produces its final policy output.
7. ACS checks for a latched resolution error and normalizes the verdict.
   Agent Hooks composes final verdicts. The host proceeds only after permission.

There is no preliminary allow verdict, second Hooks emission, or serialized
continuation. A and B are parts of the same Rego evaluation.

Keep `input.annotations` immutable and limited to eager outputs. On-demand
values come back through the function. Reading
`input.annotations.eligibility` would not trigger a lazy property lookup.
Return a separate bounded resolution report so the reported policy input
remains the input the evaluator actually saw.

The resolver's mutable state lasts for one evaluation. It contains the
deadline, completed results, in-progress markers, fatal failure, and report.
It must not affect later evaluations.

## Repeated calls, dependencies, and failures

Memoize each validated raw provider output once per binding per evaluation.
Repeated true calls return that same value. False calls always return
`not_required`, even if an earlier true call completed, without erasing the
stored result. With fixed binding input, the declared graph bounds the number
of logical provider calls.

Keep `needs` as a static prerequisite list. A true demand resolves its dependency
closure first, using the existing lexical ready-node rule within that closure.
Eager dependency outputs are reused. An on-demand dependency is forced by a
demand for its consumer, even if an earlier direct call to it had a false guard.
A consumer callback receives raw direct-dependency outputs, preserving its
existing `from` paths. The completed envelope belongs to the policy function.

Reject eager-to-on-demand dependency edges initially, because they would force
the deferred work upfront. Reject cycles, unknown names, and reentrant
resolution. A false demand does not resolve its dependency closure.
Unrelated eager work has already happened and cannot be saved by that guard.
The contract does not promise a global order among independent demands made
by separate Rego rules.

Any attempted provider operation that times out, fails authentication, returns
malformed or oversized data, or cannot be associated with the request latches a
fatal evaluation error. A policy must not recover it into an allow.
Use `runtime_error:policy_invocation_failed` at the outer dispatcher boundary
and keep the typed cause in the report. Eager annotation errors retain their
existing reasons. The Hooks host owns `host_error:interceptor_timeout`.

Use one absolute deadline for admission, eager work, policy evaluation,
provider calls, and result handling. Reserve time to finish the decision.
Cancellation prevents the guarded action and closes the attempt even if the
provider later succeeds. It does not necessarily stop remote execution.
Capacity remains charged until underlying work terminates.

Start with one provider attempt per demanded binding and no cross-evaluation
result cache. A `202 Accepted` response is not completed enrichment.
If retries are added later, they must be bounded, read-only, idempotent, and
part of the same deadline. A timeout does not prove the provider did no work.

## Preparation and SDK work

Regorus already supports host-defined functions through `Engine::add_extension`.
That makes this design plausible, but it is not enough to expose a manifest flag.

The current ACS warmer evaluates a query with empty input. Once the query can
call an annotator, that could contact the provider during activation.
Preparation must compile or validate without performing those calls.

Regorus also documents that registered extensions cannot be replaced and that
engine clones copy them. A local probe confirmed that cloning an engine after
a memoized completion can carry that result into another evaluation. Prepared
engine caches must not contain live request context, credentials, or completed
provider data.

Either separate prepared code from per-evaluation function bindings through a
supported evaluator API, or start with a fresh engine per evaluation.
The latter costs preparation time, but is preferable to a shared mutable
"current request" slot. Keep the same resolver across an internal
`eval_rule` to `eval_query` fallback so it cannot repeat a provider operation.

| Surface | Required work |
| --- | --- |
| Runtime and dispatcher interface | Pass an explicit per-evaluation resolver to supporting policy dispatchers. Today's invocation does not carry it. |
| Rego backend | Register the function, isolate memo state, preserve fatal errors, and prepare without I/O. |
| Reporting | Expose bounded resolution outcomes separately from policy input and the Hooks verdict. Preserve existing verdict-returning APIs where possible. |
| Python | Bind resolver callbacks, reports, and typed causes. Use bounded offloading for blocking evaluations. |
| Node | Resolve callback thread affinity. A Rego worker cannot wait on a JS thread that is blocked waiting for that worker. Use native providers or supported async outer evaluation and callback marshalling. |
| .NET | Extend the native/managed bridge for the resolver, reports, and typed failures. The current synchronous JSON delegate does not install a Rego function. |
| Hosted services and other backends | Declare and validate support. General ACS conformance does not imply support for callable annotations. |

The existing Python async adapter stops waiting on cancellation but cannot
terminate a native callback. The current Node annotation callback is synchronous
and returns JSON, not a Promise. Those limits still need to be handled by the
implementation rather than hidden by the function syntax.

## Host trust, evidence, and concurrency

The host approves capabilities for a policy pack and tenant, fixes their input
projection and authentication audience, and keeps credentials in transport.
Naming a binding does not grant a fetched policy access to host secrets or
upstream data. Preserve the existing URL-source provenance restrictions.

Provider adapters must enforce egress restrictions, validate resolved
destinations and redirects, and bound requests, decompressed responses, depth,
and execution time. Do not forward the full snapshot merely because the
callback can read it. Registered internal services need explicit authorization.
Provider text is data, never code or a request for more capabilities.

Also bound active and pending work and calls per session, tenant, and stream.
Reject recursive policy entry from a provider and unauthorized replacement of
the callable function. A provider that fans out internally needs its own bounds.

Each concurrent tool call and each ACS interceptor gets a separate resolution
context. A future shared cache would need exact request and authority checks,
freshness rules, and recorded cache provenance. It must not turn transport
failure into a business result or serve a stale positive after refresh failure.

The resolution report should distinguish unrequested bindings, skipped uses,
dependency-forced calls, completions, and failures. Bind it to the evaluation,
policy pack, capability revision, full relevant input, and request/response
digests. Correlate it with the Hooks session, sequence, interceptor registration,
and tool call ID.

The default Hooks identity excludes optional fields and internal ACS annotations.
It cannot prove which provider result the policy used. Keep that binding separate.
Use a defined canonical encoding, not an assumption that ACS's sorted JSON helper
is the Hooks identity algorithm. A digest-only record supports correlation, not
replay without the data. Keep sensitive replay material in a separate protected
store when required.

Determinism remains conditional on captured inputs and dispatcher results.
Replay uses those results instead of fresh provider calls. Restrict ambient
time, random values, and other undeclared inputs in the supported policy profile.
Provider authentication establishes origin, not classifier correctness.

The lookup and action are not one transaction. The action service still needs
to enforce its own invariants or use a version-bound conditional operation.
ACS cannot make separate services atomic.

## Streaming and transforms

An unresolved demand never advances a stream watermark. Each evaluated prefix
or window has its own resolver, and a false guard for one prefix says nothing
about later text. All applicable tasks must clear a segment before release.
Structured tool-argument fragments remain on the whole-value path.

The initial callable profile should withhold output until clearance. It must
not claim prevention in deferred-release mode. Cancellation settles the stream
attempt, withholds remaining text, and does not persist uncleared content.
Already released content cannot be recalled. A later output denial must be
recorded without claiming it prevented that release.

Sequential Hooks transforms change the input seen by later controls. Bind
provider results to that effective input. A later transform that invalidates a
prior check needs a recheck before execution. Parallel controls evaluate
isolated copies of the original snapshot.

## Versioning and rollout

This requires a new manifest contract version. Existing `0.4.0-alpha.1` and
`0.5.0-alpha.1` semantics stay unchanged, including dispatching every bound
annotation on a successful graph.

Annotator fields are currently open to host extensions. An old engine could
accept `execution: on_demand`, ignore it, and call the provider upfront.
Require the new version on the root and every parent in an `extends` chain.
The version gate for `needs` in [PR 78](https://github.com/responsibleai/agent-control-spec/pull/78)
is the relevant precedent.

A supporting engine keeps omitted modes eager. It rejects a callable manifest
when its backend or host cannot support it, even if the first request would
not reach the callable branch. An ignored metadata flag is not negotiation.
Cedar and other languages need explicit execution profiles of their own.
Hosted AACS support has not been established by this proposal.

Before release, exercise the same fixtures through every claimed SDK and host:
false guards, repeated references, dependency forcing, fatal errors, undefined
guard paths in supported policies, zero-I/O preparation, query fallback,
cross-evaluation isolation, cancellation, reload, transforms, and stream release.
Provider authentication and actual egress controls also need deployment tests.
Mock conformance tests cannot establish them.

Start with a local provider and fixed request projection. Keep the current
host-callback pattern available for integrations that need conditional work
before this feature ships. Migrate by changing the contract version and
replacing eager annotation reads with function results together.
Do not downgrade a callable manifest by changing its version string alone.

## Alternatives

| Option | Why not make it the default design? |
| --- | --- |
| Put a separate selector inside an ordinary annotator callback | Works with current APIs, but authors still cannot invoke the annotator from their policy. |
| Add a manifest `when` selector before annotation dispatch | Credible, but separates the condition from the policy that consumes the result. |
| Hide A, the call, and B in a custom policy dispatcher | Useful for a domain integration, but creates a private composite-policy contract instead of a reusable annotation operation. |
| Host plans, fetches facts, then evaluates ACS | Good for asynchronous or shared context gathering, but needs another planning and input-binding contract. |
| Enable arbitrary `http.send` | Exposes much broader transport authority. A registered capability does not require policy-authored networking. |
| Add a data-request verdict and continuation | Adds unnecessary protocol for bounded synchronous fact acquisition. |

Work that must survive process restart, outlive the request, or coordinate a
transaction belongs in a durable host workflow followed by a new evaluation.
It should not overload allow, deny, transform, warnings, or approval.

## Decisions to settle

The main questions are the binding property and function names, the accepted
guard shapes, dependency-forcing rules, the resolver/report API, and how the
Rego backend separates preparation from request state. The host owners need
to choose provider authority, freshness, audit retention, and whether audit
unavailability blocks an action.

I would start with an explicit boolean guard, fixed binding input, one attempt,
and no cross-evaluation cache. Dynamic request arguments and other policy
languages can follow once the first contract has cross-host evidence.

## Source anchors

This proposal was checked against ACS
`d96d97913a51497d99a98d4bc73d247100da7995`, Agent Hooks
`5d04b3b27efe1198d68c9e2df952804d8b4040be`, and Regorus 0.12.0 on October 3, 2026.
The source anchors below describe current behavior, not the proposed contract.

- ACS [specification](../../spec/SPECIFICATION.md), sections 1.1, 2.1, 6-7,
  10, 12-13, and 18.1, plus
  [annotation chaining tests](../../engine/tests/annotation_chaining.rs).
- [Runtime](../../engine/src/runtime.rs): `evaluate_inner`, `collect_annotations`,
  and `PolicyDispatcher`. [Annotation interface](../../engine/src/annotation.rs):
  `AnnotatorDispatcher` and `AnnotatorInvocation`.
- [Rego dispatcher](../../engine/src/rego.rs): `warm`, `evaluate`,
  `build_engine`, and `shadow_http_send`.
  [Rego tests](../../engine/tests/rego.rs):
  `a_policy_reaching_for_the_network_fails_closed_rather_than_open`.
- Regorus 0.12.0 [engine API source](https://docs.rs/crate/regorus/0.12.0/source/src/engine.rs),
  `add_extension`, and
  [interpreter source](https://docs.rs/crate/regorus/0.12.0/source/src/interpreter.rs),
  `eval_call_impl` and `eval_builtin_call`.
- [Python async adapter](../../sdk/python/agent_control_spec/async_interceptor.py),
  [Node callback types](../../sdk/node/src/index.ts), and
  [.NET host hooks](../../sdk/dotnet/src/AgentControlSpec/HostHooks.cs).
- [Agent Hooks specification](https://github.com/responsibleai/agent-hooks/blob/5d04b3b27efe1198d68c9e2df952804d8b4040be/spec/AGENT-HOOKS-0.1.md),
  sections 5-10 and 12, and its
  [threat model](https://github.com/responsibleai/agent-hooks/blob/5d04b3b27efe1198d68c9e2df952804d8b4040be/docs/THREAT-MODEL.md).
- OPA's [extension](https://www.openpolicyagent.org/docs/extensions),
  [HTTP built-in](https://www.openpolicyagent.org/docs/policy-reference/builtins/http),
  and [external-data](https://www.openpolicyagent.org/docs/external-data) guidance
  describe host functions, caching, and the limits on using them for side effects.

The local probes used fixed data and counters, not production endpoints.
They establish the observations above, not implementation of this ACS contract,
safe transport cancellation, or cross-SDK conformance.
