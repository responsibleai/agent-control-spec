# Call an annotator from Rego when needed

Manifest contract `0.6.0-alpha.1` lets a policy call a registered annotator instead
of running it upfront. The host still owns the provider implementation,
credentials, and external I/O. This contract is available in the source build,
not the published alpha.4 packages.

Mark the annotation's point binding:

```yaml
agent_control_specification_version: 0.6.0-alpha.1
# Other manifest sections omitted here.
intervention_points:
  pre_tool_call:
    policy_target: $snap.tool_call.args
    tool_name_from: $snap.tool_call.name
    policy:
      id: refunds
    annotations:
      eligibility:
        from: $target
        execution: on_demand
```

Then call it from Rego:

```rego
# The request amount must be validated before this comparison.
required := input.policy_target.value.amount_cents >= 10000
eligibility := acs.annotate("eligibility", required)
```

False returns `{"status":"not_required"}` with no provider or dependency work.
True returns `{"status":"completed","value":...}` after resolving the binding.
The rest of the policy decides what the result permits. Skipping a lookup does
not itself allow the action.

The [refund example](../examples/on_demand/manifest.yaml) has a complete manifest,
[policy](../examples/on_demand/policy/refund.rego), and a
[local Python host](../examples/on_demand/host.py). It makes no network calls.
After building and installing the Python SDK from this checkout, run:

```bash
python examples/on_demand/host.py
```

## What the function can access

The name must identify an on-demand binding at the current point. Its `from`
path and host adapter determine the provider request. Rego cannot pass another
payload, URL, or credential to the function.

The resolver stores each validated raw output once per evaluation. Repeated true
calls return the same value. A false call still returns `not_required` if an
earlier true call completed. Another evaluation always starts with fresh results.

`input.annotations` contains eager outputs and stays immutable. Read callable
data from the returned function value, not from
`input.annotations.eligibility`.

## Guards and failures

Pass the boolean explicitly. A false condition elsewhere in a Rego rule does
not guarantee that a preceding call did no work.

Null and non-boolean guards that reach the function fail the policy invocation.
Undefined is different: Regorus does not invoke an extension with an undefined
argument, even with strict built-in errors. Validate the input, make the guard
defined for every admitted request, and default the final policy to deny.
The example follows that pattern. The runtime does not prove arbitrary Rego
guards are total.

Provider errors, timeouts, invalid outputs, and missing demanded input paths
fail closed as `runtime_error:policy_invocation_failed`. A failed operation
cannot become a successful empty annotation or be retried by another reference.
Existing eager annotation failures keep their existing reason codes.

The callable Rego path uses strict built-in errors and rejects ambient clock,
random UUID/integer, runtime-information, and HTTP built-ins. Keep changing
facts in explicit input or registered providers. Provider responses still need
host-specific schema and authenticity checks.

## Dependencies

`needs` remains a static prerequisite list. A true demand resolves that closure
in dependency order and reuses completed outputs. A consumer forces its
on-demand dependencies even if an earlier direct call to one had a false guard.
Its callback sees raw direct-dependency outputs, preserving `from` paths.

Eager-to-on-demand edges are rejected because they would force deferred work
upfront. Cycles and reentrant resolution fail closed. A false demand does not
resolve missing paths or dependencies, but cannot undo unrelated eager work.

## Activation and callback execution

Activation loads and parses a cached policy template without evaluating callable
queries. Each evaluation attaches a fresh resolver to a clone and compiles the
query. Neither provider results nor request callbacks enter the template cache.
The current optimization therefore avoids repeated source loading, but does
not promise zero per-evaluation compilation for callable policies.

Python's existing `annotator_dispatcher`, Node's `annotatorDispatcher`, and
.NET's `HostHooks` delegate supply providers. No separate provider API is needed.
Rust policy dispatchers must explicitly opt in through
`supports_on_demand_annotations`, `evaluate_with_annotations`, and
`warm_with_annotations`. Unsupported dispatchers are rejected at construction.
The bundled OPA CLI and Cedar paths do not support callable annotations.

Node's synchronous callbacks stay on the JavaScript thread. A Regorus worker
waiting on a JavaScript thread already blocked in evaluation would deadlock.
The engine checks the deadline after the callback returns and rejects a late
success, but cannot interrupt a blocked JavaScript callback. Run the complete
evaluation in an isolated worker when the event loop must remain responsive.
Returning a Promise from the existing callback is not supported.

FFI and .NET host callbacks also stay on the calling thread so a timed-out worker
cannot outlive the caller-owned callback roots. Python and native Rust callbacks
may execute on the Rego worker. Rust callbacks that require the
calling thread can override `requires_caller_thread`. A thread-affine telemetry
sink can request the same behavior. Native provider threads are not forcibly
terminated.

The Rego timeout covers the callable policy dispatch, including its provider
work. The host's enclosing timeout also covers admission and eager annotations.
Set finite provider deadlines. Cancellation stops permission to proceed, not
necessarily remote execution.

## Telemetry and host obligations

The `annotation_resolution` event reports each on-demand binding's final status
and provider-call, cache-hit, and skipped-call counts. It does not contain the
provider value. A failed resolution can include its underlying reserved reason.
These events are separate from the immutable policy input and are emitted even
when performance telemetry is off.

Connect the telemetry sink to the host's correlation and audit system. The
default Hooks identity does not include internal annotation results, so it
cannot prove which answer a callable returned. Capture protected replay
evidence separately if needed.

Providers should be read-only. The host must approve capability access, enforce
egress and payload limits, validate results, and keep credentials out of policy
data. Existing fetched-manifest provenance checks still apply.
The lookup and action are not a transaction. The action service must enforce
its own invariants.

Each concurrent tool call and each stream-segment evaluation has its own resolver.
An unresolved demand never clears output for release. A result for an earlier
prefix does not authorize later text. Agent Hooks still owns composition,
transforms, and enforcement of the final verdict.

## Compatibility

Omitted execution mode remains eager. Under `0.4.0-alpha.1` and
`0.5.0-alpha.1`, `execution` is still opaque host extension data and does not
defer calls. Rename any such host field before upgrading, and move the root and
all `extends` parents to `0.6.0-alpha.1` together.

Do not add the new property under an old version or downgrade by changing only
the version string. An older engine could ignore the property and call the
provider upfront. See [specification section 10.4](../spec/SPECIFICATION.md#104-on-demand-annotations)
for the contract.
