# Example: refund eligibility on demand

This example shows the [proposed on-demand annotator contract](on-demand-annotators.md).
The execution mode and function are not supported ACS syntax today. The new
manifest version is intentionally unassigned.

The example policy allows valid refunds below 10,000 cents without an eligibility
lookup. Larger refunds need an eligible result and a sufficient
`max_amount_cents`. These are illustrative business rules. The host separately
authenticates the actor, and the refund service still enforces its transactional
constraints when executing.

## Bind the provider without running it upfront

This is an authoring sketch, not a loadable current-version manifest:

```text
Manifest contract: a new version supporting on-demand bindings

policies:
  refunds:
    type: rego
    query: data.refund.verdict

annotators:
  eligibility:
    type: endpoint

intervention_points:
  pre_tool_call:
    policy_target: $snap.tool_call.args
    tool_name_from: $snap.tool_call.name
    policy:
      id: refunds
    annotations:
      eligibility:
        from: $target
        execution: on_demand    [proposed property]

tools:
  issue_refund:
    description: Issue a refund for an order
```

The host registers a read-only provider for `eligibility` under the approved
policy pack and tenant. The binding selects the refund arguments. The host
fixes the request projection, authentication audience, schemas, and finite
limits. The policy does not choose a URL or supply credentials.

## Keep the condition and decision in Rego

```rego
package refund
import rego.v1

valid_request if {
    is_number(input.policy_target.value.amount_cents)
    input.policy_target.value.amount_cents == floor(input.policy_target.value.amount_cents)
    input.policy_target.value.amount_cents > 0
    input.policy_target.value.amount_cents <= 1000000
    is_string(input.policy_target.value.order_id)
    count(input.policy_target.value.order_id) > 0
}

required := input.policy_target.value.amount_cents >= 10000 if valid_request

eligibility := acs.annotate("eligibility", required)

default verdict := {"decision": "deny", "reason": "refund_not_permitted"}

verdict := {"decision": "allow", "reason": "small_refund"} if {
    valid_request
    required == false
    eligibility.status == "not_required"
}

verdict := {"decision": "allow", "reason": "eligibility_confirmed"} if {
    valid_request
    required == true
    eligibility.status == "completed"
    eligibility.value.eligible == true
    is_number(eligibility.value.max_amount_cents)
    input.policy_target.value.amount_cents <= eligibility.value.max_amount_cents
}
```

`required` is the cheap condition A. The verdict rules are B. The function
returns the provider result directly, so the policy does not need another
evaluation or a separate host-registered selector query.

Before evaluation, the host validates integer amount bounds and a bounded,
nonempty order identifier. The condition produces a boolean for every admitted
input. The Rego validity check also leaves the policy at deny if invalid data
reaches it.

Undefined arguments are a separate concern from provider errors. Regorus does
not call the extension with an undefined guard, even in strict mode. Do not
replace this default-deny policy with a default allow that depends on the
extension detecting a missing argument.

## A 12,000-cent request

The host captures one normal Hooks context:

```json
{
  "spec": "agent-hooks/0.1",
  "agent": {"id": "refund-agent", "framework": "example"},
  "session": {"id": "session-1"},
  "sequence": 7,
  "timestamp": "2026-10-03T12:00:00Z",
  "interception_point": "pre_tool_call",
  "tool_call": {
    "id": "call-7",
    "name": "issue_refund",
    "args": {"order_id": "order-7", "amount_cents": 12000}
  },
  "target": {"order_id": "order-7", "amount_cents": 12000}
}
```

ACS builds its normal five-root policy input. There are no eager annotations in
this example, so `input.annotations` is empty and stays empty throughout Rego
evaluation. The host has not issued the refund.

The condition returns true. The resolver selects the bound input and calls
the provider once. It can include trusted actor and tenant identifiers from the
host's approved projection, but does not forward the full snapshot or put
credentials in the request body.

The provider returns:

```json
{"eligible": true, "max_amount_cents": 20000}
```

The response schema is a closed object containing a boolean `eligible` and an
integer `max_amount_cents` between zero and 1,000,000. After authentication and
validation, the resolver stores the raw result and returns:

```json
{
  "status": "completed",
  "value": {"eligible": true, "max_amount_cents": 20000}
}
```

The Rego policy returns:

```json
{"decision": "allow", "reason": "eligibility_confirmed"}
```

Agent Hooks still composes that verdict with the other controls. The host
executes the refund only after the combined result permits it, using the
effective target. This example returns no transform.

## Other paths

| Request or outcome | Provider work | Result |
| --- | --- | --- |
| 9,999 cents | No call. The function returns `not_required`. | The small-refund rule allows. |
| 10,000 cents, eligible up to 20,000 | One call. | Allow. |
| 25,000 cents, eligible only up to 20,000 | One call. | Deny. |
| Valid response with `eligible: false` | One completed call. | Deny. |
| String amount `"12000"` | Reject before policy through schema validation. The policy also defaults to deny if it receives it. | No provider call. |
| Malformed response such as `{"eligible":"true"}` | The attempted call fails validation. | Fatal policy invocation failure, not a business result. |
| Provider timeout or bad authentication | The attempted call fails. | Fatal policy invocation failure. |
| Caller cancellation followed by a late success | Cancel if possible and keep the attempt terminal. | The refund remains blocked. |

Repeated true references reuse the result within this evaluation. A false
reference returns `not_required` without erasing a previous completion.
A separate evaluation gets a new memo table, even for the same policy version.

The report binds the request and response to the evaluation, policy pack,
capability revision, and effective input. The host correlates it with the Hooks
record. The normal Hooks identity alone does not bind this internal provider
result.

The Rego block was exercised with a local Regorus 0.12.0 extension for the
9,999, 10,000, 12,000, 25,000, and invalid-string amount cases. That checks the
example's policy logic. It does not establish support for the proposed manifest
or production transport, cancellation, and SDK behavior.
