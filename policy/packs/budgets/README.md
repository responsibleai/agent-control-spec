# Budgets

**Purpose:** refuse a planned model/tool operation that would exceed a
host-maintained quota. This runnable decision requires atomic accounting.
ACS does not count usage, reserve capacity or stop an already-running task.

**Points:** `pre_model_call`, `pre_tool_call`. **Target:** `$.target`, the
actual planned request/arguments.

## Configuration and snapshot

`config.json` sets nonnegative integer limits for `tool_calls` (50),
`tokens` (100,000), `cost_microunits` (10,000,000) and `elapsed_ms` (300,000).
Cost units are application-defined millionths of one fixed billing
currency, not floating-point USD. Add/remove metrics only when the host
supplies corresponding counters for every governed operation.

```json
{
  "extensions": {
    "policy_packs": {
      "budget": {
        "used": {"tool_calls": 49, "tokens": 1000, "cost_microunits": 500, "elapsed_ms": 10000},
        "reserved": {"tool_calls": 1, "tokens": 0, "cost_microunits": 0, "elapsed_ms": 1000}
      }
    }
  }
}
```

For each configured metric, **used + reserved <= limit** permits.
One over the limit denies with `budget_exceeded`. A missing/non-integer/
negative/boolean counter or limit denies with `budget_data_invalid`.
Zero is a real value, never an inferred replacement for missing data.

## Install and account correctly

Use the [shared install](../README.md#install-and-run) and register
`AcsInterceptor("policy/packs/budgets/manifest.yaml")` at both gates.
Only the trusted ledger may populate counters.

`used` must include completed usage **and other outstanding reservations**.
`reserved` is the conservative upper bound for this proposed action. The
host must check and acquire a reservation atomically, serialize evaluations
with the ledger or use a versioned compare-and-swap/retry. Two concurrent
calls evaluating the same unreserved balance are not protected by ACS.
Reconcile actual usage and release unused reservation after execution.

Count a concrete tool call as at least one where tool quotas apply. Include
input tokens and the enforced maximum output tokens for a model request.
Use nonzero bounds for billable operations. A zero cost estimate does not
make an action free. Enforce timeouts, maximum generation and tool resource
limits separately so actual usage cannot exceed the reservation.

## Boundaries

Tests exercise equality/one-over for every metric at both points, missing
and malformed used/reserved fields, clean composition and hard denials.
They do not simulate a production concurrent ledger or billing meter.
Unlike the stock `agt.budgets` helper, this pack deliberately does not
default absent counters to zero and accounts for the planned operation.
