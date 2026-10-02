# Model routing

**Purpose:** limit model requests to approved provider, deployment and
region combinations. This runnable decision template requires the host's
actual routing configuration.

**Point:** `pre_model_call`. **Target:** `$.target`, the model request.
This pack does not interpret a model's self-reported location or identity.

## Configuration and trusted route

`config.json` contains a nonempty `pack.routes` array. Each entry has
exactly three nonempty string fields:

```json
{"provider": "private", "deployment": "support", "region": "us"}
```

This is an illustrative internal route ID tuple, not a built-in provider
or a claim that a deployment exists. Replace it with real approved routes.
The router supplies the same shape at:

```json
{
  "extensions": {
    "policy_packs": {
      "model_route": {"provider": "private", "deployment": "support", "region": "us"}
    }
  }
}
```

Only an exact tuple match allows. A well-formed unapproved tuple denies
with `model_route_denied`. Missing, extra or malformed fields deny with
`model_route_data_invalid`. Separate field allowlists are intentionally
not used because they could permit an unapproved cross-product of routes.

## Install and enforce

Follow the [shared install](../README.md#install-and-run) and register
`AcsInterceptor("policy/packs/model-routing/manifest.yaml")` on the model
emitter. The host resolves the route from trusted configuration immediately
before dispatch and binds it to the endpoint/request it actually uses.
Reevaluate on fallback, retry to a different deployment or region change.

Passing the gate does not establish data residency, provider retention
policy or contractual guarantees. Verify those outside ACS. Combine
with credential scanning, IFC and resource budgets. Never derive
`model_route` from prompt text or accept it from model-generated arguments.

Tests permit the configured tuple, deny changes to each component, reject
each missing component and exercise allow/deny composition. No model
request or route provisioning is performed.
