# Tool permissions

**Purpose:** prevent an authenticated principal from invoking a tool outside
its permitted roles. This runnable decision requires a trusted identity
integration.

**Point:** `pre_tool_call`. **Target:** `$.target`, the actual arguments.
`$.tool_call.name` must be the name the host will execute. ACS projects it
from the manifest `tools` catalog before evaluating Rego.

## Configure and provide identity

Edit `manifest.yaml`, not agent input, to configure `allowed_roles`:

| Tool | Shipped roles |
| --- | --- |
| `search`, `read_document` | `reader`, `operator` |
| `send_email` | `operator` |
| `delete_record` | `administrator` |

Each tool requires a nonempty string list. Unknown tools fail closed with
ACS `runtime_error:tool_unknown`. Include the complete tool inventory for
the scope in which you register this control.

The authenticated host supplies:

```json
{
  "extensions": {
    "policy_packs": {"subject": "alice", "roles": ["reader"]}
  }
}
```

`subject` must be a nonempty string. `roles` must be an array of nonempty
strings. An empty role set is valid but has no permissions. Missing or
malformed metadata denies with `tool_permissions_data_invalid`. A valid
principal without a matching role denies with `tool_permission_denied`.

## Installation and enforcement

Use the [shared install](../README.md#install-and-run) and register
`AcsInterceptor("policy/packs/tool-permissions/manifest.yaml")` on the
tool emitter. The host resolves the authenticated subject's roles itself.
Never copy `subject` or `roles` from a prompt or tool argument. The test
suite proves such argument claims do not authorize a call.

A reader's `search` permits while their `send_email` denies. An operator
can send email subject to separately composed approval/disclosure rules.
An administrator role does not authorize an uncatalogued `shell` tool.
Tests also cover empty roles, malformed identity and both composition
orders with an approving resolver and a hard permission denial.

This gate controls tool identity, not arbitrary behavior hidden inside a
tool. A permitted shell/SQL/HTTP wrapper can still perform dangerous
operations unless independently constrained. Roles and catalog entries
must match the actual tool implementation and current identity policy.
