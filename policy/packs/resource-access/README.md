# Resource access

**Purpose:** prevent cross-tenant or unauthorized record/document operations.
This runnable decision template requires authenticated identity and a
trusted, fresh resource/ACL lookup.

**Point:** `pre_tool_call`. **Target:** `$.target`, the actual arguments.
Register this gate around concrete resource operations, not unrelated
tools without a resource.

## Configuration and resource contract

`config.json` defaults to `operations: ["read"]` and
`require_same_tenant: true`. The host supplies:

```json
{
  "extensions": {
    "policy_packs": {
      "subject": "alice",
      "tenant": "tenant-a",
      "resource": {
        "id": "record-42",
        "tenant": "tenant-a",
        "operation": "read",
        "allowed_subjects": ["alice"]
      }
    }
  }
}
```

Subject, tenant, resource ID, resource tenant and operation must be
nonempty strings. `allowed_subjects` must be an array of nonempty strings.
An empty ACL is valid and grants nobody access.

Permit requires membership in the resource ACL, an allowed operation and,
by default, equal subject/resource tenants. Missing/malformed metadata
denies with `resource_access_data_invalid`; failed authorization denies
with `resource_access_denied`. Setting `require_same_tenant: false`
deliberately enables explicit cross-tenant ACL grants. It does not bypass
the ACL or operation checks.

## Install and host duties

Follow the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/resource-access/manifest.yaml")` in the
resource tool's emitter.

The host must derive the exact resource ID and operation from the concrete
action, authenticate the caller and retrieve the matching resource ACL.
Keep those values bound to immutable execution arguments. Do not copy
`allowed_subjects`, `subject`, `tenant` or resource attributes from the
agent. Do not authorize one record and execute another. Recheck after ACL
changes or enforce a transactional/versioned authorization decision.

For batch operations, mediate every resource or build an application
policy covering the entire batch. A single authorized row cannot authorize
an arbitrary SQL query. Filesystem path resolution, SQL parsing and
row-level enforcement are not supplied by this pack.

## Cases

Tests allow a same-tenant authorized read, deny another subject or tenant,
deny writes by default, deny an empty ACL and reject every missing resource
field. They also cover missing identity and composition with a credential
deny. No directory service, resource lookup client or ACL cache is shipped.
