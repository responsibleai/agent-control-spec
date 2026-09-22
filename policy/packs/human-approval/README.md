# Human approval

**Purpose:** hold sensitive tools and large refunds for an authenticated
human decision. The pack can block offline. Permitting a held operation
requires a real host approval resolver.

**Point:** `pre_tool_call`. **Target:** `$.target`, the tool arguments.
The host sets the actual `$.tool_call.name`.

## Configuration

`config.json` lists known tools and those that always require review.
Defaults hold `send_email` and `delete_record`, permit ordinary `search`
and `read_document`, and hold `issue_refund` above 10,000 integer minor
units. A refund at exactly 10,000 allows this gate. Amounts below zero,
fractional, boolean, missing or represented as strings deny without an
approval block. Unknown tools likewise deny without a liftable approval.

```json
{"target": {"amount_minor": 10001}, "tool_call": {"name": "issue_refund"}}
```

This context fragment requests approval. The policy uses the existing
`agt.approval.escalate_if` helper. ACS normalizes the intent to a `deny`
with `approval: {}` and reason `human_approval_required`. It never returns
allow because an argument contains `approved: true`.

Configure `allowed_tools`, `approval_tools`, `refund_tool` and
`refund_limit_minor` for the application. Approval/refund tools must be in
the known-tool list. This sample assumes one host-established currency and
amount unit. Multi-currency conversion, per-customer entitlements, fraud
checks and aggregate refund limits require additional policy/state.

## Install and enforce

Follow the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/human-approval/manifest.yaml")`.
Without a resolver, held operations remain blocked.

The host must present the exact current action to an authenticated reviewer,
bind the response to the request's context identity and recheck that identity
before execution. A resolver that approves should return Agent Hooks
`ApprovalResolution(APPROVE, request.context_identity, Verdict.allow())`
**only after** the real reviewer approved that request. The test resolver
is synthetic and must not be copied as an automatic production approver.

Do not store approval success in agent-controlled arguments. Resolve expiry,
single-use/replay protection, durable suspension and later resumption in the
host. Do not replay already-executed actions. Preserve framework and CLI
permission prompts. Use deny-preserving composition with mandatory controls.

## Coverage

Native tests cover ordinary use, the exact amount boundary, malformed
amounts, unknown tools and ignored self-approval. Real Agent Hooks host
tests demonstrate successful identity-bound approval, rejection of a wrong
identity, and hard-deny precedence in either registration order.
No approval service, UI or durable approval store is supplied.
