# Approval for concrete tool actions

Gate irreversible operations such as document updates, deployments or sending messages at `pre_tool_call`. `$.target` is the actual argument object, and `$.tool_call.name` is the tool the host will execute. There is no mandatory refund workflow.

## Rules

`config.json` maps tool names to one of three modes. Tools without a rule deny. Malformed rules and unexpected rule fields also deny rather than being ignored.

```json
{
  "pack": {
    "tools": {
      "search": {"mode": "allow"},
      "deploy": {"mode": "review"},
      "issue_refund": {
        "mode": "threshold",
        "argument_path": ["amount_minor"],
        "max_without_approval": 10000
      },
      "provision": {
        "mode": "threshold",
        "argument_path": ["capacity", "instances"],
        "max_without_approval": 10
      }
    }
  }
}
```

`allow` passes this gate, not every other policy. `review` always returns an approval request. `threshold` requires a nonnegative integer at the configured path and requests review only above the inclusive limit. Missing, fractional, boolean, negative or string values deny without an approval block. Paths are nonempty lists of object-member names. Choose the units in your application's tool schema. Currency conversion, aggregate refunds, fraud and per-customer entitlements remain separate policies.

The shipped sample allows `search` and `read_document` and reviews `send_email` and `delete_record`. Replace the map with your actual tool inventory. A deployment-only configuration can contain just `{"tools": {"deploy": {"mode": "review"}}}` under `pack`.

## Integrate

Use the [shared installation](../README.md#install-and-run), activate `manifest.yaml`, and register the control with an enforcing Agent Hooks emitter. ACS normalizes `agt.approval.escalate_if` to `deny` plus an approval block. It never grants approval because arguments contain `approved: true`.

The [document recipe](../recipes/README.md#document-service) makes actual SQLite writes only after authorization and identity-bound approval. Rejected, missing or cancelled approval leaves the database unchanged. Its scripted test reviewer is not a production approver. The host must authenticate reviewers, display the exact action, bind responses to its context identity, enforce expiry/replay rules and implement durable suspension if needed. Preserve additional CLI/framework prompts.

Tests cover standalone deployments, nested capacity thresholds, refund configuration as an optional example, malformed arguments and configuration, unknown tools, actual approved/rejected writes, cancellation and hard-deny precedence. The earlier draft's `refund_tool`/`refund_limit_minor` configuration was replaced before release; the existing upstream stock approval library is unchanged.
