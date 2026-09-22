# Credential disclosure

**Purpose:** block recognizable plaintext credentials before sending them
to a model/tool or releasing retrieved/generated content. This pack runs
offline and does not need host extension metadata.

**Points:** `pre_model_call`, `pre_tool_call`, `post_tool_call`,
`post_model_call`, `output`. **Target:** `$.target`, any non-null JSON
value. The policy examines nested string values and a JSON serialization
of the target to catch structured credential fields.

## Configure

`config.json` contains `pack.patterns`, a nonempty list of Regorus-compatible
regular expressions. Defaults recognize private-key headers, selected
`gh*`, `github_pat_`, `AKIA`/`ASIA` and `sk-` token prefixes, bearer
authorization fields and credential-like assignments such as
`TOKEN=synthetic-value` or `{"client_secret": "synthetic-value"}`.
The assignment pattern deliberately requires at least four value characters.

The pack reuses `agt.patterns.matches_any`. It verifies each configured
regex through the real engine before permitting a decision. Empty lists,
invalid syntax and unsupported constructs fail closed with
`credential_scan_invalid`; detected patterns deny with `credential_detected`.
Reasons do not echo the matched material.

## Install and examples

Follow the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/credentials/manifest.yaml")` at the documented
points. `demo.py` includes both a safe output and a synthetic assignment.

```json
{"target": {"content": "Please reset my password"}}
```

The target above allows. These targets deny:

```json
{"target": {"password": "synthetic-value"}}
```

```json
{"target": {"nested": [{"text": "-----BEGIN PRIVATE KEY-----"}]}}
```

These are target fragments. Use a full Agent Hooks envelope for emission.
Native tests exercise nested structures, numeric results, legitimate
credential-management discussion, custom patterns and all five points.
Every other pack is tested in composition with this control.

## Host requirements and limits

Block before any governed text is sent or released. Scan the whole model
request, including history and retrieved context, and assembled output,
not individual stream chunks. Do not include host-injected transport
credentials in agent-visible targets. Inject such credentials separately
after authorization through the trusted transport.

Regexes are not a complete secret detector. Encoding, encryption,
fragmentation across values/calls, unsupported credential formats and very
short assignments can evade these defaults. Public documentation containing
synthetic key examples can trigger them. Configure accepted use cases
explicitly rather than teaching the agent to bypass the gate. This is not
a credential vault, taint tracker or network containment system.
