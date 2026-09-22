# Configurable PII

**Purpose:** deny or redact selected personal-data patterns in text.
Defaults target email addresses and hyphenated US SSN-like values. This is
pattern matching, not a claim of complete PII identification or compliance.

**Points:** `input`, `post_model_call`, `post_tool_call`, `output`.
**Target:** `$.target`, either a string or an object with string `content`.
Additional fields are scanned as nested string values and serialized JSON.
A match outside `content` denies with `pii_unredactable_fields`, even in
redaction mode. Safe `role`, `tool_calls` and `finish_reason` fields are
preserved. Targets without string content, including multimodal/array
targets, deny with `pii_data_invalid`. Use a dedicated adapter for those
types rather than discarding content to make the check pass.

## Configure

`config.json` sets:

```json
{
  "pack": {
    "action": "deny",
    "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
    "replacement": "[REDACTED]"
  }
}
```

This example permits ordinary business email while still gating SSN-like
text. The shipped file also includes an email pattern. Select `redact`
instead of `deny` to replace all matches with the configured replacement.
Patterns must be a nonempty valid Regorus regex list. Unknown actions or
malformed configuration deny. A replacement that still matches the
configured patterns denies with `pii_replacement_unsafe`.

The pack reuses `agt.patterns` and `agt.redact.apply_patterns` without
changing the stock libraries. It produces one replacement for the whole
governed string, so multiple matching patterns are redacted in one verdict.

## Install and enforce transforms

Follow the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/pii/manifest.yaml")`. Reactivate after editing
configuration. A string target produces a `$target` transform. A content
object produces `$target.content`, preserving its other fields.
The host must execute/deliver `outcome.target` returned by the enforcing
emitter, not a cached copy of the original content.

With `redact`, `Contact a@example.com about 123-45-6789` becomes
`Contact [REDACTED] about [REDACTED]`. With shipped `deny`, it is blocked.
An ordinary technical explanation permits unchanged.

## Coverage and tradeoffs

Tests cover every point and both target shapes, multiple replacements,
configurable email handling, invalid/unsupported regexes, canonical SDK
model responses, personal data in other fields and transform forwarding through the real Agent Hooks
emitter. Composition with credential scanning proves residual credentials
still block. Text-only tests do not establish image/audio or general JSON
redaction. Regex matching has false positives, no SSN validity check and
no linguistic/name/address coverage. Hosts must assemble streams and avoid
logging original sensitive values.
