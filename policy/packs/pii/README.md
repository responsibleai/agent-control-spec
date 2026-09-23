# Personal-data pattern filtering

Use this as a configurable plaintext disclosure rule at `input`, `post_model_call`, `post_tool_call` and `output`. It is not a general PII detector or a substitute for a DLP service. Defaults match email addresses and SSN-shaped strings. They do not establish whether an identifier is real.

## Ordinary JSON targets

The rule scans strings throughout `$.target`, including nested values, tool-call arguments and object keys. Safe objects, arrays, numbers and null values can pass. In particular, a model response with `content: null` and tool calls is normal and does not fail simply because it has no prose. A tool-call argument that contains a matching personal-data pattern still blocks.

With `action: "deny"`, any match denies with `pii_detected`. With `action: "redact"`, a matching string target or string `content` can be replaced. Matches elsewhere deny with `pii_unredactable_fields`. The policy does not rewrite resource IDs, tool arguments or arbitrary structured data behind the host's back. A clean structured result is allowed in either mode.

## Configure

```json
{
  "pack": {
    "action": "redact",
    "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
    "replacement": "[REDACTED]"
  }
}
```

This configuration permits business email while redacting SSN-like strings. The shipped default additionally matches email and uses `deny`. Configure the detector patterns for the data you actually handle, including legitimate data that must remain usable. Empty or invalid pattern lists deny. A replacement that reintroduces a matching value denies.

Patterns scan decoded JSON strings and their serialization, not the semantics of images, audio, encrypted values or encoded documents. Do not interpret an allow as evidence those modalities were analyzed. Use an appropriate detector/adapter when a workload requires that coverage.

## Integrate

Follow the [shared install](../README.md#install-and-run). The rule reuses `agt.patterns` and `agt.redact.apply_patterns`. A string target returns a `$target` replacement. A content object returns `$target.content` and preserves other fields.

The [document response recipe](../recipes/README.md#disclosure) reads a real database record and delivers `outcome.target` after enforcement. It does not deliver a cached copy of the original record. Apply the same discipline around model/output buffers, and assemble streams before release.

Native tests cover multiple matches, configured business-email exceptions, unsafe replacements, null-content tool-call responses, nested results and actual emitted transformations. A generic document-body redactor, name/address classifier, multimodal detector and format-aware file sanitizer are outside this pattern rule.
