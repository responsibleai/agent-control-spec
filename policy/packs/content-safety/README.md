# Harmful-content decisions

Gate input, generated responses and retrieved content using a classifier's category severities. This is the decision rule. The [Azure Content Safety recipe](../recipes/README.md#azure-content-safety) supplies a reference REST dispatcher and checks its wire contract through real loopback HTTP.

**Points:** `input`, `post_model_call`, `post_tool_call`, `output`. **Target:** `$.target`. The dispatcher must inspect the whole governed target or fail. A post-action gate can prevent later consumption/release but cannot undo the earlier action.

## Configure

`config.json` contains a nonempty `pack.thresholds` map. Defaults deny at severity 4 or above for `hate`, `self_harm`, `sexual` and `violence` on a 0..7 scale. Choose categories/thresholds to fit the workload and the detector's actual scale.

The `content_safety` dispatcher returns:

```json
{"scores": {"hate": 0, "self_harm": 0, "sexual": 0, "violence": 3}}
```

Every configured category must be present with an integer severity between 0 and 7. Missing or malformed categories deny with `content_safety_data_invalid`. Meeting the threshold denies with `content_safety_threshold`. Adapter exceptions fail closed in ACS. The supplied Azure adapter requests `EightSeverityLevels`, validates every category and maps the provider's category names into this contract. Do not feed its four-level normalized stock-dispatcher scores directly into a policy expecting 0..7.

## Use

Follow the [shared install](../README.md#install-and-run), then the [provider setup](../recipes/README.md#azure-content-safety). Pass the dispatcher to `AcsInterceptor` or use the recipe profile. Provision the service and provide credentials through the host. The default manifest has no endpoint and cannot classify content by itself.

Screen disclosure before making remote classifier calls. The recipe uses first-deny composition so a credential denial prevents any provider request. Do not assume a later deny in a run-all chain undoes an earlier annotation's network transfer.

Unit tests cover every point, threshold edges and malformed annotations. Integration tests verify actual HTTP payloads, response normalization and provider failures against scripted service-shaped responses. They do not establish classifier quality, multilingual coverage, live service availability or deployment safety. The supplied adapter rejects recognized media blocks and over-limit text rather than claiming it analyzed them.
