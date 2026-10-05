# Prompt-injection decisions

Gate user instructions and untrusted retrieval results before the agent uses them. This decision rule does not detect attacks by itself. The [Azure Prompt Shields adapter](../recipes/README.md#azure-content-safety) supplies a concrete integration rather than requiring an invented "safe" field.

**Points:** `input`, `post_tool_call`. **Target:** `$.target`. The post-tool point is after retrieval but before the result is incorporated into the model context. Denying it cannot undo the retrieval.

## Configure and integrate

`config.json` sets `pack.deny_at` to `0.8`. A host dispatcher returns `{"score": 0.1}` on a normalized 0..1 contract. The rule permits below the threshold and denies at or above it. Missing, nonnumeric or out-of-range scores deny. A dispatcher error produces a runtime annotation denial.

The supplied Prompt Shields adapter maps boolean attack flags to 0 or 1. They are not calibrated probabilities. Its response validation requires an analysis of the user prompt and every submitted document. Other detectors may supply continuous scores, but their interpretation and threshold calibration belong to that integration.

Use the [shared install](../README.md#install-and-run) and [provider recipe](../recipes/README.md#azure-content-safety). At `input`, the adapter sends the governed target as the user prompt. At `post_tool_call`, it sends the target as a retrieved document and requires the host-captured original user prompt at `extensions.policy_packs.user_prompt`. It does not treat an instruction inside that document as authorization.

The profile screens credentials before any external annotation and stops on denial. Keep tool authorization and output controls even after an injection detector allows a message. Separation of instructions from retrieved data remains a host/framework concern.

Tests cover numeric boundaries, missing/failed adapters, both real HTTP request shapes, partial provider results and denied inputs that cause zero external requests. Provider responses are fixtures. No live detector efficacy, adversarial robustness, paid model campaign or deployed protection is claimed.
