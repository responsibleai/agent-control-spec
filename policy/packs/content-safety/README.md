# Content safety

**Purpose:** hold user input, retrieved results and generated responses whose
trusted classifier severity meets a configured threshold. This is a runnable
decision pack, not an installed content classifier.

**Points:** `input`, `post_model_call`, `post_tool_call`, `output`.
**Target:** `$.target`, including structured targets. The classifier must
inspect all content in that target or fail the annotation. A post-action
check only prevents subsequent consumption/release, not the action itself.

## Configuration and classifier contract

`config.json` contains `pack.thresholds`, a nonempty category-to-integer map.
Defaults deny at severity **4 or above** for hate, self-harm, sexual and
violence content on a normalized 0..7 scale. Change thresholds and categories
to match the application's requirements. Do not directly feed scores from a
different scale into this policy.

The host dispatcher for `content_safety` receives the preliminary policy
input and must return:

```json
{"scores": {"hate": 0, "self_harm": 0, "sexual": 0, "violence": 3}}
```

Every configured category must exist and be an integer from 0 through 7.
Missing categories, strings, booleans and fractional/out-of-range scores
deny with `content_safety_data_invalid`. A score at the threshold denies
with `content_safety_threshold`. An adapter error fails closed in ACS.
There is no configured provider endpoint and no network fallback.

## Install and wire

Follow the [shared installation](../README.md#install-and-run), preserve
relative library paths, then construct the interceptor with your dispatcher:

```python
from agent_control_spec import AcsInterceptor

# classify implements dispatch(name, declaration, preliminary_policy_input).
# Register this interceptor with an enforcing Agent Hooks emitter.
control = AcsInterceptor(
    "policy/packs/content-safety/manifest.yaml",
    annotator_dispatcher=classify,
)
```

The callable's `preliminary_policy_input["policy_target"]["value"]` is what
must be classified. Provider adapters own credentials, normalization,
timeouts, retries and schema validation. Agent-supplied `scores` inside
the target or extensions are not classifier results.

## Boundaries and coverage

The runtime tests allow severity 3, deny 4, cover every bound point, reject
missing/malformed categories and exercise unavailable classifiers.
Composition tests show a credential deny still wins, and clean content can
pass both controls. Test classifiers return fixed synthetic annotations.
They do **not** measure safety accuracy, images/audio coverage, multilingual
coverage, contextual exceptions or classifier resistance to manipulation.
Do not release streamed content before the complete-target check.
