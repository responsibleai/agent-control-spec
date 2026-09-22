# Prompt injection

**Purpose:** gate user instructions and untrusted tool/retrieval results
before incorporating them into the agent loop. This pack requires an
external trusted detector. It is not a keyword denylist or a proven defense
against all indirect instructions.

**Points:** `input`, `post_tool_call`. **Target:** `$.target`, any shape your
detector can fully inspect. Tool results have already been produced at the
post-tool point. A denial must prevent their subsequent use.

## Configuration and annotation

`config.json` sets `pack.deny_at` to `0.8`. The threshold must be a number
greater than zero and at most one. The host `prompt_injection` dispatcher
must return a normalized score:

```json
{"score": 0.1}
```

Scores in `[0, 0.8)` allow by default. Scores in `[0.8, 1]` deny with
`prompt_injection_detected`. A missing/non-number/out-of-range score denies
with `prompt_injection_data_invalid`. Missing or failed adapters produce a
runtime annotation denial, not a clean-content default.

## Installation and host obligations

Use the [shared install](../README.md#install-and-run), then pass your
dispatcher when constructing
`AcsInterceptor("policy/packs/prompt-injection/manifest.yaml",
annotator_dispatcher=detector)` and register it with an enforcing host.
The dispatcher receives the selected target in the preliminary policy
input. It must normalize the detector result, cover the whole payload and
raise on incomplete analysis or service failure. No provider or credentials
are shipped.

Do not accept an agent's own risk score. Bind annotations to the current
target, separate retrieved data from privileged instructions and retain
tool authorization controls even when the detector allows. A low score
does not authorize tools, disclose secrets or relax approvals.

## Cases and limitations

Native tests cover scores 0, 0.799, 0.8 and 1 at both points, invalid and
missing scores, adapter failures and composition. Fixed detector fixtures
test decision semantics, not detection efficacy. Domain-specific detector
calibration and false-positive handling remain integration work.
