# Information flow

**Purpose:** enforce no write down for host-labelled data at tool, model
and response sinks. This is a runnable decision template requiring a
trusted provenance tracker. ACS is stateless and cannot infer prior taint.

**Points:** `pre_tool_call`, `pre_model_call`, `output`.
**Target:** `$.target`, the data entering the sink. Labels must describe
the whole effective target, including relevant prompt history/derivations,
not just the newest message.

## Configuration and labels

The policy reuses `agent_control_specification.lib.ifc` with its existing
`public < internal < confidential < secret` lattice.

For `pre_tool_call`, ACS projects `tool_call.name` from the manifest
catalog: `send_email` has `public` clearance and `archive` has
`confidential`. Unknown tools deny during projection. Extend the complete
catalog for your scope. `config.json` sets model clearance `internal` and
output clearance `public`. These are sink policy, not agent claims.

The trusted host supplies:

```json
{"extensions": {"policy_packs": {"source_labels": ["public", "confidential"]}}}
```

The extension path is deliberate. It keeps all new host contracts under
one namespace. Existing helpers using `snapshot.ifc.source_labels` or
AGT-specific paths are unchanged. This pack passes labels explicitly into
the stock helper.

Missing, empty, malformed or unknown labels deny with `ifc_data_invalid`.
So does a sink that cannot dominate every input label. A permit includes
the joined sensitivity in `result_labels`. No labels are returned on deny.
Changing the lattice requires a deliberate policy/library change, not
inventing an unrecognized label in a snapshot.

## Install and propagate

Use the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/information-flow/manifest.yaml")`.
Only trusted code assigns initial labels, tracks lineage and unions
labels across retrieval, memory, tools and model context.

Persist returned `result_labels` with produced data **only if the action
actually proceeds**. Use them on subsequent derived targets. A later tool
result may introduce more sensitive data than its arguments. The host must
join trusted source/resource classifications into that result rather than
assuming the pre-tool result label fully describes it. A deny cannot erase
labels already attached to other data.

Do not let the model declassify content, select its own sink clearance or
claim that redaction removed sensitivity. This pack performs no
declassification. Bind model/output clearances to the actual deployment
and caller; a generic public output default does not grant a caller access
to confidential data.

## Cases

Public data permits into public email. Public plus confidential data
permits into the archive and yields `["confidential"]`; forwarding those
labels into public output denies. Tests cover every point, malformed and
unknown labels, actual propagation of the returned join and composition.
They prove the stateless decisions, not complete taint tracking in a host.
