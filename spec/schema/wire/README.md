# Wire JSON schemas

These schemas describe ACS wire JSON carried between hosts, SDK bindings, and policy dispatchers. All schemas use JSON Schema draft 2020-12.

| Schema | Governs |
|---|---|
| `snapshot.schema.json` | Host supplied facts for one intervention point. |
| `policy-input.schema.json` | Canonical policy dispatcher input built by `build_policy_input`. |
| `verdict.schema.json` | Policy output normalized into the core `Verdict`. A `transform` verdict carries one `{path, value}` replacement under `$target`; the host applies it. |
| `request.schema.json` | Intervention request envelope accepted by the JSON wire bindings. |
| `result.schema.json` | Result envelope the JSON wire bindings return; its embedded verdict may carry `runtime_error:` reasons. |
