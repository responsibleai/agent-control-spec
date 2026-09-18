# Natural-language policy authoring

`acs-policy-gen` takes an agent description, system prompt, or policy statement
and asks a model for a JSON policy plan. It renders the plan as an ACS manifest,
Rego module, and review report. The output is a draft. Review the rules and test
them against your application's inputs before activating the policy.

This is a port of AGT's `acs-generate --prompt` flow from
[`policy-engine/generator/` at `c63c51e8`](https://github.com/microsoft/agent-governance-toolkit/tree/c63c51e881c442fbc060705f7e211f29993f2c1b/policy-engine/generator).
The guided `acs-generate init` designer is not included. The distribution
`agent-control-spec-generator` and command `acs-policy-gen` have different names
so they can coexist with AGT's generator.

### Behavior changes from AGT

- Manifests read the agent-hooks `$.target` shape. Saved plans using old model
  request/response paths or assuming a scalar input/output target need updating.
- Effects on non-transform decisions, empty annotation `from` paths, undeclared
  explicit annotator bindings, and unsupported conditions are rejected. AGT
  dropped some effects, defaulted empty paths, and accepted a wider set of builtins.
  In particular, this authoring subset rejects `time.now_ns`, `glob.match`, and
  `regex.template_match`.
- Sampling uses the provider default rather than requesting `temperature: 0`.
- Empty verdict messages and `extends: []` are omitted. Names beginning with a
  digit get a `policy_` prefix, so `2fa Agent` becomes `policy_2fa_agent`.
- The raw `--api-key` flag is removed. Use the environment or `--api-key-file`.
- Existing output directories require explicit replacement; old artifacts are
  retained in a backup rather than overwritten in place.

## Install from this checkout

The generator is a separate Python package with version metadata kept in lockstep
with ACS. It is not part of the runtime wheel or the tag-driven publication set.
See [RELEASING.md](../RELEASING.md). This change does not publish it to PyPI.

From the repository root, in a virtual environment:

```bash
python -m pip install ./sdk/python ./generator
```

Building `sdk/python` requires Rust and the package's maturin build backend.
The dependency floor is SDK `0.4.0a4`, the first version with the authoring helper.
Until that SDK release is available, install both packages from this checkout.
If dependency resolution is bypassed or an editable native build is stale, the
generator reports the incompatible binding on first use, before any model call.

Neither generation nor runtime evaluation requires an OPA executable. The
Python SDK exposes Regorus's in-process parser through
`agent_control_spec.authoring`. The generator inspects that AST, and ACS uses
Regorus to compile and evaluate the resulting policy. No parser subprocess or
temporary Rego file is needed.

## Generate a draft

```bash
export ACS_GENERATOR_API_KEY="..."
export ACS_GENERATOR_MODEL="your-model-or-deployment"

acs-policy-gen \
  --prompt "A support assistant. At output, redact account numbers matching
            acct_[0-9]+ from target.content. Do not use annotators." \
  --out build/support-policy
```

The directory contains:

| File | Contents |
| --- | --- |
| `manifest.yaml` | Bound interception points, tool catalog, annotator declarations, and policy queries |
| `policy/<slug>.rego` | One module with point-specific entrypoints |
| `report.md` | Rules, assumptions, checks performed, and review limitations |

Use `--prompt-file FILE` for a system prompt or policy document.
`--prompt-file -` reads stdin. `--dry-run` still calls the model and validates its
response, but prints the artifacts without writing them.

The same inputs are available through Python:

```python
from pathlib import Path

from agent_control_spec_generator import GenerationEngine, OpenAICompatibleLanguageModel

result = GenerationEngine(OpenAICompatibleLanguageModel(), max_attempts=3).generate(
    prompt=Path("guardrails.txt").read_text(encoding="utf-8"),
    out_dir=Path("build/support-policy"),
    tool_inventory={"lookup": {"clearance": "internal"}},
)
print(result.attempts, result.warnings)
```

`GenerationResult` contains the manifest dict and YAML text, Rego source, report,
warnings, slug, and attempt count. Pass `write=False` to keep the artifacts in
memory. A custom model only needs `complete(system, user) -> str`.

## Provider configuration

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--api-base` | `ACS_GENERATOR_API_BASE` | `https://api.openai.com/v1` |
| `--api-key-file` | `ACS_GENERATOR_API_KEY` when no file is supplied | Required |
| `--model` | `ACS_GENERATOR_MODEL` | `gpt-4o-mini` |
| `--api-version` | `ACS_GENERATOR_API_VERSION` | Unset |
| `--max-attempts` | None | 5, with an allowed range of 1 through 5 |

The CLI never accepts a raw key value in argv. Set `ACS_GENERATOR_API_KEY`, or
pass a UTF-8 key file to `--api-key-file`; `-` reads the key from stdin.
The prompt and key cannot both read stdin. The provider constructor is the
single reader of the four `ACS_GENERATOR_*` variables.
The provider receives the authoring instructions, supplied prose,
tool inventory, and any rejected plan and repair diagnostic. Do not supply
secrets or customer data unless that endpoint is approved to receive them.

For Azure deployment chat completions, set the resource root as `--api-base`,
the deployment name as `--model`, and `--api-version`. An explicit
`/openai/deployments/NAME` base is also accepted. Without `--api-version`, an Azure
resource root uses `/openai/v1`; a caller-supplied v1 base is used as written.
Azure requests use `api-key`; other v1 requests use bearer authorization.

Requests require HTTPS, except for loopback test servers. Redirects are refused.
Each request has a 60-second socket timeout, a 120-second response deadline,
a 4,096-completion-token budget, and a 1 MB response limit. A monotonic budget
limits every response receive, including status/header parsing, so a trickling
server cannot keep resetting the timeout. Platform DNS resolution still follows
the host resolver's limits; this is not a deadline for the whole generation.
HTTPS uses the standard proxy environment variables. Loopback HTTP bypasses all
proxies to keep its credential on the local connection.
Sampling is left to the provider; generation is not deterministic.

A rejected plan gets another attempt with the previous response and diagnostic.
Provider failures, refusals, truncated responses, missing credentials, and write
errors stop the operation. They do not consume policy repair attempts. Provider
response bodies are omitted from errors.

## Tools and annotators

Supply the complete tool catalog with `--tools-file FILE`, a JSON or YAML mapping
of tool names to objects. `--tool NAME:LABEL,LABEL` adds a tool with security labels;
use a tools file for `clearance` or other host metadata. The Python equivalent is
`tool_inventory`.

The generator preserves supplied entries, adds missing `id` and `name` members,
and reports tool names inferred from conditions without inventory metadata.
When a catalog is present, tool points project the named entry into `input.tool`.
An unknown tool is denied by ACS. Without a catalog, rules may inspect tool
arguments, but rules that require `input.tool` are rejected.

Annotator references produce manifest bindings, including references through
simple aliases and quoted keys. Undeclared references receive a classifier
declaration and a warning. The host must provide and configure that dispatcher;
generation does not implement a classifier or call an annotator service.
Explicit bindings may use other roots accepted by ACS, such as `$snap` or `$pi`.
The report warns about every explicit binding outside `$target`; review the data
it exposes before configuring a real dispatcher.

## Supported plans and review limits

The model returns `name`, `guarded_points`, `tools`, `annotators`, `annotations`,
`rules`, and `warnings`. Each rule has a point, decision, reason, optional message,
Rego condition statements, and optional transform effects. Unknown fields,
duplicate JSON keys, invalid types, empty plans, and non-finite values are
rejected rather than silently discarded.

Regorus parses the conditions before ACS evaluates anything. The authoring subset
allows request comparisons, common string and collection operations, and regex
calls with literal patterns or variables bound to literal strings. Unsupported
functions, network calls, external data, input overrides, dynamic annotation
names, and unresolved regex patterns are rejected with repair diagnostics.
Iteration uses top-level `some` statements. Comprehensions and `every` blocks are
outside this single-scope authoring subset, so nested bindings cannot be mistaken
for a regex's literal pattern.
This is a bounded authoring subset, not a general Rego type checker.
After leading comments and blank lines, a condition body cannot start with `-`.
Write `0 - ...` explicitly; Regorus can otherwise attach a leading unary minus
to the renderer's preceding guard across a newline.

The native authoring helper accepts at most 64 KiB of Rego source per call and
8 MiB of serialized AST output. A pre-parse guard limits nesting to 12 levels,
structural tokens to 1,024, and depth-weighted byte work to 262,144 units.
This rejects inputs that would trigger excessive parser backtracking before
Regorus starts; it is not a timeout that leaves a native thread running.
Regorus's own parser limits also apply. Its AST
layout is pinned to Regorus 0.12.0 and is not an ACS interchange format.
The generator rejects unsupported AST variants rather than skipping checks.

ACS then validates the manifest and compiles the Rego bundle. The generator
checks collected patterns with the runtime regex engine and evaluates synthetic
contexts at every bound point. These smoke cases use empty annotation results
and do not prove that a rule ever matches. Application-specific properties,
regex coverage, policy completeness, and host enforcement still need tests.
Multiple iteration clauses produce a warning because they may form a Cartesian
product, including across different collections. This covers `some ... in`,
wildcard lookups such as `input.x[_]`, and lookups using unbound named indices.
Repeated uses of an already-bound index do not add an iteration. The warning
is not a performance bound.

The default verdict is allow. Rules use a first-match chain ordered
`deny > escalate > transform > warn > allow`, with plan order breaking ties.
Only one rule contributes a verdict, so matching warnings are not accumulated.
`warn` and `escalate` are policy intents that ACS normalizes to `allow` with
warnings and `deny` with an approval block.

There is at most one transform rule per point. It carries one replacement or
multiple same-path redactions. Valid paths are preserved, including quoted keys
and real nested members such as `$target.value`. A redact operation must target
a string. Every effect path also passes the runtime's path parser independently
of the smoke cases. All generated manifests read `$.target`, the agent-hooks value under
evaluation. Lifecycle transforms are rejected.

The [Python SDK](../sdk/python/README.md) can activate these files or their
in-memory equivalents. Agent-hooks hosts apply transforms and resolve approvals;
ACS only returns verdicts. Generation does not activate or approve a policy.

## Output replacement

Both the CLI and Python API require a new or empty output directory by default.
`--force` or `force=True` permits replacement of an artifact-only directory.
Directories containing unrelated top-level entries or symlinks are rejected.

The writer stages every file first, retains the old directory as a sibling
`.NAME.backup-...`, then publishes the new directory. A failed publication rename
restores the previous directory. Backups are never automatically deleted.
Replacing an existing directory uses two renames, not an atomic exchange.
Use versioned directories and activate them after generation rather than loading
from a directory while it is being replaced.

A sibling lock rejects concurrent generator writers. An interrupted process can
leave its lock file; remove it only after confirming the writer has stopped.

## Offline example and tests

From the repository root:

```bash
python generator/examples/payments_agent.py
python -m pytest generator
```

The example uses a scripted model and a local example annotator. It generates
artifacts and evaluates password, transfer, and redaction cases through ACS.
It does not execute a bank transfer or enforce a host action. Tests require no
provider credentials; transport tests use loopback servers or recorded responses.
