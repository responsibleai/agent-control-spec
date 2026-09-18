# agent-control-spec (Python)

Python binding for the Agent Control Specification runtime: a stateless
policy decision engine that plugs into any
[agent-hooks](https://github.com/responsibleai/agent-hooks) host as an
interceptor.

```bash
pip install --pre agent-control-spec
```

```python
from agent_hooks import InterceptionEmitter, EnforcementMode
from agent_control_spec import AcsInterceptor

emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
emitter.register(AcsInterceptor("manifest.yaml"), "acs")
```

The manifest binds policies (Rego and Cedar through their built-in
evaluators, or `test` doubles) to interception points; the
runtime evaluates each context and returns an agent-hooks verdict.
Engine failures never raise into the host loop: they normalize into
fail-closed `deny` verdicts with `runtime_error:*` reasons.

## Activating a policy version

A host that pins a policy version and serves traffic against it wants
the expensive work done once, at a moment of its choosing.
`ActivatedPolicy` reads the manifest, loads every Rego module and data
document, and compiles the entrypoint each intervention point queries;
every later `evaluate` costs no I/O and no compile.

Compiling is bounded by the eval timeout. A policy too slow to compile in
that window activates anyway, not necessarily fully readied, and pays compilation
on its first decision instead.


```python
from agent_control_spec import ActivatedPolicy

policy = ActivatedPolicy("manifest.yaml")  # once per policy version
verdict = policy.evaluate("input", context)  # many times, hot path
policy.intervention_points  # what this version governs
```

The instance is immutable and evaluation releases the GIL, so one
instance serves concurrent threads. A policy edit on disk needs a new
activation: the host decides when a version changes. Evaluation stays
fail-closed, including for a point the version does not bind; only
boundary problems (an unknown point name, a context that will not
serialize) raise.

A service that keeps manifests and Rego in a database has no directory
to point a manifest at. `from_memory` takes both as values, so nothing
is staged to a temporary directory per activation:

```python
policy = ActivatedPolicy.from_memory(
    manifest_yaml,
    {"gate": {"modules": {"gate.rego": rego_source}}},
)
```

A bundle may also carry data documents, as
`{"mount": ["limits"], "document": {...}}` entries under `"data"`. A Rego
policy left naming a relative `bundle` or data path is rejected: manifest text
has no directory of its own, so the path would resolve against the
process working directory. Absolute paths are left as written.

Manifests can also be checked on their own, without building a runtime
or resolving a policy bundle. Useful when generating or migrating manifests:

```python
from agent_control_spec import ManifestInvalidError, validate_manifest

try:
    validate_manifest(source)
except ManifestInvalidError as error:
    print(error)  # names the offending field
```

A manifest that uses `extends` cannot be judged from its own source,
because validation checks references across the merged document. Pass a
path instead and the chain is resolved first:

```python
from agent_control_spec import validate_manifest_file

validate_manifest_file("manifest.yaml")
```

`supported_manifest_versions()` reports the grammar versions this
engine accepts. Read it rather than hardcoding the set.

## Authoring inspection

This checkout adds an in-process Rego parser for Python authoring tools:

```python
from agent_control_spec.authoring import REGORUS_AST_VERSION, parse_rego_ast

policies = parse_rego_ast("package example\nallow if { input.approved == true }\n")
assert REGORUS_AST_VERSION == "0.12.0"
module = policies[0]["ast"]
```

The helper calls Regorus's `add_policy` and `get_ast_as_json` without evaluating
the policy, fetching imports or reading files. It releases the GIL and raises
`ValueError` for malformed source or exceeded authoring limits. Input is capped
at 64 KiB and serialized output at 8 MiB; Regorus's parser limits also apply.
Before parsing, a conservative guard rejects nesting beyond 12 levels, more
than 1,024 structural tokens, or more than 262,144 depth-weighted byte units.
Each byte costs `2^nesting_depth` units. Delimiters inside strings and comments
do not change depth, but their bytes still count toward the work budget.
This bounds admission to parser paths that can otherwise backtrack excessively
on tiny nested arrays. Budget failures are ordinary `ValueError` exceptions.

The returned structure is the pinned Regorus AST, not a stable ACS wire format.
It is separate from the runtime API and intended for inspection rather than
cross-SDK interchange or persistent artifacts. The generator uses it instead
of an external OPA installation.

This helper first ships in SDK `0.4.0a4`; it is not in the previously published
0.4.0a3 wheel. Until alpha.4 is published, install the SDK from this checkout
alongside the generator. Tests compare the compiled Regorus version marker with
the exact Cargo requirement and resolved lockfile to catch dependency-pin drift.

Trust model: a cooperative contract, not a security boundary — the host
is fully trusted. See the repository's SECURITY.md.

Benchmark: `python sdk/python/bench/activation_bench.py` runs against
`examples/bank_agent`, reporting activation cost, first-evaluate cost,
warm p50/p95/p99, and a thread-count throughput sweep up to 32.

Docs and spec: https://github.com/responsibleai/agent-control-spec
