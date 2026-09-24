# agent-control-spec (Python)

Python binding for the Agent Control Specification runtime: a stateless
policy decision engine that plugs into any
[agent-hooks](https://github.com/responsibleai/agent-hooks) host as an
interceptor.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --pre agent-control-spec
python -m pip check
```

ACS requires Python 3.11 or newer. `--pre` includes prereleases.
Use normal dependency resolution, not `--no-deps`.

The example files are not included in the wheel. From the repository root,
run the complete
[two-policy example](https://github.com/responsibleai/agent-control-spec/blob/main/examples/python_composition/README.md):

```bash
python examples/python_composition/compose.py
python -m unittest discover -s examples/python_composition -v
```

It includes both manifests, their Rego policies, an evaluation context,
and an inert operation. For the composition logic, see
[ACS and Agent Hooks](https://github.com/responsibleai/agent-control-spec/blob/main/docs/ACS-AND-AGENT-HOOKS.md).

The Python snippets below build on one another. Run them in the same
interpreter from the repository root. First, register one policy:

```python
from agent_hooks import InterceptionEmitter, EnforcementMode
from agent_control_spec import AcsInterceptor

emitter = InterceptionEmitter(mode=EnforcementMode.ENFORCE)
emitter.register(AcsInterceptor("examples/python_composition/limits.yaml"), "limits")
```

The manifest binds policies (Rego and Cedar through their built-in
evaluators, or `test` doubles) to interception points; the
runtime evaluates each context and returns an agent-hooks verdict.
Evaluation failures normalize into fail-closed `deny` verdicts with
`runtime_error:*` reasons. Construction raises on loading errors, and
`intercept()` raises if the context cannot be serialized. An unknown or
missing point name in that context returns a fail-closed deny.
Do not catch failures and return an allow.

## Activating a policy version

A host that pins a policy version and serves traffic against it wants
the expensive work done once, at a moment of its choosing.
`ActivatedPolicy` reads the manifest, loads every Rego module and data
document, and compiles the entrypoint each intervention point queries,
avoiding repeated bundle loading and compilation.

Compiling is bounded by the eval timeout. A policy too slow to compile in
that window activates anyway, not necessarily fully readied, and pays compilation
on its first decision instead.

```python
from pathlib import Path
from agent_control_spec import ActivatedPolicy
from agent_hooks import AgentContextBuilder

manifest_path = Path("examples/python_composition/limits.yaml")
policy = ActivatedPolicy(str(manifest_path))  # once per policy version
builder = AgentContextBuilder(
    agent_id="refund-assistant", framework="example", session_id="evaluation"
)
for amount in (40, 150):
    context = builder.pre_tool_call(
        call_id=f"refund-{amount}",
        name="issue_refund",
        args={"order_id": "A-1001", "amount": amount},
    )
    verdict = policy.evaluate("pre_tool_call", context)
    print(verdict.to_wire())
```

This returns `allow` for 40 and a `transform` setting `$target.amount`
to 100 for 150. Evaluation alone neither changes the context nor runs
the operation. The host must prevent denied calls and apply permitted
transforms. An Agent Hooks emitter applies them and returns
`outcome.target`; the operation must use that value. `emit()` raises
`InterceptionBlocked` on denial. The complete example handles both paths.
In `EVALUATE_ONLY` mode, denies and transforms are recorded but not enforced.

`warn` policy output becomes an allow carrying warnings; `escalate`
becomes a deny carrying an `approval` block. Without a resolver, an
enforcing host treats a liftable deny as a deny.

The instance is immutable and evaluation releases the GIL, so one
instance serves concurrent threads. A policy edit on disk needs a new
activation: the host decides when a version changes. Evaluation stays
fail-closed, including for a point the version does not bind; only
boundary problems (an unknown point name, a context that will not
serialize) raise. A known unbound point returns
`runtime_error:intervention_point_unknown`. Read
`policy.intervention_points` or `policy.governs(point)` to inspect an
activation's scope. These methods belong to `ActivatedPolicy`, not
`AcsInterceptor`. When registering interceptors, either bind every point
the emitter receives or use a dedicated emitter for each point, containing
the controls that bind it.

`evaluate()` and `AcsInterceptor.intercept()` are synchronous. GIL
release is not an asyncio yield, and the emitter's timeout cannot
preempt an inline synchronous call. In an async service, offload
evaluation with bounded admission and drain outstanding work at shutdown;
cancelling the await does not stop the worker. This release does not provide
an async interceptor.

The supplied policies have no annotators. A manifest that opts into
bundled annotators can make network requests during evaluation.

`from_memory` takes manifest text and Rego sources as values, so nothing
is staged to a temporary directory per activation. Using the files above:

```python
manifest_yaml = manifest_path.read_text()
rego_source = (manifest_path.parent / "policy" / "limits.rego").read_text()
policy = ActivatedPolicy.from_memory(
    manifest_yaml,
    {"limits": {"modules": {"limits.rego": rego_source}}},
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
    validate_manifest(manifest_path.read_text())
except ManifestInvalidError as error:
    print(error)  # names the offending field; do not serve this version
    raise
```

A manifest that uses `extends` cannot be judged from its own source,
because validation checks references across the merged document. Pass a
path instead and the chain is resolved first:

```python
from agent_control_spec import validate_manifest_file

validate_manifest_file(str(manifest_path))
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

Trust model: a cooperative contract, not a security boundary. The host
is fully trusted. See the
[Agent Hooks threat model](https://github.com/responsibleai/agent-hooks/blob/main/docs/THREAT-MODEL.md).

Benchmark: `python sdk/python/bench/activation_bench.py` runs against
`examples/bank_agent`, reporting activation cost, first-evaluate cost,
warm p50/p95/p99, and a thread-count throughput sweep up to 32.

Docs and spec: https://github.com/responsibleai/agent-control-spec
