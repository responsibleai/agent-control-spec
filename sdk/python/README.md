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

`AcsInterceptor` is synchronous. Releasing the GIL lets other threads
run, but does not yield the calling event loop. Agent Hooks can enforce
its interceptor timeout only on an awaitable return.

## Async hosts and partial-policy scope

`AsyncAcsInterceptor` is an awaitable adapter over an `ActivatedPolicy`,
with a dedicated worker pool. Activate once outside the serving loop,
reuse the adapter across requests, and close it before shutting down
that loop.

```python
from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor, Scope
from agent_hooks import AgentContextBuilder, InterceptionEmitter

policy = ActivatedPolicy.activate("manifest.yaml")  # startup, not per request


async def serve():
    async with AsyncAcsInterceptor(
        policy,
        scope=Scope.BOUND_POINTS_ONLY,
        max_concurrency=8,
    ) as control:
        emitter = InterceptionEmitter(timeout=1.0).register(control, control.name)
        context = AgentContextBuilder(
            agent_id="example", framework="example", session_id="session-1"
        )
        await emitter.emit(context.agent_startup(tools_registered=["search"]))
        # For a pre_tool_call-only policy, startup is outside this control.
        # Its tool policy still decides, and emit raises on a denial.
        await emitter.emit(
            context.pre_tool_call(call_id="call-1", name="search", args={"q": "x"})
        )
```

The default is `Scope.STRICT`: evaluate every point, including unbound
points, preserving the existing fail-closed behavior.
`Scope.BOUND_POINTS_ONLY` explicitly allows **known** lifecycle points
that this activation does not bind. It never catches evaluation errors
and turns them into allows. Invalid point names remain boundary errors;
bound-point runtime failures remain denials. Keep emitting every host
lifecycle point so other registered controls still run. A scoped allow
is only this control's verdict, not a global exemption.

### Admission, cancellation, and shutdown

`max_concurrency` (default 8) bounds submitted evaluations per adapter.
The adapter does not put overflow evaluations into the executor queue.

| Setting | Behavior at capacity |
| --- | --- |
| `on_saturation="reject"` (default) | Immediate deny, `acs_async_capacity_exceeded`. |
| `on_saturation="wait"` | Wait up to `admission_timeout` (default 0.1 seconds), then deny `acs_async_admission_timeout`. |
| Waiter count reaches `max_pending` (default 64) | Immediate deny, `acs_async_capacity_exceeded`. |

All these denials are final (no approval). These are adapter reason
codes, not new reserved ACS or Agent Hooks errors. Waiters are bounded,
but FIFO fairness is not promised. Configuration must use positive
integer capacities and a finite positive admission timeout.

The emitter timeout covers admission **and** the awaited evaluation.
Its expiry yields `host_error:interceptor_timeout`. Caller cancellation
propagates as cancellation. Neither cancels a running native call:
capacity stays occupied until that call actually returns. A timed-out
call's eventual verdict cannot authorize the abandoned action.

Use `async with` or `await control.aclose()`. Closing wakes queued
waiters and rejects new calls with `acs_async_closed`, drains active
work, and joins the executor without blocking the loop. Cancellation
of `aclose()` leaves cleanup running; await it again before closing the
loop. An operation that never returns can prevent draining indefinitely.
Do not create a replacement adapter per timeout: that would defeat the
capacity bound. An adapter belongs to one event loop; cross-loop use
raises an error.

Context variables are copied to evaluation workers. Custom annotator,
policy, and telemetry callbacks must be thread-safe. Unexpected worker
exceptions are propagated to the awaiter and logged by exception type
only, including after timeout; payloads and exception messages are not
logged by the adapter. Engine failure verdicts retain their existing
telemetry behavior.

### Operation deadlines

The emitter timeout bounds the caller's wait, not downstream execution.
Configure finite deadlines before activation:

- Bundled HTTP annotators accept a positive `timeout_ms` in their
  declaration, for example `timeout_ms: 1000`. A local HTTP regression
  checks that this returns `runtime_error:annotation_timeout` even with
  the emitter timeout disabled.
- Custom dispatchers own connect/read/overall deadlines and retry
  budgets. A thread wrapper cannot impose hard termination on them.
- The bundled Rego runner reads `ACS_OPA_TIMEOUT_MS` at initialization
  (default 5000 ms). This bounds policy evaluation/readying, not the
  whole annotation-plus-policy pipeline. Its internal worker controls
  remain separate from the adapter's bound on calls to `evaluate`.
- `limits["manifest_url_timeout_ms"]` applies to manifest loading,
  not annotation or policy execution.

Budget for the sum of this point's sequential annotator deadlines,
policy work, and callback overhead. There is no universal wall-clock
bound when arbitrary host callbacks are involved. Eight lifecycle
points do not imply eight annotator calls: only each point's configured
`annotations` request annotation work.

The adapter can run as a source-supplied module over the released
`agent-control-spec==0.4.0a3` and `agent-hooks-sdk==0.1.0a5`; it is not
itself included in that release. The activation options below require
the new native build. Publishing the earlier GIL fix (#56) alone does
not provide this async integration.

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

The constructor, `activate`, and `from_memory` all accept
`annotator_dispatcher`, `policy_dispatcher`, `telemetry_sink`,
`perf_telemetry` (`"off"`, `"external"`, or `"full"`), and `limits`,
as keyword arguments. These configure the activation used by the async
adapter too. Limits default field by field; inspect `DEFAULT_LIMITS`.
File activation applies loader limits while resolving `extends`.
In-memory activation still requires already-composed manifest text
and rejects unresolved relative bundle paths.

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

Trust model: a cooperative contract, not a security boundary — the host
is fully trusted. See the repository's SECURITY.md.

Benchmark: `python sdk/python/bench/activation_bench.py` runs against
`examples/bank_agent`, reporting activation cost, first-evaluate cost,
warm p50/p95/p99, and a thread-count throughput sweep up to 32.

Docs and spec: https://github.com/responsibleai/agent-control-spec
