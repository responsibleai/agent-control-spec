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
from agent_control_spec import ActivatedPolicy, AsyncAcsInterceptor
from agent_hooks import AgentContextBuilder, InterceptionEmitter

policy = ActivatedPolicy.activate("manifest.yaml")  # startup, not per request


async def serve():
    async with AsyncAcsInterceptor(policy, max_concurrency=8) as control:
        emitter = InterceptionEmitter(timeout=1.0).register(control, control.name)
        context = AgentContextBuilder(
            agent_id="example", framework="example", session_id="session-1"
        )
        await emitter.emit(context.agent_startup(tools_registered=["search"]))
        # The manifest must bind each emitted point. emit raises on denial.
        await emitter.emit(
            context.pre_tool_call(call_id="call-1", name="search", args={"q": "x"})
        )
```

The default is `Scope.STRICT`: evaluate every point, including unbound
points, preserving the existing fail-closed behavior.
For a deliberately partial control, opt in with
`AsyncAcsInterceptor(policy, scope=Scope.BOUND_POINTS_ONLY)` after
importing `Scope` from `agent_control_spec`. This allows **known**
lifecycle points that this activation does not bind. It never catches evaluation errors
and turns them into allows. Invalid point names remain boundary errors;
bound-point runtime failures remain denials. Keep emitting every host
lifecycle point so other registered controls still run. A scoped allow
is only this control's verdict, not a global exemption.
It carries `acs_point_unbound` in the record's per-interceptor
`verdicts[].reason`, so readers can distinguish a bypass from an
ordinary bare allow. The combined verdict may discard an allow reason.

### Admission, cancellation, and shutdown

`max_concurrency` (default 8) bounds submitted evaluations per adapter.
The adapter does not put overflow evaluations into the executor queue.

| Setting | Behavior at capacity |
| --- | --- |
| `on_saturation=Saturation.REJECT` (default) | Immediate deny, `runtime_error:acs_async_capacity_exceeded`. |
| `on_saturation=Saturation.WAIT` | Wait up to `admission_timeout` (default 5 seconds), then deny `runtime_error:acs_async_admission_timeout`. |
| Waiter count reaches `max_pending` (default 64) | Immediate deny, `runtime_error:acs_async_capacity_exceeded`. |

Import `Saturation` from `agent_control_spec`; the equivalent strings
`"reject"` and `"wait"` are also accepted. The five-second admission
default matches the emitter's default interceptor budget. These are
independent settings, not automatic deadline sharing. A shorter emitter
timeout still caps the combined wait and evaluation; standalone calls
retain a finite admission limit. Set a shorter admission timeout when
earlier rejection is preferable.

Admission uses elapsed time, including event-loop delays, through
submission of a queued call. A busy loop can consume the budget even
after a worker becomes free. Expired queued calls are not submitted.
Choose a budget that accounts for expected evaluation latency, queue
depth and host-loop work; a longer timeout does not create capacity.

All these denials are final (no approval). The three
`runtime_error:acs_async_*` reasons are reserved for the `sdk-adapter`
producer. ACS rejects policy output that tries to use them, so a
policy cannot impersonate these adapter failures.

`acs_point_unbound` remains an ordinary diagnostic label on an allow,
not a runtime error. A policy can return that label too; it does not
provide authenticated attribution for a scope bypass.

The read-only `control.in_flight`, `control.waiting`, and
`control.closed` properties expose current occupancy and whether closing
has started. Read them on the adapter's event loop; `closed` can be true
while active calls are draining. Eligible waiters receive slots in FIFO
order; new calls cannot overtake a waiter whose slot was just granted.
This is admission order, not execution or completion order across workers.
`waiting` excludes granted reservations, while `in_flight` counts
submitted calls, so their sum can briefly exclude reserved slots.
Configuration must use positive integer capacities and a finite positive
admission timeout.

The emitter timeout covers admission **and** the awaited evaluation.
Its expiry yields `host_error:interceptor_timeout`. Caller cancellation
propagates as cancellation. Neither cancels a running native call:
capacity stays occupied until that call actually returns. A timed-out
call's eventual verdict cannot authorize the abandoned action.

Use `async with` or `await control.aclose()`. Closing wakes queued
waiters and rejects new calls with `runtime_error:acs_async_closed`, drains active
work, and joins the executor without blocking the loop. Cancellation
of `aclose()` leaves cleanup running; await it again before closing the
loop. An operation that never returns can prevent draining and interpreter
exit indefinitely: the interpreter joins the executor's worker threads.
Even `shutdown(wait=False)` cannot forcibly stop a running native callback.
Do not create a replacement adapter per timeout: that would defeat the
capacity bound. An adapter belongs to one event loop. A direct cross-loop
call raises `AsyncAcsLoopMismatchError` (a `RuntimeError` subclass);
through the emitter it produces a recorded `host_error:interceptor_failed`
denial with that exception type as its message.
Prefer closing the adapter before the owning loop. If that loop has
already closed, call `control.close()` synchronously, or await
`control.aclose()` from a replacement loop. Both reject further work,
cancel native work that has not started, join running workers, and clear
the abandoned loop's bookkeeping after native completion. Late worker
exceptions are still reported by type. Recovery does not make evaluation
on another loop valid.

`close()` can block while native work finishes. Never call it while the
owning loop is still open, even if temporarily stopped; use that loop's
`aclose()` instead. Cancelling an `aclose()` recovery awaiter does not
stop its shutdown thread. Recovery cannot terminate a hung callback.

Context variables are copied to evaluation workers. Custom annotator,
policy, and telemetry callbacks must be thread-safe. Unexpected worker
exceptions are propagated to the awaiter and logged by exception type
only, including after timeout; payloads and exception messages are not
logged by the adapter. Context serialization happens before submission;
serialization errors reach the caller/emitter without occupying a worker.

Adapter denials and scope bypasses never enter the engine, so they
produce Agent Hooks records but no engine telemetry events. An abandoned
call can later emit an engine decision of `allow` even though the host
already denied it on timeout or cancellation. That event describes the
evaluation, not what the host enforced.

A sink may receive one session's decision events out of lifecycle order.
Engine telemetry has no session/sequence fields; use the Agent Hooks
record trail and its sequence numbers to reconstruct order and determine
what the host enforced.

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
