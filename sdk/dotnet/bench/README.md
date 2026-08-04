# .NET activated-policy benchmark

Measures the surface a host serving traffic against a pinned policy
version actually pays for: `AcsPolicy.Activate` once, `Evaluate` on
every agent action.

## Running it

One command, from `sdk/dotnet`:

```bash
cargo build --release -p agent-control-spec-ffi   # from the repo root, once
LD_LIBRARY_PATH=$PWD/../../target/release \
  dotnet run -c Release --project bench/AgentControlSpec.Bench
```

The workload defaults to `examples/bank_agent`, found by walking up from
the build output. Pass another example directory as the first argument
to point it elsewhere; it must contain `manifest.yaml` and a
`snapshots/<intervention_point>.json` for each point the manifest binds.

The benchmark passes the manifest by absolute path. A manifest names its
bundle relative to itself, so nothing depends on the working directory.

It uses `manifest.bench.yaml` rather than `manifest.yaml`. Every annotator
type the specification defines calls an HTTP endpoint, so under the
annotated manifest an evaluation through a binding fails closed at
annotation before the policy engine is reached: the numbers would be the
cost of the annotator error path, roughly an order of magnitude below a
real evaluation. The Node and Python benches use the same variant.

## What it reports

| Section | Question it answers |
| --- | --- |
| Cold start | What does the first of everything cost — `Activate()` on its own, then the first `Evaluate` per point? |
| Warm latency | p50/p95/p99/max/mean per `Evaluate`, per intervention point and pooled. |
| Throughput at concurrency 32 | Does one shared handle hold up under contention? |
| Cold vs warm cache hit | What a host saves by keying activated handles on policy version — acquisition and first evaluation, separately. |

The last section is measured after the .NET side is already warm, so it
reports engine cost rather than JIT. Its "cold: first Evaluate" row is
the check on activation's own promise: if activation really compiled the
bundle, a fresh handle's first evaluation is close to a warm one rather
than milliseconds away from it.

## Reproducibility

Iteration counts are compile-time constants at the top of `Program.cs`
(warmup 200 and 2,000 measured per point; 20 cold activations; 200,000
cache hits; 32 threads × 2,000 evaluations). Warmup iterations are
timed and discarded, never folded into a reported number. Percentiles
are nearest-rank with no interpolation, so every printed latency is one
a call actually saw.

Absolute numbers are machine-specific — treat the ratios between rows as
the durable result, not the microseconds.
