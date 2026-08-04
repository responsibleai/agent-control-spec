// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Benchmark for the activated-policy surface.
//
// What it measures, and why those four things:
//
//   1. Cold start. Activation is deliberately the expensive call, so the
//      cost a host defers off its hot path is worth naming: activate()
//      on its own, then the first Evaluate against the fresh handle.
//   2. Warm per-Evaluate latency (p50/p95/p99). The steady state a
//      governed agent actually runs in.
//   3. Throughput at concurrency 32. The engine's policy handle is
//      Send + Sync and the wrapper adds no lock, so this says whether
//      that holds up under real contention.
//   4. Cold activation vs a warm cache hit. A host keyed on policy
//      version pays (1) once and (4) on every request afterwards.
//
// Workload: examples/bank_agent — a Rego bundle with eight bound
// intervention points and a recorded snapshot for each.
//
// Reproducing it is a single command; see bench/README.md.

using System.Collections.Concurrent;
using System.Diagnostics;
using AgentHooks;

namespace AgentControlSpec.Bench;

internal static class Program
{
    // Fixed so two runs are comparable. Warmup iterations are measured
    // and thrown away, never folded into a reported number.
    private const int WarmupPerPoint = 200;
    private const int MeasuredPerPoint = 2_000;
    private const int ColdActivations = 20;
    private const int CacheHits = 200_000;
    private const int Concurrency = 32;
    private const int ThroughputPerThread = 2_000;

    private static int Main(string[] args)
    {
        string exampleDir;
        try
        {
            exampleDir = args.Length > 0 ? Path.GetFullPath(args[0]) : DefaultExampleDir();
        }
        catch (DirectoryNotFoundException e)
        {
            Console.Error.WriteLine(e.Message);
            return 1;
        }

        // A manifest names its bundle relative to itself, so an
        // absolute manifest path is enough and the working directory of
        // whatever process hosts this is left alone.
        //
        // The bench variant, not manifest.yaml: every annotator type the
        // specification defines calls an HTTP endpoint, so under the
        // annotated manifest a binding-side evaluation fails closed at
        // annotation before the policy engine is reached, and this would
        // time the annotator error path instead of Rego evaluation. The
        // Node and Python benches use the same variant, which is what
        // makes the three sets of numbers comparable.
        // Named outright rather than probed for: falling back to the
        // annotated manifest is exactly how this benchmark previously
        // came to time the annotation error path while printing
        // plausible numbers.
        string Manifest = Path.Combine(exampleDir, "manifest.bench.yaml");

        var workload = Workload.Load(Path.Combine(exampleDir, "snapshots"));
        if (workload.Count == 0)
        {
            Console.Error.WriteLine($"no usable snapshots under {exampleDir}/snapshots");
            return 1;
        }

        // Refuses to report numbers for work that never reached the
        // policy: an evaluation that fails closed before Rego runs costs
        // about a tenth of a real decision.
        using (var probe = AcsPolicy.Activate(Manifest))
        {
            foreach (var (point, context) in workload.Cases)
            {
                var reason = probe.Evaluate(point, context).Reason;
                if (reason is not null
                    && reason.StartsWith("runtime_error", StringComparison.Ordinal))
                {
                    Console.Error.WriteLine(
                        $"{point.ToWireName()} fails closed with '{reason}' before reaching the "
                        + "policy; timing it would measure the error path.");
                    return 1;
                }
            }
        }

        Console.WriteLine("Agent Control Specification — .NET activated-policy benchmark");
        Console.WriteLine();
        Console.WriteLine($"  workload            {exampleDir}");
        Console.WriteLine($"  runtime             {Environment.Version}, "
            + $"{(Environment.Is64BitProcess ? "x64" : "x86")}, "
            + $"server GC {System.Runtime.GCSettings.IsServerGC}");
        Console.WriteLine($"  cores               {Environment.ProcessorCount}");
        Console.WriteLine($"  iterations          warmup {WarmupPerPoint}, measured "
            + $"{MeasuredPerPoint} per intervention point");
        Console.WriteLine();

        ColdStart(Manifest, workload);
        var policy = AcsPolicy.Activate(Manifest);
        using (policy)
        {
            WarmLatency(policy, workload);
            Throughput(policy, workload);
        }
        ActivationVsCacheHit(Manifest, workload);

        return 0;
    }

    // ---------------------------------------------------------------
    // 1. Cold start: activate(), then the first Evaluate on the fresh
    //    handle. The reachability probe has already activated once, so
    //    the JIT and the page cache are warm and these are lower than a
    //    host's true first call.
    // ---------------------------------------------------------------
    private static void ColdStart(string manifest, Workload workload)
    {
        var activateUs = Time(() => AcsPolicy.Activate(manifest), out var policy);
        using (policy)
        {
            Console.WriteLine("Cold start (after the reachability probe)");
            Console.WriteLine();
            Console.WriteLine("  stage                                        ms");
            Console.WriteLine("  ------------------------------------  ---------");
            Console.WriteLine($"  {"AcsPolicy.Activate()",-36}  {activateUs / 1000.0,9:F3}");

            foreach (var (point, context) in workload.Cases)
            {
                var us = Time(() => policy.Evaluate(point, context), out _);
                Console.WriteLine(
                    $"  {"first Evaluate(" + point.ToWireName() + ")",-36}  {us / 1000.0,9:F3}");
            }
            Console.WriteLine();
        }
    }

    // ---------------------------------------------------------------
    // 2. Warm per-Evaluate latency, per intervention point.
    // ---------------------------------------------------------------
    private static void WarmLatency(ActivatedPolicy policy, Workload workload)
    {
        Console.WriteLine("Warm Evaluate latency, single thread "
            + $"({MeasuredPerPoint} measured, {WarmupPerPoint} warmup discarded)");
        Console.WriteLine();
        Console.WriteLine("  intervention point        p50 us     p95 us     p99 us"
            + "     max us    mean us");
        Console.WriteLine("  --------------------  ----------  ---------  ---------"
            + "  ---------  ---------");

        var all = new List<double>(workload.Count * MeasuredPerPoint);
        foreach (var (point, context) in workload.Cases)
        {
            for (var i = 0; i < WarmupPerPoint; i++)
                policy.Evaluate(point, context);

            var samples = new double[MeasuredPerPoint];
            for (var i = 0; i < MeasuredPerPoint; i++)
                samples[i] = Time(() => policy.Evaluate(point, context), out _);

            all.AddRange(samples);
            Array.Sort(samples);
            Row(point.ToWireName(), samples);
        }

        var pooled = all.ToArray();
        Array.Sort(pooled);
        Console.WriteLine("  --------------------  ----------  ---------  ---------"
            + "  ---------  ---------");
        Row("all points", pooled);
        Console.WriteLine();

        static void Row(string label, double[] sorted) => Console.WriteLine(
            $"  {label,-20}  {Percentile(sorted, 0.50),10:F2}  {Percentile(sorted, 0.95),9:F2}"
            + $"  {Percentile(sorted, 0.99),9:F2}  {sorted[^1],9:F2}  {sorted.Average(),9:F2}");
    }

    // ---------------------------------------------------------------
    // 3. Throughput with one shared handle across 32 threads.
    // ---------------------------------------------------------------
    private static void Throughput(ActivatedPolicy policy, Workload workload)
    {
        // Warm every thread's view before the clock starts, so tiered
        // JIT promotion is not charged to the measurement.
        Parallel.For(0, Concurrency, new ParallelOptions { MaxDegreeOfParallelism = Concurrency },
            _ =>
            {
                foreach (var (point, context) in workload.Cases)
                    for (var i = 0; i < WarmupPerPoint / 4; i++)
                        policy.Evaluate(point, context);
            });

        var cases = workload.Cases;
        var latencies = new double[Concurrency][];
        var started = new Barrier(Concurrency + 1);
        var threads = new Thread[Concurrency];
        for (var t = 0; t < Concurrency; t++)
        {
            var slot = t;
            threads[t] = new Thread(() =>
            {
                var mine = new double[ThroughputPerThread];
                started.SignalAndWait();
                for (var i = 0; i < ThroughputPerThread; i++)
                {
                    var (point, context) = cases[(slot + i) % cases.Count];
                    mine[i] = Time(() => policy.Evaluate(point, context), out _);
                }
                latencies[slot] = mine;
            })
            { IsBackground = true };
            threads[t].Start();
        }

        started.SignalAndWait();
        var wall = Stopwatch.StartNew();
        foreach (var thread in threads)
            thread.Join();
        wall.Stop();

        var total = Concurrency * ThroughputPerThread;
        var pooled = latencies.SelectMany(x => x).ToArray();
        Array.Sort(pooled);

        Console.WriteLine($"Throughput at concurrency {Concurrency}, one shared handle "
            + $"({total:N0} evaluations)");
        Console.WriteLine();
        Console.WriteLine("  metric                            value");
        Console.WriteLine("  ----------------------  ---------------");
        Console.WriteLine($"  {"wall clock",-22}  {wall.Elapsed.TotalSeconds,12:F3} s");
        Console.WriteLine($"  {"throughput",-22}  {total / wall.Elapsed.TotalSeconds,12:N0} eval/s");
        Console.WriteLine($"  {"p50 latency",-22}  {Percentile(pooled, 0.50),12:F2} us");
        Console.WriteLine($"  {"p95 latency",-22}  {Percentile(pooled, 0.95),12:F2} us");
        Console.WriteLine($"  {"p99 latency",-22}  {Percentile(pooled, 0.99),12:F2} us");
        Console.WriteLine();
    }

    // ---------------------------------------------------------------
    // 4. Cold activation of the custom policy vs a warm cache hit.
    //
    //    Every activation is cold: the engine's compiled-policy cache
    //    lives inside the handle, so a second Activate() of the same
    //    manifest re-reads and re-compiles the bundle. The cache a host
    //    wants is therefore over handles, keyed by policy version —
    //    which is the pattern measured on the right-hand side.
    //
    //    Both paths are measured with the evaluation that follows them,
    //    separately from the acquisition itself. Activation claims to
    //    compile the bundle up front, and the only way to see whether it
    //    did is the first Evaluate on a fresh handle in a process where
    //    the .NET side is already warm — which is what "cold, first
    //    Evaluate" is. Read it against the "warm cache hit" Evaluate row.
    // ---------------------------------------------------------------
    private static void ActivationVsCacheHit(string manifest, Workload workload)
    {
        var (point, context) = workload.Cases[0];

        var cold = new double[ColdActivations];
        var coldFirstEval = new double[ColdActivations];
        for (var i = 0; i < ColdActivations; i++)
        {
            cold[i] = Time(() => AcsPolicy.Activate(manifest), out var policy);
            coldFirstEval[i] = Time(() => policy.Evaluate(point, context), out _);
            policy.Dispose();
        }

        var cache = new PolicyCache();
        for (var i = 0; i < 10_000; i++)
            cache.Get(manifest).Evaluate(point, context);

        var hit = new double[CacheHits];
        for (var i = 0; i < CacheHits; i++)
            hit[i] = Time(() => cache.Get(manifest), out _);

        var hitEval = new double[MeasuredPerPoint];
        var cached = cache.Get(manifest);
        for (var i = 0; i < MeasuredPerPoint; i++)
            hitEval[i] = Time(() => cached.Evaluate(point, context), out _);

        Array.Sort(cold);
        Array.Sort(coldFirstEval);
        Array.Sort(hit);
        Array.Sort(hitEval);

        Console.WriteLine("Custom-policy activation: cold vs warm cache hit");
        Console.WriteLine($"  ({ColdActivations} cold activations, {CacheHits:N0} cache hits, "
            + "10,000 discarded warmup hits; the .NET side is already warm here, so "
            + "these are engine costs)");
        Console.WriteLine();
        Console.WriteLine("  path                                        mean         p50"
            + "         p99");
        Console.WriteLine("  -----------------------------------  -----------  ----------"
            + "  ----------");
        Row("cold: Activate()", cold);
        Row($"cold: first Evaluate({point.ToWireName()})", coldFirstEval);
        Row("warm: cache hit (handle lookup)", hit);
        Row($"warm: Evaluate({point.ToWireName()})", hitEval);
        Console.WriteLine("  -----------------------------------  -----------  ----------"
            + "  ----------");
        Console.WriteLine($"  {"acquisition, cold / warm",-35}  {cold.Average() / hit.Average(),10:N0}x");
        Console.WriteLine($"  {"first evaluation, cold / warm",-35}"
            + $"  {coldFirstEval.Average() / hitEval.Average(),10:N2}x");
        Console.WriteLine();

        cache.Dispose();

        static void Row(string label, double[] sorted) => Console.WriteLine(
            $"  {label,-35}  {sorted.Average(),8:F3} us  {Percentile(sorted, 0.50),7:F3} us"
            + $"  {Percentile(sorted, 0.99),7:F3} us");
    }

    private static double Percentile(double[] sorted, double q)
    {
        // Nearest-rank. No interpolation: these are latencies, and an
        // interpolated p99 is a number no request ever saw.
        var rank = (int)Math.Ceiling(q * sorted.Length) - 1;
        return sorted[Math.Clamp(rank, 0, sorted.Length - 1)];
    }

    private static double Time<T>(Func<T> action, out T result)
    {
        var start = Stopwatch.GetTimestamp();
        result = action();
        return (Stopwatch.GetTimestamp() - start) * 1_000_000.0 / Stopwatch.Frequency;
    }

    private static string DefaultExampleDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "examples", "bank_agent");
            if (File.Exists(Path.Combine(candidate, "manifest.yaml")))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(
            "could not find examples/bank_agent above " + AppContext.BaseDirectory
            + "; pass the example directory as the first argument");
    }
}

/// <summary>
/// The handle cache a host would keep, keyed by policy version. Stands
/// in for that here so the cache-hit column measures a real lookup.
/// </summary>
internal sealed class PolicyCache : IDisposable
{
    private readonly ConcurrentDictionary<string, Lazy<ActivatedPolicy>> _entries = new();

    public ActivatedPolicy Get(string manifestPath) =>
        _entries.GetOrAdd(
            manifestPath,
            path => new Lazy<ActivatedPolicy>(
                () => AcsPolicy.Activate(path), LazyThreadSafetyMode.ExecutionAndPublication))
            .Value;

    public void Dispose()
    {
        foreach (var entry in _entries.Values)
            if (entry.IsValueCreated)
                entry.Value.Dispose();
        _entries.Clear();
    }
}

/// <summary>The recorded snapshot for every point the example binds.</summary>
internal sealed class Workload
{
    private Workload(IReadOnlyList<(InterceptionPoint Point, string Context)> cases) =>
        Cases = cases;

    public IReadOnlyList<(InterceptionPoint Point, string Context)> Cases { get; }

    public int Count => Cases.Count;

    public static Workload Load(string snapshotDir)
    {
        // Ordered by the intervention point's position in an agent's
        // lifecycle rather than by filename, so the cold-start table
        // reads the way a session runs. `pre_tool_call.safe.json` is a
        // second snapshot for a point already covered; one per point
        // keeps the per-point rows comparable.
        var cases = new List<(InterceptionPoint, string)>();
        foreach (InterceptionPoint point in Enum.GetValues<InterceptionPoint>())
        {
            var path = Path.Combine(snapshotDir, point.ToWireName() + ".json");
            if (File.Exists(path))
                cases.Add((point, File.ReadAllText(path, System.Text.Encoding.UTF8)));
        }
        return new Workload(cases);
    }
}
