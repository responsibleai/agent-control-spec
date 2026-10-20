// Copyright (c) Microsoft. All rights reserved.

// The wrapper contract: manifest-bound evaluation surfaces as
// agent-hooks verdicts, fail-closed on every failure path, and the
// interceptor registers cleanly with an agent-hooks emitter.

using System.Diagnostics;
using System.Text.Json.Nodes;
using AgentHooks;
using Xunit;

namespace AgentControlSpec.Tests;

public sealed class AcsInterceptorTests
{
    private static readonly string Manifest =
        Path.Combine(AppContext.BaseDirectory, "fixtures", "manifest.yaml");

    private static AgentContextBuilder Builder() =>
        new(agentId: "a", framework: "test", sessionId: "s");

    [Fact]
    public async Task AllowPolicyPermitsInput()
    {
        using var acs = AcsInterceptor.FromPath(Manifest);
        var verdict = await acs.InterceptAsync(Builder().Input("hello"));
        Assert.Equal(Decision.Allow, verdict.Decision);
    }

    [Fact]
    public async Task DenyPolicyBlocksToolCallWithReason()
    {
        using var acs = AcsInterceptor.FromPath(Manifest);
        var ctx = Builder().PreToolCall("t1", "search", new JsonObject { ["q"] = "x" });
        var verdict = await acs.InterceptAsync(ctx);
        Assert.Equal(Decision.Deny, verdict.Decision);
        Assert.Equal("blocked_by_policy", verdict.Reason);
        Assert.Null(verdict.Approval);
    }

    [Fact]
    public async Task ApprovalCarryingDenyIsLiftable()
    {
        using var acs = AcsInterceptor.FromPath(Manifest);
        var verdict = await acs.InterceptAsync(Builder().Output("final answer"));
        Assert.Equal(Decision.Deny, verdict.Decision);
        Assert.Equal("requires_human", verdict.Reason);
        Assert.NotNull(verdict.Approval);
    }

    [Fact]
    public async Task DisposeIsIdempotentAndInterceptAfterItIsRejected()
    {
        var acs = AcsInterceptor.FromPath(Manifest);
        acs.Dispose();
        acs.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await acs.InterceptAsync(Builder().Input("hello")));
        Assert.Throws<ObjectDisposedException>(() => acs.Name);
    }

    [Fact]
    public async Task DisposeDuringConcurrentInterceptDoesNotFreeUnderACallInFlight()
    {
        // The failure this would catch is a use-after-free, which shows
        // up as a crashed test host rather than a failed assertion.
        var acs = AcsInterceptor.FromPath(Manifest);
        using var started = new CountdownEvent(8);

        var readers = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            started.Signal();
            for (var i = 0; i < 500; i++)
            {
                try
                {
                    await acs.InterceptAsync(Builder().Input("hello"));
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
            }
        })).ToArray();

        started.Wait();
        acs.Dispose();
        await Task.WhenAll(readers);
    }

    [Fact]
    public async Task EngineFailureFailsClosedAsRuntimeErrorDeny()
    {
        using var acs = AcsInterceptor.FromPath(Manifest);
        var b = Builder();
        b.PreToolCall("t1", "search", new JsonObject { ["q"] = "x" });
        var ctx = b.PostToolCall("t1", "search", new JsonObject { ["q"] = "x" }, "r");
        var verdict = await acs.InterceptAsync(ctx);
        Assert.Equal(Decision.Deny, verdict.Decision);
        Assert.StartsWith("runtime_error:", verdict.Reason);
    }

    [Fact]
    public void UnreadableManifestIsAConstructionError()
    {
        var ex = Assert.Throws<AgentControlSpecNativeException>(
            () => AcsInterceptor.FromPath("/nonexistent/manifest.yaml"));
        Assert.Contains("manifest", ex.Message);
    }

    // A custom policy answered by a host dispatcher: nothing is read from
    // disk during evaluation, so the directory can go once the interceptor
    // is built.
    private static string WriteBlockingManifest(string dir)
    {
        var manifest = Path.Combine(dir, "manifest.yaml");
        File.WriteAllText(manifest, """
            agent_control_specification_version: "0.4.0-alpha.1"
            policies:
              gate:
                type: custom
                adapter: host
            intervention_points:
              input:
                policy_target: "$.input"
                policy:
                  id: gate
            """);
        return manifest;
    }

    [Fact]
    public async Task CancellationStopsTheWaitNotTheEvaluation()
    {
        // The token ends the caller's wait. It cannot reach into native
        // code, so the dispatcher the engine is inside keeps running, the
        // interceptor stays alive under it, and the call finishes once the
        // dispatcher returns.
        var dir = Directory.CreateTempSubdirectory("acs-cancel").FullName;
        try
        {
            using var inDispatcher = new ManualResetEventSlim();
            using var release = new ManualResetEventSlim();
            using var finished = new ManualResetEventSlim();
            var calls = 0;
            var interceptor = AcsHostInterceptor.FromPath(
                WriteBlockingManifest(dir),
                policy: _ =>
                {
                    Interlocked.Increment(ref calls);
                    inDispatcher.Set();
                    release.Wait(TimeSpan.FromSeconds(10));
                    finished.Set();
                    return """{"decision":"allow"}""";
                });
            var ctx = Builder().Input("hello");

            // Cancel only once the dispatcher is known to be blocked, so
            // the test measures the wait ending and not a work item that
            // never started.
            using var cts = new CancellationTokenSource();
            var call = interceptor.InterceptAsync(ctx, cts.Token).AsTask();
            Assert.True(inDispatcher.Wait(TimeSpan.FromSeconds(10)), "the dispatcher never ran");
            var sw = Stopwatch.StartNew();
            cts.Cancel();
            var cancelled = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
            sw.Stop();

            Assert.Equal(cts.Token, cancelled.CancellationToken);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"cancellation took {sw.Elapsed}");
            Assert.False(finished.IsSet, "the dispatcher returned before the token fired");

            // A token already cancelled never reaches the engine.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await interceptor.InterceptAsync(ctx, new CancellationToken(canceled: true)));
            Assert.Equal(1, Volatile.Read(ref calls));

            release.Set();
            Assert.True(finished.Wait(TimeSpan.FromSeconds(10)), "the abandoned call did not finish");
            interceptor.Dispose();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void MaxConcurrencyMustBeAtLeastOne()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AcsInterceptor.FromPath(Manifest, maxConcurrency: 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AcsHostInterceptor.FromPath(Manifest, maxConcurrency: -1));
    }

    [Fact]
    public async Task RegistersWithAnAgentHooksEmitterEndToEnd()
    {
        // The agent-hooks emitter needs its own native library
        // (agent_hooks_ffi). The ResponsibleAI.AgentHooks package ships
        // it under runtimes/<rid>/native and the test host resolves it
        // through the package's deps.json, so the test runs wherever the
        // package restores. A missing library fails here with
        // DllNotFoundException instead of passing with the body skipped.
        using var acs = AcsInterceptor.FromPath(Manifest, name: "acs");
        var emitter = new InterceptionEmitter(EnforcementMode.Enforce);
        emitter.Register(acs, "acs");
        var b = Builder();

        var allowed = await emitter.EmitUncheckedAsync(b.Input("hello"));
        Assert.Equal(Decision.Allow, allowed.Verdict.Decision);

        var denied = await emitter.EmitUncheckedAsync(
            b.PreToolCall("t1", "search", new JsonObject { ["q"] = "x" }));
        Assert.Equal(Decision.Deny, denied.Verdict.Decision);
        Assert.Equal("blocked_by_policy", denied.Verdict.Reason);
        Assert.Equal(0, denied.DecidedBy);
        Assert.Equal("jcs-sha256", denied.IdentityProvider);
    }
}
