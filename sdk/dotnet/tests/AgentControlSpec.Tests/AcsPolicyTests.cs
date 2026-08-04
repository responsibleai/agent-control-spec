// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// The activated-policy contract: a policy version readied once, then
// evaluated by name, concurrently, until the host releases it.

using AgentHooks;
using Xunit;

namespace AgentControlSpec.Tests;

public sealed class AcsPolicyTests
{
    private static readonly string Manifest =
        Path.Combine(AppContext.BaseDirectory, "fixtures", "manifest.yaml");

    private static AgentContextBuilder Builder() =>
        new(agentId: "a", framework: "test", sessionId: "s");

    private static string Context(InterceptionPoint point)
    {
        var b = Builder();
        AgentContext ctx = point switch
        {
            InterceptionPoint.Input => b.Input("hello"),
            InterceptionPoint.Output => b.Output("final answer"),
            InterceptionPoint.PreToolCall =>
                b.PreToolCall("t1", "search", new System.Text.Json.Nodes.JsonObject { ["q"] = "x" }),
            InterceptionPoint.AgentStartup => b.AgentStartup(["search"]),
            _ => throw new ArgumentOutOfRangeException(nameof(point)),
        };
        return ctx.Json.ToJsonString();
    }

    [Fact]
    public void ActivateThenEvaluateReturnsAVerdict()
    {
        using var policy = AcsPolicy.Activate(Manifest);

        var allowed = policy.Evaluate(InterceptionPoint.Input, Context(InterceptionPoint.Input));
        Assert.Equal(Decision.Allow, allowed.Decision);

        var denied = policy.Evaluate(
            InterceptionPoint.PreToolCall, Context(InterceptionPoint.PreToolCall));
        Assert.Equal(Decision.Deny, denied.Decision);
        Assert.Equal("blocked_by_policy", denied.Reason);
    }

    [Fact]
    public void InterventionPointsAreTheOnesTheManifestBinds()
    {
        using var policy = AcsPolicy.Activate(Manifest);

        Assert.Equal(
            new[]
            {
                InterceptionPoint.Input,
                InterceptionPoint.PreToolCall,
                InterceptionPoint.PostToolCall,
                InterceptionPoint.Output,
            }.Order(),
            policy.InterventionPoints.Order());
        Assert.True(policy.Governs(InterceptionPoint.Input));
        Assert.False(policy.Governs(InterceptionPoint.AgentStartup));
    }

    [Fact]
    public void UnboundPointFailsClosedRatherThanThrowing()
    {
        using var policy = AcsPolicy.Activate(Manifest);

        var verdict = policy.Evaluate(
            InterceptionPoint.AgentStartup, Context(InterceptionPoint.AgentStartup));

        Assert.Equal(Decision.Deny, verdict.Decision);
        Assert.StartsWith("runtime_error:", verdict.Reason);
    }

    [Fact]
    public void UnreadableManifestIsAnActivationError()
    {
        var ex = Assert.Throws<AgentControlSpecNativeException>(
            () => AcsPolicy.Activate("/nonexistent/manifest.yaml"));
        Assert.Contains("manifest", ex.Message);
    }

    [Fact]
    public void DisposeIsIdempotentAndEvaluationAfterItIsRejected()
    {
        var policy = AcsPolicy.Activate(Manifest);
        policy.Dispose();
        policy.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => policy.Evaluate(InterceptionPoint.Input, Context(InterceptionPoint.Input)));
    }

    [Fact]
    public void ContextMustBeAJsonObject()
    {
        using var policy = AcsPolicy.Activate(Manifest);

        var ex = Assert.Throws<AgentControlSpecNativeException>(
            () => policy.Evaluate(InterceptionPoint.Input, "[]"));
        Assert.Contains("object", ex.Message);
    }

    [Fact]
    public void ConcurrentEvaluationIsSafeAndAgrees()
    {
        // The engine's activated policy is Send + Sync, so one handle
        // serves every thread. What this guards is the wrapper: no
        // shared mutable state, and no torn read of the handle.
        using var policy = AcsPolicy.Activate(Manifest);
        var input = Context(InterceptionPoint.Input);
        var toolCall = Context(InterceptionPoint.PreToolCall);

        const int Threads = 32;
        const int PerThread = 64;
        Parallel.For(0, Threads, new ParallelOptions { MaxDegreeOfParallelism = Threads }, _ =>
        {
            for (var i = 0; i < PerThread; i++)
            {
                Assert.Equal(
                    Decision.Allow,
                    policy.Evaluate(InterceptionPoint.Input, input).Decision);
                Assert.Equal(
                    Decision.Deny,
                    policy.Evaluate(InterceptionPoint.PreToolCall, toolCall).Decision);
            }
        });
    }

    [Fact]
    public async Task DisposeDuringConcurrentEvaluationDoesNotFreeUnderACallInFlight()
    {
        // The failure this would catch is a use-after-free, which shows
        // up as a crashed test host rather than a failed assertion.
        var policy = AcsPolicy.Activate(Manifest);
        var input = Context(InterceptionPoint.Input);
        using var started = new CountdownEvent(8);

        var readers = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            started.Signal();
            for (var i = 0; i < 500; i++)
            {
                try
                {
                    policy.Evaluate(InterceptionPoint.Input, input);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
            }
        })).ToArray();

        started.Wait();
        policy.Dispose();
        await Task.WhenAll(readers);
    }
}
