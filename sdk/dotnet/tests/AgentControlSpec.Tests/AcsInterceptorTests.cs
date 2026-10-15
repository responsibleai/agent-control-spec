// The wrapper contract: manifest-bound evaluation surfaces as
// agent-hooks verdicts, fail-closed on every failure path, and the
// interceptor registers cleanly with an agent-hooks emitter.

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
