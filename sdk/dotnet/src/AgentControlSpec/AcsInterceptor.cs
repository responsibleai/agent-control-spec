// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Agent Control Specification — .NET wrapper.
//
// ACS is a stateless policy decision runtime that plugs into
// agent-hooks as an interceptor: a host registers AcsInterceptor with
// its agent-hooks emitter; on every emission the engine runs the
// manifest-bound evaluation pipeline (annotators -> policy dispatcher
// -> normalization) and returns the resulting verdict. Every failure
// path is fail-closed: a deny whose reason carries the engine's
// runtime_error:* namespace.
//
// The interception contract - points, context, verdicts, host
// obligations - is defined by AGENT-HOOKS-0.1 and consumed from the
// ResponsibleAI.AgentHooks package.

using System.Text.Json.Nodes;
using AgentHooks;

namespace AgentControlSpec;

/// <summary>Wraps the ACS engine as an agent-hooks interceptor.</summary>
public sealed class AcsInterceptor : IInterceptor, IDisposable
{
    private readonly IntPtr _handle;
    private bool _disposed;

    private AcsInterceptor(IntPtr handle) => _handle = handle;

    /// <summary>
    /// Build an interceptor from a manifest path using the zero-config
    /// dispatchers: bundled annotators; Rego policies in process,
    /// Cedar through the built-in evaluator, test policies through
    /// their embedded verdict. Custom policies require a host
    /// dispatcher and fail closed under this construction.
    /// </summary>
    public static AcsInterceptor FromPath(string manifestPath, string? name = null)
    {
        var interceptor = new AcsInterceptor(Native.InterceptorNew(manifestPath));
        if (name is not null)
            Native.SetName(interceptor._handle, name);
        return interceptor;
    }

    /// <summary>Payload-free identifier for the record's verdicts[].name.</summary>
    public string Name => Native.Name(_handle);

    /// <summary>
    /// Evaluate one agent context. Evaluation failures return a
    /// fail-closed deny verdict (runtime_error:* reason); this method
    /// throws only on boundary problems.
    /// </summary>
    public ValueTask<Verdict> InterceptAsync(AgentContext context, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var wire = Native.Intercept(_handle, context.Json.ToJsonString());
        var parsed = JsonNode.Parse(wire) as JsonObject
            ?? throw new AgentControlSpecNativeException("engine returned a non-object verdict");
        return ValueTask.FromResult(Verdict.FromWire(parsed));
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Native.Free(_handle);
    }
}
