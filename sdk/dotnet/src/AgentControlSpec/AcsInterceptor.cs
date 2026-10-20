// Copyright (c) Microsoft. All rights reserved.

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

using AgentHooks;

namespace AgentControlSpec;

/// <summary>Wraps the ACS engine as an agent-hooks interceptor.</summary>
public sealed class AcsInterceptor : IInterceptor, IDisposable
{
    /// <summary>
    /// Evaluations <see cref="InterceptAsync"/> may have in flight at once
    /// unless <see cref="FromPath"/> is given another cap. The Python
    /// async adapter uses the same default.
    /// </summary>
    public const int DefaultMaxConcurrency = 8;

    private readonly Evaluation _evaluation;

    private AcsInterceptor(InterceptorHandle handle, int maxConcurrency) =>
        _evaluation = new Evaluation(handle, this, maxConcurrency);

    /// <summary>
    /// Build an interceptor from a manifest path using the zero-config
    /// dispatchers: bundled annotators; Rego policies in process,
    /// Cedar through the built-in evaluator, test policies through
    /// their embedded verdict. Custom policies require a host
    /// dispatcher and fail closed under this construction.
    /// </summary>
    /// <param name="manifestPath">Manifest to load.</param>
    /// <param name="name">Payload-free identifier for the record's verdicts[].name, or null for the engine's.</param>
    /// <param name="maxConcurrency">
    /// Evaluations allowed in flight at once; a call past the cap is denied
    /// without evaluation. Must be at least 1.
    /// </param>
    public static AcsInterceptor FromPath(
        string manifestPath, string? name = null, int maxConcurrency = DefaultMaxConcurrency)
    {
        Evaluation.CheckMaxConcurrency(maxConcurrency);
        var interceptor = new AcsInterceptor(Native.InterceptorNew(manifestPath), maxConcurrency);
        if (name is not null)
            Native.SetName(interceptor._evaluation.Handle, name);
        return interceptor;
    }

    /// <summary>Payload-free identifier for the record's verdicts[].name.</summary>
    public string Name
    {
        get
        {
            _evaluation.ThrowIfDisposed();
            return Native.Name(_evaluation.Handle);
        }
    }

    /// <summary>
    /// Evaluate one agent context. Evaluation failures return a
    /// fail-closed deny verdict (runtime_error:* reason); this method
    /// throws only on boundary problems and on cancellation.
    /// </summary>
    /// <remarks>
    /// The engine runs on a thread of its own, so an awaiting agent-hooks
    /// emitter can enforce its timeout; cancelling <paramref name="ct"/>
    /// ends the wait, not the engine call, which runs on until every
    /// dispatcher returns. Once <c>maxConcurrency</c> evaluations are in
    /// flight, further calls return a deny with
    /// <c>runtime_error:acs_async_capacity_exceeded</c> without evaluating.
    /// </remarks>
    public ValueTask<Verdict> InterceptAsync(AgentContext context, CancellationToken ct = default) =>
        _evaluation.InterceptAsync(context, ct);

    /// <summary>
    /// Marks the interceptor closed. A call already in flight on another
    /// thread finishes first; the native free runs when the last such call
    /// returns. Later calls throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose() => _evaluation.Dispose();
}
