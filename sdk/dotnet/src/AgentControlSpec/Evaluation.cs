// Copyright (c) Microsoft. All rights reserved.

// The evaluation path shared by AcsInterceptor and AcsHostInterceptor.
// The native call runs on a thread of its own and the caller awaits it,
// so the agent-hooks emitter's timeout, or the caller's token, can end
// the wait on time; nothing here can interrupt native code, so what
// ends is the wait, not the evaluation. The decisions that follow from
// that are noted where they are made.

using System.Text.Json.Nodes;
using AgentHooks;

namespace AgentControlSpec;

internal sealed class Evaluation
{
    private readonly InterceptorHandle _handle;
    private readonly object _owner;
    private readonly int _maxConcurrency;
    private int _inFlight;
    private volatile bool _disposed;

    /// <param name="handle">The native interceptor.</param>
    /// <param name="owner">The wrapper, named by <see cref="ObjectDisposedException"/>.</param>
    /// <param name="maxConcurrency">Evaluations allowed in flight at once.</param>
    internal Evaluation(InterceptorHandle handle, object owner, int maxConcurrency)
    {
        CheckMaxConcurrency(maxConcurrency);
        _handle = handle;
        _owner = owner;
        _maxConcurrency = maxConcurrency;
    }

    internal InterceptorHandle Handle => _handle;

    internal static void CheckMaxConcurrency(int maxConcurrency) =>
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrency, 1);

    internal void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(_disposed || _handle.IsClosed, _owner);

    // Compare-and-swap rather than increment-then-check, so a caller that
    // races a call just finishing is never denied while a slot is free.
    private bool TryAdmit()
    {
        while (true)
        {
            var current = Volatile.Read(ref _inFlight);
            if (current >= _maxConcurrency)
                return false;
            if (Interlocked.CompareExchange(ref _inFlight, current + 1, current) == current)
                return true;
        }
    }

    /// <summary>
    /// Marks the wrapper disposed, then closes the handle. The flag is
    /// what refuses a later call: the handle reports closed only once
    /// its last reference is gone, and an abandoned evaluation holds one
    /// for as long as its dispatcher blocks.
    /// </summary>
    internal void Dispose()
    {
        _disposed = true;
        _handle.Dispose();
    }

    /// <exception cref="ObjectDisposedException">The wrapper was disposed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled.</exception>
    /// <exception cref="AgentControlSpecNativeException">A boundary problem, not a policy outcome.</exception>
    internal async ValueTask<Verdict> InterceptAsync(AgentContext context, CancellationToken ct)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();

        // Serialize on the caller's thread so a context that cannot be
        // serialized fails here, before any thread is taken.
        var json = context.Json.ToJsonString();

        // Admission is a counter, not a queue: a call past the cap is
        // denied at once with the reason spec/reserved-reasons.json
        // registers for the ACS async adapter, as the Node and Python
        // bindings do. Nothing else is minted here; a timeout is the
        // emitter's to record.
        if (!TryAdmit())
        {
            return Verdict.Deny(
                "runtime_error:acs_async_capacity_exceeded",
                $"ACS interceptor already has {_maxConcurrency} evaluation(s) in flight (maxConcurrency); this call was denied without evaluation");
        }

        // A thread of its own, not a pool thread: an abandoned call blocks
        // until its dispatchers return, and enough of them on the shared
        // pool would starve the continuation that fails closed on the
        // deadline. The token is deliberately not passed to the task; a
        // token there only stops a queued item from starting, and the
        // wait below is where cancellation takes effect. Native.Intercept
        // holds a DangerousAddRef for the whole call, so a Dispose that
        // races the abandoned call leaves the free to the call's own
        // release. Capacity returns before the task completes, so a
        // caller that sees the verdict can submit the next call.
        Task<string> work;
        try
        {
            work = Task.Factory.StartNew(
                () =>
                {
                    try
                    {
                        return Native.Intercept(_handle, json);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _inFlight);
                    }
                },
                CancellationToken.None,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default);
        }
        catch
        {
            // The thread never started, so nothing will give the slot back.
            Interlocked.Decrement(ref _inFlight);
            throw;
        }

        string wire;
        try
        {
            wire = await work.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Nobody will await the abandoned call. Observe a late fault so
            // it never surfaces as TaskScheduler.UnobservedTaskException.
            _ = work.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }

        var parsed = JsonNode.Parse(wire) as JsonObject
            ?? throw new AgentControlSpecNativeException("engine returned a non-object verdict");
        return Verdict.FromWire(parsed);
    }
}
