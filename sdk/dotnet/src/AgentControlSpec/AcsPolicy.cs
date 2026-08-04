// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// One policy version, readied once and evaluated many times.
//
// AcsInterceptor answers "evaluate this agent context against a
// manifest", and readies the policy lazily on the first emission. A
// host that pins a policy version and serves traffic against it wants
// the opposite split: pay for reading and compiling the bundle once, at
// a moment of its choosing, then evaluate a named intervention point
// with nothing left to set up. That is what this surface is.
//
//     using var policy = AcsPolicy.Activate("manifest.yaml");
//     policy.Evaluate(InterceptionPoint.Input, contextJson);
//     policy.Evaluate(InterceptionPoint.PreToolCall, contextJson);

using System.Text.Json;
using System.Text.Json.Nodes;
using AgentHooks;

namespace AgentControlSpec;

/// <summary>Entry point for activating a policy version.</summary>
/// <remarks>
/// Activation is deliberately the expensive call and evaluation the
/// cheap one, so a host controls when a policy version changes rather
/// than discovering it mid-traffic.
/// </remarks>
public static class AcsPolicy
{
    /// <summary>
    /// Activates the manifest at <paramref name="manifestPath"/>,
    /// readying every policy it binds.
    /// </summary>
    /// <remarks>
    /// Reads the manifest, loads every policy bundle and data document,
    /// and compiles the entrypoint each intervention point queries. Do
    /// this once per policy version and keep the result;
    /// <see cref="ActivatedPolicy.Evaluate(InterceptionPoint, string)"/>
    /// then costs no I/O and no compile.
    /// <para>
    /// Compiling is bounded by the eval timeout. A policy too slow to
    /// compile in that window activates anyway, loaded but uncompiled,
    /// and pays compilation on its first decision instead.
    /// </para>
    /// <para>
    /// A manifest names its bundle relative to itself, so the path given
    /// here is the only thing that has to be right; the host's working
    /// directory does not matter.
    /// </para>
    /// </remarks>
    /// <param name="manifestPath">Path to the manifest.</param>
    /// <exception cref="AgentControlSpecNativeException">
    /// The manifest could not be read, parsed, or readied. The message is
    /// the engine's own.
    /// </exception>
    public static ActivatedPolicy Activate(string manifestPath)
    {
        ArgumentNullException.ThrowIfNull(manifestPath);
        return ActivatedPolicy.FromHandle(Native.PolicyActivate(manifestPath));
    }
}

/// <summary>An immutable, ready-to-evaluate policy version.</summary>
/// <remarks>
/// Safe to share across threads: evaluation holds no wrapper state, and
/// the engine's activated policy is itself immutable and concurrently
/// evaluable. Disposal is safe against evaluations already in flight
/// and safe to repeat.
/// </remarks>
public sealed class ActivatedPolicy : IDisposable
{
    private readonly ActivatedPolicyHandle _handle;
    private readonly IReadOnlyList<InterceptionPoint> _points;

    private ActivatedPolicy(ActivatedPolicyHandle handle)
    {
        _handle = handle;
        // Read once: the bound set is fixed for the life of a policy
        // version, so re-crossing the boundary per query would buy
        // nothing.
        _points = ReadInterventionPoints(handle);
    }

    internal static ActivatedPolicy FromHandle(ActivatedPolicyHandle handle)
    {
        try
        {
            return new ActivatedPolicy(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The intervention points this policy version binds. Use it to skip
    /// emitting points the policy does not govern.
    /// </summary>
    public IReadOnlyList<InterceptionPoint> InterventionPoints => _points;

    /// <summary>Whether this policy version governs <paramref name="point"/>.</summary>
    public bool Governs(InterceptionPoint point) => _points.Contains(point);

    /// <summary>
    /// Evaluates one intervention point against a context snapshot. This
    /// is the hot path.
    /// </summary>
    /// <remarks>
    /// Evaluation failures return a fail-closed deny verdict with a
    /// <c>runtime_error:*</c> reason; this method throws only on
    /// boundary problems. A point the policy does not bind is one such
    /// failure rather than an exception: it denies with
    /// <c>runtime_error:intervention_point_unknown</c>. Check
    /// <see cref="Governs"/> first if the host would rather not emit at
    /// all there.
    /// </remarks>
    /// <param name="point">The intervention point to evaluate.</param>
    /// <param name="contextJson">The agent context, as a JSON object.</param>
    /// <exception cref="ObjectDisposedException">The policy was disposed.</exception>
    /// <exception cref="AgentControlSpecNativeException">
    /// The context is not a JSON object, or the boundary failed.
    /// </exception>
    public Verdict Evaluate(InterceptionPoint point, string contextJson)
    {
        ArgumentNullException.ThrowIfNull(contextJson);
        ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
        var wire = Native.PolicyEvaluate(_handle, point.ToWireName(), contextJson);
        var parsed = JsonNode.Parse(wire) as JsonObject
            ?? throw new AgentControlSpecNativeException("engine returned a non-object verdict");
        return Verdict.FromWire(parsed);
    }

    /// <summary>
    /// Evaluates the intervention point the context declares.
    /// </summary>
    /// <param name="context">The agent context.</param>
    public Verdict Evaluate(AgentContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Evaluate(context.InterceptionPoint, context.Json.ToJsonString());
    }

    private static IReadOnlyList<InterceptionPoint> ReadInterventionPoints(
        ActivatedPolicyHandle handle)
    {
        var names = JsonSerializer.Deserialize<string[]>(
            Native.PolicyInterventionPoints(handle)) ?? [];
        var points = new List<InterceptionPoint>(names.Length);
        foreach (var name in names)
        {
            // A point this build of agent-hooks does not know is the
            // engine being ahead of the binding, not a corrupt manifest.
            try
            {
                points.Add(InterceptionPointExtensions.FromWireName(name));
            }
            catch (ArgumentException)
            {
                continue;
            }
        }
        return points;
    }

    public void Dispose() => _handle.Dispose();
}
