// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Host extension points and manifest tooling.
//
// The engine takes an annotator dispatcher, a policy dispatcher, a
// telemetry sink and a perf level. The zero-config constructors pick
// defaults for all four, which is right for a host that wants a policy
// decision and nothing else. A host that classifies through its own
// service, evaluates through its own engine, or records its own audit
// trail supplies them here.

using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using AgentHooks;

namespace AgentControlSpec;

/// <summary>How much timing detail the engine records.</summary>
public enum PerfTelemetry
{
    /// <summary>Record nothing.</summary>
    Off,

    /// <summary>Record the time spent outside the engine.</summary>
    External,

    /// <summary>Record every phase.</summary>
    Full,
}

/// <summary>One finding about a manifest.</summary>
/// <param name="Code">The engine's reason code.</param>
/// <param name="Message">What is wrong, in the engine's words.</param>
/// <param name="Severity">How bad it is.</param>
public sealed record ManifestDiagnostic(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("severity")] string Severity);

/// <summary>
/// Classifies one annotation on the host's behalf.
/// </summary>
/// <param name="annotatorName">The annotator the manifest bound.</param>
/// <param name="invocationJson">The binding's configured fields.</param>
/// <param name="policyInputJson">The policy input built so far.</param>
/// <returns>The annotation value as JSON.</returns>
/// <remarks>
/// Throwing fails the evaluation closed. An annotation that could not be
/// produced must not read as an annotation that found nothing.
/// </remarks>
public delegate string AnnotatorDispatcher(
    string annotatorName, string invocationJson, string policyInputJson);

/// <summary>Evaluates one prepared policy invocation on the host's behalf.</summary>
/// <param name="invocationJson">The prepared invocation, tagged by engine type.</param>
/// <returns>The policy output as JSON.</returns>
public delegate string PolicyDispatcher(string invocationJson);

/// <summary>Receives one telemetry event as JSON.</summary>
/// <remarks>A sink cannot fail an evaluation, so it has no error channel.</remarks>
public delegate void TelemetrySink(string eventJson);

/// <summary>Manifest reading and validation for authoring and tooling.</summary>
public static class AcsManifestTools
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Parse manifest text and return it as JSON. Parsing is not
    /// validation: this answers what the document says, which a tool
    /// needs before the document is runnable.
    /// </summary>
    public static string Parse(string yaml) => Native.ManifestParse(yaml);

    /// <summary>
    /// Compose a chain of manifest documents into one, outermost base
    /// first. This is the overlay case: a base policy plus the deltas an
    /// environment layers on it.
    /// </summary>
    public static string Merge(IEnumerable<string> yamls) =>
        Native.ManifestMerge(JsonSerializer.Serialize(yamls.ToArray()));

    /// <summary>
    /// Validate manifest text and return every finding. An empty list
    /// means valid.
    /// </summary>
    /// <remarks>
    /// <see cref="AcsManifest.Validate"/> answers yes or no by throwing,
    /// which a linter cannot render against a document. This returns the
    /// findings instead.
    /// </remarks>
    public static IReadOnlyList<ManifestDiagnostic> Diagnostics(string yaml) =>
        JsonSerializer.Deserialize<List<ManifestDiagnostic>>(Native.ManifestDiagnostics(yaml), Json)
        ?? throw new AgentControlSpecNativeException("diagnostics did not deserialize");

    /// <summary>
    /// Validate a manifest together with the Rego it names, and return
    /// every finding. An empty list means both halves are sound.
    /// </summary>
    /// <param name="manifestYaml">The manifest source.</param>
    /// <param name="bundles">
    /// Policy id to in-memory Rego bundle, the same shape
    /// <see cref="AcsPolicy.ActivateFromMemory"/> takes. Null means the
    /// manifest names no Rego, and the answer then equals
    /// <see cref="Diagnostics"/>.
    /// </param>
    /// <remarks>
    /// <see cref="Diagnostics"/> answers only for the document. A manifest
    /// can name a bundle, satisfy the grammar, and still fail at
    /// activation because the Rego does not compile. Compilation happens
    /// at activation, so this activates in memory and reports what that
    /// surfaced, which moves the failure from a host's first agent action
    /// to its CI.
    /// </remarks>
    public static IReadOnlyList<ManifestDiagnostic> ValidateArtifacts(
        string manifestYaml, string? bundles = null) =>
        JsonSerializer.Deserialize<List<ManifestDiagnostic>>(
            Native.ArtifactDiagnostics(manifestYaml, bundles), Json)
        ?? throw new AgentControlSpecNativeException("diagnostics did not deserialize");
}

/// <summary>
/// An interceptor wired to host-supplied extension points.
///
/// Anything left null keeps the bundled default for that slot, so a host
/// overrides only what it needs.
/// </summary>
/// <example>
/// <code>
/// using var interceptor = AcsHostInterceptor.FromPath(
///     "manifest.yaml",
///     annotator: (name, invocation, input) =&gt; Classify(input));
/// </code>
/// </example>
public sealed class AcsHostInterceptor : IInterceptor, IDisposable
{
    // The delegates are held so the GC cannot collect them while native
    // code still holds their function pointers. Dropping this field is
    // the classic way to turn a working callback into an intermittent
    // crash under load.
    private readonly List<Delegate> _pinned = [];
    private readonly IntPtr _handle;
    private bool _disposed;

    private AcsHostInterceptor(IntPtr handle) => _handle = handle;

    private delegate IntPtr NativeAnnotator(
        IntPtr ctx, IntPtr name, IntPtr invocation, IntPtr input, out IntPtr errOut);

    private delegate IntPtr NativePolicy(IntPtr ctx, IntPtr invocation, out IntPtr errOut);

    private delegate void NativeTelemetry(IntPtr ctx, IntPtr eventJson);

    private delegate void NativeFree(IntPtr ctx, IntPtr value);

    private static string Read(IntPtr p) => Marshal.PtrToStringUTF8(p) ?? string.Empty;

    /// <summary>Build an interceptor with host-supplied extension points.</summary>
    /// <param name="manifestPath">Manifest to load.</param>
    /// <param name="annotator">Host classifier, or null for the bundled annotators.</param>
    /// <param name="policy">Host policy engine, or null for the bundled dispatchers.</param>
    /// <param name="telemetry">Host telemetry sink, or null to record nothing.</param>
    /// <param name="perfTelemetry">How much timing detail to record.</param>
    public static AcsHostInterceptor FromPath(
        string manifestPath,
        AnnotatorDispatcher? annotator = null,
        PolicyDispatcher? policy = null,
        TelemetrySink? telemetry = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off)
    {
        var pinned = new List<Delegate>();

        // Freed by the native side through this callback, so the string a
        // host callback returns never crosses allocators.
        NativeFree free = (_, value) => Marshal.FreeCoTaskMem(value);
        pinned.Add(free);

        IntPtr annotatorPtr = IntPtr.Zero;
        if (annotator is not null)
        {
            NativeAnnotator shim = (IntPtr _, IntPtr name, IntPtr invocation, IntPtr input, out IntPtr err) =>
            {
                err = IntPtr.Zero;
                try
                {
                    return Marshal.StringToCoTaskMemUTF8(
                        annotator(Read(name), Read(invocation), Read(input)));
                }
                catch (Exception e)
                {
                    err = Marshal.StringToCoTaskMemUTF8(e.Message);
                    return IntPtr.Zero;
                }
            };
            pinned.Add(shim);
            annotatorPtr = Marshal.GetFunctionPointerForDelegate(shim);
        }

        IntPtr policyPtr = IntPtr.Zero;
        if (policy is not null)
        {
            NativePolicy shim = (IntPtr _, IntPtr invocation, out IntPtr err) =>
            {
                err = IntPtr.Zero;
                try
                {
                    return Marshal.StringToCoTaskMemUTF8(policy(Read(invocation)));
                }
                catch (Exception e)
                {
                    err = Marshal.StringToCoTaskMemUTF8(e.Message);
                    return IntPtr.Zero;
                }
            };
            pinned.Add(shim);
            policyPtr = Marshal.GetFunctionPointerForDelegate(shim);
        }

        IntPtr telemetryPtr = IntPtr.Zero;
        if (telemetry is not null)
        {
            NativeTelemetry shim = (IntPtr _, IntPtr payload) =>
            {
                // A sink that throws must not fail the action it merely
                // describes, and an exception here would cross the
                // native boundary.
                try
                {
                    telemetry(Read(payload));
                }
                catch
                {
                    // Intentionally swallowed: see above.
                }
            };
            pinned.Add(shim);
            telemetryPtr = Marshal.GetFunctionPointerForDelegate(shim);
        }

        var handle = Native.InterceptorNewWithHooks(
            manifestPath,
            annotatorPtr, IntPtr.Zero,
            policyPtr, IntPtr.Zero,
            telemetryPtr, IntPtr.Zero,
            Marshal.GetFunctionPointerForDelegate(free),
            perfTelemetry.ToString().ToLowerInvariant());

        var interceptor = new AcsHostInterceptor(handle);
        interceptor._pinned.AddRange(pinned);
        return interceptor;
    }

    /// <summary>Evaluate one agent context.</summary>
    public ValueTask<Verdict> InterceptAsync(AgentContext context, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var wire = Native.Intercept(_handle, context.Json.ToJsonString());
        var parsed = System.Text.Json.Nodes.JsonNode.Parse(wire) as System.Text.Json.Nodes.JsonObject
            ?? throw new AgentControlSpecNativeException("engine returned a non-object verdict");
        return ValueTask.FromResult(Verdict.FromWire(parsed));
    }

    /// <summary>Release the native interceptor.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Native.Free(_handle);
        _pinned.Clear();
    }
}
