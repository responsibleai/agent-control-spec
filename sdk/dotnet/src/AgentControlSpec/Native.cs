// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// P/Invoke bindings for agent_control_spec_ffi (sdk/ffi).
//
// Boundary conventions mirror the library: fallible functions take an
// err_out pointer; on failure the return is null and err_out carries a
// message freed with acs_free_string. Evaluation failures never
// surface here — the engine normalizes them into fail-closed deny
// verdicts, so errors on this boundary mean construction or
// marshalling problems only.

using System.Runtime.InteropServices;

namespace AgentControlSpec;

/// <summary>Boundary failure from the native engine binding.</summary>
public sealed class AgentControlSpecNativeException(string message) : Exception(message);

/// <summary>A manifest failed grammar validation.</summary>
/// <remarks>
/// The message is the engine's own, which names the offending field.
/// </remarks>
public sealed class ManifestInvalidException(string message) : Exception(message);

internal static partial class Native
{
    private const string Lib = "agent_control_spec_ffi";

    [LibraryImport(Lib)]
    private static partial IntPtr acs_interceptor_new_ex(
        ReadOnlySpan<byte> manifestPath, nuint manifestPathLen, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial void acs_interceptor_set_name(IntPtr handle, string name, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_intercept(IntPtr handle, string contextJson, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial IntPtr acs_interceptor_name(IntPtr handle, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial void acs_interceptor_free(IntPtr handle);

    [LibraryImport(Lib)]
    private static partial void acs_free_string(IntPtr s);

    // Activated policy: one policy version readied once, evaluated many
    // times. Same err_out convention as the interceptor entry points.
    [LibraryImport(Lib)]
    private static partial IntPtr acs_policy_activate(
        ReadOnlySpan<byte> manifestPath, nuint manifestPathLen, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_policy_activate_from_memory(
        string manifestYaml, string? bundlesJson, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_policy_evaluate(
        IntPtr handle, string point, string contextJson, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial IntPtr acs_policy_intervention_points(IntPtr handle, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial void acs_policy_free(IntPtr handle);

    // Explicit byte length rather than a NUL-terminated string, because
    // manifest text may contain an interior NUL and stopping there would
    // validate only the prefix.
    [LibraryImport(Lib)]
    private static partial int acs_validate_manifest(
        ReadOnlySpan<byte> source, nuint sourceLen, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial IntPtr acs_supported_manifest_versions(out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial int acs_validate_manifest_file(
        ReadOnlySpan<byte> path, nuint pathLen, out IntPtr errOut);

    private static string TakeString(IntPtr s)
    {
        try
        {
            return Marshal.PtrToStringUTF8(s) ?? string.Empty;
        }
        finally
        {
            acs_free_string(s);
        }
    }

    private static void ThrowIfError(IntPtr errOut)
    {
        if (errOut != IntPtr.Zero)
            throw new AgentControlSpecNativeException(TakeString(errOut));
    }

    internal static IntPtr InterceptorNew(string manifestPath)
    {
        byte[] pathBytes;
        try
        {
            pathBytes = StrictUtf8.GetBytes(manifestPath);
        }
        catch (System.Text.EncoderFallbackException e)
        {
            throw new AgentControlSpecNativeException(
                $"manifestPath is not encodable as UTF-8: {e.Message}");
        }

        var handle = acs_interceptor_new_ex(pathBytes, (nuint)pathBytes.Length, out var err);
        ThrowIfError(err);
        if (handle == IntPtr.Zero)
            throw new AgentControlSpecNativeException("acs_interceptor_new returned no handle");
        return handle;
    }

    internal static void SetName(IntPtr handle, string name)
    {
        acs_interceptor_set_name(handle, name, out var err);
        ThrowIfError(err);
    }

    internal static string Intercept(IntPtr handle, string contextJson)
    {
        var verdict = acs_intercept(handle, contextJson, out var err);
        ThrowIfError(err);
        return TakeString(verdict);
    }

    internal static string Name(IntPtr handle)
    {
        var name = acs_interceptor_name(handle, out var err);
        ThrowIfError(err);
        return TakeString(name);
    }

    private const int ManifestValid = 0;
    private const int ManifestInvalid = 1;

    // Throwing rather than substituting U+FFFD. The library contract is
    // that invalid encoding is an explicit error and never lossily
    // converted; replacing a lone surrogate would have the engine judge
    // a document the caller never supplied.
    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static void ValidateManifest(string source)
    {
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(source);
        }
        catch (System.Text.EncoderFallbackException e)
        {
            throw new AgentControlSpecNativeException(
                $"source is not encodable as UTF-8: {e.Message}");
        }
        var code = acs_validate_manifest(bytes, (nuint)bytes.Length, out var err);
        var message = err != IntPtr.Zero ? TakeString(err) : null;

        switch (code)
        {
            case ManifestValid:
                return;
            case ManifestInvalid:
                throw new ManifestInvalidException(
                    message ?? "the engine rejected the manifest without a message");
            default:
                // The manifest was never judged, so this is a boundary
                // failure and must not be reported as a bad manifest.
                throw new AgentControlSpecNativeException(
                    message ?? "acs_validate_manifest failed without a message");
        }
    }

    internal static void ValidateManifestFile(string path)
    {
        byte[] pathBytes;
        try
        {
            pathBytes = StrictUtf8.GetBytes(path);
        }
        catch (System.Text.EncoderFallbackException e)
        {
            throw new AgentControlSpecNativeException(
                $"path is not encodable as UTF-8: {e.Message}");
        }

        var code = acs_validate_manifest_file(pathBytes, (nuint)pathBytes.Length, out var err);
        var message = err != IntPtr.Zero ? TakeString(err) : null;

        switch (code)
        {
            case ManifestValid:
                return;
            case ManifestInvalid:
                throw new ManifestInvalidException(
                    message ?? "the engine rejected the manifest without a message");
            default:
                throw new AgentControlSpecNativeException(
                    message ?? "acs_validate_manifest_file failed without a message");
        }
    }

    internal static string SupportedManifestVersions()
    {
        var json = acs_supported_manifest_versions(out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static void Free(IntPtr handle) => acs_interceptor_free(handle);

    internal static ActivatedPolicyHandle PolicyActivate(string manifestPath)
    {
        byte[] pathBytes;
        try
        {
            pathBytes = StrictUtf8.GetBytes(manifestPath);
        }
        catch (System.Text.EncoderFallbackException e)
        {
            throw new AgentControlSpecNativeException(
                $"manifestPath is not encodable as UTF-8: {e.Message}");
        }

        var raw = acs_policy_activate(pathBytes, (nuint)pathBytes.Length, out var err);
        // Take ownership before anything can throw, so a handle the
        // engine did return is never leaked by an error on the way out.
        var handle = new ActivatedPolicyHandle(raw);
        try
        {
            ThrowIfError(err);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        if (handle.IsInvalid)
            throw new AgentControlSpecNativeException("acs_policy_activate returned no handle");
        return handle;
    }

    internal static ActivatedPolicyHandle PolicyActivateFromMemory(
        string manifestYaml, string? bundlesJson)
    {
        var raw = acs_policy_activate_from_memory(manifestYaml, bundlesJson, out var err);
        // Ownership first, as above: an error raised on the way out must
        // not strand a handle the engine did return.
        var handle = new ActivatedPolicyHandle(raw);
        try
        {
            ThrowIfError(err);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        if (handle.IsInvalid)
        {
            throw new AgentControlSpecNativeException(
                "acs_policy_activate_from_memory returned no handle");
        }
        return handle;
    }

    // The ref-count pair is what makes concurrent evaluation safe against
    // a racing Dispose: the native pointer cannot be freed while a call
    // is in flight. The engine's own policy handle is Send + Sync, so
    // beyond that no lock is needed.
    internal static string PolicyEvaluate(
        ActivatedPolicyHandle handle, string point, string contextJson)
    {
        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            var verdict = acs_policy_evaluate(
                handle.DangerousGetHandle(), point, contextJson, out var err);
            ThrowIfError(err);
            return TakeString(verdict);
        }
        finally
        {
            if (added)
                handle.DangerousRelease();
        }
    }

    internal static string PolicyInterventionPoints(ActivatedPolicyHandle handle)
    {
        var added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            var json = acs_policy_intervention_points(handle.DangerousGetHandle(), out var err);
            ThrowIfError(err);
            return TakeString(json);
        }
        finally
        {
            if (added)
                handle.DangerousRelease();
        }
    }

    internal static void PolicyFree(IntPtr handle) => acs_policy_free(handle);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_stream_session_new(string configJson, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial void acs_stream_session_free(IntPtr handle);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long acs_stream_session_observe(
        IntPtr handle, string sourceType, uint runes, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long acs_stream_session_observe_text(
        IntPtr handle, string sourceType, string text, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int acs_stream_session_record_outcome(
        IntPtr handle, string task, string sourceType, uint start, uint end, string outcome, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int acs_stream_session_record_verdict(
        IntPtr handle, string task, string sourceType, uint start, uint end, string verdictJson, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long acs_stream_session_advance(IntPtr handle, string track, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long acs_stream_session_safe_offset(IntPtr handle, string track, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long acs_stream_session_pending(IntPtr handle, string track, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_stream_session_watermark(IntPtr handle, string track, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial IntPtr acs_stream_session_state(IntPtr handle, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial int acs_stream_session_end_of_payloads(IntPtr handle, out IntPtr errOut);

    [LibraryImport(Lib)]
    private static partial IntPtr acs_stream_session_finish(IntPtr handle, out IntPtr errOut);

    internal static StreamSessionHandle StreamSessionNew(string configJson)
    {
        var handle = acs_stream_session_new(configJson, out var err);
        if (handle == IntPtr.Zero)
        {
            ThrowIfError(err);
            throw new AgentControlSpecNativeException("stream session creation returned no handle");
        }

        return new StreamSessionHandle(handle);
    }

    internal static void StreamSessionFree(IntPtr handle) => acs_stream_session_free(handle);

    // A scalar query answers with the value, -1 for absent, or -2 for a
    // boundary failure. Absent is a real answer (a settled session has no
    // safe offset), so it becomes null rather than an exception.
    private static long? Scalar(long value, IntPtr err)
    {
        if (value == -2)
        {
            ThrowIfError(err);
            throw new AgentControlSpecNativeException("stream session call failed without a message");
        }

        return value == -1 ? null : value;
    }

    internal static int StreamObserve(StreamSessionHandle handle, string sourceType, uint runes)
    {
        var received = acs_stream_session_observe(handle.DangerousGetHandle(), sourceType, runes, out var err);
        return checked((int)Scalar(received, err)!.Value);
    }

    internal static int StreamObserveText(StreamSessionHandle handle, string sourceType, string text)
    {
        var received = acs_stream_session_observe_text(handle.DangerousGetHandle(), sourceType, text, out var err);
        return checked((int)Scalar(received, err)!.Value);
    }

    internal static void StreamRecordOutcome(
        StreamSessionHandle handle, string task, string sourceType, uint start, uint end, string outcome)
    {
        if (acs_stream_session_record_outcome(
                handle.DangerousGetHandle(), task, sourceType, start, end, outcome, out var err) != 0)
        {
            ThrowIfError(err);
            throw new AgentControlSpecNativeException("recording the outcome failed without a message");
        }
    }

    internal static void StreamRecordVerdict(
        StreamSessionHandle handle, string task, string sourceType, uint start, uint end, string verdictJson)
    {
        if (acs_stream_session_record_verdict(
                handle.DangerousGetHandle(), task, sourceType, start, end, verdictJson, out var err) != 0)
        {
            ThrowIfError(err);
            throw new AgentControlSpecNativeException("recording the verdict failed without a message");
        }
    }

    internal static int? StreamAdvance(StreamSessionHandle handle, string track)
    {
        var offset = acs_stream_session_advance(handle.DangerousGetHandle(), track, out var err);
        return (int?)Scalar(offset, err);
    }

    internal static int? StreamSafeOffset(StreamSessionHandle handle, string track)
    {
        var offset = acs_stream_session_safe_offset(handle.DangerousGetHandle(), track, out var err);
        return (int?)Scalar(offset, err);
    }

    internal static int StreamPending(StreamSessionHandle handle, string track)
    {
        var pending = acs_stream_session_pending(handle.DangerousGetHandle(), track, out var err);
        return checked((int)Scalar(pending, err)!.Value);
    }

    internal static string StreamWatermark(StreamSessionHandle handle, string track)
    {
        var json = acs_stream_session_watermark(handle.DangerousGetHandle(), track, out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static string StreamState(StreamSessionHandle handle)
    {
        var json = acs_stream_session_state(handle.DangerousGetHandle(), out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static void StreamEndOfPayloads(StreamSessionHandle handle)
    {
        if (acs_stream_session_end_of_payloads(handle.DangerousGetHandle(), out var err) != 0)
        {
            ThrowIfError(err);
            throw new AgentControlSpecNativeException("closing the payload stream failed without a message");
        }
    }

    internal static string StreamFinish(StreamSessionHandle handle)
    {
        var json = acs_stream_session_finish(handle.DangerousGetHandle(), out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    [LibraryImport(Lib)]
    private static partial IntPtr acs_interceptor_new_with_hooks(
        ReadOnlySpan<byte> manifestPath, nuint manifestPathLen,
        IntPtr annotatorFn, IntPtr annotatorCtx,
        IntPtr policyFn, IntPtr policyCtx,
        IntPtr telemetryFn, IntPtr telemetryCtx,
        IntPtr hookFree,
        IntPtr perfTelemetry,
        IntPtr limitsJson,
        out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_manifest_parse(string yaml, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_manifest_merge(string yamlsJson, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_manifest_diagnostics(string yaml, out IntPtr errOut);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_artifact_diagnostics(
        string manifestYaml, string? bundlesJson, out IntPtr errOut);

    internal static IntPtr InterceptorNewWithHooks(
        string manifestPath,
        IntPtr annotatorFn, IntPtr annotatorCtx,
        IntPtr policyFn, IntPtr policyCtx,
        IntPtr telemetryFn, IntPtr telemetryCtx,
        IntPtr hookFree,
        string? perfTelemetry,
        string? limitsJson)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(manifestPath);
        var perf = perfTelemetry is null
            ? IntPtr.Zero
            : Marshal.StringToCoTaskMemUTF8(perfTelemetry);
        var limits = limitsJson is null ? IntPtr.Zero : Marshal.StringToCoTaskMemUTF8(limitsJson);
        try
        {
            var handle = acs_interceptor_new_with_hooks(
                bytes, (nuint)bytes.Length,
                annotatorFn, annotatorCtx, policyFn, policyCtx,
                telemetryFn, telemetryCtx, hookFree, perf, limits, out var err);
            if (handle == IntPtr.Zero)
            {
                ThrowIfError(err);
                throw new AgentControlSpecNativeException("interceptor construction returned no handle");
            }

            return handle;
        }
        finally
        {
            if (perf != IntPtr.Zero)
                Marshal.FreeCoTaskMem(perf);
            if (limits != IntPtr.Zero)
                Marshal.FreeCoTaskMem(limits);
        }
    }

    internal static string ManifestParse(string yaml)
    {
        var json = acs_manifest_parse(yaml, out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static string ManifestMerge(string yamlsJson)
    {
        var json = acs_manifest_merge(yamlsJson, out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static string ManifestDiagnostics(string yaml)
    {
        var json = acs_manifest_diagnostics(yaml, out var err);
        ThrowIfError(err);
        return TakeString(json);
    }

    internal static string ArtifactDiagnostics(string manifestYaml, string? bundlesJson)
    {
        var json = acs_artifact_diagnostics(manifestYaml, bundlesJson, out var err);
        ThrowIfError(err);
        return TakeString(json);
    }
}

internal sealed class StreamSessionHandle : SafeHandle
{
    internal StreamSessionHandle(IntPtr handle)
        : base(IntPtr.Zero, ownsHandle: true) => SetHandle(handle);

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.StreamSessionFree(handle);
        return true;
    }
}

internal sealed class ActivatedPolicyHandle : SafeHandle
{
    internal ActivatedPolicyHandle(IntPtr handle)
        : base(IntPtr.Zero, ownsHandle: true) => SetHandle(handle);

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.PolicyFree(handle);
        return true;
    }
}
