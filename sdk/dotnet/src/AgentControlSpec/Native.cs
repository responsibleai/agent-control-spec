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
}
