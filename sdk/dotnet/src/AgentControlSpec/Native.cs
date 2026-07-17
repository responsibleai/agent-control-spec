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

internal static partial class Native
{
    private const string Lib = "agent_control_spec_ffi";

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr acs_interceptor_new(string manifestPath, out IntPtr errOut);

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
        var handle = acs_interceptor_new(manifestPath, out var err);
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

    internal static void Free(IntPtr handle) => acs_interceptor_free(handle);
}
