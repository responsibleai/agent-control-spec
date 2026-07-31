// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Manifest grammar checks that do not require a runtime.

using System.Text.Json;

namespace AgentControlSpec;

/// <summary>Grammar checks over manifest source.</summary>
/// <remarks>
/// Authoring and migration tools need to know whether a manifest is
/// valid before any policy is runnable. Building an
/// <see cref="AcsInterceptor"/> would additionally require the bundled
/// dispatchers and, for Rego policies, an <c>opa</c> binary on PATH.
/// </remarks>
public static class AcsManifest
{
    /// <summary>Validates manifest source against the grammar.</summary>
    /// <param name="source">The manifest document.</param>
    /// <exception cref="ManifestInvalidException">
    /// The manifest was rejected. The message is the engine's own.
    /// </exception>
    /// <exception cref="AgentControlSpecNativeException">
    /// The manifest uses <c>extends</c>, so it cannot be judged from its
    /// own source. Use <see cref="ValidateFile"/>.
    /// </exception>
    public static void Validate(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        Native.ValidateManifest(source);
    }

    /// <summary>Validates a manifest file, resolving <c>extends</c> first.</summary>
    /// <remarks>
    /// Use this for a manifest that inherits. It reads from disk and may
    /// fetch URL <c>extends</c>, exactly as loading a runtime would.
    /// </remarks>
    /// <param name="path">Path to the manifest.</param>
    /// <exception cref="ManifestInvalidException">
    /// The merged manifest was rejected. The message is the engine's own.
    /// </exception>
    public static void ValidateFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        Native.ValidateManifestFile(path);
    }

    /// <summary>
    /// The manifest grammar versions this engine accepts. Read it rather
    /// than hardcoding the set; it moves with the engine.
    /// </summary>
    public static IReadOnlyList<string> SupportedVersions() =>
        JsonSerializer.Deserialize<string[]>(Native.SupportedManifestVersions()) ?? [];
}
