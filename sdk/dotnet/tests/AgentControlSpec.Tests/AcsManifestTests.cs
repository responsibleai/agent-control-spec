// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Grammar checks are reachable without building a runtime.

using Xunit;

namespace AgentControlSpec.Tests;

public sealed class AcsManifestTests
{
    private static readonly string Valid = File.ReadAllText(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "manifest.yaml"));

    // tests/AgentControlSpec.Tests/bin/Debug/net8.0 -> repository root
    private static readonly string RepoRoot =
        Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", ".."));

    [Fact]
    public void ValidManifestIsAccepted()
    {
        AcsManifest.Validate(Valid);
    }

    [Fact]
    public void UnsupportedVersionIsRejectedWithTheEngineMessage()
    {
        var source = Valid.Replace("\"0.4.0-alpha.1\"", "\"0.3.1-beta\"");
        var error = Assert.Throws<ManifestInvalidException>(() => AcsManifest.Validate(source));
        Assert.Contains("0.3.1-beta", error.Message);
    }

    [Fact]
    public void RetiredPolicyTargetRootIsRejected()
    {
        var source = Valid.Replace("\"$.input\"", "\"$policy_target.input\"");
        Assert.Throws<ManifestInvalidException>(() => AcsManifest.Validate(source));
    }

    [Fact]
    public void MalformedYamlIsRejected()
    {
        Assert.Throws<ManifestInvalidException>(
            () => AcsManifest.Validate("agent_control_specification_version: ["));
    }

    [Fact]
    public void InteriorNulDoesNotTruncateTheDocument()
    {
        // A NUL-terminated parameter would validate only the prefix and
        // call this acceptable, which is a fail-open.
        Assert.Throws<ManifestInvalidException>(
            () => AcsManifest.Validate(Valid + "\0garbage: ["));
    }

    [Fact]
    public void ALoneSurrogateIsABoundaryFailureNotABadManifest()
    {
        // Lossy encoding would substitute U+FFFD and have the engine
        // judge a document the caller never supplied.
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifest.Validate("\ud800"));
    }

    [Fact]
    public void ExtendsIsNotReportedAsAnInvalidManifest()
    {
        // The runtime loads this file fine; judging the child alone would
        // blame it for an annotator its parent defines.
        var child = Path.Combine(RepoRoot, "examples", "coding_agent", "manifest.yaml");
        var source = File.ReadAllText(child);
        var error = Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifest.Validate(source));
        Assert.Contains("extends", error.Message);
        AcsManifest.ValidateFile(child);
    }

    [Fact]
    public void AnInteriorNulInThePathIsRejected()
    {
        // Truncating would validate a different file than the one asked
        // about, and report success for it.
        var real = Path.Combine(RepoRoot, "examples", "coding_agent", "manifest.yaml");
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifest.ValidateFile(real + "\0/not/this/path.yaml"));
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsInterceptor.FromPath(real + "\0/not/this/path.yaml"));
    }

    [Fact]
    public void AnUnreadablePathIsNotReportedAsAnInvalidManifest()
    {
        // The document was never read, so its content was never judged.
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifest.ValidateFile("/nonexistent/typo.yaml"));
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifest.ValidateFile(AppContext.BaseDirectory));
    }

    [Fact]
    public void SupportedVersionsAreReportedRatherThanHardcoded()
    {
        var versions = AcsManifest.SupportedVersions();
        Assert.NotEmpty(versions);
        Assert.Contains(versions, v => Valid.Contains(v));
    }
}
