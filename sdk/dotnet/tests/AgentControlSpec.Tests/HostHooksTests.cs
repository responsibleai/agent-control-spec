// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Host extension points: the engine's own dispatchers, telemetry sink
// and perf level, reachable from .NET.
//
// The scenario is the one that blocked a real consumer on 0.3: a host
// classifier reached over HTTP, bound as an annotator, whose answer
// decides the verdict. Before these entry points there was no way to
// supply one from any language but Rust.

using System.Text.Json.Nodes;
using AgentControlSpec;
using AgentHooks;
using Xunit;

namespace AgentControlSpec.Tests;

public sealed class HostHooksTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("acs-hooks").FullName;

    private string WriteFixture()
    {
        var bundle = Path.Combine(_dir, "bundle");
        Directory.CreateDirectory(bundle);
        File.WriteAllText(Path.Combine(bundle, "policy.rego"), """
            package acs

            decision := {"decision": "deny", "reason": "unsafe_content"} if {
                input.annotations.content_safety.severity >= 4
            } else := {"decision": "allow"}
            """);

        var manifest = Path.Combine(_dir, "manifest.yaml");
        File.WriteAllText(manifest, """
            agent_control_specification_version: "0.4.0-alpha.1"
            metadata:
              name: host-hooks-test
            annotators:
              content_safety:
                type: classifier
            policies:
              gate:
                type: rego
                bundle: ./bundle
            intervention_points:
              input:
                policy_target: "$snap.input"
                annotations:
                  content_safety:
                    from: "$target"
                policy:
                  id: gate
                  query: data.acs.decision
            """);
        return manifest;
    }

    private static AgentContext Input(string text) =>
        new((JsonNode.Parse($$"""{"interception_point":"input","input":{{System.Text.Json.JsonSerializer.Serialize(text)}}}""")!).AsObject());

    [Fact]
    public async Task AHostClassifierDecidesTheVerdict()
    {
        var manifest = WriteFixture();
        var calls = 0;

        using var benign = AcsHostInterceptor.FromPath(
            manifest,
            annotator: (name, _, _) =>
            {
                calls++;
                Assert.Equal("content_safety", name);
                return """{"severity":1}""";
            });

        var allowed = await benign.InterceptAsync(Input("hello"));
        Assert.Equal(Decision.Allow, allowed.Decision);
        Assert.Equal(1, calls);

        using var harmful = AcsHostInterceptor.FromPath(
            manifest, annotator: (_, _, _) => """{"severity":7}""");

        var denied = await harmful.InterceptAsync(Input("hello"));
        Assert.Equal(Decision.Deny, denied.Decision);
        Assert.Equal("unsafe_content", denied.Reason);
    }

    [Fact]
    public async Task AClassifierThatFailsDeniesRatherThanFindingNothing()
    {
        var manifest = WriteFixture();

        using var broken = AcsHostInterceptor.FromPath(
            manifest,
            annotator: (_, _, _) => throw new InvalidOperationException("classifier unreachable"));

        var verdict = await broken.InterceptAsync(Input("hello"));

        // The point of the test: an unreachable classifier must not read
        // as a classifier that found nothing.
        Assert.Equal(Decision.Deny, verdict.Decision);
        Assert.Equal("runtime_error:annotation_failed", verdict.Reason);
    }

    [Fact]
    public async Task ATelemetrySinkSeesTheEvaluation()
    {
        var manifest = WriteFixture();
        var events = new List<string>();

        using var interceptor = AcsHostInterceptor.FromPath(
            manifest,
            annotator: (_, _, _) => """{"severity":1}""",
            telemetry: events.Add,
            perfTelemetry: PerfTelemetry.Full);

        await interceptor.InterceptAsync(Input("hello"));

        Assert.NotEmpty(events);
        Assert.Contains(events, e => e.Contains("intervention_point"));
    }

    [Fact]
    public async Task ASinkThatThrowsDoesNotFailTheAction()
    {
        var manifest = WriteFixture();

        using var interceptor = AcsHostInterceptor.FromPath(
            manifest,
            annotator: (_, _, _) => """{"severity":1}""",
            telemetry: _ => throw new InvalidOperationException("sink is down"));

        // A sink records what happened. It does not get a vote on it.
        var verdict = await interceptor.InterceptAsync(Input("hello"));
        Assert.Equal(Decision.Allow, verdict.Decision);
    }

    [Fact]
    public void ParseReadsAManifestWithoutRunningIt()
    {
        var json = AcsManifestTools.Parse("""
            agent_control_specification_version: "0.4.0-alpha.1"
            policies:
              p:
                type: test
            intervention_points:
              input:
                policy_target: "$.input"
                policy:
                  id: p
            """);

        Assert.Contains("intervention_points", json);
    }

    [Fact]
    public void ParseRejectsTextThatIsNotAManifest()
    {
        Assert.Throws<AgentControlSpecNativeException>(
            () => AcsManifestTools.Parse("this: [is not"));
    }

    [Fact]
    public void DiagnosticsNameTheProblemRatherThanThrowing()
    {
        var findings = AcsManifestTools.Diagnostics("""
            agent_control_specification_version: "0.4.0-alpha.1"
            metadata: {}
            """);

        var finding = Assert.Single(findings);
        Assert.Equal("error", finding.Severity);
        Assert.Contains("intervention point", finding.Message);
        Assert.StartsWith("runtime_error:", finding.Code);
    }

    [Fact]
    public void DiagnosticsAreEmptyForAValidManifest()
    {
        Assert.Empty(AcsManifestTools.Diagnostics("""
            agent_control_specification_version: "0.4.0-alpha.1"
            policies:
              p:
                type: test
            intervention_points:
              input:
                policy_target: "$.input"
                policy:
                  id: p
            """));
    }

    [Fact]
    public void MergeComposesABaseWithAnOverlay()
    {
        var merged = AcsManifestTools.Merge([
            """
            agent_control_specification_version: "0.4.0-alpha.1"
            policies:
              p:
                type: test
            intervention_points:
              input:
                policy_target: "$.input"
                policy:
                  id: p
            """,
            """
            agent_control_specification_version: "0.4.0-alpha.1"
            metadata:
              name: overlay-applied
            """,
        ]);

        Assert.Contains("overlay-applied", merged);
    }


    private const string RegoManifest = """
        agent_control_specification_version: "0.4.0-alpha.1"
        policies:
          gate:
            type: rego
            bundle: ./b
        intervention_points:
          input:
            policy_target: "$.input"
            policy:
              id: gate
              query: data.acs.decision
        """;

    [Fact]
    public void ArtifactValidationClearsAManifestWhoseRegoCompiles()
    {
        var bundles = """
            {"gate":{"modules":{"p.rego":"package acs\ndecision := {\"decision\":\"allow\"}\n"}}}
            """;

        Assert.Empty(AcsManifestTools.ValidateArtifacts(RegoManifest, bundles));
    }

    [Fact]
    public void ArtifactValidationCatchesRegoTheManifestCheckCannot()
    {
        var broken = """
            {"gate":{"modules":{"p.rego":"package acs\nthis is not rego at all ***\n"}}}
            """;

        // The manifest itself is sound, so the document check passes it.
        Assert.Empty(AcsManifestTools.Diagnostics(RegoManifest));

        // The Rego is not, and only activation finds that out.
        var finding = Assert.Single(AcsManifestTools.ValidateArtifacts(RegoManifest, broken));
        Assert.StartsWith("runtime_error:", finding.Code);
        Assert.Contains("p.rego", finding.Message);
    }

    [Fact]
    public void AManifestThatDoesNotParseIsReportedAsAManifestProblem()
    {
        var finding = Assert.Single(AcsManifestTools.ValidateArtifacts("this: [is not", null));

        // Naming this an activation failure would blame the wrong half.
        Assert.Contains("manifest", finding.Code);
    }

    [Fact]
    public void WithNoBundlesArtifactValidationAgreesWithTheManifestCheck()
    {
        const string Bad = """
            agent_control_specification_version: "0.4.0-alpha.1"
            metadata: {}
            """;

        Assert.Equal(
            AcsManifestTools.Diagnostics(Bad).Count,
            AcsManifestTools.ValidateArtifacts(Bad, null).Count);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
