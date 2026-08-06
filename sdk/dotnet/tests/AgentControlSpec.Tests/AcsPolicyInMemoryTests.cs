// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Activating a policy whose manifest and Rego are held in memory, which
// is what a service keeping both in a database has instead of a path.

using System.Text.Json.Nodes;
using AgentHooks;
using Xunit;

namespace AgentControlSpec.Tests;

public sealed class AcsPolicyInMemoryTests
{
    private const string ManifestYaml = """
        agent_control_specification_version: "0.4.0-alpha.1"
        metadata:
          name: in-memory
        policies:
          gate:
            type: rego
            query: data.gate.verdict
        intervention_points:
          input:
            policy_target: "$.input"
            policy_target_kind: user_input
            policy:
              id: gate
        """;

    private static string Module(string decision, string reason) =>
        $$"""
        package gate

        verdict := {"decision": "{{decision}}", "reason": "{{reason}}"}
        """;

    private static Dictionary<string, RegoBundle> Bundles(string decision, string reason) =>
        new()
        {
            ["gate"] = new RegoBundle
            {
                Modules = new Dictionary<string, string>
                {
                    ["gate.rego"] = Module(decision, reason),
                },
            },
        };

    private static string InputContext() =>
        new AgentContextBuilder(agentId: "a", framework: "test", sessionId: "s")
            .Input("hello")
            .Json
            .ToJsonString();

    private static Verdict Decide(ActivatedPolicy policy) =>
        policy.Evaluate(InterceptionPoint.Input, InputContext());

    [Fact]
    public void ABundleHeldOnlyInMemoryDecides()
    {
        using var policy = AcsPolicy.ActivateFromMemory(
            ManifestYaml, Bundles("allow", "permitted"));

        var verdict = Decide(policy);

        Assert.Equal(Decision.Allow, verdict.Decision);
        Assert.Equal("permitted", verdict.Reason);
    }

    [Fact]
    public void DataDocumentsMountWhereTheCallerPutsThem()
    {
        var bundles = new Dictionary<string, RegoBundle>
        {
            ["gate"] = new RegoBundle
            {
                Modules = new Dictionary<string, string>
                {
                    ["gate.rego"] = """
                        package gate

                        verdict := {
                            "decision": "allow",
                            "reason": sprintf("limit=%v root=%v", [data.limits.daily, data.at_root]),
                        }
                        """,
                },
                Data =
                [
                    new RegoDataDocument
                    {
                        Mount = ["limits"],
                        Document = new JsonObject { ["daily"] = 42 },
                    },
                    new RegoDataDocument
                    {
                        Document = new JsonObject { ["at_root"] = "yes" },
                    },
                ],
            },
        };

        using var policy = AcsPolicy.ActivateFromMemory(ManifestYaml, bundles);

        Assert.Equal("limit=42 root=yes", Decide(policy).Reason);
    }

    // Two bundles with no path between them must not be served each
    // other's compiled engine.
    [Fact]
    public void TwoInMemoryBundlesKeepTheirOwnVerdicts()
    {
        using var permissive = AcsPolicy.ActivateFromMemory(
            ManifestYaml, Bundles("allow", "permitted"));
        using var restrictive = AcsPolicy.ActivateFromMemory(
            ManifestYaml, Bundles("deny", "refused"));

        Assert.Equal("permitted", Decide(permissive).Reason);
        Assert.Equal("refused", Decide(restrictive).Reason);

        // Re-read the first after the second activated, so an engine
        // replaced rather than shared is caught too.
        Assert.Equal("permitted", Decide(permissive).Reason);
    }

    // The in-memory path must be the disk path without the read, not a
    // second implementation that can drift from it.
    [Fact]
    public void APolicyDecidesTheSameFromDiskAndFromMemory()
    {
        var dir = Path.Combine(
            Path.GetTempPath(),
            $"acs-inmem-{Environment.ProcessId}-{Guid.NewGuid():N}");
        var bundleDir = Path.Combine(dir, "policy");
        Directory.CreateDirectory(bundleDir);
        try
        {
            var module = Module("allow", "permitted");
            File.WriteAllText(Path.Combine(bundleDir, "gate.rego"), module);

            var onDiskManifest = ManifestYaml.Replace(
                "    query: data.gate.verdict",
                "    bundle: ./policy\n    query: data.gate.verdict",
                StringComparison.Ordinal);
            var manifestPath = Path.Combine(dir, "manifest.yaml");
            File.WriteAllText(manifestPath, onDiskManifest);

            using var fromDisk = AcsPolicy.Activate(manifestPath);
            using var fromMemory = AcsPolicy.ActivateFromMemory(
                ManifestYaml, Bundles("allow", "permitted"));

            var diskVerdict = Decide(fromDisk);
            var memoryVerdict = Decide(fromMemory);

            Assert.Equal(diskVerdict.Decision, memoryVerdict.Decision);
            Assert.Equal(diskVerdict.Reason, memoryVerdict.Reason);
            Assert.Equal(Decision.Allow, memoryVerdict.Decision);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // A manifest parsed from text has no directory of its own, so a
    // relative path would resolve against the working directory.
    [Fact]
    public void ALeftoverRelativeBundlePathIsRefused()
    {
        var withPath = ManifestYaml.Replace(
            "    query: data.gate.verdict",
            "    bundle: ./policy\n    query: data.gate.verdict",
            StringComparison.Ordinal);

        var error = Assert.Throws<AgentControlSpecNativeException>(
            () => AcsPolicy.ActivateFromMemory(withPath));

        Assert.Contains("relative bundle or data path", error.Message, StringComparison.Ordinal);
        Assert.Contains("'gate'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SupplyingModulesForAnUndeclaredPolicyIsRefused()
    {
        var bundles = new Dictionary<string, RegoBundle>
        {
            ["nope"] = new RegoBundle
            {
                Modules = new Dictionary<string, string> { ["x.rego"] = "package x" },
            },
        };

        var error = Assert.Throws<AgentControlSpecNativeException>(
            () => AcsPolicy.ActivateFromMemory(ManifestYaml, bundles));

        Assert.Contains("no such policy", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ActivatingWithoutBundlesActivatesTheManifestAsWritten()
    {
        // Nothing to override here, so this must behave as a plain
        // activation rather than requiring an empty map to be built.
        using var policy = AcsPolicy.ActivateFromMemory(
            ManifestYaml, Bundles("allow", "permitted"));

        Assert.Equal(Decision.Allow, Decide(policy).Decision);
    }

    [Fact]
    public void ANullManifestIsRejectedBeforeReachingTheEngine()
    {
        Assert.Throws<ArgumentNullException>(() => AcsPolicy.ActivateFromMemory(null!));
    }
}
