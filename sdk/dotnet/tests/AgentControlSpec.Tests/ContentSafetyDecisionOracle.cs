// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using AgentControlSpec.ContentSafety;

/// <summary>
/// Checks the ported decision logic against the service's own test expectations.
///
/// Every other test here compares this package against a model written in the
/// same session as the code, which cannot catch a shared misreading of the
/// service. These expectations were extracted from the service's own test
/// suite, so they are an independent oracle. A disagreement is a defect in this
/// port rather than a difference of opinion.
/// </summary>
internal static class ContentSafetyDecisionOracle
{
    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ContentSafetyDecisionOracle: {message}");
        }
    }

    private static string LocateFixture()
    {
        var directory = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && directory is not null; i++)
        {
            var candidate = Path.Combine(
                directory, "tests", "conformance", "streaming", "content-safety", "content-safety-decision-oracle.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = Path.GetDirectoryName(directory);
        }

        throw new FileNotFoundException("content-safety-decision-oracle.json not found");
    }

    private static ContentSafetyAction ParseAction(string name) => name switch
    {
        "(unset)" or "Unspecified" => ContentSafetyAction.Unspecified,
        "Annotate" => ContentSafetyAction.Annotate,
        "Block" => ContentSafetyAction.Block,
        "Hitl" => ContentSafetyAction.Hitl,
        "Retry" => ContentSafetyAction.Retry,
        _ => throw new InvalidOperationException($"unknown action {name}"),
    };

    private static ContentSafetyActionFlags ParseFlags(string name) => name switch
    {
        "None" => ContentSafetyActionFlags.None,
        "Annotate" => ContentSafetyActionFlags.Annotate,
        "Block" => ContentSafetyActionFlags.Block,
        "Hitl" => ContentSafetyActionFlags.Hitl,
        "Retry" => ContentSafetyActionFlags.Retry,
        _ => throw new InvalidOperationException($"unknown flags {name}"),
    };

    private static BlockingCriterionKind ParseKind(string name) => name switch
    {
        "Severity" => BlockingCriterionKind.Severity,
        "RiskLevel" => BlockingCriterionKind.RiskLevel,
        "IsDetected" => BlockingCriterionKind.IsDetected,
        "Score" => BlockingCriterionKind.Score,
        _ => throw new InvalidOperationException($"unknown criterion kind {name}"),
    };

    public static Task RunAsync()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(LocateFixture()));
        var root = document.RootElement;

        var cases = 0;
        foreach (var entry in root.GetProperty("action_flags").EnumerateArray())
        {
            var test = entry.GetProperty("test").GetString()!;
            var kind = ParseKind(entry.GetProperty("criterion_kind").GetString()!);
            var enabled = entry.GetProperty("criterion_enabled").GetBoolean();
            var configured = ParseAction(entry.GetProperty("configured_action").GetString()!);
            var expected = ParseFlags(entry.GetProperty("expected_flags").GetString()!);
            var shouldMatch = entry.GetProperty("observation_matches").GetBoolean();

            var criterion = new BlockingCriterion { Enabled = enabled, Kind = kind };
            var observation = kind switch
            {
                BlockingCriterionKind.IsDetected => TaskObservation.Detected(shouldMatch),
                BlockingCriterionKind.Score => TaskObservation.Score(shouldMatch ? 1d : 0d),
                _ => TaskObservation.Severity(shouldMatch ? 7 : 0),
            };

            Assert(
                criterion.Matches(observation) == shouldMatch,
                $"{test}: the criterion did not match as the service's test arranges");

            var actual = ContentSafetyDecision.FromAction(configured);
            Assert(
                actual == expected,
                $"{test}: the service expects {expected} for a matched {kind} criterion with "
                + $"action {configured}, this port produced {actual}");
            cases++;
        }

        // Filtered is narrower than withheld, per the service's own comment.
        var filteredCases = 0;
        foreach (var entry in root.GetProperty("filtered_rule").GetProperty("cases").EnumerateArray())
        {
            var configured = ParseAction(entry.GetProperty("configured_action").GetString()!);
            var expectedFiltered = entry.GetProperty("filtered").GetBoolean();

            var flags = ContentSafetyDecision.FromAction(configured);
            var resolved = ContentSafetyDecision.Collapse(flags);
            var outcome = new ContentSafetyOutcome(
                resolved,
                flags,
                ContentSafetyDecision.ToSegmentOutcome(resolved),
                new[] { "t" },
                new[] { "t" });

            Assert(
                outcome.Filtered == expectedFiltered,
                $"action {configured} resolves to {resolved}, for which the service reports "
                + $"filtered={expectedFiltered}, this port reports {outcome.Filtered}");

            // Human review and retry withhold while reporting not filtered, which
            // is the distinction the rule exists to preserve.
            if (resolved is ContentSafetyAction.Hitl or ContentSafetyAction.Retry)
            {
                Assert(!outcome.Permits, $"{resolved} must withhold the segment");
                Assert(!outcome.Filtered, $"{resolved} must not report the segment as filtered");
            }

            filteredCases++;
        }

        Assert(cases > 0 && filteredCases > 0, "the oracle fixture produced no cases");
        Console.WriteLine(
            $"AgentControlSpec content safety decision oracle passed "
            + $"({cases} action flag cases, {filteredCases} filtered cases).");
        return Task.CompletedTask;
    }
}
