// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentControlSpec.ContentSafety;

/// <summary>
/// A value a model reported for one task over one segment of text.
/// </summary>
public readonly record struct TaskObservation
{
    private TaskObservation(BlockingCriterionKind kind, int severity, bool detected, double score)
    {
        ObservedKind = kind;
        SeverityValue = severity;
        DetectedValue = detected;
        ScoreValue = score;
    }

    /// <summary>Shape of the value this observation carries.</summary>
    public BlockingCriterionKind ObservedKind { get; }

    internal int SeverityValue { get; }

    internal bool DetectedValue { get; }

    internal double ScoreValue { get; }

    /// <summary>
    /// An integer severity, conventionally 0 through 7. Satisfies both a
    /// <see cref="BlockingCriterionKind.Severity"/> and a
    /// <see cref="BlockingCriterionKind.RiskLevel"/> criterion, because a risk
    /// level is a bucketing of this same number.
    /// </summary>
    public static TaskObservation Severity(int severity) =>
        new(BlockingCriterionKind.Severity, severity, false, 0d);

    /// <summary>A boolean detection flag.</summary>
    public static TaskObservation Detected(bool detected) =>
        new(BlockingCriterionKind.IsDetected, 0, detected, 0d);

    /// <summary>A floating point score.</summary>
    public static TaskObservation Score(double score) =>
        new(BlockingCriterionKind.Score, 0, false, score);
}

/// <summary>
/// Raised when a task is wired to a model output whose shape its criterion
/// cannot compare, or when configuration is otherwise unusable.
///
/// This is deliberately loud rather than a silent non match. A criterion that
/// cannot evaluate its observation has failed to govern the content, and
/// reporting that as "did not match" would permit the segment.
/// </summary>
public sealed class ContentSafetyConfigurationException : InvalidOperationException
{
    public ContentSafetyConfigurationException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// The comparison a task performs to decide whether its action applies.
///
/// The four shapes and their exact comparisons are ported from a streaming
/// content safety front door so an adapter reaches the same conclusion the
/// service would. Two behaviors are preserved deliberately even though they
/// are permissive, because an adapter that disagreed with the service would be
/// worse than one that matches it.
///
/// <list type="bullet">
/// <item>A criterion whose threshold is null never matches. Null comparisons
/// are false in the source, so an enabled criterion with no configured
/// threshold permits everything. <see cref="IsWellFormed"/> exposes this so a
/// caller can reject the configuration at load time rather than discover it
/// on a decision.</item>
/// <item>A disabled criterion never matches, whatever its thresholds say.</item>
/// </list>
/// </summary>
public sealed record BlockingCriterion
{
    /// <summary>Whether this criterion participates at all.</summary>
    public bool Enabled { get; init; }

    /// <summary>Which comparison to perform.</summary>
    public BlockingCriterionKind Kind { get; init; } = BlockingCriterionKind.Unspecified;

    /// <summary>Lowest severity that matches, for <see cref="BlockingCriterionKind.Severity"/>.</summary>
    public int? AllowedSeverity { get; init; }

    /// <summary>Lowest risk level that matches, for <see cref="BlockingCriterionKind.RiskLevel"/>.</summary>
    public RiskLevel? AllowedRiskLevel { get; init; }

    /// <summary>Lowest score that matches, for <see cref="BlockingCriterionKind.Score"/>.</summary>
    public double? AllowedScore { get; init; }

    /// <summary>
    /// Whether this criterion can ever match. An enabled criterion of a
    /// threshold kind whose threshold is null cannot, which is almost always a
    /// configuration mistake rather than an intent to permit everything.
    /// </summary>
    public bool IsWellFormed => !Enabled || Kind switch
    {
        BlockingCriterionKind.Severity => AllowedSeverity is not null,
        BlockingCriterionKind.RiskLevel => AllowedRiskLevel is not null,
        BlockingCriterionKind.Score => AllowedScore is not null,
        BlockingCriterionKind.IsDetected => true,
        _ => false,
    };

    /// <summary>
    /// Bucket an integer severity into a risk level.
    ///
    /// Ported exactly, so 0 and 1 are safe, 2 and 3 are low, 4 and 5 are
    /// medium, 6 and 7 are high, and anything else is unspecified.
    /// </summary>
    public static RiskLevel ToRiskLevel(int severity) => severity switch
    {
        0 or 1 => RiskLevel.Safe,
        2 or 3 => RiskLevel.Low,
        4 or 5 => RiskLevel.Medium,
        6 or 7 => RiskLevel.High,
        _ => RiskLevel.Unspecified,
    };

    /// <summary>Whether <paramref name="observation"/> triggers this criterion.</summary>
    public bool Matches(TaskObservation observation)
    {
        if (!Enabled)
        {
            return false;
        }

        switch (Kind)
        {
            case BlockingCriterionKind.Severity:
                RequireObservation(observation, BlockingCriterionKind.Severity);
                return AllowedSeverity is { } allowed && allowed <= observation.SeverityValue;

            case BlockingCriterionKind.RiskLevel:
                // A risk level criterion consumes the same integer severity and
                // buckets it before comparing.
                RequireObservation(observation, BlockingCriterionKind.Severity);
                return AllowedRiskLevel is { } allowedRisk
                    && allowedRisk <= ToRiskLevel(observation.SeverityValue);

            case BlockingCriterionKind.IsDetected:
                RequireObservation(observation, BlockingCriterionKind.IsDetected);
                // The criterion carries no stored value. Being enabled and of
                // this kind is the whole configuration; the model's flag is the
                // whole input.
                return observation.DetectedValue;

            case BlockingCriterionKind.Score:
                RequireObservation(observation, BlockingCriterionKind.Score);
                return AllowedScore is { } allowedScore && allowedScore <= observation.ScoreValue;

            default:
                return false;
        }
    }

    private void RequireObservation(TaskObservation observation, BlockingCriterionKind expected)
    {
        if (observation.ObservedKind != expected)
        {
            throw new ContentSafetyConfigurationException(
                $"a {Kind} criterion needs a {expected} observation but received {observation.ObservedKind}");
        }
    }
}
