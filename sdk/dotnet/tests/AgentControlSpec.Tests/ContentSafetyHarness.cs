// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentControlSpec;
using AgentControlSpec.ContentSafety;

/// <summary>
/// Harness for the content safety front door adapter.
///
/// The comparisons, the precedence order, the source folding, and the
/// watermark routing are ported from a streaming content safety service, so
/// these checks are written as fidelity assertions against that behavior
/// rather than as tests of a design chosen here. Where this adapter
/// deliberately diverges, the check names say so.
/// </summary>
internal static class ContentSafetyHarness
{
    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ContentSafetyHarness: {message}");
        }
    }

    private static TException Throws<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException error)
        {
            return error;
        }

        throw new InvalidOperationException($"ContentSafetyHarness: {message}");
    }

    private static ContentSafetyTask Task(
        string label,
        ContentSafetyAction action,
        BlockingCriterion criterion,
        params ContentSafetyAppliedSource[] appliesTo) =>
        new()
        {
            Label = label,
            Action = action,
            Criterion = criterion,
            AppliesTo = appliesTo,
        };

    private static BlockingCriterion Severity(int allowed) =>
        new() { Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = allowed };

    private static ContentSafetySession Session(params ContentSafetyTask[] tasks) =>
        ContentSafetySession.Create(new ContentSafetySessionOptions { Tasks = tasks });

    public static Task RunAsync()
    {
        SeverityCriterionComparesAtOrAbove();
        RiskLevelCriterionBucketsTheSameSeverity();
        IsDetectedCriterionCarriesNoStoredThreshold();
        ScoreCriterionComparesAtOrAbove();
        ADisabledCriterionNeverMatches();
        ANullThresholdNeverMatchesAndIsReportedMalformed();
        AMismatchedObservationIsRejectedNotTreatedAsNoMatch();
        UnsetActionOnAMatchFailsClosed();
        FlagsCollapseByStrictPrecedence();
        AnUnknownFlagBitIsRejected();
        NoMatchedTaskPermitsAndAnnotates();
        SourceFoldingMatchesTheService();
        WatermarkRoutingUsesTheRawSourceNotTheFoldedOne();
        AStalledTaskHoldsTheTrack();
        ABlockEndsTheSessionAndReleasesNothing();
        HitlAndRetryWithholdButKeepTheirAction();
        TracksAdvanceIndependently();
        WatermarkReturnsNegativeOneWhenItDoesNotAdvance();
        UnclearedResidueFailsClosedAtSettlement();
        AnUnconfiguredTrackNeverAdvances();
        DuplicateAndEmptyTaskLabelsAreRejected();
        RunesAreCountedAsScalarValues();
        TwoTasksAtDifferentOffsetsReleaseTheMinimum();
        OnlyPromptCompletionAndAllScopesGateRelease();
        ANonGatingScopeNeitherHoldsNorEvaluatesATrack();
        Console.WriteLine("AgentControlSpec content safety adapter tests passed.");
        return System.Threading.Tasks.Task.CompletedTask;
    }

    private static void SeverityCriterionComparesAtOrAbove()
    {
        var criterion = Severity(4);
        Assert(!criterion.Matches(TaskObservation.Severity(3)), "severity 3 is below the allowed 4");
        Assert(criterion.Matches(TaskObservation.Severity(4)), "severity 4 matches at the boundary");
        Assert(criterion.Matches(TaskObservation.Severity(7)), "severity 7 is above the allowed 4");
    }

    private static void RiskLevelCriterionBucketsTheSameSeverity()
    {
        foreach (var (severity, expected) in new[]
                 {
                     (0, RiskLevel.Safe), (1, RiskLevel.Safe),
                     (2, RiskLevel.Low), (3, RiskLevel.Low),
                     (4, RiskLevel.Medium), (5, RiskLevel.Medium),
                     (6, RiskLevel.High), (7, RiskLevel.High),
                 })
        {
            Assert(
                BlockingCriterion.ToRiskLevel(severity) == expected,
                $"severity {severity} buckets to {expected}");
        }

        Assert(
            BlockingCriterion.ToRiskLevel(9) == RiskLevel.Unspecified,
            "an out of range severity is unspecified");

        var criterion = new BlockingCriterion
        {
            Enabled = true,
            Kind = BlockingCriterionKind.RiskLevel,
            AllowedRiskLevel = RiskLevel.Medium,
        };
        Assert(!criterion.Matches(TaskObservation.Severity(3)), "low is below medium");
        Assert(criterion.Matches(TaskObservation.Severity(4)), "medium matches at the boundary");
        Assert(criterion.Matches(TaskObservation.Severity(6)), "high is above medium");
    }

    private static void IsDetectedCriterionCarriesNoStoredThreshold()
    {
        // The service tests only that the criterion is enabled and of this
        // kind. The model's flag is the entire input.
        var criterion = new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.IsDetected };
        Assert(criterion.Matches(TaskObservation.Detected(true)), "a detection matches");
        Assert(!criterion.Matches(TaskObservation.Detected(false)), "no detection does not match");
    }

    private static void ScoreCriterionComparesAtOrAbove()
    {
        var criterion = new BlockingCriterion
        {
            Enabled = true,
            Kind = BlockingCriterionKind.Score,
            AllowedScore = 0.8d,
        };
        Assert(!criterion.Matches(TaskObservation.Score(0.79d)), "0.79 is below the allowed 0.8");
        Assert(criterion.Matches(TaskObservation.Score(0.8d)), "0.8 matches at the boundary");
        Assert(criterion.Matches(TaskObservation.Score(0.95d)), "0.95 is above the allowed 0.8");
    }

    private static void ADisabledCriterionNeverMatches()
    {
        var criterion = new BlockingCriterion
        {
            Enabled = false,
            Kind = BlockingCriterionKind.Severity,
            AllowedSeverity = 0,
        };
        Assert(!criterion.Matches(TaskObservation.Severity(7)), "a disabled criterion never matches");
        Assert(criterion.IsWellFormed, "a disabled criterion is not malformed");
    }

    private static void ANullThresholdNeverMatchesAndIsReportedMalformed()
    {
        // Preserved from the service, where a null comparison is false. It is
        // surfaced as malformed so a caller can reject it at load time.
        var criterion = new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.Severity };
        Assert(!criterion.Matches(TaskObservation.Severity(7)), "a null threshold never matches");
        Assert(!criterion.IsWellFormed, "a null threshold is reported malformed");
    }

    private static void AMismatchedObservationIsRejectedNotTreatedAsNoMatch()
    {
        // A criterion that cannot compare its observation has failed to govern
        // the content. Reporting that as no match would permit the segment.
        var criterion = Severity(4);
        Throws<ContentSafetyConfigurationException>(
            () => criterion.Matches(TaskObservation.Detected(true)),
            "a severity criterion cannot consume a detection flag");
    }

    private static void UnsetActionOnAMatchFailsClosed()
    {
        Assert(
            ContentSafetyDecision.FromAction(ContentSafetyAction.Unspecified)
                == ContentSafetyActionFlags.Block,
            "an unset action on a matched criterion blocks");
        Assert(
            ContentSafetyDecision.FromAction((ContentSafetyAction)99)
                == ContentSafetyActionFlags.Block,
            "an unrecognised action on a matched criterion blocks");
    }

    private static void FlagsCollapseByStrictPrecedence()
    {
        var all = ContentSafetyActionFlags.Annotate
            | ContentSafetyActionFlags.Retry
            | ContentSafetyActionFlags.Hitl
            | ContentSafetyActionFlags.Block;
        Assert(ContentSafetyDecision.Collapse(all) == ContentSafetyAction.Block, "block wins over everything");
        Assert(
            ContentSafetyDecision.Collapse(all & ~ContentSafetyActionFlags.Block)
                == ContentSafetyAction.Hitl,
            "human in the loop wins over retry and annotate");
        Assert(
            ContentSafetyDecision.Collapse(
                ContentSafetyActionFlags.Annotate | ContentSafetyActionFlags.Retry)
                == ContentSafetyAction.Retry,
            "retry wins over annotate");
        Assert(
            ContentSafetyDecision.Collapse(ContentSafetyActionFlags.Annotate)
                == ContentSafetyAction.Annotate,
            "annotate alone collapses to annotate");
        Assert(
            ContentSafetyDecision.Collapse(ContentSafetyActionFlags.None)
                == ContentSafetyAction.Annotate,
            "no flags collapses to annotate");
    }

    private static void AnUnknownFlagBitIsRejected()
    {
        Throws<ContentSafetyConfigurationException>(
            () => ContentSafetyDecision.Collapse((ContentSafetyActionFlags)64),
            "an unrecognised flag bit is rejected rather than dropped");
    }

    private static void NoMatchedTaskPermitsAndAnnotates()
    {
        // The service starts its accumulator at annotate, so a segment no task
        // matched is permitted rather than withheld.
        Assert(
            ContentSafetyDecision.Initial == ContentSafetyActionFlags.Annotate,
            "the accumulator starts at annotate");

        var session = Session(Task("harm", ContentSafetyAction.Block, Severity(4)));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "safe text");
        var outcome = session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            9,
            new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(1) });
        Assert(outcome.Permits, "a severity below the threshold permits");
        Assert(outcome.Action == ContentSafetyAction.Annotate, "and reports annotate");
        Assert(outcome.MatchedTasks.Count == 0, "with no matched tasks");
        Assert(session.TryAdvanceWatermark(StreamTrack.Response) == 9, "the watermark advances");
    }

    private static void SourceFoldingMatchesTheService()
    {
        var unset = ContentSafetySource.Unknown;
        Assert(
            ContentSafetySourceMapping.Resolve(unset, ContentSafetyTextKind.Context)
                == ContentSafetySource.ModelGenerated,
            "context folds into model generated");
        Assert(
            ContentSafetySourceMapping.Resolve(unset, ContentSafetyTextKind.ConcatAll)
                == ContentSafetySource.UserRequest,
            "a concatenated history folds into the request");
        Assert(
            ContentSafetySourceMapping.Resolve(unset, ContentSafetyTextKind.Unspecified)
                == ContentSafetySource.ModelGenerated,
            "an unrecognised kind folds to model generated");
        Assert(
            ContentSafetySourceMapping.Resolve(ContentSafetySource.Context, ContentSafetyTextKind.Unspecified)
                == ContentSafetySource.ModelGenerated,
            "a set context source also folds into model generated");
        Assert(
            ContentSafetySourceMapping.Resolve(ContentSafetySource.PreToolCall, ContentSafetyTextKind.Unspecified)
                == ContentSafetySource.PreToolCall,
            "a tool role survives folding");
        Assert(
            ContentSafetySourceMapping.IsRequestRole(ContentSafetySource.PostRun),
            "the run roles group with the request for applicability");
    }

    private static void WatermarkRoutingUsesTheRawSourceNotTheFoldedOne()
    {
        // The divergence this adapter preserves. The service folds a
        // concatenated history into the request for the purpose of deciding
        // which tasks apply, but routes its offsets by the raw source, so the
        // same payload counts on the completion track.
        Assert(
            ContentSafetySourceMapping.Resolve(ContentSafetySource.ConcatAll, ContentSafetyTextKind.Unspecified)
                == ContentSafetySource.UserRequest,
            "a concatenated history resolves to the request role");
        Assert(
            ContentSafetySourceMapping.WatermarkTrack(ContentSafetySource.ConcatAll) == StreamTrack.Response,
            "but its runes count on the response track");
        Assert(
            ContentSafetySourceMapping.WatermarkTrack(ContentSafetySource.UserRequest) == StreamTrack.Request,
            "only a literal request source advances the request track");
        foreach (var source in new[]
                 {
                     ContentSafetySource.PreToolCall, ContentSafetySource.PostToolCall,
                     ContentSafetySource.PreRun, ContentSafetySource.PostRun,
                     ContentSafetySource.Context, ContentSafetySource.Unknown,
                 })
        {
            Assert(
                ContentSafetySourceMapping.WatermarkTrack(source) == StreamTrack.Response,
                $"{source} counts on the response track despite its applicability role");
        }
    }

    private static void AStalledTaskHoldsTheTrack()
    {
        var session = Session(
            Task("harm", ContentSafetyAction.Block, Severity(4)),
            Task("pii", ContentSafetyAction.Block, new BlockingCriterion
            {
                Enabled = true,
                Kind = BlockingCriterionKind.IsDetected,
            }));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "0123456789");

        // Only one of the two tasks reports.
        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            10,
            new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(1) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "a task that never reported holds the whole track");

        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            10,
            new Dictionary<string, TaskObservation> { ["pii"] = TaskObservation.Detected(false) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == 10,
            "the track advances once every task has reported");
    }

    private static void ABlockEndsTheSessionAndReleasesNothing()
    {
        var session = Session(Task("harm", ContentSafetyAction.Block, Severity(4)));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "bad text");
        var outcome = session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            8,
            new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(6) });
        Assert(!outcome.Permits, "a matched block refuses");
        Assert(outcome.Action == ContentSafetyAction.Block, "and reports block");
        Assert(outcome.MatchedTasks.Count == 1 && outcome.MatchedTasks[0] == "harm", "naming the task");
        Assert(session.IsEnded, "the session is terminal");
        Assert(session.SafeOffset(StreamTrack.Response) is null, "nothing was released");
        var settlement = session.Finish();
        Assert(!settlement.Clean, "the stream does not settle clean");
        Assert(settlement.Action == ContentSafetyAction.Block, "settlement reports block");
    }

    private static void HitlAndRetryWithholdButKeepTheirAction()
    {
        foreach (var action in new[] { ContentSafetyAction.Hitl, ContentSafetyAction.Retry })
        {
            var session = Session(Task("harm", action, Severity(4)));
            session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "text");
            var outcome = session.RecordSegment(
                ContentSafetySource.ModelGenerated,
                0,
                4,
                new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(5) });
            Assert(!outcome.Permits, $"{action} withholds the segment");
            Assert(outcome.Action == action, $"{action} survives on the outcome rather than becoming a bare block");
            Assert(session.SafeOffset(StreamTrack.Response) is null, $"{action} releases nothing");
        }
    }

    private static void TracksAdvanceIndependently()
    {
        var session = Session(
            Task("jailbreak", ContentSafetyAction.Block, Severity(4), ContentSafetyAppliedSource.Prompt),
            Task("harm", ContentSafetyAction.Block, Severity(4), ContentSafetyAppliedSource.Completion));
        session.OnPayload(ContentSafetySource.UserRequest, ContentSafetyTextKind.Unspecified, "prompt");
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "completion");

        session.RecordSegment(
            ContentSafetySource.UserRequest,
            0,
            6,
            new Dictionary<string, TaskObservation> { ["jailbreak"] = TaskObservation.Severity(0) });
        Assert(session.TryAdvanceWatermark(StreamTrack.Request) == 6, "the request track advances");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "clearing one track releases nothing on the other");
    }

    private static void WatermarkReturnsNegativeOneWhenItDoesNotAdvance()
    {
        // The service's sentinel for no progress, so a caller emits a
        // watermark message only on real movement.
        var session = Session(Task("harm", ContentSafetyAction.Block, Severity(4)));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "0123456789");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "nothing cleared yet reports no progress");
        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            4,
            new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(0) });
        Assert(session.TryAdvanceWatermark(StreamTrack.Response) == 4, "real progress reports the offset");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "asking again without progress reports no progress");
    }

    private static void UnclearedResidueFailsClosedAtSettlement()
    {
        // A divergence this adapter makes deliberately. The service's
        // watermark simply stalls on unevaluated text; here it is a fail
        // closed settlement.
        var session = Session(Task("harm", ContentSafetyAction.Block, Severity(4)));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "0123456789");
        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            4,
            new Dictionary<string, TaskObservation> { ["harm"] = TaskObservation.Severity(0) });
        session.EndOfPayloads();
        var settlement = session.Finish();
        Assert(!settlement.Clean, "unevaluated text does not settle clean");
        Assert(settlement.Action == ContentSafetyAction.Block, "and reports block");
        Assert(settlement.Reason is StreamEndReason.Failed, "with a failed reason");
    }

    private static void AnUnconfiguredTrackNeverAdvances()
    {
        // Every task is request scoped, so the response track has no task.
        var session = Session(
            Task("jailbreak", ContentSafetyAction.Block, Severity(4), ContentSafetyAppliedSource.Prompt));
        session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, "completion");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "a track no task evaluates never advances");
        session.EndOfPayloads();
        Assert(!session.Finish().Clean, "and its text is uncleared residue at settlement");
    }

    private static void DuplicateAndEmptyTaskLabelsAreRejected()
    {
        Throws<ContentSafetyConfigurationException>(
            () => Session(
                Task("harm", ContentSafetyAction.Block, Severity(4)),
                Task("harm", ContentSafetyAction.Annotate, Severity(2))),
            "a duplicate task label is rejected");
        Throws<ContentSafetyConfigurationException>(
            () => Session(Task(string.Empty, ContentSafetyAction.Block, Severity(4))),
            "an empty task label is rejected");
        Throws<ContentSafetyConfigurationException>(
            () => ContentSafetySession.Create(
                new ContentSafetySessionOptions { Tasks = Array.Empty<ContentSafetyTask>() }),
            "a session with no tasks is rejected");
    }

    private static void TwoTasksAtDifferentOffsetsReleaseTheMinimum()
    {
        // The worked example from the integration design review. Two tasks
        // report independent offsets over one response stream and the released
        // offset is the smaller of them.
        var session = Session(
            Task("Hate", ContentSafetyAction.Block, Severity(4)),
            Task("JB", ContentSafetyAction.Block, Severity(4)));
        session.OnPayload(ContentSafetySource.ModelGenerated, 1200);
        Assert(session.SafeOffset(StreamTrack.Response) == 0, "the stream starts at offset 0");

        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            1000,
            new Dictionary<string, TaskObservation> { ["Hate"] = TaskObservation.Severity(0) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == -1,
            "Hate reaching 1000 releases nothing while JB is still at 0");

        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            500,
            new Dictionary<string, TaskObservation> { ["JB"] = TaskObservation.Severity(0) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == 500,
            "JB reaching 500 releases 500, the minimum across the two tasks");

        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            500,
            1200,
            new Dictionary<string, TaskObservation> { ["JB"] = TaskObservation.Severity(0) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == 1000,
            "JB overtaking Hate moves the minimum to Hate at 1000");

        session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            1000,
            1200,
            new Dictionary<string, TaskObservation> { ["Hate"] = TaskObservation.Severity(0) });
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == 1200,
            "both tasks cleared releases the whole stream");
        session.EndOfPayloads();
        Assert(session.Finish().Clean, "the stream settles clean");
    }

    private static void OnlyPromptCompletionAndAllScopesGateRelease()
    {
        // The front door builds one watermark per track and registers a task on
        // it only when the task's scope equals that watermark's scope or is all.
        Assert(
            ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.All, StreamTrack.Request)
                && ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.All, StreamTrack.Response),
            "the all scope gates both tracks");
        Assert(
            ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.Prompt, StreamTrack.Request)
                && !ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.Prompt, StreamTrack.Response),
            "the prompt scope gates the request track only");
        Assert(
            ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.Completion, StreamTrack.Response)
                && !ContentSafetySourceMapping.GatesTrack(ContentSafetyAppliedSource.Completion, StreamTrack.Request),
            "the completion scope gates the response track only");
        foreach (var scope in new[]
                 {
                     ContentSafetyAppliedSource.System, ContentSafetyAppliedSource.Document,
                     ContentSafetyAppliedSource.Tool, ContentSafetyAppliedSource.PreToolCall,
                     ContentSafetyAppliedSource.PostToolCall,
                 })
        {
            Assert(
                !ContentSafetySourceMapping.GatesTrack(scope, StreamTrack.Request)
                    && !ContentSafetySourceMapping.GatesTrack(scope, StreamTrack.Response),
                $"the {scope} scope gates neither track");
        }
    }

    private static void ANonGatingScopeNeitherHoldsNorEvaluatesATrack()
    {
        // A task scoped to tool call arguments must not fire on model output.
        var session = Session(
            Task("toolGuard", ContentSafetyAction.Block, Severity(4), ContentSafetyAppliedSource.PreToolCall),
            Task("harm", ContentSafetyAction.Block, Severity(4), ContentSafetyAppliedSource.Completion));
        session.OnPayload(ContentSafetySource.ModelGenerated, 10);
        var outcome = session.RecordSegment(
            ContentSafetySource.ModelGenerated,
            0,
            10,
            new Dictionary<string, TaskObservation>
            {
                ["toolGuard"] = TaskObservation.Severity(7),
                ["harm"] = TaskObservation.Severity(0),
            });
        Assert(outcome.Action == ContentSafetyAction.Annotate, "the non gating task did not decide the segment");
        Assert(outcome.MatchedTasks.Count == 0, "and did not match");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Response) == 10,
            "nor did it hold the track it does not gate");
    }

    private static void RunesAreCountedAsScalarValues()
    {
        var session = Session(Task("harm", ContentSafetyAction.Block, Severity(4)));
        // 7 scalar values, 8 UTF-16 code units.
        const string Sample = "héllo 🌍";
        Assert(Sample.Length == 8, "the sample is 8 UTF-16 code units");
        Assert(
            session.OnPayload(ContentSafetySource.ModelGenerated, ContentSafetyTextKind.Unspecified, Sample) == 7,
            "a payload advances by its scalar value count");
    }
}
