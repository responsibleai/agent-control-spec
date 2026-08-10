// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentHooks;
using AgentControlSpec;

/// <summary>
/// Parity harness for the release accounting in specification section 18.1.
/// Mirrors the Rust core tests in <c>core/src/stream_session.rs</c> so the two
/// implementations of this security gate cannot drift apart silently.
/// </summary>
internal static class StreamSessionHarness
{
    private const StreamSourceType Req = StreamSourceType.UserRequest;
    private const StreamSourceType Res = StreamSourceType.ModelGenerated;

    private static StreamSessionConfig Config(SafetyLevel level, params string[] tasks) =>
        new(level, 0, 0, tasks, tasks);

    private static StreamSession Session(SafetyLevel level, params string[] tasks) =>
        new(Config(level, tasks));

    private static StreamSpan Span(StreamSourceType source, int start, int end) =>
        StreamSpan.Create(source, start, end);

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"StreamSessionHarness: {message}");
        }
    }

    private static StreamMediationException Throws(Action action, string message)
    {
        try
        {
            action();
        }
        catch (StreamMediationException error)
        {
            return error;
        }

        throw new InvalidOperationException($"StreamSessionHarness: {message}");
    }

    public static Task RunAsync()
    {
        SafetyLevelRoundTripsAndUnknownFailsClosed();
        SourceTypeRoundTripsAndMapsToInterceptionPoints();
        SingleTaskClearsAndAdvances();
        WatermarkIsTheMinimumAndAStalledTaskHoldsTheTrack();
        NonContiguousOutcomeFailsClosed();
        OverlappingSpansAreAccepted();
        StaleOutcomeIsIgnoredNotAnError();
        DenialIsTerminalAndCarriesTheRange();
        FirstTerminalReasonWins();
        ARewriteEndsTheStreamAndReportsNoWatermark();
        TransformFailsClosedUnderANonWithholdingLevel();
        TransformFailsClosedOverAlreadyReleasedText();
        OutcomePastObservedTextFailsClosed();
        UnknownTaskFailsClosed();
        ARefusalFromAnUnconfiguredTaskIsRefusedNotRecorded();
        EmptySpanIsRejectedAtConstruction();
        UnclearedResidueFailsClosedUnderEverySafetyLevel();
        FinishAdvancesBeforeCheckingResidue();
        TracksCarryIndependentOffsetsAndTaskSets();
        AResumedSessionKeepsOffsetsComparable();
        ObserveTextCountsRunesNotCodeUnits();
        RuneCountingAgreesWithTheCoreOnAdversarialText();
        OutcomesStillLandAfterThePayloadStreamCloses();
        PayloadAfterTheStreamClosesIsTerminal();
        ATrackWithNoTasksIsUnmediated();
        VerdictsMapOntoOutcomes();
        Console.WriteLine("AgentControlSpec stream release-accounting parity tests passed.");
        return Task.CompletedTask;
    }

    private static void SafetyLevelRoundTripsAndUnknownFailsClosed()
    {
        foreach (var level in new[] { SafetyLevel.Blocking, SafetyLevel.Complete, SafetyLevel.Deferred })
        {
            Assert(
                StreamMediationExtensions.ParseSafetyLevel(level.ToWireName()) == level,
                $"{level} must round trip through its wire name");
        }

        Throws(
            () => StreamMediationExtensions.ParseSafetyLevel("permissive"),
            "an unknown safety level must fail closed");
        Assert(SafetyLevel.Blocking.Withholds(), "blocking withholds");
        Assert(SafetyLevel.Complete.Withholds(), "complete withholds");
        Assert(!SafetyLevel.Deferred.Withholds(), "deferred does not withhold");
    }

    private static void SourceTypeRoundTripsAndMapsToInterceptionPoints()
    {
        foreach (var source in new[] { Req, Res })
        {
            Assert(
                StreamMediationExtensions.ParseSourceType(source.ToWireName()) == source,
                $"{source} must round trip through its wire name");
        }

        Throws(
            () => StreamMediationExtensions.ParseSourceType("tool_result"),
            "an unknown source type must fail closed");
        Assert(Req.ToInterceptionPoint() == InterceptionPoint.Input, "request maps to input");
        Assert(
            Res.ToInterceptionPoint() == InterceptionPoint.PostModelCall,
            "response maps to post_model_call");
        Assert(Req.ToTrack() == StreamTrack.Request, "request track");
        Assert(Res.ToTrack() == StreamTrack.Response, "response track");
    }

    private static void SingleTaskClearsAndAdvances()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        Assert(session.Observe(Res, 10) == 10, "observe returns the new end offset");
        Assert(session.SafeOffset(StreamTrack.Response) == 0, "nothing is safe before an outcome");
        session.RecordOutcome("safety", Span(Res, 0, 10), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 10, "the watermark advances to 10");
        Assert(session.Advance(StreamTrack.Response) is null, "no further progress emits no watermark");
    }

    private static void WatermarkIsTheMinimumAndAStalledTaskHoldsTheTrack()
    {
        var session = Session(SafetyLevel.Blocking, "safety", "pii");
        session.Observe(Res, 20);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) is null, "one of two tasks releases nothing");
        session.RecordOutcome("pii", Span(Res, 0, 12), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 12, "the watermark is the minimum");
        Assert(session.Pending(StreamTrack.Response) == 8, "eight runes stay pending");
    }

    private static void NonContiguousOutcomeFailsClosed()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 30);
        session.RecordOutcome("safety", Span(Res, 0, 10), SegmentOutcome.Cleared);
        Throws(
            () => session.RecordOutcome("safety", Span(Res, 20, 30), SegmentOutcome.Cleared),
            "a gap must fail closed");
        Assert(session.IsEnded, "the session is terminal");
        Assert(session.SafeOffset(StreamTrack.Response) is null, "the gap never became releasable");
    }

    private static void OverlappingSpansAreAccepted()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 40);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Cleared);
        session.RecordOutcome("safety", Span(Res, 10, 40), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 40, "overlapping windows clear the track");
    }

    private static void StaleOutcomeIsIgnoredNotAnError()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 20);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Cleared);
        session.RecordOutcome("safety", Span(Res, 0, 10), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 20, "a stale span does not move the frontier back");
    }

    private static void DenialIsTerminalAndCarriesTheRange()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 20);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Denied);
        Assert(
            session.EndReason is StreamEndReason.Denied
            {
                Track: StreamTrack.Response, Task: "safety", Range.Start: 0, Range.End: 20
            },
            "the denial carries its task and range");
        Assert(session.SafeOffset(StreamTrack.Response) is null, "a denial releases nothing");
        Assert(!session.Finish().Reason.IsClean, "a denied stream does not settle clean");
    }

    private static void FirstTerminalReasonWins()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 20);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Denied);
        Throws(
            () => session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Cleared),
            "a closed session rejects further outcomes");
        Assert(
            session.EndReason is StreamEndReason.Denied,
            "a later failure must not downgrade the denial");
    }

    private static void ARewriteEndsTheStreamAndReportsNoWatermark()
    {
        // The substitution replaces the policy target with a new whole value.
        // Its runes are not the ones this session counted and no task
        // evaluated it, so any watermark over it would name a position in a
        // sequence that no longer exists.
        var session = Session(SafetyLevel.Blocking, "pii");
        session.Observe(Res, 20);
        session.RecordOutcome("pii", Span(Res, 0, 20), SegmentOutcome.Transformed);
        Assert(session.Transformed, "the session records that the stream was rewritten");
        Assert(session.IsEnded, "and a rewrite ends it");
        Assert(
            session.Advance(StreamTrack.Response) is null,
            "a rewritten track has no release point");
        Assert(
            session.SafeOffset(StreamTrack.Response) is null,
            "and offers nothing to emit through");
        var completion = session.Finish();
        Assert(
            completion.Reason is StreamEndReason.Rewritten
            {
                Track: StreamTrack.Response, Task: "pii", Range.Start: 0, Range.End: 20
            },
            "settlement names the track, task and range that rewrote it");
        Assert(completion.Transformed, "settlement reports the modification");
        Assert(!completion.Reason.IsClean, "the host still owes an evaluation");
    }

    private static void TransformFailsClosedUnderANonWithholdingLevel()
    {
        var session = Session(SafetyLevel.Deferred, "pii");
        session.Observe(Res, 20);
        Throws(
            () => session.RecordOutcome("pii", Span(Res, 0, 20), SegmentOutcome.Transformed),
            "deferred already emitted the payload, so a transform must fail closed");
        Assert(session.IsEnded, "the session is terminal");
    }

    private static void TransformFailsClosedOverAlreadyReleasedText()
    {
        var session = Session(SafetyLevel.Blocking, "pii");
        session.Observe(Res, 40);
        session.RecordOutcome("pii", Span(Res, 0, 20), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 20, "the first span is released");
        Throws(
            () => session.RecordOutcome("pii", Span(Res, 10, 40), SegmentOutcome.Transformed),
            "a transform reaching released text must fail closed");
        Assert(session.IsEnded, "the session is terminal");
    }

    private static void OutcomePastObservedTextFailsClosed()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 10);
        Throws(
            () => session.RecordOutcome("safety", Span(Res, 0, 25), SegmentOutcome.Cleared),
            "an offset past the observed text must fail closed");
        Assert(session.IsEnded, "the session is terminal");
    }

    private static void UnknownTaskFailsClosed()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 10);
        Throws(
            () => session.RecordOutcome("unconfigured", Span(Res, 0, 10), SegmentOutcome.Cleared),
            "an unconfigured task must fail closed");
        Assert(session.IsEnded, "the session is terminal");
    }

    private static void ARefusalFromAnUnconfiguredTaskIsRefusedNotRecorded()
    {
        // A refusal returns before the watermark is touched, so the task check
        // in RecordOutcome is the only thing standing between a bogus task name
        // and a terminal reason attributed to it.
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 10);
        Throws(
            () => session.RecordOutcome("not_configured", Span(Res, 0, 10), SegmentOutcome.Denied),
            "an unconfigured task may not refuse");
        Assert(
            session.EndReason is not StreamEndReason.Denied,
            "the session recorded a denial attributed to a task it does not configure");
    }

    private static void EmptySpanIsRejectedAtConstruction()
    {
        Throws(() => Span(Res, 5, 5), "an empty span is rejected");
        Throws(() => Span(Res, 9, 4), "an inverted span is rejected");
        Throws(() => Span(Res, -1, 4), "a negative start is rejected");
    }

    private static void UnclearedResidueFailsClosedUnderEverySafetyLevel()
    {
        foreach (var level in new[] { SafetyLevel.Blocking, SafetyLevel.Complete, SafetyLevel.Deferred })
        {
            var session = Session(level, "safety");
            session.Observe(Res, 30);
            session.RecordOutcome("safety", Span(Res, 0, 12), SegmentOutcome.Cleared);
            session.EndOfPayloads();
            var completion = session.Finish();
            Assert(
                completion.Reason is StreamEndReason.Failed failed
                    && failed.Detail.Contains("18 uncleared runes", StringComparison.Ordinal),
                $"{level} must not settle clean with uncleared runes");
        }
    }

    private static void FinishAdvancesBeforeCheckingResidue()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 20);
        session.RecordOutcome("safety", Span(Res, 0, 20), SegmentOutcome.Cleared);
        var completion = session.Finish();
        Assert(completion.Reason is StreamEndReason.Complete, "finish recomputes the watermark itself");
        Assert(!completion.Transformed, "an untransformed stream reports so");
    }

    private static void TracksCarryIndependentOffsetsAndTaskSets()
    {
        var session = new StreamSession(
            new StreamSessionConfig(
            SafetyLevel.Blocking,
            0,
            0, new[] { "jailbreak" }, new[] { "safety" }));
        session.Observe(Req, 8);
        session.Observe(Res, 25);
        session.RecordOutcome("jailbreak", Span(Req, 0, 8), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Request) == 8, "the request track advances");
        Assert(session.SafeOffset(StreamTrack.Response) == 0, "the response track is untouched");
        Throws(
            () => session.RecordOutcome("safety", Span(Req, 0, 8), SegmentOutcome.Cleared),
            "a response task may not clear the request track");
    }

    private static void AResumedSessionKeepsOffsetsComparable()
    {
        var session = new StreamSession(
            new StreamSessionConfig(
            SafetyLevel.Blocking,
            100,
            100, new[] { "safety" }, new[] { "safety" }));
        Assert(session.SafeOffset(StreamTrack.Response) == 100, "the session starts at the resume offset");
        Assert(session.Observe(Res, 20) == 120, "observe continues the earlier offset space");
        session.RecordOutcome("safety", Span(Res, 100, 120), SegmentOutcome.Cleared);
        Assert(session.Advance(StreamTrack.Response) == 120, "the watermark advances to 120");
        Assert(session.Finish().Reason is StreamEndReason.Complete, "the resumed stream settles clean");
    }

    private static void ObserveTextCountsRunesNotCodeUnits()
    {
        var session = Session(SafetyLevel.Blocking, "safety");
        // 7 scalar values, 8 UTF-16 code units.
        const string Sample = "héllo 🌍";
        Assert(Sample.Length == 8, "the sample is 8 UTF-16 code units");
        Assert(StreamSession.CountRunes(Sample) == 7, "the sample is 7 runes");
        Assert(session.ObserveText(Res, Sample) == 7, "observe counts runes, not code units");
    }

    private static void RuneCountingAgreesWithTheCoreOnAdversarialText()
    {
        // The same table the Rust core pins. Any disagreement here means the
        // two implementations would compute different offsets for the same
        // bytes, which puts a host and the session out of step.
        var samples = new (string Text, int Runes, int Utf16)[]
        {
            ("hello", 5, 5),
            ("h\u00e9llo", 5, 5),
            ("h\u00e9llo \U0001F30D", 7, 8),
            ("\U0001F30D\U0001F30E\U0001F30F", 3, 6),
            ("\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466", 7, 11),
            ("e\u0301", 2, 2),
            ("\u00e9", 1, 1),
            ("\u0928\u092e\u0938\u094d\u0924\u0947", 6, 6),
            ("\u0645\u0631\u062d\u0628\u0627", 5, 5),
            ("\U0001F1EF\U0001F1F5", 2, 4),
            ("\U0002070E\U00020731\U00020779", 3, 6),
        };

        foreach (var (text, runes, utf16) in samples)
        {
            Assert(
                text.Length == utf16,
                $"sample {runes} runes: expected {utf16} UTF-16 code units, saw {text.Length}");
            Assert(
                StreamSession.CountRunes(text) == runes,
                $"sample: expected {runes} runes, counted {StreamSession.CountRunes(text)}");

            var session = Session(SafetyLevel.Blocking, "t");
            Assert(
                session.ObserveText(Res, text) == runes,
                $"observe advanced by the wrong amount for a {runes} rune sample");
        }
    }

    private static void OutcomesStillLandAfterThePayloadStreamCloses()
    {
        // The separation a deferred classifier needs. Payload arrival and
        // settlement are distinct, so a verdict can still arrive at EOF.
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 10);
        session.EndOfPayloads();
        session.RecordOutcome("safety", Span(Res, 0, 10), SegmentOutcome.Cleared);
        Assert(session.Finish().Reason is StreamEndReason.Complete, "outcomes still land after EOF");
    }

    private static void PayloadAfterTheStreamClosesIsTerminal()
    {
        // Rejecting the call is not enough. A host that ignored the refusal
        // would settle clean over runes the accounting never counted and no
        // task ever evaluated.
        var session = Session(SafetyLevel.Blocking, "safety");
        session.Observe(Res, 10);
        session.EndOfPayloads();
        Throws(() => session.Observe(Res, 5), "a payload after EOF fails the session");
        Assert(session.IsEnded, "the disagreement is terminal");
        Assert(!session.Finish().Reason.IsClean, "so it cannot settle clean");
    }

    private static void ATrackWithNoTasksIsUnmediated()
    {
        // Guarding only the model stream is the ordinary shape, so an empty
        // task set means that track is not mediated rather than being an
        // error. Only a session mediating neither track is refused.
        var responseOnly = new StreamSession(new StreamSessionConfig(
            SafetyLevel.Blocking, 0, 0, Array.Empty<string>(), new[] { "safety" }));
        responseOnly.Observe(Res, 10);
        responseOnly.RecordOutcome("safety", Span(Res, 0, 10), SegmentOutcome.Cleared);
        Assert(
            responseOnly.Advance(StreamTrack.Response) == 10,
            "a response only session settles on its own track");

        Throws(
            () => new StreamSession(new StreamSessionConfig(
                SafetyLevel.Blocking, 0, 0, Array.Empty<string>(), Array.Empty<string>())),
            "a session mediating neither track gates nothing");
    }

    private static void VerdictsMapOntoOutcomes()
    {
        foreach (var (decision, clears) in new[]
                 {
                     (Decision.Allow, true),
                     (Decision.Deny, false),
                 })
        {
            var session = Session(SafetyLevel.Blocking, "safety");
            session.Observe(Res, 10);
            session.RecordVerdict("safety", Span(Res, 0, 10), new Verdict(decision));
            if (clears)
            {
                Assert(session.Advance(StreamTrack.Response) == 10, $"{decision} clears");
            }
            else
            {
                Assert(session.EndReason is StreamEndReason.Denied, $"{decision} must deny");
            }
        }

        var transform = Session(SafetyLevel.Blocking, "pii");
        transform.Observe(Res, 10);
        transform.RecordVerdict("pii", Span(Res, 0, 10), new Verdict(Decision.Transform));
        Assert(transform.Transformed, "a transform verdict obliges the host to substitute");
        Assert(transform.Finish().Transformed, "settlement reports the modification");
    }
}
