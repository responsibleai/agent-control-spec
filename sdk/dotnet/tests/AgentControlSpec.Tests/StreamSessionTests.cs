// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Streaming reaches .NET through the C ABI, so these run the real engine.
// They are the .NET half of a suite that asserts the same scenarios in
// every supported language.

using AgentControlSpec;
using Xunit;

namespace AgentControlSpec.Tests;

public sealed class StreamSessionTests
{
    [Fact]
    public void AClearedSpanReleasesUpToItsEnd()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);

        Assert.Equal(5, session.ObserveText(StreamSourceType.ModelGenerated, "hello"));
        Assert.Equal(0, session.SafeOffset(StreamTrack.Response));

        session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared);

        Assert.Equal(5, session.Advance(StreamTrack.Response));
        Assert.Equal(5, session.SafeOffset(StreamTrack.Response));
        Assert.Equal(0, session.Pending(StreamTrack.Response));

        var completion = session.Finish();
        Assert.Equal("complete", completion.Reason.Kind);
        Assert.True(completion.IsClean);
        Assert.False(completion.Transformed);
    }

    [Fact]
    public void ARefusalEndsTheSessionAndStillReportsHowFarItGot()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hello world");
        session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared);
        session.Advance(StreamTrack.Response);
        Assert.Equal(5, session.SafeOffset(StreamTrack.Response));

        session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 5, 11, SegmentOutcome.Denied);

        Assert.True(session.IsEnded);
        Assert.Null(session.SafeOffset(StreamTrack.Response));

        // The audit path: the offset the stream reached survives settlement.
        Assert.Equal(5, session.Watermark(StreamTrack.Response).Confirmed);

        var reason = session.EndReason;
        Assert.NotNull(reason);
        Assert.Equal("denied", reason!.Kind);
        Assert.Equal("pii", reason.Task);
        Assert.Equal("response", reason.Track);
        Assert.False(session.Finish().IsClean);
    }

    [Fact]
    public void EveryTaskMustClearASpanBeforeItReleases()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii", "harm"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hello");

        session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared);
        Assert.Null(session.Advance(StreamTrack.Response));
        Assert.Equal(0, session.SafeOffset(StreamTrack.Response));

        session.RecordOutcome("harm", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared);
        Assert.Equal(5, session.Advance(StreamTrack.Response));
        Assert.Equal(5, session.SafeOffset(StreamTrack.Response));
    }

    [Fact]
    public void ObserveTextCountsRunesNotUtf16CodeUnits()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);

        // One astral-plane scalar. .NET stores it as two UTF-16 code units,
        // so a host counting string.Length would release twice what was
        // evaluated.
        const string Emoji = "\U0001F600";
        Assert.Equal(2, Emoji.Length);
        Assert.Equal(1, session.ObserveText(StreamSourceType.ModelGenerated, Emoji));
    }

    [Fact]
    public void APayloadOnAnUnmediatedTrackIsRefused()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);

        // No task mediates the request track, so nothing would ever clear
        // text sent there. The engine refuses the payload rather than
        // releasing it unevaluated.
        var error = Assert.Throws<AgentControlSpecNativeException>(() =>
            session.ObserveText(StreamSourceType.UserRequest, "hi"));
        Assert.Contains("unmediated", error.Message);
        Assert.Empty(session.Watermark(StreamTrack.Request).Tasks);
    }

    [Fact]
    public void TheTwoTracksAccountIndependently()
    {
        using var session = new StreamSession(
            SafetyLevel.Blocking, requestTasks: ["pii"], responseTasks: ["pii"]);

        session.ObserveText(StreamSourceType.UserRequest, "abc");
        session.ObserveText(StreamSourceType.ModelGenerated, "defghi");

        session.RecordOutcome("pii", StreamSourceType.UserRequest, 0, 3, SegmentOutcome.Cleared);
        session.Advance(StreamTrack.Request);

        Assert.Equal(3, session.SafeOffset(StreamTrack.Request));
        Assert.Equal(0, session.SafeOffset(StreamTrack.Response));
        Assert.Equal(6, session.Watermark(StreamTrack.Response).Received);
    }

    [Fact]
    public void AResumedStreamStartsFromItsRecordedOffsets()
    {
        using var session = new StreamSession(
            SafetyLevel.Blocking, responseTasks: ["pii"], responseStartRuneOffset: 10);

        Assert.Equal(10, session.Config.ResponseStartRuneOffset);
        session.ObserveText(StreamSourceType.ModelGenerated, "abc");
        Assert.Equal(13, session.Watermark(StreamTrack.Response).Received);
    }

    [Fact]
    public void ARewriteIsTerminalAndReportsItself()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hello");

        session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Transformed);

        Assert.True(session.IsEnded);
        Assert.True(session.Transformed);
        Assert.Equal("rewritten", session.EndReason!.Kind);
        Assert.Null(session.SafeOffset(StreamTrack.Response));
    }

    [Fact]
    public void AVerdictFeedsBackWithoutTranslation()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hello");

        // Shaped as ActivatedPolicy.Evaluate returns one.
        session.RecordVerdict(
            "pii", StreamSourceType.ModelGenerated, 0, 5,
            """{"decision":"allow","reasons":[]}""");

        Assert.Equal(5, session.Advance(StreamTrack.Response));
        Assert.Equal(5, session.SafeOffset(StreamTrack.Response));
    }

    [Fact]
    public void AnUnknownTaskIsRefusedRatherThanIgnored()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hello");

        Assert.Throws<AgentControlSpecNativeException>(() =>
            session.RecordOutcome("nope", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared));
    }

    [Fact]
    public void ASessionThatEvaluatesNothingIsRefused()
    {
        Assert.Throws<AgentControlSpecNativeException>(() => new StreamSession(SafetyLevel.Blocking));
    }

    [Fact]
    public void AnOutcomeReachingUnobservedTextIsRefused()
    {
        using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
        session.ObserveText(StreamSourceType.ModelGenerated, "hi");

        Assert.Throws<AgentControlSpecNativeException>(() =>
            session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 99, SegmentOutcome.Cleared));
    }
}
