// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentControlSpec.ContentSafety;

/// <summary>One configured evaluation a front door runs over stream text.</summary>
public sealed record ContentSafetyTask
{
    /// <summary>Label the front door reports this task's offset under.</summary>
    public required string Label { get; init; }

    /// <summary>What to do when <see cref="Criterion"/> matches.</summary>
    public ContentSafetyAction Action { get; init; } = ContentSafetyAction.Unspecified;

    /// <summary>The comparison that decides whether <see cref="Action"/> applies.</summary>
    public required BlockingCriterion Criterion { get; init; }

    /// <summary>
    /// Scopes this task declares itself applicable to. An empty list means
    /// <see cref="ContentSafetyAppliedSource.All"/>, matching the front door's
    /// treatment of an unset applicability.
    ///
    /// This is the task's own scope and NOT a payload source. Only the prompt,
    /// completion and all scopes gate released text. See
    /// <see cref="ContentSafetyAppliedSource"/>.
    /// </summary>
    public IReadOnlyList<ContentSafetyAppliedSource> AppliesTo { get; init; } =
        Array.Empty<ContentSafetyAppliedSource>();

    /// <summary>
    /// Whether this task gates release on <paramref name="track"/>. A task that
    /// does not gate a track neither holds it nor evaluates its segments.
    /// </summary>
    internal bool GatesTrack(StreamTrack track)
    {
        if (AppliesTo.Count == 0)
        {
            return true;
        }

        foreach (var scope in AppliesTo)
        {
            if (ContentSafetySourceMapping.GatesTrack(scope, track))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Configuration a session is opened with.</summary>
public sealed record ContentSafetySessionOptions
{
    /// <summary>How much the front door may release ahead of the watermark.</summary>
    public SafetyLevel SafetyLevel { get; init; } = SafetyLevel.Blocking;

    /// <summary>
    /// Offset the first rune of the request track occupies, for a resumed
    /// attempt. Held per track because the tracks are independent offset
    /// spaces and a retry rarely resumes both. Re sending the prompt while
    /// resuming the completion is the ordinary case.
    /// </summary>
    public int RequestStartOffset { get; init; }

    /// <summary>
    /// Offset the first rune of the completion track occupies, with the same
    /// meaning as <see cref="RequestStartOffset"/>.
    /// </summary>
    public int ResponseStartOffset { get; init; }

    /// <summary>Tasks configured for this session.</summary>
    public required IReadOnlyList<ContentSafetyTask> Tasks { get; init; }
}

/// <summary>Terminal settlement of a session.</summary>
/// <param name="Action">Action the session ended on.</param>
/// <param name="Reason">Why the underlying stream session ended.</param>
/// <param name="Clean">Whether the stream finished with no enforcement action.</param>
public sealed record ContentSafetySettlement(
    ContentSafetyAction Action,
    StreamEndReason Reason,
    bool Clean);

/// <summary>
/// The object a streaming content safety front door drives.
///
/// It answers two questions the front door asks on every stream. What action
/// does the configured policy call for over this segment, and how far into
/// each track is it now safe to emit.
///
/// It holds no stream text. The front door already accumulates payloads and
/// already decides where its evaluation segments fall, so this takes rune
/// counts and segment ranges rather than trying to own either.
///
/// <para><b>Thread safe.</b> A front door receives classifier results
/// concurrently and emits from another thread, so every operation here is
/// serialized internally. The underlying release accounting requires exclusive
/// access, and advancing the watermark while another thread records an outcome
/// would otherwise enumerate the task map during mutation and throw.</para>
///
/// <para><b>Every applicable task must report.</b> The safe offset is the
/// minimum across a track's tasks, so a task that never records an outcome
/// holds the whole track. That is the intended behavior and not a bug. It is
/// what stops a fast classifier from releasing text a slow one has not seen.
/// A caller that supplies observations for only some tasks will find the
/// watermark stops advancing.</para>
///
/// <para><b>Holding is not free, and the budget is short.</b> The proxy in
/// front of a content safety service starts a 500 millisecond countdown when
/// the final chunk of a model response arrives, and logs a completion timeout
/// if the service has not answered inside it. A stalled task therefore does not
/// stall quietly; it consumes that budget and then surfaces as a timeout
/// counted against an availability target. Every task that gates a track has to
/// finish within roughly that window of the last payload, which bounds how much
/// evaluation a caller can leave outstanding at end of stream rather than
/// spreading across it.</para>
/// </summary>
public sealed class ContentSafetySession
{
    /// <summary>
    /// Label registered on a track that no configured task evaluates.
    ///
    /// The service permits this and its watermark simply never advances,
    /// because the minimum over an empty task set is unbounded. The release
    /// accounting requires at least one task per track, so an unevaluated
    /// track gets this reserved label, which nothing ever clears. The
    /// behavior matches, so the track cannot advance. It diverges at settlement,
    /// where text that arrived on such a track is uncleared residue and fails
    /// closed rather than stalling silently.
    /// </summary>
    public const string UnconfiguredTrackTask = "__acs_unconfigured_track__";

    private readonly StreamSession _session;
    private readonly IReadOnlyList<ContentSafetyTask> _tasks;
    private readonly object _gate = new();
    private ContentSafetyActionFlags _sessionFlags = ContentSafetyDecision.Initial;

    private ContentSafetySession(StreamSession session, IReadOnlyList<ContentSafetyTask> tasks)
    {
        _session = session;
        _tasks = tasks;
    }

    /// <summary>Open a session.</summary>
    public static ContentSafetySession Create(ContentSafetySessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Tasks.Count == 0)
        {
            throw new ContentSafetyConfigurationException("a session needs at least one task");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var task in options.Tasks)
        {
            if (string.IsNullOrEmpty(task.Label))
            {
                throw new ContentSafetyConfigurationException("a task label may not be empty");
            }

            if (!seen.Add(task.Label))
            {
                throw new ContentSafetyConfigurationException($"duplicate task label {task.Label}");
            }
        }

        var config = new StreamSessionConfig(
            options.SafetyLevel,
            options.RequestStartOffset,
            options.ResponseStartOffset,
            LabelsForTrack(options.Tasks, StreamTrack.Request),
            LabelsForTrack(options.Tasks, StreamTrack.Response));

        return new ContentSafetySession(new StreamSession(config), options.Tasks);
    }

    private static IReadOnlyList<string> LabelsForTrack(
        IReadOnlyList<ContentSafetyTask> tasks,
        StreamTrack track)
    {
        var labels = new List<string>();
        foreach (var task in tasks)
        {
            if (task.GatesTrack(track))
            {
                labels.Add(task.Label);
            }
        }

        return labels.Count > 0 ? labels : new[] { UnconfiguredTrackTask };
    }

    /// <summary>Whether the session has reached its terminal state.</summary>
    public bool IsEnded
    {
        get
        {
            lock (_gate)
            {
                return _session.IsEnded;
            }
        }
    }

    /// <summary>Underlying release accounting, for callers that need its detail.</summary>
    public StreamSession Stream => _session;

    /// <summary>
    /// Report an arriving payload and return the track's new end offset.
    ///
    /// <paramref name="rawSource"/> is the source exactly as the payload
    /// carried it, before any folding, because that is what decides the track.
    /// Runes are counted in Unicode scalar values, not UTF-16 code units.
    /// </summary>
    public int OnPayload(ContentSafetySource rawSource, ContentSafetyTextKind kind, string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        _ = kind;
        lock (_gate)
        {
            return _session.ObserveText(
                ContentSafetySourceMapping.ToStreamSourceType(rawSource), text);
        }
    }

    /// <summary>
    /// Report an arriving payload by its rune count rather than its text, for
    /// a caller that has already measured it.
    ///
    /// The count MUST be Unicode scalar values. A length that counts UTF-16
    /// code units disagrees for any supplementary plane character and will
    /// put this session's offsets out of step with the front door's.
    /// </summary>
    public int OnPayload(ContentSafetySource rawSource, int runes)
    {
        lock (_gate)
        {
            return _session.Observe(ContentSafetySourceMapping.ToStreamSourceType(rawSource), runes);
        }
    }

    /// <summary>
    /// Evaluate one segment against every applicable task and record the
    /// result.
    ///
    /// Tasks are evaluated first and their actions combined, and only then is
    /// the outcome recorded, because a refusal is terminal and recording it
    /// early would stop the remaining tasks from being considered at all.
    /// </summary>
    public ContentSafetyOutcome RecordSegment(
        ContentSafetySource rawSource,
        int startOffset,
        int endOffset,
        IReadOnlyDictionary<string, TaskObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(observations);

        var streamSource = ContentSafetySourceMapping.ToStreamSourceType(rawSource);
        var track = ContentSafetySourceMapping.WatermarkTrack(rawSource);
        var span = StreamSpan.Create(streamSource, startOffset, endOffset);

        lock (_gate)
        {
            return RecordSegmentLocked(span, track, observations);
        }
    }

    private ContentSafetyOutcome RecordSegmentLocked(
        StreamSpan span,
        StreamTrack track,
        IReadOnlyDictionary<string, TaskObservation> observations)
    {

        var flags = ContentSafetyDecision.Initial;
        var matched = new List<string>();
        var reported = new List<string>();
        // What each matched task contributed, so a refusal can name the task
        // that actually drove the collapsed action rather than whichever task
        // happens to be listed first.
        var contributed = new List<(string Label, ContentSafetyActionFlags Flags)>();

        foreach (var task in _tasks)
        {
            if (!task.GatesTrack(track) || !observations.TryGetValue(task.Label, out var observation))
            {
                continue;
            }

            reported.Add(task.Label);
            if (task.Criterion.Matches(observation))
            {
                var taskFlags = ContentSafetyDecision.FromAction(task.Action);
                matched.Add(task.Label);
                contributed.Add((task.Label, taskFlags));
                flags |= taskFlags;
            }
        }

        var action = ContentSafetyDecision.Collapse(flags);
        var outcome = ContentSafetyDecision.ToSegmentOutcome(action);
        _sessionFlags |= flags;

        if (outcome == SegmentOutcome.Cleared)
        {
            foreach (var label in reported)
            {
                _session.RecordOutcome(label, span, SegmentOutcome.Cleared);
            }
        }
        else
        {
            // One refusal ends the session, so it is recorded against the task
            // that produced it rather than against every task that looked. The
            // task named MUST be one whose own action collapsed to this
            // decision. Naming any matched task would attribute a block to a
            // task configured only to annotate, which is a false record of
            // which policy refused.
            var deciding = ContentSafetyDecision.FromAction(action);
            var offender = contributed.FirstOrDefault(c => (c.Flags & deciding) != 0).Label
                ?? matched.FirstOrDefault()
                ?? reported.FirstOrDefault();
            if (offender is null)
            {
                throw new ContentSafetyConfigurationException(
                    $"segment [{span.Range.Start},{span.Range.End}) resolved to {action} with no task to attribute it to");
            }

            _session.RecordOutcome(offender, span, outcome);
        }

        return new ContentSafetyOutcome(action, flags, outcome, matched, reported);
    }

    /// <summary>
    /// Recompute a track's safe offset.
    ///
    /// Returns the new offset when it advanced, and -1 when it did not,
    /// matching the sentinel the service's watermark uses so a caller emits a
    /// watermark message only on real progress.
    ///
    /// <para><b>Only the response track has a wire representation.</b> The
    /// contract's watermark message carries a bare offset with no field naming
    /// the track it belongs to, and the service emits one only for the
    /// completion. Its prompt watermark is constructed and then read solely in a
    /// null check. A caller must therefore not emit a watermark message for the
    /// request track, because the receiver would read that offset as a
    /// completion offset and release text nothing cleared. The request track is
    /// still tracked here, since it governs whether request text may be
    /// forwarded, but that decision stays inside the host.</para>
    /// </summary>
    public int TryAdvanceWatermark(StreamTrack track)
    {
        lock (_gate)
        {
            return _session.Advance(track) ?? -1;
        }
    }

    /// <summary>
    /// Offset through which the front door may emit this track, or
    /// <c>null</c> once the session has ended.
    ///
    /// <para>A deny withholds every rune the front door has not already
    /// emitted, including runes a task had cleared, so a terminal session
    /// offers no offset to emit through. The null is carried through rather
    /// than flattened, because a front door that polls this while delivering
    /// lazily would otherwise release text the denial covers.</para>
    /// </summary>
    public int? SafeOffset(StreamTrack track)
    {
        lock (_gate)
        {
            return _session.SafeOffset(track);
        }
    }

    /// <summary>
    /// End offset of the text this session has been told about on a track.
    ///
    /// A host compares this against how far it has evaluated to find the tail
    /// no segment has covered yet, which it must evaluate before settling or
    /// the session fails closed on the residue.
    /// </summary>
    public int ReceivedOffset(StreamTrack track)
    {
        lock (_gate)
        {
            return _session.Watermark(track).Received;
        }
    }

    /// <summary>Stop accepting payloads while outcomes are still in flight.</summary>
    public void EndOfPayloads()
    {
        lock (_gate)
        {
            _session.EndOfPayloads();
        }
    }

    /// <summary>Settle the session.</summary>
    public ContentSafetySettlement Finish()
    {
        lock (_gate)
        {
            return FinishLocked();
        }
    }

    private ContentSafetySettlement FinishLocked()
    {
        var completion = _session.Finish();
        var action = completion.Reason is StreamEndReason.Complete
            ? ContentSafetyDecision.Collapse(_sessionFlags)
            : ContentSafetyAction.Block;
        return new ContentSafetySettlement(action, completion.Reason, completion.Reason.IsClean);
    }
}
