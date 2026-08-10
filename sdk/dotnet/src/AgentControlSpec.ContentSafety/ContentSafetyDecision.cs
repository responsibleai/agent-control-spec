// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentControlSpec.ContentSafety;

/// <summary>
/// Combines the actions several tasks contributed to one segment and collapses
/// them into the single action a front door reports.
/// </summary>
public static class ContentSafetyDecision
{
    /// <summary>
    /// Value an accumulation starts from before any task has contributed.
    ///
    /// This is <see cref="ContentSafetyActionFlags.Annotate"/> rather than
    /// <see cref="ContentSafetyActionFlags.None"/>, matching the service: a
    /// segment that no task matched is permitted and annotated, not withheld.
    /// </summary>
    public const ContentSafetyActionFlags Initial = ContentSafetyActionFlags.Annotate;

    private const ContentSafetyActionFlags Known =
        ContentSafetyActionFlags.Annotate
        | ContentSafetyActionFlags.Retry
        | ContentSafetyActionFlags.Hitl
        | ContentSafetyActionFlags.Block;

    /// <summary>
    /// Flags a configured action contributes when its criterion matched.
    ///
    /// An unrecognised or unset action contributes
    /// <see cref="ContentSafetyActionFlags.Block"/>. That default is
    /// deliberate and is the fail closed half of the service's pair of
    /// converters. A task whose criterion matched has found something, so not
    /// knowing what to do about it MUST NOT resolve to permitting it.
    /// </summary>
    public static ContentSafetyActionFlags FromAction(ContentSafetyAction action) => action switch
    {
        ContentSafetyAction.Annotate => ContentSafetyActionFlags.Annotate,
        ContentSafetyAction.Retry => ContentSafetyActionFlags.Retry,
        ContentSafetyAction.Hitl => ContentSafetyActionFlags.Hitl,
        ContentSafetyAction.Block => ContentSafetyActionFlags.Block,
        _ => ContentSafetyActionFlags.Block,
    };

    /// <summary>
    /// Collapse accumulated flags to the one action to report, by strict
    /// precedence, which is block, then human in the loop, then retry, then
    /// annotate.
    ///
    /// An unknown bit is rejected rather than ignored, because silently
    /// dropping it would report a weaker action than something asked for.
    /// </summary>
    public static ContentSafetyAction Collapse(ContentSafetyActionFlags flags)
    {
        if ((flags & ~Known) != 0)
        {
            throw new ContentSafetyConfigurationException(
                $"accumulated action flags {flags} contain an unrecognised bit");
        }

        if ((flags & ContentSafetyActionFlags.Block) != 0)
        {
            return ContentSafetyAction.Block;
        }

        if ((flags & ContentSafetyActionFlags.Hitl) != 0)
        {
            return ContentSafetyAction.Hitl;
        }

        if ((flags & ContentSafetyActionFlags.Retry) != 0)
        {
            return ContentSafetyAction.Retry;
        }

        return ContentSafetyAction.Annotate;
    }

    /// <summary>
    /// The release consequence of an action.
    ///
    /// Annotate permits the segment. Block refuses it. Human in the loop is an
    /// escalation, which section 17.1 makes a refusal until an approval path
    /// resolves it, and a stream cannot hold its connection open across an out
    /// of band approval.
    ///
    /// Retry has no Agent Control Specification decision of its own, and this
    /// is the one place the two vocabularies genuinely do not meet. It maps to
    /// a refusal here because the release question it answers is the same one.
    /// Text the caller is being asked to regenerate MUST NOT be emitted. The
    /// distinction survives on
    /// <see cref="ContentSafetyOutcome.Action"/>, so a caller that knows how to
    /// regenerate still sees the retry rather than a bare denial.
    /// </summary>
    public static SegmentOutcome ToSegmentOutcome(ContentSafetyAction action) => action switch
    {
        ContentSafetyAction.Annotate => SegmentOutcome.Cleared,
        ContentSafetyAction.Block => SegmentOutcome.Denied,
        ContentSafetyAction.Hitl => SegmentOutcome.Denied,
        ContentSafetyAction.Retry => SegmentOutcome.Denied,
        _ => SegmentOutcome.Denied,
    };
}

/// <summary>What a segment's evaluation concluded.</summary>
/// <param name="Action">The single action to report, after collapsing.</param>
/// <param name="Flags">Everything the tasks contributed, before collapsing.</param>
/// <param name="Outcome">The release consequence recorded against the stream.</param>
/// <param name="MatchedTasks">Labels of the tasks whose criteria matched.</param>
/// <param name="EvaluatedTasks">
/// Labels of the tasks that supplied an observation for this segment. A caller
/// that expected every gating task to report can compare this against its own
/// configuration to find a classifier that has not answered yet.
/// </param>
public sealed record ContentSafetyOutcome(
    ContentSafetyAction Action,
    ContentSafetyActionFlags Flags,
    SegmentOutcome Outcome,
    IReadOnlyList<string> MatchedTasks,
    IReadOnlyList<string> EvaluatedTasks)
{
    /// <summary>
    /// Whether any task refused this segment.
    ///
    /// This is NOT authority to emit text and MUST NOT be used as one. A
    /// segment that no task evaluated permits trivially, because nothing
    /// refused it, while the watermark has not moved and the text is still
    /// unexamined. The only authority to emit is the offset
    /// <see cref="ContentSafetySession.TryAdvanceWatermark"/> returns.
    /// </summary>
    public bool Permits => Outcome == SegmentOutcome.Cleared;

    /// <summary>
    /// Whether any task actually examined this segment. A false value means the
    /// segment passed through unevaluated, which settles as residue.
    /// </summary>
    public bool WasEvaluated => EvaluatedTasks.Count > 0;

    /// <summary>
    /// Whether the front door reports this segment as filtered.
    ///
    /// Filtered is narrower than withheld and the two MUST NOT be conflated. A
    /// segment routed to human review or to a retry is withheld, because text
    /// awaiting review or regeneration cannot be emitted, yet the service
    /// reports it as not filtered. Deriving the annotation from
    /// <see cref="Permits"/> would therefore mark those segments filtered and
    /// disagree with the service over the same content.
    /// </summary>
    public bool Filtered => Action == ContentSafetyAction.Block;
}
