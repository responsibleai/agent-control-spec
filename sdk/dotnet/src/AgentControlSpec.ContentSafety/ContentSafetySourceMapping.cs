// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentControlSpec.ContentSafety;

/// <summary>
/// Resolves the two different questions a front door asks about a payload's
/// role, which are answered by two different values in the service this
/// adapter bridges to.
///
/// <para><b>Which tasks apply</b> is answered by the resolved source, after
/// context is folded into model generated text and a concatenated history is
/// folded into the request. <see cref="Resolve"/> performs that fold.</para>
///
/// <para><b>Which track counts the offsets</b> is answered by the raw source
/// as it arrived, before any folding. <see cref="WatermarkTrack"/> performs
/// that split.</para>
///
/// <para>These disagree, and the disagreement is load bearing rather than an
/// oversight this adapter should smooth over. In the service, the payload
/// processor tests the raw source against the request role and sends
/// everything else to the completion watermark, while the source helper folds
/// several roles into the request and groups the tool and run roles with it.
/// A payload carrying a concatenated history therefore evaluates as a request
/// but has its runes counted on the completion track. An adapter that
/// "corrected" this would compute offsets the front door does not agree with,
/// and a watermark both sides do not agree on releases the wrong text.</para>
/// </summary>
public static class ContentSafetySourceMapping
{
    /// <summary>
    /// Fold a payload's declared source and text kind into the role that
    /// decides which tasks evaluate it.
    ///
    /// When no source is set the text kind stands in for it. Context folds
    /// into model generated text and a concatenated history folds into the
    /// request. Anything unrecognised folds to model generated, which is the
    /// response side, so an unknown role is still governed by the response
    /// task set rather than escaping evaluation.
    /// </summary>
    public static ContentSafetySource Resolve(ContentSafetySource source, ContentSafetyTextKind kind)
    {
        if (source == ContentSafetySource.Unknown)
        {
            return kind switch
            {
                ContentSafetyTextKind.Context => ContentSafetySource.ModelGenerated,
                ContentSafetyTextKind.ConcatAll => ContentSafetySource.UserRequest,
                ContentSafetyTextKind.UserRequest => ContentSafetySource.UserRequest,
                ContentSafetyTextKind.ModelGenerated => ContentSafetySource.ModelGenerated,
                ContentSafetyTextKind.PreToolCall => ContentSafetySource.PreToolCall,
                ContentSafetyTextKind.PostToolCall => ContentSafetySource.PostToolCall,
                ContentSafetyTextKind.PreRun => ContentSafetySource.PreRun,
                ContentSafetyTextKind.PostRun => ContentSafetySource.PostRun,
                _ => ContentSafetySource.ModelGenerated,
            };
        }

        return source switch
        {
            ContentSafetySource.Context => ContentSafetySource.ModelGenerated,
            ContentSafetySource.ConcatAll => ContentSafetySource.UserRequest,
            ContentSafetySource.UserRequest => ContentSafetySource.UserRequest,
            ContentSafetySource.PreToolCall => ContentSafetySource.PreToolCall,
            ContentSafetySource.PostToolCall => ContentSafetySource.PostToolCall,
            ContentSafetySource.PreRun => ContentSafetySource.PreRun,
            ContentSafetySource.PostRun => ContentSafetySource.PostRun,
            _ => ContentSafetySource.ModelGenerated,
        };
    }

    /// <summary>
    /// Whether a resolved role is request side for the purpose of task
    /// applicability. The tool and run roles group with the request here.
    ///
    /// This deliberately does NOT decide the watermark track. See
    /// <see cref="WatermarkTrack"/>.
    /// </summary>
    public static bool IsRequestRole(ContentSafetySource resolved) =>
        resolved is ContentSafetySource.UserRequest
            or ContentSafetySource.PreToolCall
            or ContentSafetySource.PostToolCall
            or ContentSafetySource.PreRun
            or ContentSafetySource.PostRun;

    /// <summary>
    /// Track whose offsets a payload advances.
    ///
    /// Takes the RAW source exactly as the payload carried it, because that is
    /// what the service's payload processor tests. Only a literal request
    /// source advances the request track; every other value, including the
    /// tool and run roles that <see cref="IsRequestRole"/> calls request side,
    /// advances the response track.
    /// </summary>
    public static StreamTrack WatermarkTrack(ContentSafetySource rawSource) =>
        rawSource == ContentSafetySource.UserRequest ? StreamTrack.Request : StreamTrack.Response;

    /// <summary>
    /// Whether a task declaring <paramref name="scope"/> registers on
    /// <paramref name="track"/>, and therefore gates its release.
    ///
    /// The front door builds one watermark per track and registers a task on it
    /// when the task's scope equals that watermark's own scope or is
    /// <see cref="ContentSafetyAppliedSource.All"/>. Every other scope matches
    /// neither watermark, so such a task never holds released text. That is
    /// reproduced here rather than corrected, because a task this package gated
    /// and the front door did not would stall a stream the service expects to
    /// flow.
    /// </summary>
    public static bool GatesTrack(ContentSafetyAppliedSource scope, StreamTrack track) => scope switch
    {
        ContentSafetyAppliedSource.All => true,
        ContentSafetyAppliedSource.Prompt => track == StreamTrack.Request,
        ContentSafetyAppliedSource.Completion => track == StreamTrack.Response,
        _ => false,
    };

    /// <summary>
    /// Source type to drive the release accounting with, chosen so its track
    /// matches <see cref="WatermarkTrack"/>.
    /// </summary>
    public static StreamSourceType ToStreamSourceType(ContentSafetySource rawSource) =>
        WatermarkTrack(rawSource) == StreamTrack.Request
            ? StreamSourceType.UserRequest
            : StreamSourceType.ModelGenerated;
}
