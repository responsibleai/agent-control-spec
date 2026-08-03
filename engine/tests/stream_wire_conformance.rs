//! Conformance against the external streaming contract's real drive pattern.
//!
//! These tests encode how the Azure content safety `Annotate` stream is
//! actually driven by its callers, reconstructed from the service's own
//! request handling and its end to end client utilities rather than from the
//! proto alone. They exist so a change to this module that still passes the
//! semantic tests cannot silently stop matching the wire behaviour the
//! wrapper layer has to bridge.
//!
//! Four properties matter to a bridging wrapper: the configuration message
//! arrives before any payload, payload text accumulates rather than being
//! evaluated payload by payload, request side and response side text are
//! counted in separate offset spaces on the same session, and the watermark
//! the service emits is a monotonic rune offset.
//!
//! The accumulation and the segmenting both live on the wrapper's side of the
//! boundary, because the service already does them. What the session
//! contributes is the offset the watermark message carries.
//!
//! One caveat on the request track. The service emits a watermark message for
//! completion text only, so a request track watermark has no wire
//! representation to conform to. The request assertions below fix the offset
//! space separation, which the wire does exhibit, and not a message the
//! service sends. A wrapper uses the request watermark to decide whether to
//! forward the prompt at all.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamError, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack,
};

const REQ: StreamSourceType = StreamSourceType::UserRequest;
const RES: StreamSourceType = StreamSourceType::ModelGenerated;

fn session(level: SafetyLevel) -> StreamSession {
    StreamSession::new(StreamSessionConfig {
        safety_level: level,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec!["harm".to_string()],
        response_tasks: vec!["harm".to_string()],
    })
    .unwrap()
}

fn span(source: StreamSourceType, start: u32, end: u32) -> StreamSpan {
    StreamSpan::new(source, start, end).expect("range is valid")
}

/// The contract permits a caller to degenerate to non streaming by sending
/// all of its text in one payload. The end to end client utilities do exactly
/// this for prompts, so the one shot shape must work without special casing.
#[test]
fn a_single_payload_carrying_all_text_is_supported() {
    let mut s = session(SafetyLevel::Blocking);
    let end = s
        .observe_text(REQ, "the whole prompt in one payload")
        .expect("observe");
    assert_eq!(end, 31);
    s.record_outcome("harm", &span(REQ, 0, end), SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.advance(StreamTrack::Request), Some(31));
    assert_eq!(s.finish().reason, StreamEndReason::Complete);
}

/// Payloads arrive in whatever sizes the upstream model produces. They extend
/// one accumulation on their track rather than standing alone.
#[test]
fn bursty_payloads_extend_one_accumulation() {
    let mut s = session(SafetyLevel::Blocking);
    assert_eq!(s.observe_text(RES, "a"), Ok(1));
    assert_eq!(s.observe_text(RES, "bc"), Ok(3));
    assert_eq!(s.observe_text(RES, "def"), Ok(6));
    // An empty payload is legal on the wire and moves nothing.
    assert_eq!(s.observe_text(RES, ""), Ok(6));
    assert_eq!(s.watermark(StreamTrack::Response).received(), 6);
    // The host may segment across payload boundaries however it likes.
    s.record_outcome("harm", &span(RES, 0, 6), SegmentOutcome::Cleared)
        .expect("one segment spanning three payloads");
    assert_eq!(s.advance(StreamTrack::Response), Some(6));
}

/// Prompt and completion text share a session but not an offset space, which
/// is why the service emits a separate watermark for each.
#[test]
fn one_session_carries_both_tracks_with_independent_offsets() {
    let mut s = session(SafetyLevel::Blocking);
    assert_eq!(s.observe_text(REQ, "prompt"), Ok(6));
    assert_eq!(s.observe_text(RES, "completion"), Ok(10));
    assert_eq!(s.watermark(StreamTrack::Request).received(), 6);
    assert_eq!(s.watermark(StreamTrack::Response).received(), 10);
    s.record_outcome("harm", &span(REQ, 0, 6), SegmentOutcome::Cleared)
        .expect("request clears");
    assert_eq!(s.advance(StreamTrack::Request), Some(6));
    // Clearing one track releases nothing on the other.
    assert_eq!(s.safe_offset(StreamTrack::Response), 0);
    assert_eq!(s.advance(StreamTrack::Response), None);
}

/// Configuration is the first message and the session is terminal once it
/// fails, so a caller cannot keep streaming into a closed session.
#[test]
fn configuration_precedes_payloads_and_a_terminal_session_rejects_more() {
    let mut s = session(SafetyLevel::Blocking);
    assert_eq!(s.config().safety_level, SafetyLevel::Blocking);
    s.observe_text(RES, "text").expect("observe");
    s.record_outcome("harm", &span(RES, 0, 4), SegmentOutcome::Denied)
        .expect("denial records");
    assert_eq!(s.observe_text(RES, "more"), Err(StreamError::SessionClosed));
    assert_eq!(
        s.record_outcome("harm", &span(RES, 0, 4), SegmentOutcome::Cleared),
        Err(StreamError::SessionClosed)
    );
}

/// Offsets are rune offsets. A payload of astral plane text advances the
/// track by its scalar value count, not by UTF-16 code units or bytes.
#[test]
fn every_observed_rune_occupies_offset_space() {
    let mut s = session(SafetyLevel::Blocking);
    let sample = "héllo 🌍";
    assert_eq!(sample.chars().count(), 7);
    assert_eq!(sample.encode_utf16().count(), 8);
    assert_eq!(sample.len(), 11);
    assert_eq!(s.observe_text(RES, sample), Ok(7));
    assert_eq!(s.observe_text(RES, sample), Ok(14));
    assert_eq!(s.watermark(StreamTrack::Response).received(), 14);
}

/// The watermark message is emitted only when the safe offset really moved,
/// and it never goes backwards.
#[test]
fn the_reported_watermark_is_monotonic_and_only_on_progress() {
    let mut s = session(SafetyLevel::Blocking);
    s.observe_text(RES, "0123456789").expect("observe");
    assert_eq!(
        s.advance(StreamTrack::Response),
        None,
        "nothing cleared yet"
    );
    s.record_outcome("harm", &span(RES, 0, 4), SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.advance(StreamTrack::Response), Some(4));
    assert_eq!(s.advance(StreamTrack::Response), None, "no new progress");
    // Re-reporting an already cleared span emits no watermark.
    s.record_outcome("harm", &span(RES, 0, 3), SegmentOutcome::Cleared)
        .expect("stale span is ignored");
    assert_eq!(s.advance(StreamTrack::Response), None);
    assert_eq!(s.safe_offset(StreamTrack::Response), 4);
    s.record_outcome("harm", &span(RES, 4, 10), SegmentOutcome::Cleared)
        .expect("clears the rest");
    assert_eq!(s.advance(StreamTrack::Response), Some(10));
}

/// A caller that reports a segment starting past its own frontier is asking
/// the session to confirm runes nothing evaluated.
#[test]
fn a_skipped_outcome_fails_closed_rather_than_confirming_the_gap() {
    let mut s = session(SafetyLevel::Blocking);
    s.observe_text(RES, "0123456789").expect("observe");
    s.record_outcome("harm", &span(RES, 0, 3), SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.advance(StreamTrack::Response), Some(3));
    assert_eq!(
        s.record_outcome("harm", &span(RES, 6, 10), SegmentOutcome::Cleared),
        Err(StreamError::NonContiguousOutcome {
            task: "harm".to_string(),
            expected: 3,
            found: 6,
        })
    );
    assert!(s.is_ended());
    // The gap never became releasable.
    assert_eq!(s.safe_offset(StreamTrack::Response), 3);
    assert_eq!(s.advance(StreamTrack::Response), None);
}

/// A resumed attempt continues the earlier attempt's offset space so the
/// watermarks stay comparable across a retry.
#[test]
fn a_resumed_attempt_continues_the_earlier_offset_space() {
    let mut s = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 42,
        response_start_rune_offset: 42,
        request_tasks: vec!["harm".to_string()],
        response_tasks: vec!["harm".to_string()],
    })
    .unwrap();
    assert_eq!(s.safe_offset(StreamTrack::Response), 42);
    assert_eq!(s.observe_text(RES, "resumed"), Ok(49));
    s.record_outcome("harm", &span(RES, 42, 49), SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.advance(StreamTrack::Response), Some(49));
    assert_eq!(s.finish().reason, StreamEndReason::Complete);
}
