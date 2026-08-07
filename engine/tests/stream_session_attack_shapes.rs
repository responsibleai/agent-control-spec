//! Attack shapes ported from the MAF agent-hooks review.
//!
//! The MAF review rounds (see `analysis/streaming-acs-vs-maf.md`, R9) found
//! three shapes that defeated a first implementation of buffered gating: a
//! retry middleware re-invoking the stream so a second attempt escapes the
//! first attempt's verdict, a middleware draining a successful attempt and
//! discarding it, and divergence between the streamed and the non streamed
//! evaluation of the same content. These tests pin how the section 18.1
//! accounting behaves under each shape. The session holds no stream text, so
//! where a guarantee is a host obligation rather than something the
//! accounting can check, the test asserts what the session can assert and
//! the comment names the boundary.
//!
//! Conventions follow `stream_session_mediation.rs`: a real `Runtime`, a
//! trigger policy that denies any target containing a banned term, cumulative
//! evaluation as section 18.1 obliges, and a negative control wherever the
//! shape has one.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, Runtime, RuntimeError, SafetyLevel, SegmentOutcome, StreamEndReason,
    StreamError, StreamSession, StreamSessionConfig, StreamSourceType, StreamSpan, StreamTrack,
    Verdict,
};
use serde_json::json;
use std::sync::Arc;

const MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: test
intervention_points:
  post_model_call:
    policy_target: $snap.completion
    policy:
      id: p
"#;

/// Denies any policy target whose text contains the trigger substring.
struct TriggerPolicy {
    trigger: &'static str,
}

impl PolicyDispatcher for TriggerPolicy {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let rendered = invocation
            .policy_input()
            .map(JsonValue::to_string)
            .unwrap_or_default();
        if rendered.contains(self.trigger) {
            Ok(json!({"decision": "deny", "reason": "trigger"}))
        } else {
            Ok(json!({"decision": "allow"}))
        }
    }
}

struct NoAnnotators;

impl AnnotatorDispatcher for NoAnnotators {
    fn dispatch(
        &self,
        annotator_name: &str,
        _invocation: &AnnotatorInvocation,
        _preliminary_policy_input: &JsonValue,
    ) -> Result<JsonValue, RuntimeError> {
        Err(RuntimeError::AnnotationFailed(annotator_name.to_string()))
    }
}

fn runtime(trigger: &'static str) -> Runtime {
    let manifest = Manifest::from_yaml_str(MANIFEST).unwrap();
    Runtime::new(
        manifest,
        Arc::new(NoAnnotators),
        Arc::new(TriggerPolicy { trigger }),
    )
    .unwrap()
}

/// Evaluate one policy target as an ordinary whole snapshot, which is the
/// section 18 path: one intervention point evaluation over the whole value.
fn evaluate(runtime: &Runtime, policy_target: &str) -> Verdict {
    runtime
        .evaluate_point(
            StreamSourceType::ModelGenerated.interception_point(),
            json!({"completion": {"text": policy_target}}),
        )
        .verdict
}

fn slice_runes(text: &str, start: u32, end: u32) -> String {
    text.chars()
        .skip(start as usize)
        .take(end.saturating_sub(start) as usize)
        .collect()
}

/// A response only session over `tasks`, resuming at `resume_at`.
fn response_session(tasks: &[&str], resume_at: u32) -> StreamSession {
    StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: resume_at,
        request_tasks: Vec::new(),
        response_tasks: tasks.iter().map(|task| (*task).to_string()).collect(),
    })
    .expect("config is valid")
}

/// What one incrementally mediated run of `payloads` concluded.
struct IncrementalRun {
    session: StreamSession,
    /// Text the host emitted to the caller as the watermark advanced. Empty
    /// when `emit` was false, because delivery is the host's act and not the
    /// session's.
    delivered: String,
}

/// Drive a fresh single task session over `payloads`, evaluating each span
/// over the whole accumulated prefix as section 18.1 obliges. `emit` selects
/// whether the host delivers the cleared prefix as the watermark advances or
/// drains the stream without releasing anything, which is the discard shape.
fn drive_incremental(runtime: &Runtime, payloads: &[&str], emit: bool) -> IncrementalRun {
    let mut session = response_session(&["harm"], 0);
    let mut text = String::new();
    let mut delivered = String::new();
    let mut cursor = 0;
    let mut emitted = 0;
    for payload in payloads {
        text.push_str(payload);
        let end = session
            .observe_text(StreamSourceType::ModelGenerated, payload)
            .expect("observe");
        let span =
            StreamSpan::new(StreamSourceType::ModelGenerated, cursor, end).expect("valid span");
        let verdict = evaluate(runtime, &text);
        session
            .record_verdict("harm", &span, &verdict)
            .expect("the outcome records, a denial included");
        cursor = end;
        if session.is_ended() {
            break;
        }
        if let Some(safe) = session.advance(StreamTrack::Response) {
            if emit {
                delivered.push_str(&slice_runes(&text, emitted, safe));
                emitted = safe;
            }
        }
    }
    IncrementalRun { session, delivered }
}

// ---------------------------------------------------------------------------
// Shape (a): retry re-invocation across sessions.
//
// MAF's finding was retry middleware re-invoking the stream so that a second
// attempt escaped the first attempt's verdict coverage. The ACS translation
// is two sessions over one caller visible stream: attempt one is abandoned
// mid stream, attempt two resumes at the offset the caller had reached. The
// accounting must keep the attempts isolated: the abandoned session settles
// on its own residue, the clean retry settles clean, and neither session's
// watermark leaks into the other.
// ---------------------------------------------------------------------------

#[test]
fn an_abandoned_attempt_settles_failed_and_its_retry_settles_clean() {
    let runtime = runtime("forbidden");

    // Attempt one: two tasks mediate the response. Both clear the first
    // payload, so "clean " is released. The second payload arrives and only
    // one task clears it before the caller disconnects and the host abandons
    // the attempt.
    let mut first = response_session(&["harm", "pii"], 0);
    let mut text = String::new();
    text.push_str("clean ");
    first
        .observe_text(StreamSourceType::ModelGenerated, "clean ")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 6).expect("valid span");
    first
        .record_verdict("harm", &span, &evaluate(&runtime, &text))
        .expect("harm clears");
    first
        .record_outcome("pii", &span, SegmentOutcome::Cleared)
        .expect("pii clears");
    assert_eq!(first.advance(StreamTrack::Response), Some(6));
    let released_by_first = "clean ";

    text.push_str("and mo");
    first
        .observe_text(StreamSourceType::ModelGenerated, "and mo")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 6, 12).expect("valid span");
    first
        .record_verdict("harm", &span, &evaluate(&runtime, &text))
        .expect("harm clears the tail");
    // pii never reports on [6, 12): the host abandons the attempt here.

    // Section 18.1: every session that is opened settles, an abandoned one
    // included. The residue no task cleared fails the settlement closed; it
    // is not silently dropped with the attempt.
    let completion = first.finish();
    assert_eq!(
        completion.reason,
        StreamEndReason::Failed(StreamError::UnclearedResidue {
            track: StreamTrack::Response,
            pending: 6,
        })
    );
    // The offsets stay readable for the audit record, and the failing
    // settlement did not raise the release point over the residue.
    assert_eq!(first.watermark(StreamTrack::Response).confirmed(), 6);
    assert_eq!(first.watermark(StreamTrack::Response).received(), 12);

    // Attempt two resumes at the offset the caller actually received, not at
    // the offset the abandoned attempt had evaluated. The retry re-generates
    // from there; the abandoned residue "and mo" is gone, not inherited. The
    // host retains the released tail and evaluates it under each value, per
    // the retention obligation on resumed tracks.
    let resume_at = 6;
    let mut second = response_session(&["harm", "pii"], resume_at);
    assert_eq!(
        second.watermark(StreamTrack::Response).confirmed(),
        resume_at,
        "the retry's watermark starts at the resume offset, clean of the first attempt's state"
    );
    let attempt = "fresh tail";
    let end = second
        .observe_text(StreamSourceType::ModelGenerated, attempt)
        .expect("observe");
    let span =
        StreamSpan::new(StreamSourceType::ModelGenerated, resume_at, end).expect("valid span");
    let value = format!("{released_by_first}{attempt}");
    second
        .record_verdict("harm", &span, &evaluate(&runtime, &value))
        .expect("harm clears");
    second
        .record_outcome("pii", &span, SegmentOutcome::Cleared)
        .expect("pii clears");
    assert_eq!(second.advance(StreamTrack::Response), Some(16));

    // The clean retry settles clean: the abandoned attempt's failure does not
    // bleed into it, and its own settlement claims nothing about attempt one.
    assert_eq!(second.finish().reason, StreamEndReason::Complete);
    let caller_sees = format!("{released_by_first}{attempt}");
    assert!(
        !caller_sees.contains("and mo"),
        "the abandoned attempt's uncleared residue never reached the caller"
    );
}

#[test]
fn a_retry_cannot_inherit_the_abandoned_attempts_clearance_frontier() {
    // The negative control for cross session watermark bleed. Attempt one
    // cleared through rune 12 but the host had only emitted through rune 6
    // when it abandoned the attempt, so the retry resumes at 6. A host that
    // treats the abandoned attempt's clearance frontier as carried over
    // records its first retry span starting at 12, as if [6, 12) were still
    // cleared. Clearance is per session: nothing in the retry evaluated
    // [6, 12) of the retry's own text, so confirming that span would release
    // a gap nothing evaluated, and the accounting fails it closed.
    let mut first = response_session(&["harm"], 0);
    first
        .observe_text(StreamSourceType::ModelGenerated, "clean and mo")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 12).expect("valid span");
    first
        .record_outcome("harm", &span, SegmentOutcome::Cleared)
        .expect("harm clears through 12");
    assert_eq!(first.advance(StreamTrack::Response), Some(12));
    // The host emitted only through 6 before abandoning; delivery is the
    // host's act, so the resume offset below is 6 regardless of the frontier.

    let mut second = response_session(&["harm"], 6);
    second
        .observe_text(StreamSourceType::ModelGenerated, "fresh tail")
        .expect("observe");
    let stale_frontier = StreamSpan::new(StreamSourceType::ModelGenerated, 12, 16).expect("valid");
    assert_eq!(
        second.record_outcome("harm", &stale_frontier, SegmentOutcome::Cleared),
        Err(StreamError::NonContiguousOutcome {
            task: "harm".to_string(),
            expected: 6,
            found: 12,
        }),
        "the first attempt's frontier does not clear the retry's gap"
    );
    assert!(matches!(
        second.end_reason(),
        Some(StreamEndReason::Failed(
            StreamError::NonContiguousOutcome { .. }
        ))
    ));
}

// ---------------------------------------------------------------------------
// Shape (b): success-then-discard.
//
// MAF's shape was middleware draining a successful attempt, discarding it,
// and returning something else, with the drained attempt's side effects
// escaping the covering verdict. In the 18.1 topology a host can drain a
// stream through the accounting, clear every rune, and then abandon the
// response without releasing any of it.
// ---------------------------------------------------------------------------

#[test]
fn a_fully_cleared_stream_the_host_never_emits_still_settles_complete() {
    // The session records clearance, which is permission, not a delivery
    // record. A fully cleared stream settles `Complete` whether or not the
    // host ever emitted a rune, because `Complete` says "everything was
    // evaluated and releasable" and claims nothing about delivery.
    //
    // Host obligation boundary: the session holds no text and no record of
    // what the host actually wrote to its caller, so `safe_offset` against
    // what was actually emitted is host side state the accounting cannot
    // audit. What the session CAN assert is pinned here: the settlement is
    // clean, the cleared extent is on the watermark for the audit record,
    // and the settled session offers no release point afterwards, so a host
    // that discarded the response cannot later hold up the settled session
    // as live permission to emit the drained text.
    let runtime = runtime("forbidden");
    let mut run = drive_incremental(&runtime, &["the ", "quick ", "brown "], false);
    assert_eq!(run.delivered, "", "the host drained without releasing");
    let completion = run.session.finish();
    assert!(completion.reason.is_clean());
    assert!(!completion.transformed);
    assert_eq!(
        run.session.watermark(StreamTrack::Response).confirmed(),
        16,
        "the cleared extent survives for the audit record"
    );
    assert_eq!(
        run.session.safe_offset(StreamTrack::Response),
        None,
        "a settled session offers no release point to emit the discarded text against"
    );
    assert_eq!(
        run.session
            .observe_text(StreamSourceType::ModelGenerated, "more"),
        Err(StreamError::SessionClosed),
        "and it takes no further payload"
    );
}

#[test]
fn settlement_records_clearance_not_delivery() {
    // The boundary made concrete: two identical streams, one host emits every
    // cleared prefix, the other drains and discards. The accounting cannot
    // distinguish them, and must not pretend to: their settlements and their
    // watermarks are identical, so any claim that discarded text was or was
    // not delivered is the host's to make and the host's to prove. This is
    // the file's convention of a negative control, applied to an assertion
    // the session deliberately does not make.
    let runtime = runtime("forbidden");
    let payloads = ["the ", "quick ", "brown "];
    let mut emitting = drive_incremental(&runtime, &payloads, true);
    let mut discarding = drive_incremental(&runtime, &payloads, false);
    assert_eq!(emitting.delivered, "the quick brown ");
    assert_eq!(discarding.delivered, "");
    assert_eq!(emitting.session.finish(), discarding.session.finish());
    assert_eq!(
        emitting.session.watermark(StreamTrack::Response),
        discarding.session.watermark(StreamTrack::Response),
        "the accounting carries no delivery record to tell the two hosts apart"
    );
}

// ---------------------------------------------------------------------------
// Shape (c): streaming / whole-snapshot asymmetry probe.
//
// The metamorphic suite already pins that the incremental outcome does not
// depend on segmentation. This probe pins the cross path property: the same
// content evaluated as one section 18 whole snapshot and evaluated through
// section 18.1 segments reaches the same terminal outcome. The incremental
// path differs only in exposure, because a cleared prefix is released before
// the denial lands, which is the bounded exposure the profile trades for
// latency and not a divergent verdict.
// ---------------------------------------------------------------------------

#[test]
fn a_deny_lands_on_both_the_whole_snapshot_and_the_incremental_path() {
    let runtime = runtime("forbidden");
    let content = "clean forbidden text";

    // Section 18 path: one evaluation over the whole assembled value.
    let whole = evaluate(&runtime, content);
    assert_eq!(whole.decision.as_str(), "deny");

    // Section 18.1 path: the same runes, cut into payloads none of which
    // contains the term on its own, evaluated cumulatively.
    let mut run = drive_incremental(&runtime, &["clean ", "forbid", "den text"], true);
    assert!(matches!(
        run.session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    assert!(!run.session.finish().reason.is_clean());

    // Same terminal outcome; the paths differ only in exposure. The whole
    // snapshot path emits nothing of a refused value, which is the host's
    // act under section 18. The incremental path had already released the
    // prefix cleared before the term completed, and nothing more: "forbid"
    // cleared because no cumulative value containing it held the whole term
    // yet, which is precisely the bounded exposure the profile documents.
    assert_eq!(run.delivered, "clean forbid");
    assert!(!run.delivered.contains("forbidden"));
}

#[test]
fn a_clean_stream_settles_the_same_on_both_paths() {
    // The negative control: content the policy allows must land clean both
    // ways, with the incremental path releasing everything it cleared.
    let runtime = runtime("forbidden");
    let content = "clean text throughout";

    let whole = evaluate(&runtime, content);
    assert_eq!(whole.decision.as_str(), "allow");

    let mut run = drive_incremental(&runtime, &["clean ", "text t", "hroughout"], true);
    assert_eq!(run.session.finish().reason, StreamEndReason::Complete);
    assert_eq!(run.delivered, content);
}
