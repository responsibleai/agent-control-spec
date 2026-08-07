//! End to end mediation of a streamed completion.
//!
//! These tests wire the release accounting in section 18.1 of the
//! specification to a real `Runtime`. The session holds no stream text, so
//! each test carries a small `Host` that does what a real host already does:
//! accumulate payloads, segment them, evaluate each segment as an ordinary
//! whole snapshot at `post_model_call`, and emit the prefix the session
//! clears. The runtime stays stateless and the session contributes only the
//! accounting.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    AnnotatorDispatcher, AnnotatorInvocation, JsonValue, Manifest, PolicyDispatcher,
    PreparedPolicyInvocation, RuneRange, Runtime, RuntimeError, SafetyLevel, SegmentOutcome,
    StreamEndReason, StreamError, StreamSession, StreamSessionConfig, StreamSourceType, StreamSpan,
    StreamTrack, Verdict,
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

/// Evaluate one policy target as an ordinary whole snapshot.
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

/// What the session deliberately does not do.
///
/// A real host already accumulates the stream and already runs a segmenter
/// over it, so this stands in for that half of the integration. `cumulative`
/// selects whether the host evaluates the whole accumulated prefix, which is
/// the obligation section 18.1 places on it, or only the newest delta, which
/// is the mistake the obligation exists to prevent.
struct Host {
    session: StreamSession,
    text: String,
    eval_cursor: u32,
    emitted: u32,
    delivered: String,
    target: TargetMode,
}

/// How the host chooses the value it evaluates for a span.
#[derive(Clone, Copy)]
enum TargetMode {
    /// The whole accumulated prefix, which satisfies the coverage obligation
    /// in section 18.1 unconditionally.
    Cumulative,
    /// The span's own text and nothing else. The negative control: it violates
    /// the obligation, so a term straddling a boundary escapes.
    DeltaOnly,
    /// A bounded suffix window of this many runes ending at the span's end.
    /// Sound only when the window reaches at least `L - 1` runes below the
    /// span's start, where `L` is the longest term the policy detects.
    SuffixWindow(u32),
}

impl Host {
    fn new(level: SafetyLevel, target: TargetMode) -> Self {
        let session = StreamSession::new(StreamSessionConfig {
            safety_level: level,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: vec!["harm".to_string()],
            response_tasks: vec!["harm".to_string()],
        })
        .unwrap();
        Self {
            session,
            text: String::new(),
            eval_cursor: 0,
            emitted: 0,
            delivered: String::new(),
            target,
        }
    }

    fn withholding(level: SafetyLevel) -> Self {
        Self::new(level, TargetMode::Cumulative)
    }

    /// Accept one payload and run the whole host side loop over it.
    fn feed(&mut self, runtime: &Runtime, payload: &str) -> Result<(), StreamError> {
        self.text.push_str(payload);
        let end = self
            .session
            .observe_text(StreamSourceType::ModelGenerated, payload)?;
        if !self.session.config().safety_level.withholds() {
            // Deferred emits on arrival, before any verdict exists.
            self.deliver_through(end);
        }
        if end <= self.eval_cursor {
            return Ok(());
        }
        let span = StreamSpan::new(StreamSourceType::ModelGenerated, self.eval_cursor, end)?;
        let policy_target = match self.target {
            TargetMode::Cumulative => self.text.clone(),
            TargetMode::DeltaOnly => slice_runes(&self.text, self.eval_cursor, end),
            TargetMode::SuffixWindow(window) => {
                slice_runes(&self.text, end.saturating_sub(window), end)
            }
        };
        let verdict = evaluate(runtime, &policy_target);
        self.session.record_verdict("harm", &span, &verdict)?;
        self.eval_cursor = end;
        if let Some(safe) = self.session.advance(StreamTrack::Response) {
            if self.session.config().safety_level.withholds() {
                self.deliver_through(safe);
            }
        }
        Ok(())
    }

    fn deliver_through(&mut self, offset: u32) {
        if offset > self.emitted {
            let next = slice_runes(&self.text, self.emitted, offset);
            self.delivered.push_str(&next);
            self.emitted = offset;
        }
    }

    fn drive(&mut self, runtime: &Runtime, payloads: &[&str]) -> Result<(), StreamError> {
        for payload in payloads {
            self.feed(runtime, payload)?;
        }
        Ok(())
    }
}

#[test]
fn an_approved_prefix_is_released_before_the_stream_ends() {
    let runtime = runtime("forbidden");
    let mut host = Host::withholding(SafetyLevel::Blocking);
    host.drive(&runtime, &["the ", "quick ", "brown "])
        .expect("clean stream");
    // Released mid stream rather than held until settlement.
    assert_eq!(host.delivered, "the quick brown ");
    assert_eq!(host.session.safe_offset(StreamTrack::Response), Some(16));
    assert_eq!(host.session.finish().reason, StreamEndReason::Complete);
}

#[test]
fn a_banned_span_split_across_payloads_is_still_stopped() {
    let runtime = runtime("forbidden");
    let mut host = Host::withholding(SafetyLevel::Blocking);
    // Neither payload contains the term; their concatenation does.
    let outcome = host.drive(&runtime, &["safe for", "bidden text"]);
    assert!(outcome.is_ok(), "the denial is recorded, not an error");
    assert!(matches!(
        host.session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    // Only the prefix cleared before the banned payload reached the caller.
    assert_eq!(host.delivered, "safe for");
    assert!(!host.delivered.contains("forbidden"));
}

#[test]
fn a_window_sized_only_above_the_term_still_misses_it() {
    // The obligation in section 18.1 is not satisfied by a window merely
    // longer than the term. Sizing must be measured from the span's START,
    // because a term overlapping the span can begin `L - 1` runes above it.
    //
    // Term `forbidden` is 9 runes at [4,13). Payloads of 4 runes, so spans are
    // 4 runes. A suffix window of 10 runes is longer than the term and always
    // contains the span, yet at span [12,16) it holds [6,16), `rbiddenyyy`.
    // No evaluated value ever holds the whole term, so every span clears.
    let runtime = runtime("forbidden");
    let mut host = Host::new(SafetyLevel::Blocking, TargetMode::SuffixWindow(10));
    host.drive(&runtime, &["xxxx", "forb", "idde", "nyyy"])
        .expect("no denial is ever recorded");
    assert_eq!(host.session.end_reason(), None);
    assert!(
        host.delivered.contains("forbidden"),
        "a window longer than the term is not enough"
    );
}

#[test]
fn a_window_reaching_below_the_span_start_catches_the_term() {
    // The sound bound. For spans of at most `S` runes and a longest term of
    // `L`, a suffix window must be at least `S + L - 1`, here 4 + 9 - 1 = 12.
    // The same stream the undersized window missed is now refused.
    let runtime = runtime("forbidden");
    let mut host = Host::new(SafetyLevel::Blocking, TargetMode::SuffixWindow(12));
    let outcome = host.drive(&runtime, &["xxxx", "forb", "idde", "nyyy"]);
    assert!(outcome.is_ok(), "the denial is recorded, not an error");
    assert!(matches!(
        host.session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    assert!(!host.delivered.contains("forbidden"));
}

#[test]
fn evaluating_only_the_delta_would_miss_the_split_span() {
    // The negative control for the host obligation in section 18.1: a host
    // that evaluates the isolated delta sees "safe for" then "bidden text",
    // and the policy allows both.
    let runtime = runtime("forbidden");
    let mut host = Host::new(SafetyLevel::Blocking, TargetMode::DeltaOnly);
    host.drive(&runtime, &["safe for", "bidden text"])
        .expect("no denial is ever recorded");
    assert_eq!(host.session.end_reason(), None);
    assert!(
        host.delivered.contains("forbidden"),
        "delta only evaluation is what the obligation exists to prevent"
    );
}

#[test]
fn a_denied_payload_is_never_released_and_ends_the_session() {
    let runtime = runtime("forbidden");
    let mut host = Host::withholding(SafetyLevel::Blocking);
    host.drive(&runtime, &["clean ", "forbidden"])
        .expect("denial recorded");
    assert_eq!(host.delivered, "clean ");
    assert!(matches!(
        host.session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    // Nothing further is released after settlement.
    assert!(!host.session.finish().reason.is_clean());
}

#[test]
fn withholding_holds_text_that_no_task_has_cleared() {
    let runtime = runtime("forbidden");
    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec!["harm".to_string()],
        response_tasks: vec!["harm".to_string(), "pii".to_string()],
    })
    .unwrap();
    session
        .observe_text(StreamSourceType::ModelGenerated, "hello there")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 11).unwrap();
    let verdict = evaluate(&runtime, "hello there");
    session
        .record_verdict("harm", &span, &verdict)
        .expect("one task clears");
    // The second task has not reported, so nothing is releasable.
    assert_eq!(session.advance(StreamTrack::Response), None);
    assert_eq!(session.safe_offset(StreamTrack::Response), Some(0));
    session
        .record_outcome("pii", &span, SegmentOutcome::Cleared)
        .expect("second task clears");
    assert_eq!(session.advance(StreamTrack::Response), Some(11));
}

#[test]
fn an_unevaluated_tail_fails_closed_at_the_end_of_the_stream() {
    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec!["harm".to_string()],
        response_tasks: vec!["harm".to_string()],
    })
    .unwrap();
    session
        .observe_text(StreamSourceType::ModelGenerated, "evaluated tail")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 9).unwrap();
    session
        .record_outcome("harm", &span, SegmentOutcome::Cleared)
        .expect("prefix clears");
    session.end_of_payloads();
    // The final " tail" was never evaluated.
    assert_eq!(
        session.finish().reason,
        StreamEndReason::Failed(StreamError::UnclearedResidue {
            track: StreamTrack::Response,
            pending: 5,
        })
    );
}

#[test]
fn deferred_emits_on_arrival_and_still_terminates_on_a_denial() {
    let runtime = runtime("forbidden");
    let mut host = Host::new(SafetyLevel::Deferred, TargetMode::Cumulative);
    host.drive(&runtime, &["clean ", "forbidden"])
        .expect("denial recorded behind the stream");
    // Deferred already sent the offending text; the accounting still refuses
    // to settle the stream clean.
    assert!(host.delivered.contains("forbidden"));
    assert!(matches!(
        host.session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    assert!(!host.session.finish().reason.is_clean());
}

#[test]
fn a_transform_verdict_records_the_host_obligation_to_substitute() {
    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: Vec::new(),
        response_tasks: vec!["pii".to_string()],
    })
    .unwrap();
    session
        .observe_text(StreamSourceType::ModelGenerated, "call 555 0100")
        .expect("observe");
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 13).unwrap();
    session
        .record_outcome("pii", &span, SegmentOutcome::Transformed)
        .expect("transform records");
    // A rewrite ends the stream. The replacement is a new whole value whose
    // runes are not the ones this session counted and which no task evaluated,
    // so the accounting reports no watermark over it.
    assert_eq!(
        session.advance(StreamTrack::Response),
        None,
        "a rewritten track has no release point"
    );
    let completion = session.finish();
    assert_eq!(
        completion.reason,
        StreamEndReason::Rewritten {
            track: StreamTrack::Response,
            task: "pii".to_string(),
            range: RuneRange { start: 0, end: 13 },
        }
    );
    assert!(
        completion.transformed,
        "settlement must tell the host the stream was not verbatim"
    );
}

/// A session resuming attempt 2 of a response stream whose first attempt
/// delivered runes `[0, resume_at)` before it was abandoned.
fn resumed_session(resume_at: u32) -> StreamSession {
    StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: resume_at,
        request_tasks: Vec::new(),
        response_tasks: vec!["harm".to_string()],
    })
    .expect("config is valid")
}

/// Drive a resumed attempt over `payloads`, evaluating each span over the
/// accumulated attempt text prefixed by `retained`, and return what the
/// retry released. `retained` is the tail of the earlier attempt's delivered
/// text that the host kept across the boundary; passing an empty string is
/// the host that dropped it.
fn drive_resumed(
    runtime: &Runtime,
    session: &mut StreamSession,
    resume_at: u32,
    retained: &str,
    payloads: &[&str],
) -> String {
    let mut attempt_text = String::new();
    let mut released = String::new();
    let mut cursor = resume_at;
    let mut emitted = resume_at;
    for payload in payloads {
        attempt_text.push_str(payload);
        let end = session
            .observe_text(StreamSourceType::ModelGenerated, payload)
            .expect("observe");
        let span =
            StreamSpan::new(StreamSourceType::ModelGenerated, cursor, end).expect("range is valid");
        let value = format!("{retained}{attempt_text}");
        let verdict = evaluate(runtime, &value);
        session
            .record_verdict("harm", &span, &verdict)
            .expect("the outcome records, a denial included");
        cursor = end;
        if session.is_ended() {
            break;
        }
        if let Some(safe) = session.advance(StreamTrack::Response) {
            released.push_str(&slice_runes(
                &attempt_text,
                emitted - resume_at,
                safe - resume_at,
            ));
            emitted = safe;
        }
    }
    released
}

#[test]
fn a_term_straddling_a_resume_boundary_is_caught_with_the_retained_tail() {
    // Section 18.1: the attempt boundary is not a clearance boundary. A
    // track resuming at an offset above zero MUST retain the last `L - 1`
    // runes the earlier attempt delivered and include them in the value it
    // evaluates near the boundary.
    //
    // Attempt 1 released `xxxxforb`, 8 runes, then was abandoned. The term
    // `forbidden` is 9 runes at [4, 13): it begins inside attempt 1's
    // released tail and ends inside attempt 2's first spans, so no value
    // drawn from attempt 2 alone can ever contain it. With `L - 1` of 8 the
    // tail the host must retain happens to be the whole of what attempt 1
    // delivered.
    let runtime = runtime("forbidden");
    let delivered = "xxxxforb";
    let resume_at = 8;
    let mut session = resumed_session(resume_at);
    let released = drive_resumed(
        &runtime,
        &mut session,
        resume_at,
        delivered,
        &["idde", "nyyy"],
    );
    assert!(matches!(
        session.end_reason(),
        Some(StreamEndReason::Denied { .. })
    ));
    // The retry released only the prefix cleared before the term completed.
    assert_eq!(released, "idde");
    let caller_sees = format!("{delivered}{released}");
    assert!(!caller_sees.contains("forbidden"));
}

#[test]
fn a_resumed_host_that_drops_the_prior_tail_misses_the_straddling_term() {
    // The negative control for the retention obligation. The same stream,
    // resumed by a host that evaluates only what attempt 2 accumulated:
    // every value it evaluates holds at most `iddenyyy`, so every span
    // clears, the session settles clean, and the caller assembles the term
    // across the attempts.
    let runtime = runtime("forbidden");
    let delivered = "xxxxforb";
    let resume_at = 8;
    let mut session = resumed_session(resume_at);
    let released = drive_resumed(&runtime, &mut session, resume_at, "", &["idde", "nyyy"]);
    assert_eq!(session.finish().reason, StreamEndReason::Complete);
    assert_eq!(released, "iddenyyy");
    let caller_sees = format!("{delivered}{released}");
    assert!(
        caller_sees.contains("forbidden"),
        "dropping the prior attempt's tail is what the retention obligation exists to prevent"
    );
}
