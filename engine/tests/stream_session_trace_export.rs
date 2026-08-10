//! Exports differential traces for the other SDK implementations to replay.
//!
//! The release accounting is implemented natively per SDK rather than shared
//! through the C ABI, so nothing structural stops the implementations from
//! drifting. This test generates operation sequences, records what the Rust
//! core concluded at every step, and writes them where a sibling SDK harness
//! replays them and compares. A divergence in either direction fails there.
//!
//! Set `ACS_WRITE_TRACES=1` to regenerate. The committed trace file is the
//! contract, so a change that alters it is a change to cross SDK behavior and
//! has to be reviewed as one.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack,
};
use std::fmt::Write as _;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            (self.next() % u64::from(bound)) as u32
        }
    }
}

fn level_name(level: SafetyLevel) -> &'static str {
    level.as_str()
}

fn source_name(source: StreamSourceType) -> &'static str {
    source.as_str()
}

fn track_name(track: StreamTrack) -> &'static str {
    track.as_str()
}

/// One generated case, rendered as newline delimited JSON.
fn build_case(seed: u64) -> String {
    let mut rng = Rng::new(seed);

    let policies: [(&str, &[&str], &[&str]); 4] = [
        ("policy.single", &["harm"], &["harm"]),
        ("policy.split", &["jailbreak"], &["harm", "pii"]),
        ("policy.wide", &["jb", "prof"], &["harm", "pii", "copy"]),
        ("policy.asymmetric", &["req_only"], &["a", "b"]),
    ];
    let (policy_id, request_tasks, response_tasks) =
        policies[rng.below(policies.len() as u32) as usize];
    let level = [
        SafetyLevel::Blocking,
        SafetyLevel::Complete,
        SafetyLevel::Deferred,
    ][rng.below(3) as usize];
    let start = if rng.below(100) < 20 {
        rng.below(1000)
    } else {
        0
    };

    let mut out = String::new();
    let mut ops = String::new();

    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: level,
        request_start_rune_offset: start,
        response_start_rune_offset: start,
        request_tasks: request_tasks.iter().map(|t| (*t).to_string()).collect(),
        response_tasks: response_tasks.iter().map(|t| (*t).to_string()).collect(),
    })
    .expect("config is valid");

    let steps = 12 + rng.below(18);
    let mut probes_after_end = 0;
    for _ in 0..steps {
        // Once terminal, record a couple of probes to pin the closed session
        // behavior, then stop. A long tail of identical refusals tests nothing
        // and drowns the cases that exercise the accounting.
        if session.is_ended() {
            probes_after_end += 1;
            if probes_after_end > 2 {
                break;
            }
        }
        let source = if rng.below(100) < 35 {
            StreamSourceType::UserRequest
        } else {
            StreamSourceType::ModelGenerated
        };
        let track = source.track();
        let tasks = match track {
            StreamTrack::Request => request_tasks,
            StreamTrack::Response => response_tasks,
        };

        match rng.below(100) {
            0..=39 => {
                let runes = 1 + rng.below(40);
                let result = session.observe(source, runes);
                let _ = writeln!(
                    ops,
                    r#"{{"op":"observe","source":"{}","runes":{},"result":"{}"}}"#,
                    source_name(source),
                    runes,
                    result
                        .map(|end| end.to_string())
                        .unwrap_or_else(|error| format!("error:{error}"))
                );
            }
            40..=84 => {
                let received = session.watermark(track).received();
                // The generator needs the offset the track reached, which the
                // watermark keeps after settlement, rather than the release
                // point, which a terminal session withholds.
                let confirmed = session.watermark(track).confirmed();
                if received <= confirmed {
                    continue;
                }
                // Span shapes must include the illegal ones. A generator that
                // only emits well formed spans cannot detect a divergence in
                // any of the guards, which is the whole point of the replay.
                let (span_start, span_end) = match rng.below(100) {
                    // Contiguous from the frontier.
                    0..=54 => (confirmed, confirmed + 1 + rng.below(received - confirmed)),
                    // Overlapping backwards, which a growing segmenter emits.
                    55..=66 => (
                        start + rng.below(confirmed.saturating_sub(start) + 1),
                        confirmed + 1 + rng.below(received - confirmed),
                    ),
                    // Stale, wholly at or below the frontier.
                    67..=76 => (start, confirmed.max(start + 1)),
                    // A forward skip, which must fail closed.
                    77..=88 => {
                        let gap_start = confirmed + 1 + rng.below(8);
                        (gap_start, gap_start + 1 + rng.below(12))
                    }
                    // Past the observed end, which must fail closed.
                    _ => (confirmed, received + 1 + rng.below(30)),
                };
                if span_end <= span_start {
                    continue;
                }
                let span = match StreamSpan::new(source, span_start, span_end) {
                    Ok(span) => span,
                    Err(_) => continue,
                };
                // Sometimes name a task the track does not configure. This is
                // deliberately correlated with a refusal, because a refusal
                // returns before the watermark is consulted and is therefore
                // the only outcome where the task check is load bearing.
                let unconfigured = rng.below(100) < 6;
                let task = if unconfigured {
                    "not_a_configured_task"
                } else {
                    tasks[rng.below(tasks.len() as u32) as usize]
                };
                let outcome = if unconfigured && rng.below(100) < 40 {
                    SegmentOutcome::Denied
                } else {
                    match rng.below(1000) {
                        0..=959 => SegmentOutcome::Cleared,
                        960..=984 => SegmentOutcome::Transformed,
                        _ => SegmentOutcome::Denied,
                    }
                };
                let outcome_name = match outcome {
                    SegmentOutcome::Cleared => "cleared",
                    SegmentOutcome::Transformed => "transformed",
                    SegmentOutcome::Denied => "denied",
                };
                let result = session.record_outcome(task, &span, outcome);
                let _ = writeln!(
                    ops,
                    r#"{{"op":"record","source":"{}","task":"{}","start":{},"end":{},"outcome":"{}","result":"{}"}}"#,
                    source_name(source),
                    task,
                    span_start,
                    span_end,
                    outcome_name,
                    result
                        .map(|()| "ok".to_string())
                        .unwrap_or_else(|error| format!("error:{error}"))
                );
            }
            85..=96 => {
                let advanced = session.advance(track);
                let _ = writeln!(
                    ops,
                    r#"{{"op":"advance","track":"{}","result":{}}}"#,
                    track_name(track),
                    advanced
                        .map(|offset| offset.to_string())
                        .unwrap_or_else(|| "null".to_string())
                );
            }
            _ => {
                session.end_of_payloads();
                let _ = writeln!(ops, r#"{{"op":"end_of_payloads"}}"#);
            }
        }
    }

    // Give roughly half the cases a chance to clear their tail, so settlement
    // is exercised in both directions rather than always failing on residue.
    if !session.is_ended() && rng.below(100) < 50 {
        for track in [StreamTrack::Request, StreamTrack::Response] {
            let received = session.watermark(track).received();
            let source = match track {
                StreamTrack::Request => StreamSourceType::UserRequest,
                StreamTrack::Response => StreamSourceType::ModelGenerated,
            };
            let tasks = match track {
                StreamTrack::Request => request_tasks,
                StreamTrack::Response => response_tasks,
            };
            for task in tasks {
                let confirmed = session.watermark(track).tasks().count();
                let _ = confirmed;
                let cleared = session.watermark(track).confirmed();
                if received > cleared {
                    if let Ok(span) = StreamSpan::new(source, cleared, received) {
                        let result = session.record_outcome(task, &span, SegmentOutcome::Cleared);
                        let _ = writeln!(
                            ops,
                            r#"{{"op":"record","source":"{}","task":"{}","start":{},"end":{},"outcome":"cleared","result":"{}"}}"#,
                            source_name(source),
                            task,
                            cleared,
                            received,
                            result
                                .map(|()| "ok".to_string())
                                .unwrap_or_else(|error| format!("error:{error}"))
                        );
                    }
                }
            }
        }
    }

    let completion = session.finish();
    let reason = match &completion.reason {
        StreamEndReason::Complete => "complete".to_string(),
        StreamEndReason::Denied { track, task, range } => {
            format!(
                "denied:{}:{task}:{}:{}",
                track.as_str(),
                range.start,
                range.end
            )
        }
        StreamEndReason::Rewritten { track, task, range } => {
            format!(
                "rewritten:{}:{task}:{}:{}",
                track.as_str(),
                range.start,
                range.end
            )
        }
        StreamEndReason::Failed(error) => format!("failed:{error}"),
    };

    let _ = writeln!(
        out,
        r#"{{"case":{seed},"policy":"{policy_id}","level":"{}","start":{start},"request_tasks":[{}],"response_tasks":[{}]}}"#,
        level_name(level),
        request_tasks
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(","),
        response_tasks
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    out.push_str(&ops);
    let _ = writeln!(
        out,
        r#"{{"op":"finish","reason":"{reason}","transformed":{}}}"#,
        completion.transformed
    );
    out
}

#[test]
fn export_differential_traces() {
    let mut all = String::new();
    all.push_str("# Differential traces for cross SDK replay. Generated by the Rust core.\n");
    for seed in 1..=200u64 {
        all.push_str(&build_case(seed));
        all.push_str("---\n");
    }

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/conformance/streaming/stream-session-traces.txt"
    );
    if std::env::var("ACS_WRITE_TRACES").is_ok() {
        std::fs::write(path, &all).expect("write traces");
        return;
    }

    let committed = std::fs::read_to_string(path)
        .expect("committed trace file is missing, regenerate with ACS_WRITE_TRACES=1");
    assert_eq!(
        committed, all,
        "the Rust core no longer produces the committed traces, which is a cross SDK \
         behavior change; review it, then regenerate with ACS_WRITE_TRACES=1"
    );
}
