//! Metamorphic testing of the release accounting.
//!
//! A streaming mediator is only useful when its verdict does not depend on how
//! the transport happened to chop the text. These tests fix a payload and a
//! policy, vary the segmentation across every shape a segmenter might produce,
//! and require the outcome to be identical every time.
//!
//! The policy here is a substring search over the cumulative prefix, which is
//! the shape section 18.1 obliges a host to use. That obligation is what makes
//! the property hold, so a run with a delta only policy is included as the
//! negative control and is expected to disagree with itself.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack,
};

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

/// What one mediated run concluded.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    /// Text the caller received.
    delivered: String,
    /// Whether a refusal ended the stream.
    refused: bool,
    /// Whether the stream settled clean.
    clean: bool,
}

fn runes(text: &str) -> Vec<char> {
    text.chars().collect()
}

fn slice(text: &[char], start: u32, end: u32) -> String {
    text[start as usize..end as usize].iter().collect()
}

/// Mediate `text` cut at `boundaries`, refusing when `banned` appears in the
/// evaluated policy target.
fn mediate(
    text: &str,
    boundaries: &[u32],
    banned: &str,
    tasks: &[&str],
    level: SafetyLevel,
    delta_only: bool,
) -> Run {
    let chars = runes(text);
    let total = chars.len() as u32;
    let owned: Vec<String> = tasks.iter().map(|t| (*t).to_string()).collect();

    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: level,
        start_rune_offset: 0,
        request_tasks: owned.clone(),
        response_tasks: owned.clone(),
    })
    .expect("config is valid");

    session
        .observe(StreamSourceType::ModelGenerated, total)
        .expect("observe");

    let mut delivered = String::new();
    let mut emitted = 0u32;
    let mut cursor = 0u32;
    let mut refused = false;

    if !level.withholds() {
        delivered = text.to_string();
        emitted = total;
    }

    for &boundary in boundaries {
        if boundary <= cursor || boundary > total {
            continue;
        }
        let target = if delta_only {
            slice(&chars, cursor, boundary)
        } else {
            slice(&chars, 0, boundary)
        };
        let outcome = if target.contains(banned) {
            SegmentOutcome::Denied
        } else {
            SegmentOutcome::Cleared
        };
        let span = StreamSpan::new(StreamSourceType::ModelGenerated, cursor, boundary)
            .expect("span is valid");

        let mut denied_here = false;
        for task in &owned {
            if session.record_outcome(task, &span, outcome).is_err() {
                denied_here = true;
                break;
            }
            if session.is_ended() {
                denied_here = true;
                break;
            }
        }
        cursor = boundary;
        if denied_here || session.is_ended() {
            refused = true;
            break;
        }
        if let Some(safe) = session.advance(StreamTrack::Response) {
            if level.withholds() && safe > emitted {
                delivered.push_str(&slice(&chars, emitted, safe));
                emitted = safe;
            }
        }
    }

    // Force a final segment over any tail no boundary covered.
    if !refused && cursor < total {
        let target = if delta_only {
            slice(&chars, cursor, total)
        } else {
            text.to_string()
        };
        let outcome = if target.contains(banned) {
            SegmentOutcome::Denied
        } else {
            SegmentOutcome::Cleared
        };
        let span = StreamSpan::new(StreamSourceType::ModelGenerated, cursor, total).expect("span");
        for task in &owned {
            let _ = session.record_outcome(task, &span, outcome);
            if session.is_ended() {
                refused = true;
                break;
            }
        }
        if !refused {
            if let Some(safe) = session.advance(StreamTrack::Response) {
                if level.withholds() && safe > emitted {
                    delivered.push_str(&slice(&chars, emitted, safe));
                }
            }
        }
    }

    session.end_of_payloads();
    let completion = session.finish();
    Run {
        delivered,
        refused,
        clean: completion.reason == StreamEndReason::Complete,
    }
}

/// Every distinct way to cut `total` runes into segments, capped for cost.
fn segmentations(total: u32, seed: u64, count: usize) -> Vec<Vec<u32>> {
    let mut out: Vec<Vec<u32>> = Vec::new();
    // One shot.
    out.push(vec![total]);
    // Every fixed size.
    for size in 1..=total.min(24) {
        let mut boundaries = Vec::new();
        let mut at = size;
        while at < total {
            boundaries.push(at);
            at += size;
        }
        boundaries.push(total);
        out.push(boundaries);
    }
    // Random irregular cuts, which is what a real segmenter produces.
    let mut rng = Rng::new(seed);
    while out.len() < count {
        let mut boundaries = Vec::new();
        let mut at = 0;
        while at < total {
            at += 1 + rng.below(total.min(15));
            boundaries.push(at.min(total));
        }
        if boundaries.last() != Some(&total) {
            boundaries.push(total);
        }
        out.push(boundaries);
    }
    out
}

#[test]
fn the_verdict_does_not_depend_on_how_the_text_was_segmented() {
    let cases = [
        ("the quick brown fox jumps over the lazy dog", "forbidden"),
        ("this text contains forbidden material inside", "forbidden"),
        ("forbidden right at the very beginning of it", "forbidden"),
        ("ends with the word forbidden", "forbidden"),
        ("f o r b i d d e n is not the banned token", "forbidden"),
        ("forbidden forbidden forbidden repeated here", "forbidden"),
    ];

    for (text, banned) in cases {
        let total = runes(text).len() as u32;
        let shapes = segmentations(total, 42, 120);
        let baseline = mediate(text, &[total], banned, &["a"], SafetyLevel::Blocking, false);

        for shape in &shapes {
            let run = mediate(text, shape, banned, &["a"], SafetyLevel::Blocking, false);
            assert_eq!(
                run.refused, baseline.refused,
                "text {text:?} segmentation {shape:?} disagreed on refusal"
            );
            assert_eq!(
                run.clean, baseline.clean,
                "text {text:?} segmentation {shape:?} disagreed on settlement"
            );
            // A refused stream may deliver a harmless prefix, and how much
            // depends on where the cuts fell, but it can never deliver the
            // banned token itself.
            if run.refused {
                assert!(
                    !run.delivered.contains(banned),
                    "text {text:?} segmentation {shape:?} delivered the banned token"
                );
            } else {
                assert_eq!(
                    run.delivered, text,
                    "text {text:?} segmentation {shape:?} lost or altered text"
                );
            }
        }
    }
}

#[test]
fn the_verdict_is_stable_across_task_counts_and_safety_levels() {
    let text = "a benign opening and then forbidden content follows here";
    let banned = "forbidden";
    let total = runes(text).len() as u32;
    let shapes = segmentations(total, 7, 60);

    for tasks in [
        &["a"][..],
        &["a", "b"][..],
        &["a", "b", "c"][..],
        &["harm", "pii", "jailbreak", "copyright"][..],
    ] {
        for level in [SafetyLevel::Blocking, SafetyLevel::Complete] {
            for shape in &shapes {
                let run = mediate(text, shape, banned, tasks, level, false);
                assert!(
                    run.refused,
                    "tasks {tasks:?} level {level:?} shape {shape:?} failed to refuse"
                );
                assert!(
                    !run.delivered.contains(banned),
                    "tasks {tasks:?} level {level:?} shape {shape:?} delivered the banned token"
                );
                assert!(!run.clean, "a refused stream settled clean");
            }
        }
    }
}

#[test]
fn delta_only_evaluation_is_the_negative_control_and_does_depend_on_segmentation() {
    // Proves the metamorphic property above is earned by the cumulative policy
    // target rather than holding for free. A host that evaluates only the newest
    // segment reaches different verdicts for the same text.
    let text = "aaaa forbidden bbbb";
    let banned = "forbidden";
    let total = runes(text).len() as u32;

    let mut refusals = 0;
    let mut passes = 0;
    for shape in segmentations(total, 99, 60) {
        let run = mediate(text, &shape, banned, &["a"], SafetyLevel::Blocking, true);
        if run.refused {
            refusals += 1;
        } else {
            passes += 1;
        }
    }

    assert!(
        refusals > 0 && passes > 0,
        "delta only evaluation should disagree with itself across segmentations, \
         saw {refusals} refusals and {passes} passes"
    );
}

#[test]
fn a_refused_stream_never_delivers_the_banned_token_under_any_segmentation() {
    // The security property, stated directly and searched hard.
    let mut rng = Rng::new(2024);
    for _ in 0..400 {
        let filler_len = 1 + rng.below(30);
        let filler: String = (0..filler_len).map(|_| 'x').collect();
        let tail_len = rng.below(20);
        let tail: String = (0..tail_len).map(|_| 'y').collect();
        let text = format!("{filler}forbidden{tail}");
        let total = runes(&text).len() as u32;

        for shape in segmentations(total, rng.next(), 25) {
            let run = mediate(
                &text,
                &shape,
                "forbidden",
                &["a", "b"],
                SafetyLevel::Blocking,
                false,
            );
            assert!(run.refused, "text {text:?} shape {shape:?} did not refuse");
            assert!(
                !run.delivered.contains("forbidden"),
                "text {text:?} shape {shape:?} delivered {:?}",
                run.delivered
            );
        }
    }
}
