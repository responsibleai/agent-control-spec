//! Property based testing of the release accounting invariants.
//!
//! A seeded generator drives random operation sequences at a session while a
//! shadow model tracks what the accounting is supposed to conclude. Every
//! invariant is checked after every operation, so a violation is reported at
//! the operation that caused it rather than at the end of the run.
//!
//! The generator is deliberately hostile. It emits stale spans, duplicate
//! spans, overlapping spans, spans that skip forward, spans past the observed
//! end, outcomes for unconfigured tasks, and operations after the session went
//! terminal. Sessions are built across varied policy configurations, because a
//! single task set exercises none of the per track task partitioning.
//!
//! No external crate is used. The generator is a seeded xorshift, so any
//! failure prints a seed that reproduces it exactly.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    RuneRange, SafetyLevel, SegmentOutcome, StreamEndReason, StreamError, StreamSession,
    StreamSessionConfig, StreamSourceType, StreamSpan, StreamTrack, MAX_RUNE_OFFSET,
};
use std::collections::BTreeMap;

/// Deterministic generator so every failure carries a reproducing seed.
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

    fn chance(&mut self, percent: u32) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u32) as usize]
    }
}

/// A policy configuration under test.
///
/// Distinct policy identities carry distinct task sets, because the partition
/// of tasks across tracks is exactly what a shared set would hide.
struct PolicyFixture {
    id: &'static str,
    request_tasks: Vec<String>,
    response_tasks: Vec<String>,
}

fn policies() -> Vec<PolicyFixture> {
    let owned = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
    vec![
        PolicyFixture {
            id: "policy.single",
            request_tasks: owned(&["harm"]),
            response_tasks: owned(&["harm"]),
        },
        PolicyFixture {
            id: "policy.split",
            request_tasks: owned(&["jailbreak"]),
            response_tasks: owned(&["harm", "pii"]),
        },
        PolicyFixture {
            id: "policy.wide",
            request_tasks: owned(&["jailbreak", "profanity"]),
            response_tasks: owned(&["harm", "pii", "copyright", "self_harm"]),
        },
        PolicyFixture {
            id: "policy.asymmetric",
            request_tasks: owned(&["only_request"]),
            response_tasks: owned(&["a", "b", "c"]),
        },
    ]
}

/// What the accounting is supposed to conclude, tracked independently.
struct Shadow {
    cleared: BTreeMap<String, u32>,
    received: u32,
    confirmed: u32,
    start: u32,
}

impl Shadow {
    fn new(tasks: &[String], start: u32) -> Self {
        Self {
            cleared: tasks.iter().map(|t| (t.clone(), start)).collect(),
            received: start,
            confirmed: start,
            start,
        }
    }

    fn min_cleared(&self) -> u32 {
        self.cleared.values().copied().min().unwrap_or(self.start)
    }
}

struct Harness {
    session: StreamSession,
    request: Shadow,
    response: Shadow,
    /// Highest offset the host was ever told it could release, per track.
    released: BTreeMap<StreamTrack, u32>,
    terminal: Option<StreamEndReason>,
}

impl Harness {
    fn shadow(&self, track: StreamTrack) -> &Shadow {
        match track {
            StreamTrack::Request => &self.request,
            StreamTrack::Response => &self.response,
        }
    }

    fn shadow_mut(&mut self, track: StreamTrack) -> &mut Shadow {
        match track {
            StreamTrack::Request => &mut self.request,
            StreamTrack::Response => &mut self.response,
        }
    }

    /// I2 monotonicity, I3 minimum, I1 safety.
    fn check_invariants(&mut self, seed: u64, step: usize, what: &str) {
        for track in [StreamTrack::Request, StreamTrack::Response] {
            let observed = self.session.safe_offset(track);

            // I2: the safe offset never moves backwards.
            let previously = *self.released.get(&track).unwrap_or(&0);
            assert!(
                observed >= previously,
                "seed {seed} step {step} after {what}: {track:?} safe offset went backwards, \
                 {previously} then {observed}"
            );
            self.released.insert(track, observed);

            // I1 and I3 hold only while the session is live. A terminal session
            // reports the offset it froze at, which is checked by I4.
            if self.session.is_ended() {
                continue;
            }

            let shadow = self.shadow(track);
            // I3: the released offset is the minimum across the track's tasks,
            // and never ahead of it.
            assert!(
                observed <= shadow.min_cleared(),
                "seed {seed} step {step} after {what}: {track:?} released {observed} past the \
                 minimum cleared {}",
                shadow.min_cleared()
            );

            // I1 (safety): nothing is released that was not observed first.
            assert!(
                observed <= shadow.received,
                "seed {seed} step {step} after {what}: {track:?} released {observed} past \
                 received {}",
                shadow.received
            );
        }
    }
}

fn run_one(seed: u64) {
    let mut rng = Rng::new(seed);
    let fixtures = policies();
    let policy = rng.pick(&fixtures);
    let level = *rng.pick(&[
        SafetyLevel::Blocking,
        SafetyLevel::Complete,
        SafetyLevel::Deferred,
    ]);
    // Include a resumed session, whose offsets do not start at zero.
    let start = if rng.chance(25) { rng.below(5_000) } else { 0 };

    let config = StreamSessionConfig {
        safety_level: level,
        request_start_rune_offset: start,
        response_start_rune_offset: start,
        request_tasks: policy.request_tasks.clone(),
        response_tasks: policy.response_tasks.clone(),
    };
    let session = match StreamSession::new(config) {
        Ok(session) => session,
        Err(error) => panic!("seed {seed}: policy {} rejected: {error}", policy.id),
    };

    let mut harness = Harness {
        session,
        request: Shadow::new(&policy.request_tasks, start),
        response: Shadow::new(&policy.response_tasks, start),
        released: BTreeMap::new(),
        terminal: None,
    };

    let all_tasks: Vec<String> = policy
        .request_tasks
        .iter()
        .chain(policy.response_tasks.iter())
        .cloned()
        .collect();

    let steps = 40 + rng.below(60) as usize;
    for step in 0..steps {
        let source = if rng.chance(40) {
            StreamSourceType::UserRequest
        } else {
            StreamSourceType::ModelGenerated
        };
        let track = source.track();

        match rng.below(100) {
            // Observe more text.
            0..=34 => {
                let runes = 1 + rng.below(50);
                let before = harness.session.is_ended();
                let result = harness.session.observe(source, runes);
                match result {
                    Ok(end) => {
                        assert!(
                            !before,
                            "seed {seed} step {step}: observe succeeded after end"
                        );
                        let shadow = harness.shadow_mut(track);
                        shadow.received += runes;
                        assert_eq!(
                            end, shadow.received,
                            "seed {seed} step {step}: observe returned {end}, shadow says {}",
                            shadow.received
                        );
                    }
                    Err(error) => {
                        // Only legal refusals.
                        assert!(
                            matches!(
                                error,
                                StreamError::SessionClosed
                                    | StreamError::PayloadsClosed
                                    | StreamError::OffsetOverflow
                                    // A transform rebases the track's offsets
                                    // against the text the host will emit, so
                                    // no later payload on it can be counted.
                                    | StreamError::PayloadAfterTransform { .. }
                            ),
                            "seed {seed} step {step}: unexpected observe error {error}"
                        );
                    }
                }
                harness.check_invariants(seed, step, "observe");
            }

            // Record an outcome, sometimes hostile.
            35..=89 => {
                let shadow = harness.shadow(track);
                let received = shadow.received;
                let frontier = shadow.min_cleared();
                if received <= shadow.start {
                    continue;
                }

                // Choose a span shape, including illegal ones.
                let (span_start, span_end) = match rng.below(100) {
                    // Contiguous from the frontier, the well behaved case.
                    0..=54 => {
                        let end = frontier + 1 + rng.below((received - frontier).max(1));
                        (frontier, end.min(received))
                    }
                    // Overlapping, which a growing segmenter emits.
                    55..=69 => {
                        let s = shadow.start + rng.below(frontier.saturating_sub(shadow.start) + 1);
                        let end = frontier + 1 + rng.below((received - frontier).max(1));
                        (s, end.min(received))
                    }
                    // Stale, wholly below the frontier.
                    70..=79 => {
                        let s = shadow.start;
                        (s, frontier.max(shadow.start + 1))
                    }
                    // A forward skip, which must fail closed.
                    80..=89 => {
                        let s = frontier + 1 + rng.below(10);
                        (s, (s + 1 + rng.below(20)).min(received.max(s + 1)))
                    }
                    // Past the observed end, which must fail closed.
                    _ => (frontier, received + 1 + rng.below(100)),
                };

                if span_end <= span_start {
                    continue;
                }
                let span = match StreamSpan::new(source, span_start, span_end) {
                    Ok(span) => span,
                    Err(_) => continue,
                };

                // Sometimes name a task from the other track, or a bogus one.
                let task = if rng.chance(12) {
                    rng.pick(&all_tasks).clone()
                } else if rng.chance(4) {
                    "not_a_configured_task".to_string()
                } else {
                    let tasks = match track {
                        StreamTrack::Request => &policy.request_tasks,
                        StreamTrack::Response => &policy.response_tasks,
                    };
                    rng.pick(tasks).clone()
                };

                let outcome = match rng.below(100) {
                    0..=88 => SegmentOutcome::Cleared,
                    89..=95 => SegmentOutcome::Transformed,
                    _ => SegmentOutcome::Denied,
                };

                let track_tasks = match track {
                    StreamTrack::Request => &policy.request_tasks,
                    StreamTrack::Response => &policy.response_tasks,
                };
                let task_belongs = track_tasks.contains(&task);
                let was_ended = harness.session.is_ended();
                let confirmed_before = harness.session.safe_offset(track);

                // The model's own verdict, computed before the call so both
                // directions can be checked against it. Asserting only that a
                // refusal was predicted leaves a fail open invisible, which is
                // the direction that actually releases text, so the acceptance
                // arm asserts the contrapositive against this same expression.
                let model_refuses = was_ended
                    || !task_belongs
                    || span_end > received
                    // Contiguity governs clearance only. A denial clears
                    // nothing and is terminal wherever it lands, so it is
                    // accepted over a gap that a clearing outcome could not
                    // confirm.
                    || !matches!(outcome, SegmentOutcome::Denied) && {
                        let shadow = harness.shadow(track);
                        let current = shadow.cleared.get(&task).copied().unwrap_or(shadow.start);
                        span_end > current && span_start > current
                    }
                    // A transform names a node of the policy target, whose
                    // extent the session cannot know, so it is refused once any
                    // rune on the track was released. A session resuming above
                    // zero has already delivered its prefix, so it can never
                    // transform.
                    || matches!(outcome, SegmentOutcome::Transformed)
                        && (!level.withholds() || confirmed_before > 0);

                let result = harness.session.record_outcome(&task, &span, outcome);

                match result {
                    Ok(()) => {
                        // The fail open direction. Anything the model would
                        // have refused must not have been accepted here.
                        assert!(
                            !model_refuses,
                            "seed {seed} step {step}: fail open, accepted a {outcome:?} the                              model refuses for task {task} span [{span_start},{span_end})                              received {received} confirmed {confirmed_before} level {level:?}"
                        );
                        assert!(
                            !was_ended,
                            "seed {seed} step {step}: outcome accepted after session end"
                        );
                        assert!(
                            task_belongs,
                            "seed {seed} step {step}: outcome accepted for foreign task {task}"
                        );
                        assert!(
                            span_end <= received,
                            "seed {seed} step {step}: outcome accepted past received"
                        );
                        match outcome {
                            SegmentOutcome::Denied => {
                                assert!(
                                    harness.session.is_ended(),
                                    "seed {seed} step {step}: denial did not end the session"
                                );
                                harness.terminal = harness.session.end_reason().cloned();
                            }
                            _ => {
                                // The shadow advances only when the span is
                                // contiguous with this task's frontier.
                                let shadow = harness.shadow_mut(track);
                                let current =
                                    shadow.cleared.get(&task).copied().unwrap_or(shadow.start);
                                if span_end > current {
                                    assert!(
                                        span_start <= current,
                                        "seed {seed} step {step}: non contiguous span accepted, \
                                         task at {current}, span starts {span_start}"
                                    );
                                    shadow.cleared.insert(task.clone(), span_end);
                                }
                            }
                        }
                    }
                    Err(error) => {
                        // The over refusal direction. Every refusal must be one
                        // the model predicts.
                        assert!(
                            model_refuses,
                            "seed {seed} step {step}: unpredicted refusal {error} for task \
                             {task} span [{span_start},{span_end}) received {received}"
                        );
                        if !was_ended {
                            harness.terminal = harness.session.end_reason().cloned();
                        }
                    }
                }
                harness.check_invariants(seed, step, "record_outcome");
            }

            // Advance the watermark.
            90..=97 => {
                let before = harness.session.safe_offset(track);
                let advanced = harness.session.advance(track);
                let after = harness.session.safe_offset(track);
                if let Some(offset) = advanced {
                    assert_eq!(
                        offset, after,
                        "seed {seed} step {step}: advance returned {offset} but offset is {after}"
                    );
                    assert!(
                        after > before,
                        "seed {seed} step {step}: advance reported progress without progress"
                    );
                } else {
                    assert_eq!(
                        before, after,
                        "seed {seed} step {step}: advance reported no progress but moved"
                    );
                }
                if !harness.session.is_ended() {
                    let expected = harness.shadow(track).min_cleared();
                    assert_eq!(
                        after, expected,
                        "seed {seed} step {step}: {track:?} offset {after} disagrees with the \
                         model minimum {expected}"
                    );
                    harness.shadow_mut(track).confirmed = after;
                }
                harness.check_invariants(seed, step, "advance");
            }

            // Close payloads early.
            _ => {
                harness.session.end_of_payloads();
                harness.check_invariants(seed, step, "end_of_payloads");
            }
        }

        // I4: a terminal reason, once set, never changes.
        if let Some(recorded) = &harness.terminal {
            if let Some(current) = harness.session.end_reason() {
                assert_eq!(
                    recorded, current,
                    "seed {seed} step {step}: terminal reason changed"
                );
            }
        }
    }

    // I5: settling clean implies every observed rune was cleared by every task.
    let ended_before = harness.session.is_ended();
    let completion = harness.session.finish();
    if completion.reason == StreamEndReason::Complete {
        assert!(
            !ended_before,
            "seed {seed}: a terminal session settled Complete"
        );
        for track in [StreamTrack::Request, StreamTrack::Response] {
            let shadow = harness.shadow(track);
            assert_eq!(
                shadow.min_cleared(),
                shadow.received,
                "seed {seed}: settled clean with {track:?} residue, cleared {} received {}",
                shadow.min_cleared(),
                shadow.received
            );
        }
    }

    // I4: nothing is released after settlement.
    for track in [StreamTrack::Request, StreamTrack::Response] {
        let after = harness.session.safe_offset(track);
        let peak = *harness.released.get(&track).unwrap_or(&0);
        assert!(
            after <= peak.max(after),
            "seed {seed}: offset grew after settlement"
        );
    }
}

#[test]
fn invariants_hold_across_random_hostile_operation_sequences() {
    for seed in 1..=4_000u64 {
        run_one(seed);
    }
}

#[test]
fn contiguity_is_never_violated_under_adversarial_ordering() {
    // Focused search for a confirmed gap, which is the fail open this design
    // exists to prevent.
    for seed in 1..=2_000u64 {
        let mut rng = Rng::new(seed.wrapping_mul(2_654_435_761));
        let tasks = vec!["a".to_string(), "b".to_string()];
        let mut session = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: tasks.clone(),
            response_tasks: tasks.clone(),
        })
        .expect("config is valid");

        let total = 200 + rng.below(300);
        session
            .observe(StreamSourceType::ModelGenerated, total)
            .expect("observe");

        // A record of which runes some accepted outcome actually covered.
        let mut covered = vec![false; total as usize];
        let mut per_task: BTreeMap<String, u32> = tasks.iter().map(|t| (t.clone(), 0)).collect();

        for _ in 0..60 {
            if session.is_ended() {
                break;
            }
            let task = rng.pick(&tasks).clone();
            let start = rng.below(total);
            let end = start + 1 + rng.below(40);
            if end > total {
                continue;
            }
            let span = match StreamSpan::new(StreamSourceType::ModelGenerated, start, end) {
                Ok(span) => span,
                Err(_) => continue,
            };
            if session
                .record_outcome(&task, &span, SegmentOutcome::Cleared)
                .is_ok()
                && !session.is_ended()
            {
                let current = per_task[&task];
                if end > current {
                    per_task.insert(task.clone(), end);
                }
                for rune in start..end {
                    covered[rune as usize] = true;
                }
            }
        }

        session.advance(StreamTrack::Response);
        let safe = session.safe_offset(StreamTrack::Response);

        // Every rune below the safe offset must have been covered by an
        // outcome that was actually accepted.
        for rune in 0..safe {
            assert!(
                covered[rune as usize],
                "seed {seed}: rune {rune} is below the safe offset {safe} but no accepted \
                 outcome ever covered it"
            );
        }
    }
}

#[test]
fn offset_ceiling_arithmetic_never_wraps() {
    // A wrapped offset reads as a released prefix, so the ceiling is a
    // security boundary rather than a range check.
    for start in [0u32, 1, MAX_RUNE_OFFSET - 10, MAX_RUNE_OFFSET] {
        let mut session = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: start,
            response_start_rune_offset: start,
            request_tasks: vec!["t".to_string()],
            response_tasks: vec!["t".to_string()],
        })
        .expect("config is valid");

        for _ in 0..4 {
            match session.observe(StreamSourceType::ModelGenerated, u32::MAX / 3) {
                Ok(end) => assert!(
                    end <= MAX_RUNE_OFFSET,
                    "observe returned {end} which is past the ceiling"
                ),
                Err(error) => {
                    assert_eq!(error, StreamError::OffsetOverflow);
                    break;
                }
            }
        }
        assert!(session.safe_offset(StreamTrack::Response) <= MAX_RUNE_OFFSET);
    }

    // A span cannot be constructed past the ceiling.
    assert!(StreamSpan::new(StreamSourceType::ModelGenerated, 0, u32::MAX).is_err());
    assert!(StreamSpan::new(
        StreamSourceType::ModelGenerated,
        MAX_RUNE_OFFSET - 1,
        MAX_RUNE_OFFSET
    )
    .is_ok());
}

#[test]
fn a_denial_is_never_downgraded_by_any_later_operation() {
    for seed in 1..=500u64 {
        let mut rng = Rng::new(seed);
        let mut session = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: vec!["t".to_string()],
            response_tasks: vec!["t".to_string()],
        })
        .expect("config is valid");
        session
            .observe(StreamSourceType::ModelGenerated, 100)
            .expect("observe");
        let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 50).expect("span");
        session
            .record_outcome("t", &span, SegmentOutcome::Denied)
            .expect("denial records");

        let expected = StreamEndReason::Denied {
            task: "t".to_string(),
            range: RuneRange { start: 0, end: 50 },
        };

        // Throw everything at it.
        for _ in 0..20 {
            let _ = session.observe(StreamSourceType::ModelGenerated, 1 + rng.below(10));
            let s = rng.below(90);
            if let Ok(span) = StreamSpan::new(StreamSourceType::ModelGenerated, s, s + 1) {
                let _ = session.record_outcome("t", &span, SegmentOutcome::Cleared);
                let _ = session.record_outcome("nope", &span, SegmentOutcome::Cleared);
            }
            let _ = session.advance(StreamTrack::Response);
            session.end_of_payloads();
            assert_eq!(
                session.end_reason(),
                Some(&expected),
                "seed {seed}: the denial was replaced"
            );
        }
        assert_eq!(session.finish().reason, expected);
    }
}
