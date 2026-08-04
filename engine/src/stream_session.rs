//! Release accounting for a host that emits model output before the whole
//! response exists.
//!
//! Section 18 of the specification requires a host to assemble a whole
//! snapshot before `post_model_call`. That rule keeps the runtime stateless
//! and deterministic, and it remains the default. It also forces a host to
//! withhold every token until generation finishes, which removes the
//! latency that is the whole product for callers who deliver incrementally.
//!
//! This module supplies the one piece such a host cannot get from the
//! runtime: the accounting that decides which prefix of an in flight stream
//! is safe to release once several independent tasks have each evaluated
//! parts of it. The runtime itself is untouched.
//!
//! # A session holds no text
//!
//! A session stores offsets, not stream content. The host already owns the
//! accumulated text, because the host is what receives the payloads, and the
//! host already decides how to cut that text into the units it evaluates. A
//! content safety request handler, for instance, keeps its own accumulated
//! buffer and runs its own segmenter over it.
//!
//! Duplicating either of those here would be worse than redundant. A session
//! that also chose a policy target would give a host whose segmenter chose a
//! different one two disagreeing accounts of what was evaluated over the same
//! runes. So the host declares the range it evaluated, and the session tracks
//! only what that clears.
//!
//! This leaves the host owing three obligations that a session cannot check
//! for it:
//!
//! 1. The text evaluated for a span covers at least that span. A policy
//!    target smaller than the span it gates lets a banned term slip through a
//!    segment boundary, because the policy sees `for`, then `bidden`, and
//!    allows both.
//! 2. The rune counts reported match the text accumulated.
//! 3. The outcomes fed in come from enforcement and not from an
//!    `evaluate_only` evaluation. A cleared span releases text, which
//!    specification section 20 forbids presenting an `evaluate_only` result as
//!    doing. No verdict carries the mode, so nothing here can check it.
//!
//! One capability limit is worth stating plainly, because it is not obvious
//! from the types. A `transform` ends the session. The substitution replaces
//! the policy target with a new whole value, and two things are then true of
//! it at once: its runes are not the ones this session counted, and no task
//! evaluated it. So the accounting can neither address it by offset nor vouch
//! for it, and it reports [`StreamEndReason::Rewritten`] instead of a
//! watermark. The host evaluates the replacement on the ordinary whole
//! snapshot path, where every task sees the value actually being emitted.
//!
//! Masking a value mid stream and continuing to stream is therefore outside
//! this profile. Lifting that would need the outcome to carry the
//! replacement's rune count, so the accounting could rebase, and a way for the
//! remaining tasks to evaluate the replacement rather than the text it
//! replaced. Neither exists here, and inventing either without them is what
//! three earlier attempts at this rule each did, in a different way.
//!
//! # Clearance is contiguous
//!
//! A task clears a span by recording an outcome for it, and that task's
//! offset advances only when the span starts at or below the task's current
//! frontier. A span starting past the frontier fails closed instead of
//! confirming the gap between them, which nothing evaluated. Overlapping
//! spans are accepted, which is what a growing or sliding segmenter emits.
//!
//! Offsets are rune offsets, counted in Unicode scalar values, because that
//! is the unit the external streaming contract uses. Byte offsets and UTF-16
//! code unit offsets are not interchangeable with them.

use agent_hooks::{Decision, InterceptionPoint, Verdict};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Largest rune offset a session may reach.
///
/// The external streaming contract carries offsets as signed 32 bit
/// integers. A session that would exceed that range fails closed instead of
/// wrapping, because a wrapped offset reads as a released prefix.
pub const MAX_RUNE_OFFSET: u32 = i32::MAX as u32;

/// Reserved reason a host records when a streaming session fails closed.
///
/// This is a `host_error` because release accounting is a host obligation. The
/// engine returns a verdict and never sees the stream. Section 16 keeps the
/// older `runtime_error:streaming_unsupported` reserved for compatibility while
/// the language SDKs are rebuilt, and requires new code to use the agent-hooks
/// reason, which this is.
pub const STREAMING_FAIL_CLOSED_REASON: &str = "host_error:streaming_unsupported";

/// How much of an evaluated stream a host may release before the
/// corresponding policy decisions exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// How much a host may release ahead of the watermark.
///
/// `Blocking` and `Complete` are deliberately identical to this accounting.
/// Section 18.1 groups them: under either, a host withholds a rune until the
/// watermark covers it, so there is one release rule and no code here reads
/// them apart. They stay distinct because the level is part of the contract a
/// host receives and must round trip, and because they differ in what the host
/// asks a policy to evaluate, which is the host's concern and not the
/// accounting's. `Deferred` is the only level this module branches on, through
/// [`SafetyLevel::withholds`].
pub enum SafetyLevel {
    /// Hold every span until the watermark covers it.
    Blocking,
    /// Hold every span until the watermark covers it. Distinct from
    /// `Blocking` on the wire and identical in release behavior.
    Complete,
    /// Emit each payload as it arrives and evaluate behind the stream.
    /// Denials still terminate the session, and content already emitted
    /// cannot be recalled.
    Deferred,
}

impl SafetyLevel {
    /// Wire name used by the external streaming contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Complete => "complete",
            Self::Deferred => "deferred",
        }
    }

    /// Parse a wire name. Unknown values fail closed rather than defaulting
    /// to the permissive level.
    pub fn parse(value: &str) -> Result<Self, StreamError> {
        match value {
            "blocking" => Ok(Self::Blocking),
            "complete" => Ok(Self::Complete),
            "deferred" => Ok(Self::Deferred),
            other => Err(StreamError::UnknownSafetyLevel(other.to_string())),
        }
    }

    /// Whether a host must wait for the watermark before emitting a span.
    pub fn withholds(self) -> bool {
        matches!(self, Self::Blocking | Self::Complete)
    }
}

/// Role that produced a span of stream text.
///
/// Only roles whose content is genuinely a rune addressable text stream
/// appear here. Tool calls and tool results are structured values evaluated
/// once per concrete invocation under section 18, not streams, so they are
/// deliberately absent. A host mediates those through the ordinary whole
/// snapshot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamSourceType {
    /// Text authored by the caller.
    UserRequest,
    /// Text generated by the model.
    ModelGenerated,
}

impl StreamSourceType {
    /// Wire name used by the external streaming contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserRequest => "user_request",
            Self::ModelGenerated => "model_generated",
        }
    }

    /// Parse a wire name. Unknown values fail closed.
    pub fn parse(value: &str) -> Result<Self, StreamError> {
        match value {
            "user_request" => Ok(Self::UserRequest),
            "model_generated" => Ok(Self::ModelGenerated),
            other => Err(StreamError::UnknownSourceType(other.to_string())),
        }
    }

    /// Interception point that evaluates this role.
    pub fn interception_point(self) -> InterceptionPoint {
        match self {
            Self::UserRequest => InterceptionPoint::Input,
            Self::ModelGenerated => InterceptionPoint::PostModelCall,
        }
    }

    /// Track this role accumulates on.
    pub fn track(self) -> StreamTrack {
        match self {
            Self::UserRequest => StreamTrack::Request,
            Self::ModelGenerated => StreamTrack::Response,
        }
    }
}

/// Independent offset space within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamTrack {
    Request,
    Response,
}

impl StreamTrack {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// A fail closed condition in the streaming accounting.
///
/// Most variants put a session into its terminal state. Two do not:
/// [`StreamError::UnknownSafetyLevel`] and [`StreamError::UnknownSourceType`]
/// come from parsing wire values before a session exists, so they have nothing
/// to terminate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    UnknownSafetyLevel(String),
    UnknownSourceType(String),
    /// A track was configured with no tasks, so no task could ever clear a
    /// span and its watermark could never advance.
    NoTasks(StreamTrack),
    /// An outcome named a task the track was not configured with.
    UnknownTask {
        track: StreamTrack,
        task: String,
    },
    /// A span covered no runes, so it could not clear anything.
    EmptySpan,
    /// An outcome named a range that runs past the text the session has been
    /// told about.
    OffsetPastEnd {
        offset: u32,
        received: u32,
    },
    /// The session reached the offset ceiling of the external contract.
    OffsetOverflow,
    /// A payload arrived after the payload stream closed.
    PayloadsClosed,
    /// An outcome or payload arrived after the session went terminal.
    SessionClosed,
    /// A `transform` outcome reached text the host can no longer alter,
    /// either because the safety level already emitted it or because the
    /// watermark already released it.
    TransformTooLate,
    /// A verdict the contract forbids reached the session, such as a
    /// `transform` carrying no transform body.
    VerdictInvalid,
    /// The payload stream ended while text remained uncleared.
    /// Runes that no task cleared were still outstanding at settlement.
    ///
    /// A session may hold residue on both tracks. This names the first in
    /// track order, request before response, so the reason is deterministic.
    /// The host fails closed over the whole session either way, so the choice
    /// affects which track the audit record names and nothing else.
    UnclearedResidue {
        track: StreamTrack,
        pending: u32,
    },
    /// An outcome was recorded for a span that does not continue from where
    /// the task had already cleared. Accepting it would release the gap.
    NonContiguousOutcome {
        task: String,
        expected: u32,
        found: u32,
    },
}

/// Reserved reason for a verdict whose shape the contract forbids.
///
/// The agent-hooks reserved set already names this failure, so a malformed
/// verdict is reported as one rather than as a streaming fault.
pub const VERDICT_INVALID_REASON: &str = "host_error:verdict_invalid";

impl StreamError {
    /// Reserved reason a host records when this failure denies an action.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::VerdictInvalid => VERDICT_INVALID_REASON,
            _ => STREAMING_FAIL_CLOSED_REASON,
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSafetyLevel(value) => {
                write!(f, "unknown streaming safety level {value}")
            }
            Self::UnknownSourceType(value) => write!(f, "unknown stream source type {value}"),
            Self::NoTasks(track) => {
                write!(f, "{} track configured with no tasks", track.as_str())
            }
            Self::UnknownTask { track, task } => write!(
                f,
                "outcome named task {task} which the {} track does not configure",
                track.as_str()
            ),
            Self::EmptySpan => f.write_str("span covers no runes"),
            Self::OffsetPastEnd { offset, received } => write!(
                f,
                "outcome offset {offset} runs past {received} observed runes"
            ),
            Self::OffsetOverflow => f.write_str("streaming session exceeded the offset ceiling"),
            Self::PayloadsClosed => f.write_str("streaming payload stream already closed"),
            Self::SessionClosed => f.write_str("streaming session already closed"),
            Self::TransformTooLate => {
                f.write_str("transform outcome named text the host has already emitted")
            }
            Self::VerdictInvalid => {
                f.write_str("verdict shape is invalid under the interception contract")
            }
            Self::UnclearedResidue { track, pending } => write!(
                f,
                "{} track ended with {pending} uncleared runes",
                track.as_str()
            ),
            Self::NonContiguousOutcome {
                task,
                expected,
                found,
            } => write!(
                f,
                "task {task} cleared through {expected} so an outcome starting at {found} would release a gap"
            ),
        }
    }
}

impl Error for StreamError {}

/// Half open rune range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuneRange {
    pub start: u32,
    pub end: u32,
}

impl RuneRange {
    pub fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.end <= self.start
    }
}

/// A range of one track that the host evaluated as a unit.
///
/// The host builds this from whatever its segmenter produced. The session
/// never constructs spans from text, because it holds none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSpan {
    pub source_type: StreamSourceType,
    pub range: RuneRange,
}

impl StreamSpan {
    /// Build a span over the half open rune range `[start, end)`.
    pub fn new(source_type: StreamSourceType, start: u32, end: u32) -> Result<Self, StreamError> {
        if end <= start {
            return Err(StreamError::EmptySpan);
        }
        if end > MAX_RUNE_OFFSET {
            return Err(StreamError::OffsetOverflow);
        }
        Ok(Self {
            source_type,
            range: RuneRange { start, end },
        })
    }

    /// Track this span accumulates on.
    pub fn track(&self) -> StreamTrack {
        self.source_type.track()
    }

    /// Interception point that evaluates this span.
    pub fn interception_point(&self) -> InterceptionPoint {
        self.source_type.interception_point()
    }
}

/// What a host decided for one span after evaluating it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentOutcome {
    /// The policy permitted the evaluated text unchanged.
    Cleared,
    /// The policy replaced the policy target, so the host emits a substitute.
    ///
    /// Recording one **ends the session** with [`StreamEndReason::Rewritten`].
    /// It clears nothing and moves no frontier. Under section 14 a transform
    /// names a node of the policy target rather than a rune range, so the value
    /// it produces is a new whole value whose runes are not the ones this
    /// session counted and which no task evaluated. The accounting can neither
    /// address it by offset nor vouch for it, so it reports no watermark and
    /// stops. The host applies the replacement, evaluates it on the ordinary
    /// whole snapshot path, and starts a new session if it must keep streaming.
    ///
    /// It is honored only while nothing on the track has been released, since
    /// otherwise the host can no longer alter the text it rewrites.
    Transformed,
    /// The policy refused the text, or an escalation did not resolve to an
    /// allow.
    Denied,
}

/// Reason a session reached its terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEndReason {
    /// Every observed rune was cleared by every task.
    Complete,
    /// A host recorded a denial.
    Denied {
        /// Track the refused span belongs to.
        track: StreamTrack,
        /// Task that refused it.
        task: String,
        /// Range it refused.
        range: RuneRange,
    },
    /// A task replaced the policy target, so the stream ended rewritten.
    ///
    /// The replacement is a new whole value. Its runes are not the runes this
    /// session counted, and no task on the track evaluated it, so the
    /// accounting cannot authorize releasing it and reports no watermark for
    /// it. The host emits the replacement only after evaluating it on the
    /// ordinary whole snapshot path of section 18, and starts a new session if
    /// it must keep streaming.
    Rewritten {
        /// Track that was rewritten.
        track: StreamTrack,
        /// Task that produced the substitution.
        task: String,
        /// Range it reported.
        range: RuneRange,
    },
    /// The session failed closed.
    Failed(StreamError),
}

impl StreamEndReason {
    /// Whether the stream finished without an enforcement action.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Terminal settlement of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCompletion {
    pub reason: StreamEndReason,
    /// Whether the host emitted a substitute rather than verbatim model
    /// output, which is exactly `reason` being
    /// [`StreamEndReason::Rewritten`]. Kept as its own member because a host
    /// reporting whether a response was modified should not have to match on
    /// the terminal reason to find out.
    pub transformed: bool,
}

/// Monotonic minimum offset across a fixed set of tasks.
///
/// Each task reports how far into the track it has cleared. The confirmed
/// offset is the smallest of those, so a prefix is released only when no
/// configured task is still behind it. A task that stalls holds the whole
/// track, which is the intended behavior.
///
/// A host reads one through [`StreamSession::watermark`] and cannot mutate it.
/// Every method that moves an offset is crate internal, because advancing a
/// task outside [`StreamSession::record_outcome`] would skip the task, span,
/// offset, and transform checks that stand between an outcome and a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWatermark {
    tasks: BTreeMap<String, u32>,
    confirmed: u32,
    received: u32,
}

impl StreamWatermark {
    /// Build a watermark over `tasks`, with every task starting at
    /// `start_offset`.
    ///
    /// A test convenience for exercising the watermark on its own. A session
    /// builds both of its watermarks through `for_track`, which names the track
    /// so an empty task set reports which one was empty.
    #[cfg(test)]
    fn new<I, S>(tasks: I, start_offset: u32) -> Result<Self, StreamError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::for_track(tasks, start_offset)
    }

    fn for_track<I, S>(tasks: I, start_offset: u32) -> Result<Self, StreamError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if start_offset > MAX_RUNE_OFFSET {
            return Err(StreamError::OffsetOverflow);
        }
        let tasks: BTreeMap<String, u32> = tasks
            .into_iter()
            .map(|task| (task.into(), start_offset))
            .collect();
        Ok(Self {
            tasks,
            confirmed: start_offset,
            received: start_offset,
        })
    }

    /// Task labels this watermark tracks, in deterministic order.
    pub fn tasks(&self) -> impl Iterator<Item = &str> {
        self.tasks.keys().map(String::as_str)
    }

    /// Highest offset released so far.
    pub fn confirmed(&self) -> u32 {
        self.confirmed
    }

    /// End offset of the text the session has been told about.
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Runes observed but not yet cleared by every task, as of the last
    /// `advance`.
    pub fn pending(&self) -> u32 {
        self.received.saturating_sub(self.confirmed)
    }

    /// Runes no task has cleared, measured against the tasks themselves rather
    /// than the committed offset, so it is accurate without an `advance` and
    /// can be read without moving the release point.
    fn uncleared(&self) -> u32 {
        let lowest = self.tasks.values().copied().min().unwrap_or(self.confirmed);
        self.received.saturating_sub(lowest)
    }

    /// Extend the observed length by `runes` and return the new end offset.
    pub(crate) fn extend(&mut self, runes: u32) -> Result<u32, StreamError> {
        self.received = self
            .received
            .checked_add(runes)
            .filter(|total| *total <= MAX_RUNE_OFFSET)
            .ok_or(StreamError::OffsetOverflow)?;
        Ok(self.received)
    }

    /// Record that `task` cleared a span running from `start` to `offset`.
    ///
    /// A stale or repeated offset is ignored rather than treated as an error,
    /// so a host may re-report a span. A span that starts past the task's
    /// frontier is refused, because confirming it would release the gap
    /// between them, which nothing evaluated.
    pub(crate) fn record(
        &mut self,
        track: StreamTrack,
        task: &str,
        start: u32,
        offset: u32,
    ) -> Result<(), StreamError> {
        if offset > self.received {
            return Err(StreamError::OffsetPastEnd {
                offset,
                received: self.received,
            });
        }
        let current = self
            .tasks
            .get_mut(task)
            .ok_or_else(|| StreamError::UnknownTask {
                track,
                task: task.to_string(),
            })?;
        if offset <= *current {
            // A repeated or stale outcome for text this task already cleared.
            return Ok(());
        }
        if start > *current {
            return Err(StreamError::NonContiguousOutcome {
                task: task.to_string(),
                expected: *current,
                found: start,
            });
        }
        *current = offset;
        Ok(())
    }

    /// Recompute the confirmed offset.
    ///
    /// Returns the new offset when it advanced and `None` when it did not, so
    /// a caller emits a watermark only on real progress.
    pub(crate) fn advance(&mut self) -> Option<u32> {
        let minimum = self.tasks.values().copied().min().unwrap_or(self.confirmed);
        if minimum > self.confirmed {
            self.confirmed = minimum;
            Some(self.confirmed)
        } else {
            None
        }
    }
}

/// Reason prefixes a policy may not author, mirroring the set the policy output
/// normalizer screens.
const RESERVED_REASON_PREFIXES: [&str; 2] = ["runtime_error:", "host_error:"];

/// Whether a verdict has a shape the section 5 contract does not admit.
///
/// A host may hand over a verdict it decoded from the wire or one it built as a
/// typed value, and the two paths do not enforce the same rules on their own.
/// The wire decoder checks the whole of section 5, while `Verdict::validate`
/// covers only what survives into the typed form. This function closes that
/// gap, so the accounting applies one rule set whichever path the host used.
/// The correspondence, wire check to enforcement here:
///
/// * the verdict is an object: the type.
/// * decision is a known value: the type.
/// * `reason` does not start with `host_error:`: `validate`, with the denial
///   carve out below. Note that this is narrower than the reserved set. A
///   `runtime_error:` reason is reserved too and is deliberately not checked,
///   because the profile grants it no trust to abuse and a forged one is no
///   stronger than a forged bare `allow`.
/// * `warnings[].reason` uses neither reserved prefix: checked here, since
///   `validate` reads only the top level reason. This is stricter than the wire
///   decoder, which screens `host_error:` alone.
/// * `message` and `warnings[].message` are strings or absent: the type.
/// * `warnings` is an array of objects: the type.
/// * `approval` only on a deny: `validate`. `approval` is an object: the type.
/// * `transform.path` is present: the type. It parses:
///   [`agent_hooks::parse_transform_path`], which is the same parser the wire
///   decoder calls, so the two cannot accept different path languages.
/// * `transform.value` may be any JSON including null: the type.
/// * `result_labels` is an array of strings: the type.
/// * `evidence` is an object that deserializes: the type.
/// * decision and transform agree: `validate`.
/// * `evidence` is within its size ceiling: `validate`.
///
/// Every wire check appears above. The ones marked "the type" need no code
/// here because a typed `Verdict` cannot express the shape they reject. The two
/// marked "checked here" are restated rather than delegated, because the wire
/// decoder is reachable only from a serialized verdict and a host may build one
/// as a typed value instead. Restating them means they can drift from the
/// decoder, so a change to its reserved reason handling has to be mirrored
/// here. The path grammar cannot drift, because it is the same function.
///
/// The agent-hooks checks are authoritative and are reused rather than
/// restated, so this cannot drift from them. Two adjustments are needed for
/// this call site.
///
/// `Verdict::validate` rejects any `host_error:` reason, because an interceptor
/// must not forge a host error over the wire. A verdict reaching the accounting
/// may instead have been synthesized by the host itself, which is exactly who
/// owns that namespace, so a host that denies on its own interceptor timeout is
/// well formed here.
///
/// That exemption covers a denial and nothing else. A `host_error:` reason
/// states that something the host relied on failed, and the only sound reading
/// of a failure is to withhold. An `allow` carrying one would release text on
/// the strength of an evaluation that reports itself broken, and a `transform`
/// carrying one would rewrite on the same basis, so both stay rejected.
///
/// The contract also does not check the transform path, since the runtime does
/// that when it builds the verdict. A host may hand over a verdict from
/// anywhere, so the path is parsed here with the same grammar the host will
/// use at apply time. A path outside `$target` escapes the policy target and
/// section 14 forbids it.
fn verdict_shape_is_invalid(verdict: &Verdict) -> bool {
    let host_authored_denial = verdict.decision == Decision::Deny
        && verdict
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("host_error:"));
    let contract_check = if host_authored_denial {
        let mut without_reason = verdict.clone();
        without_reason.reason = None;
        without_reason.validate()
    } else {
        verdict.validate()
    };
    if contract_check.is_err() {
        return true;
    }
    // The typed check covers the top level reason only, so a reserved reason
    // riding on a warning reaches the record unexamined. Both reserved
    // namespaces are rejected here, for every decision.
    //
    // `host_error:` because a warning is a recorded concern and never the host
    // reporting its own failure, which is the one thing the carve out above
    // exists for. `runtime_error:` because that namespace belongs to the
    // runtime, and the screen the policy output normalizer applies to a
    // policy's top level reason does not extend to a warning's. Neither prefix
    // changes whether the text is released, since the decision does that, but a
    // reserved reason in an audit record is a claim about who failed, so the
    // accounting should not carry one it cannot account for.
    if verdict
        .warnings
        .iter()
        .filter_map(|warning| warning.reason.as_deref())
        .any(|reason| {
            RESERVED_REASON_PREFIXES
                .iter()
                .any(|prefix| reason.starts_with(prefix))
        })
    {
        return true;
    }
    match &verdict.transform {
        Some(transform) => agent_hooks::parse_transform_path(&transform.path).is_err(),
        None => false,
    }
}

/// Streaming parameters a host supplies once, before any payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSessionConfig {
    /// How much the host may release ahead of the watermark.
    pub safety_level: SafetyLevel,
    /// Offset the first rune of the request track occupies. A retry that
    /// resumes a partially delivered stream sets this so offsets stay
    /// comparable with the earlier attempt.
    ///
    /// Held per track because the tracks are independent offset spaces and a
    /// retry rarely resumes both. Re sending the prompt while resuming the
    /// response is the ordinary case, and a single offset could not express
    /// it: the re sent prompt's spans would fall below the resumed frontier,
    /// read as already cleared, and the session would settle with residue the
    /// host was never warned about.
    pub request_start_rune_offset: u32,
    /// Offset the first rune of the response track occupies, with the same
    /// meaning as `request_start_rune_offset`.
    pub response_start_rune_offset: u32,
    /// Tasks that gate the request track. These correspond to whatever the
    /// host binds at `input`. Empty means the request track is not mediated,
    /// which is the ordinary shape for a host guarding only the model stream;
    /// payload on an unmediated track then fails closed.
    pub request_tasks: Vec<String>,
    /// Tasks that gate the response track. These correspond to whatever the
    /// host binds at `post_model_call`. Kept separate from `request_tasks`
    /// because a task bound at one intervention point has no counterpart at
    /// the other, and a shared set would stall a track on a task that can
    /// never evaluate it.
    pub response_tasks: Vec<String>,
    // Note for maintainers: every task on a track binds at the same
    // intervention point, because the point is a function of the source type
    // and so of the track. That is what makes the minimum across a track's
    // tasks a meaningful quantity.
}

impl StreamSessionConfig {
    /// Tasks gating one track.
    fn tasks_for(&self, track: StreamTrack) -> &[String] {
        match track {
            StreamTrack::Request => &self.request_tasks,
            StreamTrack::Response => &self.response_tasks,
        }
    }
}

/// Release accounting over a stream the host holds.
///
/// A session holds no policy, performs no evaluation, and stores no stream
/// text. The host drives it: the host reports how much text arrived, declares
/// the spans its segmenter produced, evaluates those spans with the ordinary
/// runtime, records each outcome, and asks which prefix it may now release.
///
/// The session settles in two steps. `end_of_payloads` says no more text is
/// coming while outcomes are still in flight, which is what a `Deferred` host
/// needs so a late denial can still land. `finish` settles the session.
#[derive(Debug, Clone)]
pub struct StreamSession {
    config: StreamSessionConfig,
    request: StreamWatermark,
    response: StreamWatermark,
    ended: Option<StreamEndReason>,
    payloads_closed: bool,
}

impl StreamSession {
    /// Open a session.
    pub fn new(config: StreamSessionConfig) -> Result<Self, StreamError> {
        // A track with no tasks is not mediated, which is the ordinary shape
        // for a host guarding only the model stream. Payload on such a track
        // fails closed, since nothing would gate it. A session mediating
        // neither track would gate nothing at all, so that is refused.
        if config.request_tasks.is_empty() && config.response_tasks.is_empty() {
            return Err(StreamError::NoTasks(StreamTrack::Response));
        }
        let request = StreamWatermark::for_track(
            config.request_tasks.clone(),
            config.request_start_rune_offset,
        )?;
        let response = StreamWatermark::for_track(
            config.response_tasks.clone(),
            config.response_start_rune_offset,
        )?;
        Ok(Self {
            config,
            request,
            response,
            ended: None,
            payloads_closed: false,
        })
    }

    /// Streaming parameters this session was opened with.
    pub fn config(&self) -> &StreamSessionConfig {
        &self.config
    }

    /// Terminal reason, when the session has ended.
    pub fn end_reason(&self) -> Option<&StreamEndReason> {
        self.ended.as_ref()
    }

    /// Whether the session has reached its terminal state.
    pub fn is_ended(&self) -> bool {
        self.ended.is_some()
    }

    /// Whether any span cleared through a `Transformed` outcome.
    pub fn transformed(&self) -> bool {
        matches!(self.ended, Some(StreamEndReason::Rewritten { .. }))
    }

    /// Watermark for a track.
    pub fn watermark(&self, track: StreamTrack) -> &StreamWatermark {
        match track {
            StreamTrack::Request => &self.request,
            StreamTrack::Response => &self.response,
        }
    }

    fn watermark_mut(&mut self, track: StreamTrack) -> &mut StreamWatermark {
        match track {
            StreamTrack::Request => &mut self.request,
            StreamTrack::Response => &mut self.response,
        }
    }

    /// Offset through which the host may emit this track.
    pub fn safe_offset(&self, track: StreamTrack) -> u32 {
        self.watermark(track).confirmed()
    }

    /// Runes observed but not yet cleared by every task on this track.
    pub fn pending(&self, track: StreamTrack) -> u32 {
        self.watermark(track).pending()
    }

    /// Report that `runes` more runes arrived on this role's track, and
    /// return the track's new end offset.
    ///
    /// This only moves the bound that outcomes are checked against. It does
    /// not release anything and does not decide what the host evaluates.
    pub fn observe(
        &mut self,
        source_type: StreamSourceType,
        runes: u32,
    ) -> Result<u32, StreamError> {
        if self.ended.is_some() {
            return Err(StreamError::SessionClosed);
        }
        if self.payloads_closed {
            return Err(self.fail(StreamError::PayloadsClosed));
        }
        let track = source_type.track();
        if self.config.tasks_for(track).is_empty() {
            return Err(self.fail(StreamError::NoTasks(track)));
        }
        match self.watermark_mut(track).extend(runes) {
            Ok(end) => Ok(end),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Report arriving text by counting its runes.
    ///
    /// Provided so a host does not reach for a length that counts UTF-16 code
    /// units or bytes, neither of which is interchangeable with a rune offset.
    /// The text itself is not retained.
    pub fn observe_text(
        &mut self,
        source_type: StreamSourceType,
        text: &str,
    ) -> Result<u32, StreamError> {
        let runes = match u32::try_from(text.chars().count()) {
            Ok(runes) => runes,
            Err(_) => {
                if self.ended.is_some() {
                    return Err(StreamError::SessionClosed);
                }
                return Err(self.fail(StreamError::OffsetOverflow));
            }
        };
        self.observe(source_type, runes)
    }

    /// Record what a host decided for `span` under `task`.
    pub fn record_outcome(
        &mut self,
        task: &str,
        span: &StreamSpan,
        outcome: SegmentOutcome,
    ) -> Result<(), StreamError> {
        if self.ended.is_some() {
            return Err(StreamError::SessionClosed);
        }
        let track = span.track();
        if !self
            .config
            .tasks_for(track)
            .iter()
            .any(|known| known == task)
        {
            return Err(self.fail(StreamError::UnknownTask {
                track,
                task: task.to_string(),
            }));
        }
        if span.range.is_empty() {
            return Err(self.fail(StreamError::EmptySpan));
        }
        // Validated for every outcome, including a refusal. A span past the
        // observed end means the host and the session disagree about how much
        // text exists, and recording a refusal over runes the session was never
        // told about would carry that disagreement into the terminal reason and
        // into whatever audits it.
        let received = self.watermark(track).received();
        if span.range.end > received {
            return Err(self.fail(StreamError::OffsetPastEnd {
                offset: span.range.end,
                received,
            }));
        }
        match outcome {
            SegmentOutcome::Denied => {
                self.ended = Some(StreamEndReason::Denied {
                    track,
                    task: task.to_string(),
                    range: span.range,
                });
                return Ok(());
            }
            SegmentOutcome::Transformed => {
                // A transform is only meaningful while the host can still
                // alter the text it rewrites. Under a non withholding level the
                // payload was emitted on arrival, so nothing can be rewritten.
                if !self.config.safety_level.withholds() {
                    return Err(self.fail(StreamError::TransformTooLate));
                }
                // A transform addresses a node of the policy target, not a rune
                // range, and the session holds no text, so it cannot know how
                // far below this span the target reaches. A host evaluating the
                // accumulated prefix has a target covering the whole track, so
                // any released rune is inside it. Requiring that no rune has
                // ever been released is therefore the only bound that holds
                // without the host declaring the rewritten extent.
                //
                // The comparison is against zero and not against the track's
                // resume offset, because a session resuming a partially
                // delivered stream starts above zero precisely because those
                // earlier runes already reached the caller. Comparing against
                // the resume offset would honor a transform over text a failed
                // attempt had already emitted, and comparing against the span
                // start would honor one over a prefix this attempt emitted.
                if self.watermark(track).confirmed() > 0 {
                    return Err(self.fail(StreamError::TransformTooLate));
                }
                // The substitution replaces the policy target with a new whole
                // value, and this is where the track's offsets stop meaning
                // anything. They count runes of the original; the host now
                // holds a replacement of some other length that no task
                // evaluated. Reporting any watermark over it would be reporting
                // a position in a sequence that no longer exists, which is what
                // three earlier attempts at this rule each got wrong in a
                // different way. So the accounting reports none, and the stream
                // ends rewritten. The replacement is a whole value and belongs
                // on the ordinary path of section 18, where every task sees it.
                self.ended = Some(StreamEndReason::Rewritten {
                    track,
                    task: task.to_string(),
                    range: span.range,
                });
                return Ok(());
            }
            SegmentOutcome::Cleared => {}
        }
        let watermark = self.watermark_mut(track);
        if let Err(error) = watermark.record(track, task, span.range.start, span.range.end) {
            return Err(self.fail(error));
        }
        Ok(())
    }

    /// Map a verdict onto an outcome and record it.
    ///
    /// `allow` clears, carrying any `warnings` through untouched, because a
    /// warning is a recorded concern rather than a release decision.
    /// `transform` records a `Transformed` outcome, which obliges the host to
    /// apply `verdict.transform` to the policy target it evaluated before
    /// emitting anything. The transform names a node under `$target`, not a
    /// rune range, so it does not necessarily correspond to this span.
    ///
    /// A verdict whose shape section 5 does not admit fails the stream closed
    /// with [`StreamError::VerdictInvalid`] before its decision is read.
    ///
    /// A `deny` denies, whether or not it carries an `approval` block. A deny
    /// carrying one is liftable through the host's approval seam, defined in
    /// AGENT-HOOKS-0.1 section 9, but lifting is a host
    /// obligation that happens before the outcome reaches here, because a
    /// session cannot hold its connection open across an out of band approval.
    /// A host that runs an approval seam resolves the deny first and records
    /// the resolved result through [`record_outcome`](Self::record_outcome).
    /// One that hands an unresolved liftable deny to this method gets the
    /// denial the verdict asked for, which is the conservative reading and
    /// keeps the refused range on the terminal reason.
    ///
    /// The verdict is validated first, so a shape the contract forbids, such as
    /// a `transform` carrying no transform body, fails closed rather than
    /// clearing the span.
    pub fn record_verdict(
        &mut self,
        task: &str,
        span: &StreamSpan,
        verdict: &Verdict,
    ) -> Result<(), StreamError> {
        if verdict_shape_is_invalid(verdict) {
            if self.ended.is_some() {
                return Err(StreamError::SessionClosed);
            }
            return Err(self.fail(StreamError::VerdictInvalid));
        }
        let outcome = match verdict.decision {
            Decision::Allow => SegmentOutcome::Cleared,
            Decision::Deny => SegmentOutcome::Denied,
            Decision::Transform => SegmentOutcome::Transformed,
        };
        self.record_outcome(task, span, outcome)
    }

    /// Recompute the watermark for `track` and return it when it advanced.
    pub fn advance(&mut self, track: StreamTrack) -> Option<u32> {
        if self.ended.is_some() {
            return None;
        }
        self.watermark_mut(track).advance()
    }

    /// Stop accepting payloads while outcomes are still in flight.
    ///
    /// A `Deferred` host calls this at payload EOF so a classifier running
    /// behind the stream can still record a denial before `finish`.
    pub fn end_of_payloads(&mut self) {
        self.payloads_closed = true;
    }

    /// Settle the session.
    ///
    /// Recomputes both watermarks first, so a host that recorded every outcome
    /// is not failed closed for having skipped an explicit `advance`. Any rune
    /// no task cleared is a fail closed condition under every safety level: a
    /// `Deferred` host cannot recall what it emitted, but it can still refuse
    /// to settle the stream clean.
    pub fn finish(&mut self) -> StreamCompletion {
        if let Some(reason) = &self.ended {
            return StreamCompletion {
                reason: reason.clone(),
                transformed: self.transformed(),
            };
        }
        self.payloads_closed = true;
        // Residue is measured without committing it. Recomputing through
        // `advance` here would raise the release point as a side effect of
        // failing, and a settlement that fails is exactly when the host must
        // emit nothing further. `advance` itself already refuses to move a
        // terminal session, so committing here would also contradict it.
        for track in [StreamTrack::Request, StreamTrack::Response] {
            let pending = self.watermark(track).uncleared();
            if pending > 0 {
                let reason =
                    StreamEndReason::Failed(StreamError::UnclearedResidue { track, pending });
                self.ended = Some(reason.clone());
                return StreamCompletion {
                    reason,
                    transformed: self.transformed(),
                };
            }
        }
        // Nothing is outstanding, so committing is safe and lets a host that
        // recorded every outcome skip a final explicit `advance`.
        self.request.advance();
        self.response.advance();
        self.ended = Some(StreamEndReason::Complete);
        StreamCompletion {
            reason: StreamEndReason::Complete,
            transformed: self.transformed(),
        }
    }

    /// Record a terminal failure, keeping the first terminal reason so a
    /// recorded denial is never downgraded to a transport failure.
    ///
    /// Every path that can reach this function checks for a terminal session
    /// first and returns [`StreamError::SessionClosed`], so this currently
    /// never runs with a reason already set. A caller may do work before that
    /// check, as verdict shape validation and rune counting both do, but
    /// neither reaches here without passing it. The guard is defense against a
    /// future entry point that forgets the check. Mutation testing confirms no
    /// test distinguishes the guarded form from an unconditional assignment,
    /// which is expected rather than a coverage gap.
    fn fail(&mut self, error: StreamError) -> StreamError {
        if self.ended.is_none() {
            self.ended = Some(StreamEndReason::Failed(error.clone()));
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: StreamSourceType = StreamSourceType::UserRequest;
    const RES: StreamSourceType = StreamSourceType::ModelGenerated;

    /// A transform verdict the agent-hooks contract accepts, which requires a
    /// substitution body naming the node to rewrite.
    fn transform_verdict() -> Verdict {
        Verdict {
            transform: Some(agent_hooks::Transform {
                path: "$target.content".to_string(),
                value: serde_json::Value::String("[redacted]".to_string()),
            }),
            ..verdict(Decision::Transform)
        }
    }

    fn verdict(decision: Decision) -> Verdict {
        Verdict {
            decision,
            reason: None,
            message: None,
            warnings: Vec::new(),
            approval: None,
            transform: None,
            evidence: None,
            result_labels: Vec::new(),
        }
    }

    /// A `deny` carrying an `approval` block, which AGENT-HOOKS-0.1 section 9
    /// makes liftable through the host's approval seam.
    fn liftable_deny() -> Verdict {
        Verdict {
            approval: Some(serde_json::Map::new()),
            ..verdict(Decision::Deny)
        }
    }

    fn config(tasks: &[&str], level: SafetyLevel) -> StreamSessionConfig {
        let tasks: Vec<String> = tasks.iter().map(|task| (*task).to_string()).collect();
        StreamSessionConfig {
            safety_level: level,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: tasks.clone(),
            response_tasks: tasks,
        }
    }

    fn session(tasks: &[&str], level: SafetyLevel) -> StreamSession {
        StreamSession::new(config(tasks, level)).expect("config is valid")
    }

    fn span(source: StreamSourceType, start: u32, end: u32) -> StreamSpan {
        StreamSpan::new(source, start, end).expect("range is valid")
    }

    #[test]
    fn safety_level_round_trips_and_unknown_fails_closed() {
        for level in [
            SafetyLevel::Blocking,
            SafetyLevel::Complete,
            SafetyLevel::Deferred,
        ] {
            assert_eq!(SafetyLevel::parse(level.as_str()), Ok(level));
        }
        assert!(SafetyLevel::parse("permissive").is_err());
        assert!(SafetyLevel::Blocking.withholds());
        assert!(SafetyLevel::Complete.withholds());
        assert!(!SafetyLevel::Deferred.withholds());
    }

    #[test]
    fn source_type_round_trips_and_maps_to_intervention_points() {
        for source in [REQ, RES] {
            assert_eq!(StreamSourceType::parse(source.as_str()), Ok(source));
        }
        assert!(StreamSourceType::parse("tool_result").is_err());
        assert_eq!(REQ.interception_point(), InterceptionPoint::Input);
        assert_eq!(RES.interception_point(), InterceptionPoint::PostModelCall);
        assert_eq!(REQ.track(), StreamTrack::Request);
        assert_eq!(RES.track(), StreamTrack::Response);
    }

    #[test]
    fn single_task_clears_and_advances() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        assert_eq!(s.observe(RES, 10), Ok(10));
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("outcome records");
        assert_eq!(s.advance(StreamTrack::Response), Some(10));
        assert_eq!(s.safe_offset(StreamTrack::Response), 10);
        // No further progress means no further watermark.
        assert_eq!(s.advance(StreamTrack::Response), None);
    }

    #[test]
    fn watermark_is_the_minimum_and_a_stalled_task_holds_the_track() {
        let mut s = session(&["safety", "pii"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Cleared)
            .expect("safety clears");
        // Only one of two tasks cleared, so nothing is releasable.
        assert_eq!(s.advance(StreamTrack::Response), None);
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        s.record_outcome("pii", &span(RES, 0, 12), SegmentOutcome::Cleared)
            .expect("pii clears part");
        assert_eq!(s.advance(StreamTrack::Response), Some(12));
        assert_eq!(s.pending(StreamTrack::Response), 8);
    }

    #[test]
    fn non_contiguous_outcome_fails_closed() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 30).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("first span clears");
        // Skipping [10,20) would confirm runes nothing evaluated.
        let error = s
            .record_outcome("safety", &span(RES, 20, 30), SegmentOutcome::Cleared)
            .expect_err("gap must fail closed");
        assert_eq!(
            error,
            StreamError::NonContiguousOutcome {
                task: "safety".to_string(),
                expected: 10,
                found: 20,
            }
        );
        assert!(s.is_ended());
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
    }

    #[test]
    fn overlapping_spans_are_accepted() {
        // What a growing or sliding segmenter emits.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 40).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Cleared)
            .expect("first window");
        s.record_outcome("safety", &span(RES, 10, 40), SegmentOutcome::Cleared)
            .expect("overlapping window");
        assert_eq!(s.advance(StreamTrack::Response), Some(40));
    }

    #[test]
    fn stale_outcome_is_ignored_not_an_error() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Cleared)
            .expect("clears");
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("re-reporting an older span is not an error");
        assert_eq!(s.advance(StreamTrack::Response), Some(20));
    }

    #[test]
    fn denial_is_terminal_and_carries_the_range() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Denied)
            .expect("denial records");
        assert_eq!(
            s.end_reason(),
            Some(&StreamEndReason::Denied {
                track: StreamTrack::Response,
                task: "safety".to_string(),
                range: RuneRange { start: 0, end: 20 },
            })
        );
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        let completion = s.finish();
        assert!(!completion.reason.is_clean());
    }

    #[test]
    fn first_terminal_reason_wins() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Denied)
            .expect("denial records");
        // A later transport failure must not overwrite the denial.
        let error = s
            .record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Cleared)
            .expect_err("session is closed");
        assert_eq!(error, StreamError::SessionClosed);
        assert!(matches!(
            s.end_reason(),
            Some(StreamEndReason::Denied { .. })
        ));
    }

    #[test]
    fn transform_fails_closed_under_a_non_withholding_level() {
        // Deferred emitted the payload on arrival, so there is nothing left
        // to substitute.
        let mut s = session(&["pii"], SafetyLevel::Deferred);
        s.observe(RES, 20).expect("observe");
        let error = s
            .record_outcome("pii", &span(RES, 0, 20), SegmentOutcome::Transformed)
            .expect_err("transform must fail closed");
        assert_eq!(error, StreamError::TransformTooLate);
        assert!(s.is_ended());
    }

    #[test]
    fn the_watermark_type_validates_its_own_inputs() {
        // No host path reaches these directly: the mutators are crate internal
        // and the constructor is test only. The session validates the same
        // things before delegating, so these assertions pin the watermark
        // layer's own behavior rather than a public contract.
        let mut watermark =
            StreamWatermark::new(["a", "b"], 0).expect("two tasks is a valid watermark");
        assert_eq!(watermark.received(), 0);
        assert_eq!(watermark.confirmed(), 0);

        // An offset past what was received is refused.
        assert_eq!(
            watermark.record(StreamTrack::Response, "a", 0, 5),
            Err(StreamError::OffsetPastEnd {
                offset: 5,
                received: 0,
            })
        );

        watermark.extend(100).expect("extend");
        assert_eq!(watermark.received(), 100);
        assert_eq!(
            watermark.record(StreamTrack::Response, "a", 0, 101),
            Err(StreamError::OffsetPastEnd {
                offset: 101,
                received: 100,
            })
        );

        // An unconfigured task is refused.
        assert!(matches!(
            watermark.record(StreamTrack::Response, "c", 0, 10),
            Err(StreamError::UnknownTask { .. })
        ));

        // A gap is refused.
        watermark
            .record(StreamTrack::Response, "a", 0, 10)
            .expect("contiguous clears");
        assert_eq!(
            watermark.record(StreamTrack::Response, "a", 20, 30),
            Err(StreamError::NonContiguousOutcome {
                task: "a".to_string(),
                expected: 10,
                found: 20,
            })
        );

        // The minimum governs, and only real progress reports a watermark.
        assert_eq!(watermark.advance(), None, "task b is still at zero");
        watermark
            .record(StreamTrack::Response, "b", 0, 4)
            .expect("b clears part");
        assert_eq!(watermark.advance(), Some(4));
        assert_eq!(watermark.advance(), None);
        assert_eq!(watermark.pending(), 96);

        // A stale offset is ignored rather than moving the frontier backwards.
        watermark
            .record(StreamTrack::Response, "b", 0, 2)
            .expect("a stale offset is not an error");
        assert_eq!(watermark.advance(), None);
        assert_eq!(watermark.confirmed(), 4);

        // Task labels are reported in deterministic order.
        assert_eq!(watermark.tasks().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn the_watermark_type_refuses_an_impossible_configuration() {
        assert_eq!(
            StreamWatermark::new(["a"], MAX_RUNE_OFFSET + 1),
            Err(StreamError::OffsetOverflow)
        );
        let mut watermark = StreamWatermark::new(["a"], MAX_RUNE_OFFSET).expect("at the ceiling");
        assert_eq!(watermark.extend(1), Err(StreamError::OffsetOverflow));
    }

    #[test]
    fn a_refusal_past_observed_text_also_fails_closed() {
        // A refusal is terminal either way, so this is not a release hazard.
        // It is validated because a terminal reason naming runes the session
        // never saw is a false record of what was refused.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let error = s
            .record_outcome("safety", &span(RES, 0, 500), SegmentOutcome::Denied)
            .expect_err("a refusal past the observed end must fail closed");
        assert_eq!(
            error,
            StreamError::OffsetPastEnd {
                offset: 500,
                received: 10,
            }
        );
        assert!(matches!(
            s.end_reason(),
            Some(StreamEndReason::Failed(StreamError::OffsetPastEnd { .. }))
        ));
    }

    #[test]
    fn a_refusal_from_an_unconfigured_task_is_refused_not_recorded() {
        // A refusal returns before the watermark is touched, so the task check
        // in record_outcome is the only thing standing between a bogus task
        // name and a terminal reason attributed to it.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let error = s
            .record_outcome("not_configured", &span(RES, 0, 10), SegmentOutcome::Denied)
            .expect_err("an unconfigured task may not refuse");
        assert!(matches!(error, StreamError::UnknownTask { .. }));
        assert!(
            !matches!(s.end_reason(), Some(StreamEndReason::Denied { .. })),
            "the session recorded a denial attributed to a task it does not configure"
        );
    }

    #[test]
    fn every_outcome_validates_the_span_identically() {
        // The three outcomes must agree on what a well formed span is, or the
        // validation a host relies on depends on the verdict it happens to get.
        for outcome in [
            SegmentOutcome::Cleared,
            SegmentOutcome::Transformed,
            SegmentOutcome::Denied,
        ] {
            let mut s = session(&["safety"], SafetyLevel::Blocking);
            s.observe(RES, 10).expect("observe");
            assert!(
                s.record_outcome("safety", &span(RES, 0, 25), outcome)
                    .is_err(),
                "{outcome:?} accepted a span past the observed end"
            );
            let mut s = session(&["safety"], SafetyLevel::Blocking);
            s.observe(RES, 10).expect("observe");
            assert!(
                s.record_outcome("nobody", &span(RES, 0, 5), outcome)
                    .is_err(),
                "{outcome:?} accepted an unconfigured task"
            );
        }
    }

    #[test]
    fn a_transform_leaving_the_policy_target_fails_closed() {
        // Section 14 confines a transform to the policy target. The contract
        // check does not parse the path, because the runtime does that when it
        // builds a verdict, and a host may hand one over from anywhere.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let escaping = Verdict {
            transform: Some(agent_hooks::Transform {
                path: "$snapshot.messages".to_string(),
                value: serde_json::Value::String("x".to_string()),
            }),
            ..verdict(Decision::Transform)
        };
        assert!(
            escaping.validate().is_ok(),
            "the contract check alone does not catch this"
        );
        let error = s
            .record_verdict("t", &span(RES, 0, 10), &escaping)
            .expect_err("a transform outside the policy target must fail closed");
        assert_eq!(error, StreamError::VerdictInvalid);
    }

    #[test]
    fn a_warning_may_carry_neither_reserved_prefix() {
        // `runtime_error:` belongs to the runtime, and the screen applied to a
        // policy's top level reason does not extend to a warning's, so without
        // this check one could reach the record as a claim about who failed.
        for prefix in ["runtime_error:", "host_error:"] {
            let mut s = session(&["t"], SafetyLevel::Blocking);
            s.observe(RES, 10).expect("observe");
            let forged = Verdict {
                warnings: vec![agent_hooks::Warning {
                    reason: Some(format!("{prefix}policy_timeout")),
                    message: None,
                }],
                ..verdict(Decision::Allow)
            };
            let error = s
                .record_verdict("t", &span(RES, 0, 10), &forged)
                .unwrap_err();
            assert_eq!(error, StreamError::VerdictInvalid, "for {prefix}");
            assert_eq!(s.advance(StreamTrack::Response), None, "for {prefix}");
        }
    }

    #[test]
    fn a_warning_may_never_carry_a_reserved_reason() {
        // The typed contract check covers the top level reason only, while the
        // agent-hooks wire decoder also rejects a reserved reason on a warning.
        // A verdict handed over as a typed value skips that decoder, so an
        // allow could otherwise carry a forged host error into the record and
        // still release the text.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let forged = Verdict {
            warnings: vec![agent_hooks::Warning {
                reason: Some("host_error:interceptor_timeout".to_string()),
                message: None,
            }],
            ..verdict(Decision::Allow)
        };
        assert!(
            forged.validate().is_ok(),
            "the typed contract check alone does not catch this"
        );
        let error = s
            .record_verdict("t", &span(RES, 0, 10), &forged)
            .expect_err("a forged reserved reason must fail closed");
        assert_eq!(error, StreamError::VerdictInvalid);
        assert_eq!(s.advance(StreamTrack::Response), None, "nothing released");
    }

    #[test]
    fn only_a_denial_may_carry_a_host_error_reason() {
        // A `host_error:` reason states that something the host relied on
        // failed. Withholding is the only sound reading, so exempting the whole
        // namespace from the contract check would let an allow release text on
        // the strength of an evaluation reporting itself broken.
        for decision in [Decision::Allow, Decision::Transform] {
            let mut s = session(&["t"], SafetyLevel::Blocking);
            s.observe(RES, 10).expect("observe");
            let base = if decision == Decision::Transform {
                transform_verdict()
            } else {
                verdict(decision)
            };
            let broken = Verdict {
                reason: Some("host_error:interceptor_timeout".to_string()),
                ..base
            };
            let error = s
                .record_verdict("t", &span(RES, 0, 10), &broken)
                .expect_err("a non denial carrying a host error reason must fail closed");
            assert_eq!(error, StreamError::VerdictInvalid, "for {decision:?}");
            assert_eq!(s.advance(StreamTrack::Response), None, "for {decision:?}");
        }
    }

    #[test]
    fn a_host_synthesized_deny_is_a_well_formed_final_verdict() {
        // The contract check rejects a `host_error:` reason so an interceptor
        // cannot forge one over the wire. The host drives this profile and owns
        // that namespace, so its own fail closed verdict must record as the
        // denial it is rather than as a session fault that loses the range.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let host_deny = Verdict {
            reason: Some("host_error:interceptor_timeout".to_string()),
            ..verdict(Decision::Deny)
        };
        assert!(
            host_deny.validate().is_err(),
            "the contract check alone rejects this"
        );
        s.record_verdict("t", &span(RES, 0, 10), &host_deny)
            .expect("a host authored deny records as a denial");
        assert_eq!(
            s.end_reason(),
            Some(&StreamEndReason::Denied {
                track: StreamTrack::Response,
                task: "t".to_string(),
                range: RuneRange { start: 0, end: 10 },
            })
        );
    }

    #[test]
    fn an_empty_span_built_around_the_constructor_still_fails_closed() {
        // `StreamSpan` has public fields, so `StreamSpan::new` is not the only
        // way to build one and its own emptiness check is not the binding one.
        // Without the check in `record_outcome` an empty span sitting exactly
        // on a task's frontier records as stale and silently succeeds.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.record_outcome("t", &span(RES, 0, 5), SegmentOutcome::Cleared)
            .expect("clears to 5");
        let empty = StreamSpan {
            source_type: RES,
            range: RuneRange { start: 5, end: 5 },
        };
        assert_eq!(
            StreamSpan::new(RES, 5, 5),
            Err(StreamError::EmptySpan),
            "the constructor rejects it, but a literal bypasses the constructor"
        );
        let error = s
            .record_outcome("t", &empty, SegmentOutcome::Cleared)
            .expect_err("an empty span carries no evaluation and must fail closed");
        assert_eq!(error, StreamError::EmptySpan);
    }

    #[test]
    fn a_stale_refusal_is_terminal_rather_than_ignored() {
        // The ignore rule for a span below the frontier covers clearance only.
        // A refusal is the host reporting that it evaluated text and rejected
        // it, and no reading of that is safe to discard.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.record_outcome("t", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("clears");
        s.record_outcome("t", &span(RES, 0, 5), SegmentOutcome::Denied)
            .expect("a late refusal still denies");
        assert!(matches!(
            s.end_reason(),
            Some(StreamEndReason::Denied { .. })
        ));
    }

    #[test]
    fn a_verdict_the_contract_forbids_fails_closed() {
        // A transform decision carrying no transform body is invalid under
        // section 5. Clearing the span on it would release text on the strength
        // of a substitution that does not exist.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let bodyless = verdict(Decision::Transform);
        assert!(
            bodyless.validate().is_err(),
            "the contract rejects this shape"
        );
        let error = s
            .record_verdict("t", &span(RES, 0, 10), &bodyless)
            .expect_err("an invalid verdict must fail closed");
        assert_eq!(error, StreamError::VerdictInvalid);
        assert_eq!(error.reason(), VERDICT_INVALID_REASON);
        assert!(s.is_ended());
    }

    #[test]
    fn an_invalid_verdict_after_a_denial_does_not_overwrite_the_denial() {
        // The validity check runs before the decision is read, so it must not
        // let a late malformed verdict replace the reason the caller is owed.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.record_outcome("t", &span(RES, 0, 10), SegmentOutcome::Denied)
            .expect("denial records");
        let error = s
            .record_verdict("t", &span(RES, 0, 10), &verdict(Decision::Transform))
            .expect_err("session is closed");
        assert_eq!(error, StreamError::SessionClosed);
        assert!(matches!(
            s.end_reason(),
            Some(StreamEndReason::Denied { .. })
        ));
    }

    #[test]
    fn an_unresolved_liftable_deny_denies_and_keeps_its_range() {
        // Resolving a liftable deny is a host obligation that happens before
        // the outcome is recorded. One that arrives unresolved is taken at its
        // word, which withholds the text and keeps the refused range on the
        // terminal reason rather than reporting a session fault.
        let mut s = session(&["t"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.record_verdict("t", &span(RES, 0, 10), &liftable_deny())
            .expect("a liftable deny records as a denial");
        assert_eq!(
            s.end_reason(),
            Some(&StreamEndReason::Denied {
                track: StreamTrack::Response,
                task: "t".to_string(),
                range: RuneRange { start: 0, end: 10 },
            })
        );
    }

    #[test]
    fn outcome_past_observed_text_fails_closed() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let error = s
            .record_outcome("safety", &span(RES, 0, 25), SegmentOutcome::Cleared)
            .expect_err("offset runs past observed text");
        assert_eq!(
            error,
            StreamError::OffsetPastEnd {
                offset: 25,
                received: 10,
            }
        );
        assert!(s.is_ended());
    }

    #[test]
    fn unknown_task_fails_closed() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let error = s
            .record_outcome("unconfigured", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect_err("task is not configured");
        assert!(matches!(error, StreamError::UnknownTask { .. }));
        assert!(s.is_ended());
    }

    #[test]
    fn empty_span_is_rejected_at_construction() {
        assert_eq!(StreamSpan::new(RES, 5, 5), Err(StreamError::EmptySpan));
        assert_eq!(StreamSpan::new(RES, 9, 4), Err(StreamError::EmptySpan));
        assert_eq!(
            StreamSpan::new(RES, 0, MAX_RUNE_OFFSET + 1),
            Err(StreamError::OffsetOverflow)
        );
    }

    #[test]
    fn uncleared_residue_fails_closed_under_every_safety_level() {
        for level in [
            SafetyLevel::Blocking,
            SafetyLevel::Complete,
            SafetyLevel::Deferred,
        ] {
            let mut s = session(&["safety"], level);
            s.observe(RES, 30).expect("observe");
            s.record_outcome("safety", &span(RES, 0, 12), SegmentOutcome::Cleared)
                .expect("partial clear");
            s.end_of_payloads();
            let completion = s.finish();
            assert_eq!(
                completion.reason,
                StreamEndReason::Failed(StreamError::UnclearedResidue {
                    track: StreamTrack::Response,
                    pending: 18,
                }),
                "{level:?} must not settle clean with uncleared runes"
            );
        }
    }

    #[test]
    fn finish_advances_before_checking_residue() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 20), SegmentOutcome::Cleared)
            .expect("clears");
        // No explicit advance call; finish must recompute.
        let completion = s.finish();
        assert_eq!(completion.reason, StreamEndReason::Complete);
        assert!(!completion.transformed);
    }

    #[test]
    fn tracks_carry_independent_offsets_and_task_sets() {
        let config = StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: vec!["jailbreak".to_string()],
            response_tasks: vec!["safety".to_string()],
        };
        let mut s = StreamSession::new(config).expect("config is valid");
        s.observe(REQ, 8).expect("observe request");
        s.observe(RES, 25).expect("observe response");
        s.record_outcome("jailbreak", &span(REQ, 0, 8), SegmentOutcome::Cleared)
            .expect("request clears");
        assert_eq!(s.advance(StreamTrack::Request), Some(8));
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        // A response task may not clear the request track.
        let error = s
            .record_outcome("safety", &span(REQ, 0, 8), SegmentOutcome::Cleared)
            .expect_err("task belongs to the other track");
        assert!(matches!(error, StreamError::UnknownTask { .. }));
    }

    #[test]
    fn a_resumed_session_keeps_offsets_comparable() {
        let mut config = config(&["safety"], SafetyLevel::Blocking);
        config.request_start_rune_offset = 100;
        config.response_start_rune_offset = 100;
        let mut s = StreamSession::new(config).expect("config is valid");
        assert_eq!(s.safe_offset(StreamTrack::Response), 100);
        assert_eq!(s.observe(RES, 20), Ok(120));
        s.record_outcome("safety", &span(RES, 100, 120), SegmentOutcome::Cleared)
            .expect("clears");
        assert_eq!(s.advance(StreamTrack::Response), Some(120));
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }

    #[test]
    fn observe_text_counts_runes_not_code_units() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        // 7 scalar values, 8 UTF-16 code units, 11 bytes.
        let sample = "héllo 🌍";
        assert_eq!(sample.chars().count(), 7);
        assert_eq!(sample.encode_utf16().count(), 8);
        assert_eq!(sample.len(), 11);
        assert_eq!(s.observe_text(RES, sample), Ok(7));
    }

    #[test]
    fn offset_ceiling_fails_closed() {
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, MAX_RUNE_OFFSET).expect("observe to ceiling");
        let error = s.observe(RES, 1).expect_err("one rune past the ceiling");
        assert_eq!(error, StreamError::OffsetOverflow);
        assert!(s.is_ended());
    }

    #[test]
    fn outcomes_still_land_after_the_payload_stream_closes() {
        // The separation a deferred classifier needs. Payload arrival and
        // settlement are distinct, so a verdict can still arrive at EOF.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.end_of_payloads();
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("outcome still records");
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }

    #[test]
    fn a_rewrite_ends_the_stream_and_reports_no_watermark() {
        // Regression covering four rounds of the same category error. The
        // replacement is a new whole value: its runes are not the ones this
        // session counted, and no task evaluated it. Any watermark over it
        // would name a position in a sequence that no longer exists, so the
        // accounting reports none and the stream ends rewritten.
        let mut s = session(&["pii"], SafetyLevel::Blocking);
        s.observe_text(RES, "call me on 555-0100 now")
            .expect("23 runes");
        s.record_outcome("pii", &span(RES, 0, 23), SegmentOutcome::Transformed)
            .expect("the rewrite records");
        assert_eq!(
            s.advance(StreamTrack::Response),
            None,
            "a rewritten track has no release point"
        );
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        assert!(s.is_ended());
        let done = s.finish();
        assert_eq!(
            done.reason,
            StreamEndReason::Rewritten {
                track: StreamTrack::Response,
                task: "pii".to_string(),
                range: RuneRange { start: 0, end: 23 },
            }
        );
        assert!(done.transformed);
        assert!(!done.reason.is_clean(), "the host still owes an evaluation");
    }

    #[test]
    fn a_rewrite_does_not_release_on_a_lagging_task() {
        // The multi task case that broke every previous attempt. A slower task
        // evaluated the original text, never the replacement, so its clearance
        // cannot authorize releasing the replacement. Nothing is released and
        // its later outcome cannot reopen the stream.
        let mut s = session(&["pii", "harm"], SafetyLevel::Blocking);
        s.observe(RES, 23).expect("observe");
        s.record_outcome("pii", &span(RES, 0, 23), SegmentOutcome::Transformed)
            .expect("the rewrite records");
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
        s.record_outcome("harm", &span(RES, 0, 23), SegmentOutcome::Cleared)
            .expect_err("the stream already ended rewritten");
        assert_eq!(s.safe_offset(StreamTrack::Response), 0);
    }

    #[test]
    fn a_rewrite_keeps_its_own_terminal_reason() {
        // First terminal reason wins, so a later transport failure cannot
        // downgrade a recorded rewrite.
        let mut s = session(&["pii"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.record_outcome("pii", &span(RES, 0, 10), SegmentOutcome::Transformed)
            .expect("rewrite");
        assert_eq!(
            s.observe(RES, 5),
            Err(StreamError::SessionClosed),
            "a settled session takes no more payload"
        );
        assert!(matches!(
            s.end_reason(),
            Some(StreamEndReason::Rewritten { .. })
        ));
    }

    #[test]
    fn a_failing_settlement_does_not_raise_the_release_point() {
        // Settlement measures residue without committing it. Recomputing the
        // watermark here would raise `safe_offset` as a side effect of
        // failing, and a failed settlement is exactly when the host must emit
        // nothing further.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 20).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("half clears");
        let before = s.safe_offset(StreamTrack::Response);
        let done = s.finish();
        assert!(matches!(
            done.reason,
            StreamEndReason::Failed(StreamError::UnclearedResidue { .. })
        ));
        assert_eq!(
            s.safe_offset(StreamTrack::Response),
            before,
            "failing must not move the release point"
        );
    }

    #[test]
    fn settlement_sees_residue_without_an_explicit_advance() {
        // The residue measure reads the tasks directly, so a host that
        // recorded every outcome but never called `advance` still settles
        // clean, and one with an unevaluated tail still fails.
        let mut clean = session(&["safety"], SafetyLevel::Blocking);
        clean.observe(RES, 10).expect("observe");
        clean
            .record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("clears");
        assert_eq!(clean.finish().reason, StreamEndReason::Complete);

        let mut short = session(&["safety"], SafetyLevel::Blocking);
        short.observe(RES, 10).expect("observe");
        short
            .record_outcome("safety", &span(RES, 0, 4), SegmentOutcome::Cleared)
            .expect("clears a prefix");
        assert!(!short.finish().reason.is_clean());
    }

    #[test]
    fn a_retry_may_resume_one_track_while_restarting_the_other() {
        // The ordinary retry: the prompt is re sent from the beginning while
        // the response picks up where the failed attempt stopped. A single
        // resume offset could not express this. The re sent prompt's spans
        // would fall below a frontier of 100, read as already cleared, and the
        // session would settle with residue the host was never warned about.
        let mut s = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 100,
            request_tasks: vec!["safety".to_string()],
            response_tasks: vec!["safety".to_string()],
        })
        .expect("config");
        s.observe(REQ, 12).expect("the prompt is re sent in full");
        s.record_outcome("safety", &span(REQ, 0, 12), SegmentOutcome::Cleared)
            .expect("and clears from zero");
        assert_eq!(s.advance(StreamTrack::Request), Some(12));
        s.observe(RES, 10).expect("the response resumes at 100");
        s.record_outcome("safety", &span(RES, 100, 110), SegmentOutcome::Cleared)
            .expect("and clears from there");
        assert_eq!(s.advance(StreamTrack::Response), Some(110));
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }

    #[test]
    fn payload_after_the_stream_closes_is_terminal() {
        // Text arriving after the host declared EOF means the session was told
        // the stream ended when it had not. Rejecting the call is not enough,
        // because a host that ignores the error would settle clean over runes
        // the session never counted and no task ever evaluated.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        s.end_of_payloads();
        assert_eq!(s.observe(RES, 5), Err(StreamError::PayloadsClosed));
        assert!(s.is_ended(), "the disagreement must end the session");
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect_err("a closed session records nothing");
        assert!(!s.finish().reason.is_clean());
    }

    #[test]
    fn a_track_with_no_tasks_is_unmediated_and_takes_no_payload() {
        // Guarding only the model stream is the ordinary case, so an empty task
        // set means that track is not mediated rather than being an error.
        // Payload on it still fails closed, since nothing would gate it.
        let mut s = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: Vec::new(),
            response_tasks: vec!["safety".to_string()],
        })
        .expect("a response only session is valid");
        assert_eq!(
            s.observe(REQ, 5),
            Err(StreamError::NoTasks(StreamTrack::Request)),
            "an unmediated track gates nothing, so it takes nothing"
        );
        assert!(s.is_ended());
    }

    #[test]
    fn a_session_mediating_neither_track_is_refused() {
        assert_eq!(
            StreamSession::new(StreamSessionConfig {
                safety_level: SafetyLevel::Blocking,
                request_start_rune_offset: 0,
                response_start_rune_offset: 0,
                request_tasks: Vec::new(),
                response_tasks: Vec::new(),
            })
            .map(|_| ()),
            Err(StreamError::NoTasks(StreamTrack::Response))
        );
    }

    #[test]
    fn a_response_only_session_settles_on_its_own_track() {
        let mut s = StreamSession::new(StreamSessionConfig {
            safety_level: SafetyLevel::Blocking,
            request_start_rune_offset: 0,
            response_start_rune_offset: 0,
            request_tasks: Vec::new(),
            response_tasks: vec!["safety".to_string()],
        })
        .expect("config");
        s.observe(RES, 10).expect("observe");
        s.record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("clears");
        assert_eq!(s.advance(StreamTrack::Response), Some(10));
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }

    #[test]
    fn verdicts_map_onto_outcomes() {
        for (decision, clears) in [(Decision::Allow, true), (Decision::Deny, false)] {
            let mut s = session(&["safety"], SafetyLevel::Blocking);
            s.observe(RES, 10).expect("observe");
            s.record_verdict("safety", &span(RES, 0, 10), &verdict(decision))
                .expect("verdict records");
            if clears {
                assert_eq!(s.advance(StreamTrack::Response), Some(10), "{decision:?}");
            } else {
                assert!(
                    matches!(s.end_reason(), Some(StreamEndReason::Denied { .. })),
                    "{decision:?} must deny"
                );
            }
        }
    }

    #[test]
    fn an_allow_carrying_warnings_still_clears() {
        // A warning is a recorded concern, not a release decision. Under the
        // three decision contract a former `warn` arrives as this shape, so it
        // must clear exactly as a bare allow does.
        let mut s = session(&["safety"], SafetyLevel::Blocking);
        s.observe(RES, 10).expect("observe");
        let mut warned = verdict(Decision::Allow);
        warned.warnings.push(agent_hooks::Warning {
            reason: Some("content.borderline".to_string()),
            message: Some("a recorded concern".to_string()),
        });
        s.record_verdict("safety", &span(RES, 0, 10), &warned)
            .expect("an allow with warnings clears");
        assert_eq!(s.advance(StreamTrack::Response), Some(10));
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }

    #[test]
    fn a_resolved_liftable_deny_is_recorded_through_the_outcome_path() {
        // Once the host has run its approval seam it records the resolved
        // outcome directly, which is the supported path for both results.
        let mut cleared = session(&["safety"], SafetyLevel::Blocking);
        cleared.observe(RES, 10).expect("observe");
        cleared
            .record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Cleared)
            .expect("an approved lift clears");
        assert_eq!(cleared.advance(StreamTrack::Response), Some(10));

        let mut denied = session(&["safety"], SafetyLevel::Blocking);
        denied.observe(RES, 10).expect("observe");
        denied
            .record_outcome("safety", &span(RES, 0, 10), SegmentOutcome::Denied)
            .expect("a refused lift denies");
        assert!(matches!(
            denied.end_reason(),
            Some(StreamEndReason::Denied { .. })
        ));
    }

    #[test]
    fn every_failure_carries_a_reserved_reason() {
        assert_eq!(
            StreamError::OffsetOverflow.reason(),
            STREAMING_FAIL_CLOSED_REASON
        );
        assert_eq!(
            StreamError::TransformTooLate.reason(),
            STREAMING_FAIL_CLOSED_REASON
        );
        // A malformed verdict is a contract failure, not a streaming fault,
        // and agent-hooks already reserves the name.
        assert_eq!(StreamError::VerdictInvalid.reason(), VERDICT_INVALID_REASON);
        // Both constants must track the agent-hooks reserved set, since
        // section 16 requires new code to use those reasons rather than the
        // SDK layer names it keeps only for compatibility.
        assert_eq!(
            VERDICT_INVALID_REASON,
            agent_hooks::HostError::VerdictInvalid.to_string(),
            "the constant must track the agent-hooks reserved name"
        );
        assert_eq!(
            STREAMING_FAIL_CLOSED_REASON,
            agent_hooks::HostError::StreamingUnsupported.to_string(),
            "the constant must track the agent-hooks reserved name"
        );
    }
}
