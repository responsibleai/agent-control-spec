// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! The JSON shapes every binding answers with.
//!
//! None of the streaming or telemetry types derives `Serialize`, so
//! something has to decide what a watermark looks like on the wire.
//! Before this module each binding decided separately, which put three
//! copies of that decision in three crates. Three copies of what
//! `"response"` means are three chances to disagree, and a disagreement
//! here is a host releasing text no task evaluated.
//!
//! So the contract lives with the engine that defines the behaviour.
//! The bindings translate calling conventions, not meaning, and the
//! cross-language conformance suite then checks the bindings rather
//! than re-litigating the contract in each one.

use crate::error::RuntimeError;
use crate::limits::Limits;
use crate::perf_telemetry::PerfTelemetry;
use serde_json::{json, Map, Value};

#[cfg(feature = "streaming")]
use crate::stream_session::{
    StreamCompletion, StreamEndReason, StreamSessionConfig, StreamWatermark,
};

/// Parse a perf telemetry level's wire name.
pub fn parse_perf_telemetry(value: &str) -> Result<PerfTelemetry, RuntimeError> {
    match value {
        "off" => Ok(PerfTelemetry::Off),
        "external" => Ok(PerfTelemetry::External),
        "full" => Ok(PerfTelemetry::Full),
        other => Err(RuntimeError::ManifestInvalid(format!(
            "unknown perf telemetry level '{other}'"
        ))),
    }
}

/// A perf telemetry level's wire name.
pub fn perf_telemetry_str(level: PerfTelemetry) -> &'static str {
    match level {
        PerfTelemetry::Off => "off",
        PerfTelemetry::External => "external",
        PerfTelemetry::Full => "full",
    }
}

/// Apply a JSON object of resource cap overrides onto the defaults.
///
/// Each field is individually optional, so a host raising one cap does
/// not restate the other nine. A field present but not a non-negative
/// integer is refused rather than silently kept at its default: a host
/// that asked for a smaller bound and got the larger one would believe
/// it was protected when it was not.
pub fn limits_from_json(value: &Value) -> Result<Limits, RuntimeError> {
    let Value::Object(fields) = value else {
        return Err(RuntimeError::ManifestInvalid(
            "limits must be a JSON object".to_string(),
        ));
    };
    let mut limits = Limits::default();

    let read = |key: &str| -> Result<Option<u64>, RuntimeError> {
        match fields.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(found) => found.as_u64().map(Some).ok_or_else(|| {
                RuntimeError::ManifestInvalid(format!("{key} must be a non negative integer"))
            }),
        }
    };

    macro_rules! apply {
        ($field:ident, $ty:ty) => {
            if let Some(found) = read(stringify!($field))? {
                limits.$field = found as $ty;
            }
        };
    }
    apply!(max_snapshot_bytes, usize);
    apply!(max_policy_input_depth, usize);
    apply!(max_annotators_per_point, usize);
    apply!(max_annotator_output_bytes, usize);
    apply!(max_policy_output_bytes, usize);
    apply!(max_extends_depth, usize);
    apply!(max_merged_manifest_bytes, usize);
    apply!(max_manifest_url_bytes, usize);
    apply!(manifest_url_timeout_ms, u64);
    apply!(max_manifest_url_redirects, usize);

    let unknown: Vec<&str> = fields
        .keys()
        .map(String::as_str)
        .filter(|key| !LIMIT_FIELDS.contains(key))
        .collect();
    if !unknown.is_empty() {
        // A misspelled cap that is quietly ignored is the same defect as
        // one that is quietly widened: the host believes it set a bound
        // it did not set.
        return Err(RuntimeError::ManifestInvalid(format!(
            "unknown limit field(s): {}",
            unknown.join(", ")
        )));
    }
    Ok(limits)
}

/// Every field [`limits_from_json`] accepts, in declaration order.
pub const LIMIT_FIELDS: [&str; 10] = [
    "max_snapshot_bytes",
    "max_policy_input_depth",
    "max_annotators_per_point",
    "max_annotator_output_bytes",
    "max_policy_output_bytes",
    "max_extends_depth",
    "max_merged_manifest_bytes",
    "max_manifest_url_bytes",
    "manifest_url_timeout_ms",
    "max_manifest_url_redirects",
];

/// The resource caps in force, as JSON.
pub fn limits_json(limits: &Limits) -> Value {
    json!({
        "max_snapshot_bytes": limits.max_snapshot_bytes,
        "max_policy_input_depth": limits.max_policy_input_depth,
        "max_annotators_per_point": limits.max_annotators_per_point,
        "max_annotator_output_bytes": limits.max_annotator_output_bytes,
        "max_policy_output_bytes": limits.max_policy_output_bytes,
        "max_extends_depth": limits.max_extends_depth,
        "max_merged_manifest_bytes": limits.max_merged_manifest_bytes,
        "max_manifest_url_bytes": limits.max_manifest_url_bytes,
        "manifest_url_timeout_ms": limits.manifest_url_timeout_ms,
        "max_manifest_url_redirects": limits.max_manifest_url_redirects,
    })
}

/// Manifest field names an authoring tool wants surfaced verbatim.
///
/// The engine reports validation failures as prose naming the offending
/// field, so recovering the field means finding it in the message. That
/// is a heuristic, and it belongs here rather than in each binding: a
/// heuristic implemented three times is three heuristics.
const DIAGNOSTIC_FIELDS: &[&str] = &[
    "agent_control_specification_version",
    "policy_target_kind",
    "policy_target",
    "tool_name_from",
    "annotations",
    "annotators",
    "intervention_points",
    "intervention point",
    "extends",
    "policies",
    "policy.id",
    "approval",
    "metadata",
    "tools",
];

/// The manifest field a validation message names, when it names one.
pub fn diagnostic_field(message: &str) -> Option<&'static str> {
    // Longest first, because `policy_target` is a prefix of
    // `policy_target_kind` and would otherwise swallow it.
    let mut ordered: Vec<&&str> = DIAGNOSTIC_FIELDS.iter().collect();
    ordered.sort_by_key(|field| std::cmp::Reverse(field.len()));
    ordered
        .into_iter()
        .find(|field| message.contains(**field))
        .copied()
}

/// One finding about a manifest or its artifacts.
///
/// `RuntimeError` answers by being returned, which a linter cannot
/// render against a document. This is the same information as data.
pub fn diagnostic_json(error: &RuntimeError) -> Value {
    let message = error.detail();
    json!({
        "code": error.reason(),
        "message": message,
        "severity": "error",
        "field": diagnostic_field(message),
    })
}

/// A list of findings. Empty means sound.
pub fn diagnostics_json(errors: &[RuntimeError]) -> Value {
    Value::Array(errors.iter().map(diagnostic_json).collect())
}

/// Why a session ended.
#[cfg(feature = "streaming")]
pub fn end_reason_json(reason: &StreamEndReason) -> Value {
    match reason {
        StreamEndReason::Complete => json!({ "kind": "complete" }),
        StreamEndReason::Denied { track, task, range } => json!({
            "kind": "denied",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Rewritten { track, task, range } => json!({
            "kind": "rewritten",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Failed(error) => json!({
            "kind": "failed",
            "reason": error.reason(),
            "message": error.to_string(),
        }),
    }
}

/// How far one track got and what still owes a decision.
#[cfg(feature = "streaming")]
pub fn watermark_json(track: crate::stream_session::StreamTrack, mark: &StreamWatermark) -> Value {
    json!({
        "track": track.as_str(),
        "confirmed": mark.confirmed(),
        "received": mark.received(),
        "pending": mark.pending(),
        "tasks": mark.tasks().collect::<Vec<_>>(),
    })
}

/// Terminal settlement of a session.
#[cfg(feature = "streaming")]
pub fn completion_json(completion: &StreamCompletion) -> Value {
    json!({
        "reason": end_reason_json(&completion.reason),
        "transformed": completion.transformed,
        "is_clean": completion.reason.is_clean(),
    })
}

/// The offsets and task sets a session was opened with.
#[cfg(feature = "streaming")]
pub fn stream_config_json(config: &StreamSessionConfig) -> Value {
    json!({
        "safety_level": config.safety_level.as_str(),
        "request_start_rune_offset": config.request_start_rune_offset,
        "response_start_rune_offset": config.response_start_rune_offset,
        "request_tasks": config.request_tasks,
        "response_tasks": config.response_tasks,
    })
}

/// Live state of a session: whether it ended, whether a rewrite ended
/// it, why, and the configuration in force.
#[cfg(feature = "streaming")]
pub fn stream_session_state_json(session: &crate::stream_session::StreamSession) -> Value {
    json!({
        "is_ended": session.is_ended(),
        "transformed": session.transformed(),
        "end_reason": session.end_reason().map(end_reason_json),
        "config": stream_config_json(session.config()),
    })
}

/// Read a session configuration from JSON, defaulting absent fields.
#[cfg(feature = "streaming")]
pub fn stream_config_from_json(
    value: &Value,
) -> Result<StreamSessionConfig, crate::stream_session::StreamError> {
    use crate::stream_session::{SafetyLevel, StreamError};

    let empty = Map::new();
    let fields = value.as_object().unwrap_or(&empty);

    let safety_level = SafetyLevel::parse(
        fields
            .get("safety_level")
            .and_then(Value::as_str)
            .unwrap_or("blocking"),
    )?;

    let offset = |key: &str| -> Result<u32, StreamError> {
        match fields.get(key) {
            None | Some(Value::Null) => Ok(0),
            Some(found) => found
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| {
                    StreamError::UnknownSourceType(format!("{key} is not a rune offset"))
                }),
        }
    };

    let tasks = |key: &str| -> Result<Vec<String>, StreamError> {
        match fields.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        StreamError::UnknownSourceType(format!(
                            "{key} holds a non string task name"
                        ))
                    })
                })
                .collect(),
            Some(_) => Err(StreamError::UnknownSourceType(format!(
                "{key} is not an array of task names"
            ))),
        }
    };

    Ok(StreamSessionConfig {
        safety_level,
        request_start_rune_offset: offset("request_start_rune_offset")?,
        response_start_rune_offset: offset("response_start_rune_offset")?,
        request_tasks: tasks("request_tasks")?,
        response_tasks: tasks("response_tasks")?,
    })
}

/// One telemetry event.
///
/// `TelemetryEvent` does not derive `Serialize`, so a sink reached
/// through any binding sees the shape stated here.
pub fn telemetry_event_json(event: &crate::telemetry::TelemetryEvent) -> Value {
    json!({
        "event_type": event.event_type.as_str(),
        "intervention_point": format!("{:?}", event.intervention_point).to_lowercase(),
        "decision": event.decision.map(|d| format!("{d:?}").to_lowercase()),
        "reason_code": event.reason_code,
        "error_class": event.error_class,
        "policy_id": event.policy_id,
        "annotators": event.annotators,
        "enforcement_mode": event.enforcement_mode.map(|m| format!("{m:?}").to_lowercase()),
        "duration_ms": event.duration_ms,
        "evidence_artefact": event.evidence_artefact,
        "evidence_verification_pointer_keys": event.evidence_verification_pointer_keys,
        "action_identity": event.action_identity,
        "metadata": event.metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_limit_fields_keep_their_own_defaults() {
        let limits = limits_from_json(&json!({ "max_snapshot_bytes": 64 })).expect("limits");
        assert_eq!(limits.max_snapshot_bytes, 64);
        assert_eq!(
            limits.max_policy_input_depth,
            Limits::default().max_policy_input_depth
        );
    }

    #[test]
    fn a_limit_that_is_not_a_count_is_refused() {
        assert!(limits_from_json(&json!({ "max_snapshot_bytes": "big" })).is_err());
        assert!(limits_from_json(&json!({ "max_snapshot_bytes": -1 })).is_err());
    }

    #[test]
    fn a_misspelled_limit_is_refused_rather_than_ignored() {
        let error = limits_from_json(&json!({ "max_snapshot_byte": 64 })).expect_err("refused");
        assert!(format!("{error}").contains("max_snapshot_byte"));
    }

    #[test]
    fn every_limit_field_round_trips() {
        let rendered = limits_json(&Limits::default());
        for field in LIMIT_FIELDS {
            assert!(rendered.get(field).is_some(), "{field} missing");
        }
        let parsed = limits_from_json(&rendered).expect("round trip");
        assert_eq!(parsed, Limits::default());
    }

    #[test]
    fn a_diagnostic_names_the_offending_field() {
        let error = RuntimeError::ManifestInvalid(
            "at least one intervention point config is required".to_string(),
        );
        let rendered = diagnostic_json(&error);
        assert_eq!(rendered["field"], "intervention point");
        assert_eq!(rendered["severity"], "error");
    }

    #[test]
    fn a_longer_field_name_is_not_swallowed_by_its_prefix() {
        assert_eq!(
            diagnostic_field("policy_target_kind must be a known kind"),
            Some("policy_target_kind")
        );
    }

    #[test]
    fn a_message_naming_no_field_reports_none() {
        assert_eq!(diagnostic_field("something else went wrong"), None);
    }

    #[test]
    fn perf_levels_round_trip_and_unknown_is_refused() {
        for level in [
            PerfTelemetry::Off,
            PerfTelemetry::External,
            PerfTelemetry::Full,
        ] {
            assert_eq!(
                parse_perf_telemetry(perf_telemetry_str(level)).unwrap(),
                level
            );
        }
        assert!(parse_perf_telemetry("verbose").is_err());
    }
}
