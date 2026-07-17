//! Policy-output normalization: the boundary between the policy plane
//! and the agent-hooks verdict contract.
//!
//! Dispatchers return raw JSON. This module validates it and produces
//! an [`agent_hooks::Verdict`]. Policy documents may express the
//! `warn` and `escalate` *intents* as decision names — those are
//! policy-language vocabulary, mapped here to their native shapes:
//! `warn` → `allow` carrying `warnings[]`, `escalate` → `deny`
//! carrying an `approval` block. The engine never constructs any other
//! decision vocabulary: the output of normalization is exactly the
//! three-decision agent-hooks verdict.

use crate::{JsonValue, RuntimeError};
use agent_hooks::{Decision, Evidence, Transform, Verdict, Warning};

/// Reserved prefix for engine-synthesized failure reasons. Policy
/// outputs must not use it (nor the agent-hooks `host_error:` prefix,
/// which is reserved for hosts).
const RESERVED_PREFIXES: [&str; 2] = ["runtime_error:", "host_error:"];

fn string_field(
    object: &serde_json::Map<String, JsonValue>,
    key: &str,
) -> Result<Option<String>, RuntimeError> {
    match object.get(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => Ok(Some(value.clone())),
        _ => Err(RuntimeError::PolicyOutputInvalid(format!(
            "policy output {key} must be a string"
        ))),
    }
}

fn reason_field(
    object: &serde_json::Map<String, JsonValue>,
) -> Result<Option<String>, RuntimeError> {
    let reason = string_field(object, "reason")?;
    if let Some(reason) = &reason {
        for prefix in RESERVED_PREFIXES {
            if reason.starts_with(prefix) {
                return Err(RuntimeError::PolicyOutputInvalid(format!(
                    "policy reasons must not use the reserved {prefix}* prefix"
                )));
            }
        }
    }
    Ok(reason)
}

fn warnings_field(
    object: &serde_json::Map<String, JsonValue>,
) -> Result<Vec<Warning>, RuntimeError> {
    match object.get("warnings") {
        None | Some(JsonValue::Null) => Ok(Vec::new()),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| {
                let entry = item.as_object().ok_or_else(|| {
                    RuntimeError::PolicyOutputInvalid(
                        "policy output warnings entries must be objects".to_string(),
                    )
                })?;
                Ok(Warning {
                    reason: string_field(entry, "reason")?,
                    message: string_field(entry, "message")?,
                })
            })
            .collect(),
        _ => Err(RuntimeError::PolicyOutputInvalid(
            "policy output warnings must be an array".to_string(),
        )),
    }
}

fn result_labels_field(
    object: &serde_json::Map<String, JsonValue>,
) -> Result<Vec<String>, RuntimeError> {
    match object.get("result_labels") {
        None | Some(JsonValue::Null) => Ok(Vec::new()),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    RuntimeError::PolicyOutputInvalid(
                        "policy output result_labels must be an array of strings".to_string(),
                    )
                })
            })
            .collect(),
        _ => Err(RuntimeError::PolicyOutputInvalid(
            "policy output result_labels must be an array".to_string(),
        )),
    }
}

fn approval_field(
    object: &serde_json::Map<String, JsonValue>,
) -> Result<Option<serde_json::Map<String, JsonValue>>, RuntimeError> {
    match object.get("approval") {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Object(map)) => Ok(Some(map.clone())),
        _ => Err(RuntimeError::PolicyOutputInvalid(
            "policy output approval must be an object".to_string(),
        )),
    }
}

fn transform_field(value: &JsonValue) -> Result<Transform, RuntimeError> {
    let object = value.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("transform must be an object".to_string())
    })?;
    let path = object
        .get("path")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "transform.path is required when decision is transform".to_string(),
            )
        })?;
    // The agent-hooks transform grammar is authoritative: parse with the
    // same parser the host will use at apply time, so nothing the engine
    // emits can pass here and fail there.
    agent_hooks::parse_transform_path(path).map_err(|err| {
        if path.starts_with("$target") {
            RuntimeError::TransformInvalid(format!("transform.path invalid: {err:?}"))
        } else {
            RuntimeError::TransformTargetForbidden(path.to_string())
        }
    })?;
    let value = object.get("value").cloned().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid(
            "transform.value is required when decision is transform".to_string(),
        )
    })?;
    Ok(Transform {
        path: path.to_string(),
        value,
    })
}

fn evidence_field(
    object: &serde_json::Map<String, JsonValue>,
) -> Result<Option<Evidence>, RuntimeError> {
    let value = match object.get("evidence") {
        None | Some(JsonValue::Null) => return Ok(None),
        Some(value) => value,
    };
    let entry = value.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("evidence must be an object".to_string())
    })?;
    let artefact = string_field(entry, "artefact")?;
    let verification_pointers = match entry.get("verification_pointers") {
        None | Some(JsonValue::Null) => Default::default(),
        Some(JsonValue::Object(map)) => {
            let mut out = std::collections::BTreeMap::new();
            for (key, value) in map {
                let url = value.as_str().ok_or_else(|| {
                    RuntimeError::PolicyOutputInvalid(format!(
                        "evidence.verification_pointers.{key} must be a string"
                    ))
                })?;
                out.insert(key.clone(), url.to_string());
            }
            out
        }
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "evidence.verification_pointers must be an object of strings".to_string(),
            ))
        }
    };
    Ok(Some(Evidence {
        artefact,
        verification_pointers,
    }))
}

/// Normalize raw dispatcher output into an agent-hooks verdict.
///
/// Fails closed on: unknown decisions, reserved reason prefixes, the
/// removed `effects` key, malformed transforms/warnings/approval/
/// evidence, and anything the agent-hooks §5 validation rejects
/// (including the evidence size bound).
pub fn normalize_policy_output(output: JsonValue) -> Result<Verdict, RuntimeError> {
    let object = output.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("policy output must be an object".to_string())
    })?;

    let decision_name = object
        .get("decision")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid("policy output decision is required".to_string())
        })?;

    if object.contains_key("effects") {
        return Err(RuntimeError::PolicyOutputInvalid(
            "verdict 'effects' is not supported; use the transform decision. \
             Migrate multi-step rewriting to an annotator"
                .to_string(),
        ));
    }

    let reason = reason_field(object)?;
    let message = string_field(object, "message")?;
    let mut warnings = warnings_field(object)?;
    let result_labels = result_labels_field(object)?;
    let mut approval = approval_field(object)?;
    let evidence = evidence_field(object)?;

    // Policy-language intents `warn` and `escalate` map to their native
    // agent-hooks shapes; everything else must be one of the three wire
    // decisions.
    let decision = match decision_name {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        "transform" => Decision::Transform,
        "warn" => {
            warnings.push(Warning {
                reason: reason.clone(),
                message: message.clone(),
            });
            Decision::Allow
        }
        "escalate" => {
            approval.get_or_insert_with(Default::default);
            Decision::Deny
        }
        other => {
            return Err(RuntimeError::PolicyOutputInvalid(format!(
                "unsupported decision '{other}'"
            )))
        }
    };

    if approval.is_some() && decision != Decision::Deny {
        return Err(RuntimeError::PolicyOutputInvalid(
            "approval is only permitted on the deny decision".to_string(),
        ));
    }

    let transform = match (decision, object.get("transform")) {
        (Decision::Transform, None | Some(JsonValue::Null)) => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "transform decision requires a transform object".to_string(),
            ))
        }
        (Decision::Transform, Some(value)) => Some(transform_field(value)?),
        (_, None | Some(JsonValue::Null)) => None,
        (_, Some(_)) => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "transform is only permitted on the transform decision".to_string(),
            ))
        }
    };

    let verdict = Verdict {
        decision,
        reason,
        message,
        warnings,
        approval,
        transform,
        evidence,
        result_labels,
    };

    // Final gate: the agent-hooks §5 rules (shape constraints, evidence
    // size bound) are authoritative for anything the engine hands the
    // host.
    verdict
        .validate()
        .map_err(|err| RuntimeError::PolicyOutputInvalid(format!("verdict fails §5: {err:?}")))?;
    Ok(verdict)
}

/// Engine-synthesized fail-closed verdict for a runtime error.
pub fn runtime_error_verdict(error: &RuntimeError) -> Verdict {
    let message = match error {
        RuntimeError::AnnotationFailed(detail) if !detail.is_empty() => {
            format!("Request blocked by Agent Control Specification. {detail}")
        }
        _ => "Request blocked by Agent Control Specification.".to_string(),
    };
    Verdict {
        decision: Decision::Deny,
        reason: Some(error.reason().to_string()),
        message: Some(message),
        ..Verdict::allow()
    }
}
