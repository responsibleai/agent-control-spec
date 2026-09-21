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
use agent_hooks::{canonical_json, Decision, Evidence, Transform, Verdict, Warning};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Reserved prefix for engine-synthesized failure reasons. Policy
/// outputs must not use it (nor the agent-hooks `host_error:` prefix,
/// which is reserved for hosts).
const RESERVED_PREFIXES: [&str; 2] = ["runtime_error:", "host_error:"];

/// AGENT-HOOKS-0.1 section 5.3 cap on the RFC 8785 canonical size of
/// the `evidence` member, in bytes. `Verdict::validate` in the
/// agent-hooks SDK enforces the same bound. The published SDK
/// (0.1.0-alpha.5) keeps its constant private, so the engine restates
/// it here; a unit test probes `Verdict::validate` at the boundary so
/// the two cannot drift apart unnoticed. Switch to
/// `agent_hooks::EVIDENCE_MAX_BYTES` once the next alpha exports it.
pub const EVIDENCE_MAX_BYTES: usize = 10_240;

/// Warning reason the engine appends when it degrades oversize
/// evidence (specification section 13.3). Engine owned. It carries
/// neither reserved prefix, as section 18.1 requires of every warning.
pub const EVIDENCE_TRUNCATED_REASON: &str = "evidence_truncated";

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
                let reason = string_field(entry, "reason")?;
                // Section 18.1: a warning carries neither reserved prefix.
                // The runtime and the host own those namespaces, and the
                // agent-hooks wire decoder rejects a warning that uses
                // one, so a verdict carrying it would fail the host's
                // section 5 gate as host_error:verdict_invalid.
                if let Some(reason) = &reason {
                    for prefix in RESERVED_PREFIXES {
                        if reason.starts_with(prefix) {
                            return Err(RuntimeError::PolicyOutputInvalid(format!(
                                "policy output warnings must not use the reserved {prefix}* prefix"
                            )));
                        }
                    }
                }
                Ok(Warning {
                    reason,
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
    // Only the two section 13.3 members are admitted. No detail below
    // repeats a dispatcher supplied name or value: the detail names the
    // failure class and nothing else.
    if entry
        .keys()
        .any(|key| key != "artefact" && key != "verification_pointers")
    {
        return Err(RuntimeError::PolicyOutputInvalid(
            "evidence has a member other than artefact and verification_pointers".to_string(),
        ));
    }
    let artefact = match entry.get("artefact") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(value.clone()),
        _ => {
            return Err(RuntimeError::PolicyOutputInvalid(
                "evidence.artefact must be a string".to_string(),
            ))
        }
    };
    let verification_pointers = match entry.get("verification_pointers") {
        None | Some(JsonValue::Null) => BTreeMap::new(),
        Some(JsonValue::Object(map)) => {
            let mut out = BTreeMap::new();
            for (key, value) in map {
                let url = value.as_str().ok_or_else(|| {
                    RuntimeError::PolicyOutputInvalid(
                        "evidence.verification_pointers values must be strings".to_string(),
                    )
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
/// Fails closed on: unknown decisions, reserved reason prefixes on the
/// verdict or on a warning, the removed `effects` key, malformed
/// transforms/warnings/approval/evidence, a warning that uses the
/// runtime owned `evidence_truncated` reason, and anything the
/// agent-hooks §5 validation rejects.
///
/// Evidence over the §5.3 size bound does not fail closed. It is
/// degraded by [`degrade_evidence`] before the verdict is built, so the
/// final `validate()` gate still runs and must pass.
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

    // Section 13.3: the runtime owns the evidence_truncated reason. A
    // dispatcher warning that carries it, returned directly or through
    // the warn intent, would let a policy forge the marker the runtime
    // appends below, so it fails closed. The detail names the rule and
    // repeats nothing the dispatcher sent.
    if warnings
        .iter()
        .any(|warning| warning.reason.as_deref() == Some(EVIDENCE_TRUNCATED_REASON))
    {
        return Err(RuntimeError::PolicyOutputInvalid(
            "policy output warnings must not use the runtime owned evidence_truncated reason"
                .to_string(),
        ));
    }

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

    // Section 13.3: oversize evidence is degraded, not the verdict. The
    // marker goes after every warning the dispatcher returned, the
    // `warn` intent's included.
    let evidence = match evidence {
        Some(evidence) => {
            let degraded = degrade_evidence(evidence, EVIDENCE_MAX_BYTES)?;
            warnings.extend(degraded.warning);
            Some(degraded.evidence)
        }
        None => None,
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

/// The RFC 8785 canonical form of `evidence`: the bytes the agent-hooks
/// §5.3 size check measures, and the bytes the truncation digest covers.
fn canonical_evidence(evidence: &Evidence) -> Result<String, RuntimeError> {
    let value = serde_json::to_value(evidence).map_err(|_| {
        RuntimeError::PolicyOutputInvalid("evidence could not be serialized".to_string())
    })?;
    Ok(canonical_json(&value))
}

/// Whether `evidence` is at or under `cap` by the §5.3 measure.
fn evidence_within_cap(evidence: &Evidence, cap: usize) -> Result<bool, RuntimeError> {
    Ok(canonical_evidence(evidence)?.len() <= cap)
}

/// Evidence after the cap has been applied, with the warning that marks
/// a loss when there was one.
struct DegradedEvidence {
    evidence: Evidence,
    warning: Option<Warning>,
}

/// Fit `evidence` under `cap` without touching the verdict around it.
///
/// Rule (specification section 13.3): evidence that fits is returned
/// as is. Otherwise the artefact is kept whole when it fits on its own
/// and dropped otherwise, never cut. Verification pointers are then
/// kept in RFC 8785 member order (ascending UTF-16 code units of the
/// key) for as long as the result fits, and the rest are dropped. When
/// nothing fits the result is the empty object. One `evidence_truncated`
/// warning records the original canonical size, the cap, the artefact
/// outcome, the kept and total pointer counts, and `sha256:<hex>` of the
/// full canonical evidence. The result is deterministic for a given
/// input.
fn degrade_evidence(evidence: Evidence, cap: usize) -> Result<DegradedEvidence, RuntimeError> {
    let full = canonical_evidence(&evidence)?;
    if full.len() <= cap {
        return Ok(DegradedEvidence {
            evidence,
            warning: None,
        });
    }
    let digest = crate::hex::lower(&Sha256::digest(full.as_bytes()));

    let artefact_only = Evidence {
        artefact: evidence.artefact.clone(),
        verification_pointers: BTreeMap::new(),
    };
    let artefact = if evidence_within_cap(&artefact_only, cap)? {
        evidence.artefact.clone()
    } else {
        None
    };
    let artefact_outcome = match (&evidence.artefact, &artefact) {
        (None, _) => "no artefact",
        (Some(_), Some(_)) => "artefact kept",
        (Some(_), None) => "artefact dropped",
    };

    // RFC 8785 lists object members in ascending order of the UTF-16
    // code units of the key, and that is the order the canonical bytes
    // and the digest see. A BTreeMap<String, _> iterates by Unicode
    // scalar value instead, which differs for keys outside the Basic
    // Multilingual Plane, so the candidates are sorted the canonical way
    // first. The kept pointers are then a prefix of the canonical member
    // list.
    let mut pointers: Vec<(&String, &String)> = evidence.verification_pointers.iter().collect();
    pointers.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));

    // The canonical size grows with the prefix length, so a binary
    // search over the length finds the longest prefix that fits. `fits`
    // always names a length known to fit (zero does, since the artefact
    // decision above left something that fits); `too_many` starts one
    // past the end as a bound that is never measured.
    let with_prefix = |count: usize| Evidence {
        artefact: artefact.clone(),
        verification_pointers: pointers[..count]
            .iter()
            .map(|(key, url)| ((*key).clone(), (*url).clone()))
            .collect(),
    };
    let (mut fits, mut too_many) = (0usize, pointers.len() + 1);
    while too_many - fits > 1 {
        let probe = fits + (too_many - fits) / 2;
        if evidence_within_cap(&with_prefix(probe), cap)? {
            fits = probe;
        } else {
            too_many = probe;
        }
    }
    let kept = with_prefix(fits);

    let warning = truncation_warning(
        full.len(),
        cap,
        artefact_outcome,
        fits,
        pointers.len(),
        &digest,
    );
    Ok(DegradedEvidence {
        evidence: kept,
        warning: Some(warning),
    })
}

/// The `evidence_truncated` marker. The fixed text and the digest come
/// to 201 bytes; the three counts add their decimal digits. The message
/// stays under 256 bytes for any evidence under 10^18 canonical bytes,
/// far past any policy output limit a host can set. A unit test pins
/// the 201.
fn truncation_warning(
    original_bytes: usize,
    cap: usize,
    artefact_outcome: &str,
    kept_pointers: usize,
    total_pointers: usize,
    digest_hex: &str,
) -> Warning {
    Warning {
        reason: Some(EVIDENCE_TRUNCATED_REASON.to_string()),
        message: Some(format!(
            "evidence degraded: {original_bytes} canonical bytes exceeded the {cap} byte cap; \
             {artefact_outcome}; verification_pointers kept {kept_pointers} of {total_pointers}; \
             full evidence sha256:{digest_hex}"
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pointers(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, url)| (key.to_string(), url.to_string()))
            .collect()
    }

    fn artefact_only(canonical_size: usize) -> Evidence {
        // {"artefact":"<pad>"} is 15 bytes of framing plus the pad.
        Evidence {
            artefact: Some("x".repeat(canonical_size - 15)),
            verification_pointers: BTreeMap::new(),
        }
    }

    #[test]
    fn local_cap_matches_the_sdk_validate_gate() {
        let at_cap = artefact_only(EVIDENCE_MAX_BYTES);
        assert_eq!(
            canonical_evidence(&at_cap).unwrap().len(),
            EVIDENCE_MAX_BYTES
        );
        Verdict {
            evidence: Some(at_cap),
            ..Verdict::allow()
        }
        .validate()
        .expect("evidence at the cap passes the SDK gate");

        let over = Verdict {
            evidence: Some(artefact_only(EVIDENCE_MAX_BYTES + 1)),
            ..Verdict::allow()
        };
        assert!(over.validate().is_err(), "one byte over fails the SDK gate");
    }

    #[test]
    fn canonical_evidence_matches_the_sdk_measure() {
        let evidence = Evidence {
            artefact: Some("sha256:abc".to_string()),
            verification_pointers: pointers(&[("z", "https://z"), ("a", "https://a")]),
        };
        let expected = canonical_json(&json!({
            "artefact": "sha256:abc",
            "verification_pointers": {"a": "https://a", "z": "https://z"},
        }));
        assert_eq!(canonical_evidence(&evidence).unwrap(), expected);
        assert_eq!(canonical_evidence(&Evidence::default()).unwrap(), "{}");

        // An absent artefact is skipped, not written as null.
        let pointers_only = Evidence {
            artefact: None,
            verification_pointers: pointers(&[("a", "1")]),
        };
        assert_eq!(
            canonical_evidence(&pointers_only).unwrap(),
            r#"{"verification_pointers":{"a":"1"}}"#
        );
    }

    #[test]
    fn evidence_under_the_cap_is_untouched() {
        let evidence = Evidence {
            artefact: Some("sha256:abc".to_string()),
            verification_pointers: pointers(&[("a", "1")]),
        };
        let degraded = degrade_evidence(evidence.clone(), EVIDENCE_MAX_BYTES).unwrap();
        assert_eq!(degraded.evidence, evidence);
        assert!(degraded.warning.is_none());
    }

    #[test]
    fn pointer_selection_keeps_a_key_order_prefix() {
        // {"verification_pointers":{"a":"1","b":"2","c":"3"}} is 51 bytes;
        // the two pointer prefix is 43 and the one pointer prefix 35.
        let evidence = Evidence {
            artefact: None,
            verification_pointers: pointers(&[("c", "3"), ("a", "1"), ("b", "2")]),
        };
        assert_eq!(canonical_evidence(&evidence).unwrap().len(), 51);

        let degraded = degrade_evidence(evidence, 45).unwrap();
        let kept: Vec<&str> = degraded
            .evidence
            .verification_pointers
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(kept, ["a", "b"]);
        assert_eq!(degraded.evidence.verification_pointers["a"], "1");
        assert_eq!(degraded.evidence.verification_pointers["b"], "2");
        assert_eq!(canonical_evidence(&degraded.evidence).unwrap().len(), 43);
        let message = degraded.warning.unwrap().message.unwrap();
        assert!(message.contains("no artefact"), "{message}");
        assert!(message.contains("kept 2 of 3"), "{message}");
        assert!(
            message.contains("51 canonical bytes exceeded the 45 byte cap"),
            "{message}"
        );
    }

    #[test]
    fn artefact_comes_first_and_is_never_cut() {
        // {"artefact":"xyz"} is 18 bytes; any pointer pushes it past 20.
        let evidence = Evidence {
            artefact: Some("xyz".to_string()),
            verification_pointers: pointers(&[("a", "1")]),
        };
        let degraded = degrade_evidence(evidence, 20).unwrap();
        assert_eq!(degraded.evidence.artefact.as_deref(), Some("xyz"));
        assert!(degraded.evidence.verification_pointers.is_empty());
        let message = degraded.warning.unwrap().message.unwrap();
        assert!(message.contains("artefact kept"), "{message}");
        assert!(message.contains("kept 0 of 1"), "{message}");

        // {"artefact":"<30 x>"} is 45 bytes: over a 40 byte cap on its
        // own, so it is dropped whole, and the pointer, 35 bytes on its
        // own, stays.
        let evidence = Evidence {
            artefact: Some("x".repeat(30)),
            verification_pointers: pointers(&[("a", "1")]),
        };
        let degraded = degrade_evidence(evidence, 40).unwrap();
        assert_eq!(degraded.evidence.artefact, None);
        assert_eq!(
            degraded.evidence.verification_pointers,
            pointers(&[("a", "1")])
        );
        let message = degraded.warning.unwrap().message.unwrap();
        assert!(message.contains("artefact dropped"), "{message}");
        assert!(message.contains("kept 1 of 1"), "{message}");
    }

    fn kept_keys(degraded: &DegradedEvidence) -> Vec<&str> {
        degraded
            .evidence
            .verification_pointers
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn a_pointer_prefix_that_lands_exactly_on_the_cap_is_kept() {
        // The two pointer prefix of the fixture is exactly 43 bytes, so
        // a 43 byte cap keeps it and a 42 byte cap keeps one pointer.
        // This pins the inclusive bound of the fit check.
        let evidence = Evidence {
            artefact: None,
            verification_pointers: pointers(&[("a", "1"), ("b", "2"), ("c", "3")]),
        };
        let at_cap = degrade_evidence(evidence.clone(), 43).unwrap();
        assert_eq!(kept_keys(&at_cap), ["a", "b"]);
        assert_eq!(canonical_evidence(&at_cap.evidence).unwrap().len(), 43);

        let under = degrade_evidence(evidence, 42).unwrap();
        assert_eq!(kept_keys(&under), ["a"]);
    }

    #[test]
    fn an_artefact_that_lands_exactly_on_the_cap_is_kept() {
        // {"artefact":"xyz"} is exactly 18 bytes. Next to a pointer that
        // cannot fit beside it, an 18 byte cap keeps the artefact and a
        // 17 byte cap drops it, leaving the empty object.
        let evidence = Evidence {
            artefact: Some("xyz".to_string()),
            verification_pointers: pointers(&[("a", "1")]),
        };
        let at_cap = degrade_evidence(evidence.clone(), 18).unwrap();
        assert_eq!(at_cap.evidence.artefact.as_deref(), Some("xyz"));
        assert!(at_cap.evidence.verification_pointers.is_empty());
        assert_eq!(canonical_evidence(&at_cap.evidence).unwrap().len(), 18);

        let under = degrade_evidence(evidence, 17).unwrap();
        assert_eq!(under.evidence.artefact, None);
        assert!(under.evidence.verification_pointers.is_empty());
        assert_eq!(canonical_evidence(&under.evidence).unwrap(), "{}");
    }

    #[test]
    fn pointer_selection_follows_the_canonical_member_order() {
        // U+FF5E sorts before U+10000 by scalar value and after it by
        // UTF-16 code units (D800 DC00 < FF5E). RFC 8785 uses the
        // latter, so the astral key is the first canonical member and
        // is the one kept when only one fits.
        let bmp = "\u{FF5E}";
        let astral = "\u{10000}";
        let evidence = Evidence {
            artefact: None,
            verification_pointers: pointers(&[(bmp, "1"), (astral, "2")]),
        };
        assert_eq!(
            evidence
                .verification_pointers
                .keys()
                .next()
                .map(String::as_str),
            Some(bmp),
            "BTreeMap order puts the BMP key first"
        );
        let full = canonical_evidence(&evidence).unwrap();
        assert!(full.find(astral) < full.find(bmp), "{full}");

        let degraded = degrade_evidence(evidence, full.len() - 1).unwrap();
        assert_eq!(kept_keys(&degraded), [astral]);
        assert_eq!(degraded.evidence.verification_pointers[astral], "2");
    }

    #[test]
    fn a_dispatcher_warning_with_the_runtime_owned_reason_fails_closed() {
        let direct = normalize_policy_output(json!({
            "decision": "allow",
            "warnings": [{"reason": EVIDENCE_TRUNCATED_REASON, "message": "forged"}],
        }))
        .unwrap_err();
        assert!(matches!(direct, RuntimeError::PolicyOutputInvalid(_)));
        assert!(!direct.detail().contains("forged"), "{}", direct.detail());
        assert!(direct.detail().contains(EVIDENCE_TRUNCATED_REASON));

        let via_warn_intent = normalize_policy_output(json!({
            "decision": "warn",
            "reason": EVIDENCE_TRUNCATED_REASON,
            "message": "forged",
        }))
        .unwrap_err();
        assert!(matches!(
            via_warn_intent,
            RuntimeError::PolicyOutputInvalid(_)
        ));
        assert!(!via_warn_intent.detail().contains("forged"));

        // Any other warning reason passes as before.
        let other = normalize_policy_output(json!({
            "decision": "warn",
            "reason": "evidence_truncated_by_policy",
        }))
        .unwrap();
        assert_eq!(other.warnings.len(), 1);
    }

    #[test]
    fn a_dispatcher_warning_with_a_reserved_prefix_fails_closed() {
        for prefix in RESERVED_PREFIXES {
            let error = normalize_policy_output(json!({
                "decision": "allow",
                "warnings": [{"reason": format!("{prefix}forged_zq9v"), "message": "forged"}],
            }))
            .unwrap_err();
            assert!(matches!(error, RuntimeError::PolicyOutputInvalid(_)));
            let detail = error.detail();
            assert!(detail.contains(prefix), "{detail}");
            assert!(!detail.contains("zq9v"), "{detail}");
            assert!(!detail.contains("forged"), "{detail}");
        }

        // A reason that merely contains the prefix text is not reserved.
        let unreserved = normalize_policy_output(json!({
            "decision": "allow",
            "warnings": [{"reason": "not_a_runtime_error:really"}],
        }))
        .unwrap();
        assert_eq!(unreserved.warnings.len(), 1);
    }

    #[test]
    fn digest_covers_the_full_canonical_evidence() {
        // One key outside the BMP, so RFC 8785 member order differs from
        // BTreeMap order and the expected digest cannot come from a
        // serializer that keeps the map's own order.
        let evidence = Evidence {
            artefact: Some("x".repeat(EVIDENCE_MAX_BYTES)),
            verification_pointers: pointers(&[("\u{FF5E}", "1"), ("\u{10000}", "2")]),
        };
        // The oracle is the SDK serializer over the plain JSON value,
        // not the engine's own canonical_evidence.
        let full = canonical_json(&serde_json::to_value(&evidence).unwrap());
        let expected = crate::hex::lower(&Sha256::digest(full.as_bytes()));
        assert_eq!(expected.len(), 64);

        let degraded = degrade_evidence(evidence, EVIDENCE_MAX_BYTES).unwrap();
        let message = degraded.warning.unwrap().message.unwrap();
        assert!(
            message.ends_with(&format!("sha256:{expected}")),
            "{message}"
        );
    }

    #[test]
    fn degraded_evidence_passes_the_sdk_gate() {
        let evidence = Evidence {
            artefact: Some("x".repeat(6_000)),
            verification_pointers: (0..400)
                .map(|index| {
                    (
                        format!("ptr_{index:03}"),
                        format!("https://example.com/pointers/{index:03}"),
                    )
                })
                .collect(),
        };
        let degraded = degrade_evidence(evidence, EVIDENCE_MAX_BYTES).unwrap();
        assert!(canonical_evidence(&degraded.evidence).unwrap().len() <= EVIDENCE_MAX_BYTES);
        assert!(!degraded.evidence.verification_pointers.is_empty());
        Verdict {
            evidence: Some(degraded.evidence),
            ..Verdict::allow()
        }
        .validate()
        .expect("degraded evidence passes the SDK gate");
    }

    #[test]
    fn truncation_message_stays_under_256_bytes() {
        let warning = truncation_warning(
            262_144,
            EVIDENCE_MAX_BYTES,
            "artefact dropped",
            99_999,
            99_999,
            &"f".repeat(64),
        );
        assert_eq!(warning.reason.as_deref(), Some(EVIDENCE_TRUNCATED_REASON));
        let message = warning.message.unwrap();
        assert!(message.len() < 256, "{} bytes", message.len());
        // 201 bytes of fixed text and digest plus 6 + 5 + 5 count digits.
        // A reworded message must re-check the bound stated on
        // `truncation_warning`.
        assert_eq!(message.len(), 217, "{message}");
        for prefix in RESERVED_PREFIXES {
            assert!(!EVIDENCE_TRUNCATED_REASON.starts_with(prefix));
        }
    }
}
