//! AGT D3 cedar dispatcher surface.
//!
//! See `policy-engine/spec/SPECIFICATION.md` §12.4 for the normative
//! contract. This module provides three pieces:
//!
//! 1. [`CedarPolicyDispatcher`] is the trait a host implements to evaluate a
//!    [`CedarPolicyInvocation`]. It is parallel to the rego dispatcher path
//!    that lives in [`crate::opa`]; both ultimately satisfy the runtime
//!    [`crate::PolicyDispatcher`] trait so the [`crate::Runtime`] can call
//!    into either backend uniformly.
//! 2. [`CedarTestDispatcher`] is a deterministic test double, always
//!    compiled, that parses a small JSON pseudo-cedar policy set, builds a
//!    cedar [`CedarRequest`] from the policy input per D3.2, and emits an
//!    `allow`, `deny`, or advice-translated verdict per D3.3. It matches on
//!    principal, action and resource only; the context it builds is not
//!    consulted.
//! 3. [`CedarBuiltinDispatcher`] is the AGT M2.S5 D7 feature-gated bundled
//!    dispatcher backed by the upstream `cedar-policy` crate. It evaluates
//!    the full request, context included, and maps the answer to a verdict
//!    per §12.4. It is gated behind the `cedar` Cargo feature so callers
//!    that do not want the heavyweight cedar dep can opt out at build time.
//!
//! [`build_cedar_request`] is the one place that implements the §12.4
//! request mapping. Both dispatchers, and any host dispatcher that wants
//! the same request, go through it.
//!
//! The dispatcher returns a verdict-shaped `JsonValue` exactly like the OPA
//! dispatcher does, and the runtime then normalizes the value via
//! [`crate::normalize_policy_output`]. Errors fail closed with the matching
//! reserved reason from `RuntimeError`.

use crate::{
    constants::policy_input as pi_key, runtime::PolicyDispatcher, CedarPolicyInvocation, JsonValue,
    PreparedPolicyInvocation, RuntimeError,
};
use serde::Deserialize;
use serde_json::{json, Map};

/// Cedar dispatcher contract. Implementations evaluate a prepared cedar
/// invocation and return a verdict-shaped `JsonValue` that the runtime feeds
/// to [`crate::normalize_policy_output`]. Errors fail closed with
/// `runtime_error:policy_invocation_failed` or `runtime_error:policy_output_invalid`.
pub trait CedarPolicyDispatcher: Send + Sync {
    fn evaluate_cedar(&self, invocation: &CedarPolicyInvocation)
        -> Result<JsonValue, RuntimeError>;
}

/// Cedar request derived from the policy input per `SPECIFICATION.md`
/// §12.4. The dispatcher is responsible for translating this into the
/// cedar crate's native `Request` type when evaluating against the
/// upstream engine.
///
/// `context` is the request context as a record in Cedar's JSON value
/// format, ready for `cedar_policy::Context::from_json_value`. See
/// [`build_cedar_request`] for the translation rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CedarRequest {
    pub principal: CedarEntity,
    pub action: CedarEntity,
    pub resource: CedarEntity,
    pub context: JsonValue,
}

/// Cedar entity reference of the form `Type::"id"`. The test dispatcher uses
/// this string form directly; the builtin dispatcher parses it into the
/// upstream cedar crate's `EntityUid` when evaluating.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CedarEntity {
    pub kind: String,
    pub id: String,
}

impl CedarEntity {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }

    pub fn as_display(&self) -> String {
        format!("{}::\"{}\"", self.kind, self.id)
    }
}

/// Build the cedar request per `SPECIFICATION.md` §12.4.
///
/// The principal is `Agent::"<snapshot.envelope.agent.id>"`, the action
/// is `Action::"<intervention point>"`, and the resource is
/// `Tool::"<name>"` at tool intervention points or
/// `PolicyTarget::"<kind>"` elsewhere. Returns
/// `runtime_error:policy_invocation_failed` when the input has no
/// `snapshot.envelope.agent.id`.
///
/// The context is every member of the policy input snapshot, `envelope`
/// included, plus the annotations as one nested `annotations` record, so
/// a policy reads `context.tool_call.args.host`,
/// `context.envelope.budgets.tool_call_count`, or
/// `context.annotations.confidence.score`. A snapshot member named
/// `annotations` collides with that record and fails closed, and so does
/// an `annotations` member of the policy input that is not a record.
/// Values are translated into Cedar's JSON value format:
///
/// * A JSON integer becomes a Cedar `Long`. An integer outside the `i64`
///   range fails closed.
/// * Every other JSON number becomes a Cedar `decimal`, rounded to the
///   nearest value with four fractional digits, ties to even. A value
///   outside the decimal range (about ±922337203685477.58) fails closed.
/// * A JSON `null` record member is dropped; a policy tests for it with
///   `has`. A `null` set element fails closed: no guard can tell a set
///   that lost an element from one that never had it.
/// * A record key that Cedar's JSON format reserves (`__entity`, `__extn`,
///   `__expr`) fails closed. Passing one through would let a snapshot or
///   an annotator forge an entity reference or an extension value.
/// * Strings, booleans, records and sets pass through.
///
/// Every failure is `runtime_error:policy_invocation_failed` with a detail
/// that names the offending key as a dotted path rooted at `context`. The
/// detail never carries the value: the snapshot is not error text.
pub fn build_cedar_request(policy_input: &JsonValue) -> Result<CedarRequest, RuntimeError> {
    let object = policy_input.as_object().ok_or_else(|| {
        RuntimeError::PolicyInvocationFailed(
            "cedar dispatcher received non-object policy input".to_string(),
        )
    })?;

    let snapshot = object
        .get(pi_key::SNAPSHOT)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input is missing snapshot object".to_string(),
            )
        })?;

    let envelope = snapshot
        .get("envelope")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input snapshot is missing the AGT envelope".to_string(),
            )
        })?;

    let agent_id = envelope
        .get("agent")
        .and_then(JsonValue::as_object)
        .and_then(|agent| agent.get("id"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input envelope is missing agent.id".to_string(),
            )
        })?;

    let intervention_point = object
        .get(pi_key::INTERVENTION_POINT)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input is missing intervention_point".to_string(),
            )
        })?;

    let resource = resource_entity(object);
    let context = build_cedar_context(snapshot, object.get(pi_key::ANNOTATIONS))?;

    Ok(CedarRequest {
        principal: CedarEntity::new("Agent", agent_id),
        action: CedarEntity::new("Action", intervention_point),
        resource,
        context,
    })
}

/// Record keys Cedar's JSON value format interprets as escapes rather
/// than as record members.
const CEDAR_RESERVED_KEYS: [&str; 3] = ["__entity", "__extn", "__expr"];

/// A Cedar `decimal` holds four fractional digits in an `i64`.
const DECIMAL_SCALE: f64 = 10_000.0;

/// The §12.4 request context: the snapshot with the annotations nested
/// under `annotations`, translated per [`build_cedar_request`].
fn build_cedar_context(
    snapshot: &Map<String, JsonValue>,
    annotations: Option<&JsonValue>,
) -> Result<JsonValue, RuntimeError> {
    if snapshot.contains_key(pi_key::ANNOTATIONS) {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar context key 'context.{}' is reserved for the policy input annotations",
            pi_key::ANNOTATIONS
        )));
    }
    let mut context = translate_record(snapshot, "context")?;
    let annotations = match annotations {
        None | Some(JsonValue::Null) => Map::new(),
        Some(JsonValue::Object(members)) => translate_record(members, "context.annotations")?,
        Some(_) => {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar context key 'context.{}' must be a record of annotator outputs",
                pi_key::ANNOTATIONS
            )))
        }
    };
    context.insert(
        pi_key::ANNOTATIONS.to_string(),
        JsonValue::Object(annotations),
    );
    Ok(JsonValue::Object(context))
}

/// Translate the members of one JSON object, dropping `null` members.
/// `path` is the dotted location of the object for error details.
fn translate_record(
    members: &Map<String, JsonValue>,
    path: &str,
) -> Result<Map<String, JsonValue>, RuntimeError> {
    let mut out = Map::new();
    for (member, inner) in members {
        let inner_path = format!("{path}.{member}");
        if let Some(translated) = to_cedar_value(inner, &inner_path, member)? {
            out.insert(member.clone(), translated);
        }
    }
    Ok(out)
}

/// Translate one JSON value into Cedar's JSON value format. `None` means
/// the value was `null`; a record drops such a member, a set fails
/// closed. `path` is the dotted location for error details; `key` is the
/// last segment, checked against the reserved escapes.
fn to_cedar_value(
    value: &JsonValue,
    path: &str,
    key: &str,
) -> Result<Option<JsonValue>, RuntimeError> {
    if CEDAR_RESERVED_KEYS.contains(&key) {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar context key '{path}' is reserved by the Cedar JSON format"
        )));
    }
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::Bool(_) | JsonValue::String(_) => Ok(Some(value.clone())),
        JsonValue::Number(number) => number_to_cedar(number, path).map(Some),
        JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{path}[{index}]");
                let translated = to_cedar_value(item, &item_path, "")?.ok_or_else(|| {
                    RuntimeError::PolicyInvocationFailed(format!(
                        "cedar context value at '{item_path}' is a null set element"
                    ))
                })?;
                out.push(translated);
            }
            Ok(Some(JsonValue::Array(out)))
        }
        JsonValue::Object(members) => {
            translate_record(members, path).map(|out| Some(JsonValue::Object(out)))
        }
    }
}

/// Translate one JSON number. The error details name the path and the
/// range, never the value. An integer below `i64::MIN` reaches the
/// decimal branch because `serde_json` reads it as a float, so that
/// message covers both ranges.
fn number_to_cedar(number: &serde_json::Number, path: &str) -> Result<JsonValue, RuntimeError> {
    if let Some(long) = number.as_i64() {
        return Ok(json!(long));
    }
    if number.is_u64() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar context value at '{path}' is outside the Cedar Long range"
        )));
    }
    let float = number.as_f64().ok_or_else(|| {
        RuntimeError::PolicyInvocationFailed(format!(
            "cedar context value at '{path}' is not a finite number"
        ))
    })?;
    let decimal = float_to_decimal(float).ok_or_else(|| {
        RuntimeError::PolicyInvocationFailed(format!(
            "cedar context value at '{path}' is not a Long and is outside the Cedar decimal range"
        ))
    })?;
    Ok(json!({"__extn": {"fn": "decimal", "arg": decimal}}))
}

/// Format a float as a Cedar decimal literal: scale by 10^4, round to the
/// nearest integer with ties to even (`f64::round_ties_even`, the IEEE 754
/// default and what a `Decimal` quantize does in Python), and print with a
/// fixed four digit fraction. `None` when the scaled value does not fit
/// the `i64` a Cedar decimal is stored in.
fn float_to_decimal(value: f64) -> Option<String> {
    let scaled = (value * DECIMAL_SCALE).round_ties_even();
    // 2^63 is exactly representable; anything at or beyond it overflows.
    if !scaled.is_finite() || scaled.abs() >= 9_223_372_036_854_775_808.0 {
        return None;
    }
    let scaled = scaled as i64;
    let sign = if scaled < 0 { "-" } else { "" };
    let magnitude = scaled.unsigned_abs();
    Some(format!(
        "{sign}{}.{:04}",
        magnitude / 10_000,
        magnitude % 10_000
    ))
}

fn resource_entity(policy_input: &Map<String, JsonValue>) -> CedarEntity {
    if let Some(JsonValue::Object(tool)) = policy_input.get(pi_key::TOOL) {
        if let Some(name) = tool.get("name").and_then(JsonValue::as_str) {
            return CedarEntity::new("Tool", name);
        }
    }
    let kind = policy_input
        .get(pi_key::POLICY_TARGET)
        .and_then(JsonValue::as_object)
        .and_then(|target| target.get(pi_key::KIND))
        .and_then(JsonValue::as_str)
        .unwrap_or("unspecified");
    CedarEntity::new("PolicyTarget", kind)
}

/// Deterministic cedar test dispatcher. The dispatcher parses
/// [`CedarPolicyInvocation::policy_set`] as a small JSON pseudo-cedar
/// document, builds a [`CedarRequest`] from the policy input per
/// [`build_cedar_request`], and applies the rules with a simple equality
/// match. This is the test double tests can drive without linking the
/// upstream cedar crate. It satisfies the AGT M2.S2 D3.3 contract for
/// allow / deny / advice translation.
///
/// The pseudo-cedar JSON shape is:
///
/// ```jsonc
/// {
///   "rules": [
///     { "effect": "forbid", "principal": "any", "action": "Action::\"pre_tool_call\"", "resource": "Tool::\"banned\"" },
///     { "effect": "permit", "principal": "any", "action": "any", "resource": "any" },
///     { "effect": "permit", "principal": "Agent::\"alice\"", "action": "Action::\"output\"", "resource": "PolicyTarget::\"assistant_output\"",
///       "advice": { "verdict": "warn", "reason": "needs_review" } }
///   ]
/// }
/// ```
///
/// Rules are scanned in declared order; the first `forbid` match wins.
/// Otherwise every matching `permit` contributes. A permit rule MAY carry
/// an `advice` object, which is validated against the AGT D3.3 cedar
/// advice shape and translated into the corresponding verdict; when
/// several matching permits carry advice, [`most_restrictive_advice`]
/// picks one the same way the builtin dispatcher does.
#[derive(Debug, Clone, Default)]
pub struct CedarTestDispatcher;

impl CedarTestDispatcher {
    pub fn new() -> Self {
        Self
    }
}

impl CedarPolicyDispatcher for CedarTestDispatcher {
    fn evaluate_cedar(
        &self,
        invocation: &CedarPolicyInvocation,
    ) -> Result<JsonValue, RuntimeError> {
        let policy_set_text = invocation.policy_set.as_deref().ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar test dispatcher requires an inline policy_set; policy_path is reserved for the builtin dispatcher".to_string(),
            )
        })?;
        let policy_set = parse_test_policy_set(policy_set_text)?;
        let request = build_cedar_request(&invocation.input)?;
        match policy_set.decide(&request) {
            TestDecision::Forbid(reason) => Ok(json!({
                "decision": "deny",
                "reason": reason,
            })),
            TestDecision::Permit { advice } => {
                let verdicts = advice
                    .into_iter()
                    .map(translate_advice)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(most_restrictive_advice(verdicts)
                    .unwrap_or_else(|| json!({ "decision": "allow" })))
            }
            TestDecision::NoMatch => Ok(json!({
                "decision": "deny",
                "reason": "no_matching_policy",
            })),
        }
    }
}

impl PolicyDispatcher for CedarTestDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Cedar(invocation) => self.evaluate_cedar(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar test dispatcher only supports Cedar invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TestPolicySetDoc {
    #[serde(default)]
    rules: Vec<TestRuleDoc>,
}

#[derive(Debug, Clone, Deserialize)]
struct TestRuleDoc {
    effect: TestEffectDoc,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    advice: Option<JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TestEffectDoc {
    Permit,
    Forbid,
}

#[derive(Debug, Clone)]
struct TestPolicySet {
    rules: Vec<TestRule>,
}

#[derive(Debug, Clone)]
struct TestRule {
    effect: TestEffectDoc,
    principal: Option<CedarEntity>,
    action: Option<CedarEntity>,
    resource: Option<CedarEntity>,
    reason: Option<String>,
    advice: Option<JsonValue>,
}

#[derive(Debug)]
enum TestDecision {
    Forbid(String),
    /// The advice of every matching permit, in declaration order.
    Permit {
        advice: Vec<JsonValue>,
    },
    NoMatch,
}

impl TestPolicySet {
    fn decide(&self, request: &CedarRequest) -> TestDecision {
        let mut permitted = false;
        let mut advice = Vec::new();
        for rule in &self.rules {
            if !rule.matches(request) {
                continue;
            }
            match rule.effect {
                TestEffectDoc::Forbid => {
                    return TestDecision::Forbid(
                        rule.reason
                            .clone()
                            .unwrap_or_else(|| "forbid_rule_matched".to_string()),
                    );
                }
                TestEffectDoc::Permit => {
                    permitted = true;
                    advice.extend(rule.advice.clone());
                }
            }
        }
        if permitted {
            TestDecision::Permit { advice }
        } else {
            TestDecision::NoMatch
        }
    }
}

impl TestRule {
    fn matches(&self, request: &CedarRequest) -> bool {
        entity_matches(self.principal.as_ref(), &request.principal)
            && entity_matches(self.action.as_ref(), &request.action)
            && entity_matches(self.resource.as_ref(), &request.resource)
    }
}

fn entity_matches(pattern: Option<&CedarEntity>, actual: &CedarEntity) -> bool {
    match pattern {
        None => true,
        Some(entity) => entity == actual,
    }
}

fn parse_test_policy_set(text: &str) -> Result<TestPolicySet, RuntimeError> {
    let doc: TestPolicySetDoc = serde_json::from_str(text).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "cedar test dispatcher failed to parse policy_set as JSON: {err}"
        ))
    })?;
    let mut rules = Vec::with_capacity(doc.rules.len());
    for (index, rule) in doc.rules.into_iter().enumerate() {
        rules.push(TestRule {
            effect: rule.effect,
            principal: parse_entity_pattern("principal", index, rule.principal.as_deref())?,
            action: parse_entity_pattern("action", index, rule.action.as_deref())?,
            resource: parse_entity_pattern("resource", index, rule.resource.as_deref())?,
            reason: rule.reason,
            advice: rule.advice,
        });
    }
    Ok(TestPolicySet { rules })
}

fn parse_entity_pattern(
    field: &str,
    index: usize,
    text: Option<&str>,
) -> Result<Option<CedarEntity>, RuntimeError> {
    let raw = match text {
        None => return Ok(None),
        Some(value) => value.trim(),
    };
    if raw.is_empty() || raw.eq_ignore_ascii_case("any") || raw == "*" {
        return Ok(None);
    }
    let Some((kind, rest)) = raw.split_once("::") else {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar test policy rule {index} field '{field}' must be 'any' or 'Type::\"id\"', got '{raw}'"
        )));
    };
    let id = rest
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_string();
    if kind.trim().is_empty() || id.is_empty() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar test policy rule {index} field '{field}' is missing a type or id: '{raw}'"
        )));
    }
    Ok(Some(CedarEntity::new(kind.trim(), id)))
}

/// Members `spec/schema/cedar_advice.schema.json` allows on the advice
/// object and on its `transform` member. The schema closes both objects,
/// so any other member is a mismatch and fails closed.
const ADVICE_MEMBERS: [&str; 4] = ["verdict", "reason", "message", "transform"];
const ADVICE_TRANSFORM_MEMBERS: [&str; 2] = ["path", "value"];

/// Translate AGT D3.3 cedar advice into a verdict-shaped `JsonValue` ready
/// for [`crate::normalize_policy_output`]. Advice missing the `verdict`
/// field, advice with an unknown verdict value, advice carrying a member
/// the advice schema does not list, at the top level or inside
/// `transform`, or transform advice missing its body fail closed with
/// `runtime_error:policy_output_invalid`. Path validation (rooted at
/// `$target`) is delegated to `normalize_policy_output`, which produces
/// `runtime_error:transform_target_forbidden` for an out-of-target path.
pub fn translate_advice(advice: JsonValue) -> Result<JsonValue, RuntimeError> {
    let object = advice.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("cedar advice must be a JSON object".to_string())
    })?;
    reject_unknown_members(object, &ADVICE_MEMBERS, "cedar advice")?;

    let verdict = object
        .get("verdict")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "cedar advice is missing the required 'verdict' field".to_string(),
            )
        })?;
    if !matches!(verdict, "warn" | "escalate" | "transform") {
        return Err(RuntimeError::PolicyOutputInvalid(format!(
            "cedar advice 'verdict' must be one of warn, escalate, transform; got '{verdict}'"
        )));
    }

    let mut out = Map::new();
    out.insert(
        "decision".to_string(),
        JsonValue::String(verdict.to_string()),
    );

    if let Some(reason) = object.get("reason") {
        match reason {
            JsonValue::Null => {}
            JsonValue::String(_) => {
                out.insert("reason".to_string(), reason.clone());
            }
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "cedar advice 'reason' must be a string".to_string(),
                ))
            }
        }
    }
    if let Some(message) = object.get("message") {
        match message {
            JsonValue::Null => {}
            JsonValue::String(_) => {
                out.insert("message".to_string(), message.clone());
            }
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "cedar advice 'message' must be a string".to_string(),
                ))
            }
        }
    }

    if verdict == "transform" {
        let transform = object.get("transform").ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "cedar advice with verdict 'transform' requires a transform object".to_string(),
            )
        })?;
        let members = transform.as_object().ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "cedar advice 'transform' must be a JSON object".to_string(),
            )
        })?;
        reject_unknown_members(
            members,
            &ADVICE_TRANSFORM_MEMBERS,
            "cedar advice 'transform'",
        )?;
        out.insert("transform".to_string(), transform.clone());
    } else if object.contains_key("transform") {
        return Err(RuntimeError::PolicyOutputInvalid(
            "cedar advice 'transform' is only permitted when verdict is 'transform'".to_string(),
        ));
    }

    Ok(JsonValue::Object(out))
}

/// Fail closed on the first member of `object` outside `allowed`. The
/// verdict the dispatcher builds never copies such a member, so this is
/// about matching the schema the specification promises, not about a
/// member reaching the runtime.
fn reject_unknown_members(
    object: &Map<String, JsonValue>,
    allowed: &[&str],
    what: &str,
) -> Result<(), RuntimeError> {
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(member) => Err(RuntimeError::PolicyOutputInvalid(format!(
            "{what} has a member the advice schema does not allow: '{member}'"
        ))),
        None => Ok(()),
    }
}

/// Pick one verdict from the translated advice of every contributing
/// permit, given in declaration order, per `SPECIFICATION.md` §12.4:
/// `escalate` outranks `transform`, which outranks `warn`, and among
/// permits with the same advice verdict the first declared wins. Text
/// order alone never decides, so a `warn` or `transform` permit declared
/// ahead of an `escalate` permit cannot hide the escalation. `None` when
/// no contributing permit carried advice.
pub fn most_restrictive_advice(verdicts: Vec<JsonValue>) -> Option<JsonValue> {
    // `min_by_key` returns the first minimum, which is the tiebreak.
    verdicts
        .into_iter()
        .min_by_key(|verdict| advice_rank(verdict.get("decision").and_then(JsonValue::as_str)))
}

/// Lower is more restrictive. [`translate_advice`] only emits the three
/// named verdicts; anything else sorts last.
fn advice_rank(decision: Option<&str>) -> u8 {
    match decision {
        Some("escalate") => 0,
        Some("transform") => 1,
        Some("warn") => 2,
        _ => u8::MAX,
    }
}

/// AGT M2.S5 D7 bundled cedar dispatcher backed by the upstream
/// `cedar-policy` crate. Gated behind the `cedar` Cargo feature so that
/// hosts that never need real cedar evaluation do not have to compile the
/// cedar runtime. The dispatcher parses the inline `policy_set` text (or
/// the file pointed to by `policy_path`), builds a `cedar_policy::Request`
/// from the [`CedarRequest`] produced by [`build_cedar_request`], context
/// included, and runs the upstream authorizer. When a `schema_path` is
/// set, the policy set, the entities and the request are all checked
/// against the schema, so the schema MUST declare the §12.4 context shape
/// for every action it lists.
///
/// The answer is translated into the verdict JSON the runtime feeds to
/// [`crate::normalize_policy_output`], per §12.4:
///
/// * `Deny` becomes `{"decision":"deny","reason":<reason>}`. The reason
///   is the `@id` annotation of the first contributing `forbid` in
///   declaration order. A contributing policy without `@id`, or whose
///   `@id` is empty or blank, yields its Cedar policy id (`policyN`).
///   When no policy contributed, the reason is `no_matching_policy`.
/// * `Allow` becomes `{"decision":"allow"}`, unless a contributing
///   `permit` carries an `@advice` annotation. Every such annotation is
///   parsed as JSON and translated by [`translate_advice`]; the verdict
///   is the most restrictive one, per [`most_restrictive_advice`]:
///   `escalate` over `transform` over `warn`, first declared among
///   equals. Advice on any contributing permit that is not JSON, or
///   does not translate, fails closed with
///   `runtime_error:policy_output_invalid`.
/// * An evaluation error reported by the authorizer for any policy, such
///   as an unguarded read of a missing context attribute, fails closed
///   with `runtime_error:policy_invocation_failed` whatever the decision.
///   No `@id` surfaces in that case. The detail names the policy and the
///   kind of error, not Cedar's message, which can quote snapshot values.
#[cfg(feature = "cedar")]
#[derive(Debug, Clone, Default)]
pub struct CedarBuiltinDispatcher;

#[cfg(feature = "cedar")]
impl CedarBuiltinDispatcher {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "cedar")]
impl CedarPolicyDispatcher for CedarBuiltinDispatcher {
    fn evaluate_cedar(
        &self,
        invocation: &CedarPolicyInvocation,
    ) -> Result<JsonValue, RuntimeError> {
        builtin::evaluate(invocation)
    }
}

#[cfg(feature = "cedar")]
impl PolicyDispatcher for CedarBuiltinDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Cedar(invocation) => self.evaluate_cedar(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher only supports Cedar invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[cfg(feature = "cedar")]
mod builtin {
    //! Upstream-cedar evaluation helpers for [`super::CedarBuiltinDispatcher`].
    //!
    //! Kept in a private module so the cedar crate imports never leak into
    //! the public API surface even when the `cedar` feature is enabled.

    use super::{build_cedar_request, CedarEntity, CedarRequest};
    use crate::{CedarPolicyInvocation, JsonValue, RuntimeError};
    use cedar_policy::{
        entities_json_errors::JsonDeserializationError, AuthorizationError, Authorizer, Context,
        ContextCreationError, ContextJsonError, Decision, Entities, EntityUid, EvaluationError,
        Policy, PolicyId, PolicySet, Request, RequestValidationError, Response, Schema,
        ValidationMode, Validator,
    };
    use serde_json::json;
    use std::{fs, str::FromStr};

    pub(super) fn evaluate(invocation: &CedarPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let policy_text = load_policy_text(invocation)?;
        let policy_set = PolicySet::from_str(&policy_text).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse policy_set: {err}"
            ))
        })?;
        let schema = load_schema(invocation.schema_path.as_deref())?;
        validate_policy_set(&policy_set, schema.as_ref())?;
        let entities = load_entities(invocation.entities_path.as_deref(), schema.as_ref())?;
        let request = build_cedar_request(&invocation.input)?;
        let cedar_request = build_authorizer_request(&request, schema.as_ref())?;

        let authorizer = Authorizer::new();
        let answer = authorizer.is_authorized(&cedar_request, &policy_set, &entities);
        let hard_errors = answer
            .diagnostics()
            .errors()
            .map(describe_evaluation_error)
            .collect::<Vec<_>>();
        if !hard_errors.is_empty() {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher authorizer reported errors: {}",
                hard_errors.join("; ")
            )));
        }

        let contributing = contributing_policies(&answer, &policy_set);
        match answer.decision() {
            Decision::Allow => {
                let verdicts = contributing
                    .iter()
                    .filter_map(|policy| policy.annotation("advice"))
                    .map(translate_advice_annotation)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(super::most_restrictive_advice(verdicts)
                    .unwrap_or_else(|| json!({ "decision": "allow" })))
            }
            Decision::Deny => {
                let reason = contributing.first().map_or_else(
                    || "no_matching_policy".to_string(),
                    |policy| deny_reason(policy),
                );
                Ok(json!({ "decision": "deny", "reason": reason }))
            }
        }
    }

    /// One evaluation error as the policy it came from and the kind of
    /// error. Cedar's own message is not used: for an integer overflow it
    /// quotes both operands and for a failed extension call it quotes the
    /// argument, and those can be snapshot values.
    fn describe_evaluation_error(error: &AuthorizationError) -> String {
        let AuthorizationError::PolicyEvaluationError(error) = error;
        format!(
            "policy `{}`: {}",
            error.policy_id(),
            evaluation_error_kind(error.inner())
        )
    }

    fn evaluation_error_kind(error: &EvaluationError) -> &'static str {
        match error {
            EvaluationError::EntityDoesNotExist(_) => "an entity does not exist",
            EvaluationError::EntityAttrDoesNotExist(_) => {
                "an entity attribute or tag does not exist"
            }
            EvaluationError::RecordAttrDoesNotExist(_) => "a record attribute does not exist",
            EvaluationError::FailedExtensionFunctionLookup(_) => {
                "an extension function does not exist"
            }
            EvaluationError::TypeError(_) => "type error",
            EvaluationError::WrongNumArguments(_) => {
                "wrong number of arguments to an extension function"
            }
            EvaluationError::IntegerOverflow(_) => "integer overflow",
            EvaluationError::UnlinkedSlot(_) => "a template slot is not linked",
            EvaluationError::FailedExtensionFunctionExecution(_) => "an extension function failed",
            EvaluationError::RecursionLimit(_) => "recursion limit reached",
            // `NonValue` belongs to partial evaluation, which the
            // authorizer does not run, and a build with cedar's
            // `tolerant-ast` feature adds a variant for policies that did
            // not parse.
            _ => "evaluation error",
        }
    }

    /// Parse one `@advice` annotation as JSON and translate it. A bare
    /// `@advice` is the empty string, which is not JSON, so it fails
    /// closed like any other malformed advice.
    fn translate_advice_annotation(advice: &str) -> Result<JsonValue, RuntimeError> {
        let advice: JsonValue = serde_json::from_str(advice).map_err(|err| {
            RuntimeError::PolicyOutputInvalid(format!(
                "cedar @advice annotation is not valid JSON: {err}"
            ))
        })?;
        super::translate_advice(advice)
    }

    /// The deny reason a contributing `forbid` supplies: its `@id`, or its
    /// Cedar policy id when the annotation is absent, bare or blank. Cedar
    /// returns `Some("")` for a bare `@id`, and an empty reason code is
    /// useless to a host.
    fn deny_reason(policy: &Policy) -> String {
        match policy.annotation("id") {
            Some(id) if !id.trim().is_empty() => id.to_string(),
            _ => policy.id().to_string(),
        }
    }

    /// The policies that contributed to the decision, in declaration
    /// order. `Diagnostics::reason` is a set, so the order has to be
    /// recovered: `PolicySet::from_str` names policies `policy0`,
    /// `policy1`, ... in the order they appear in the text, and the
    /// numeric suffix is that order. An id in any other form sorts after
    /// them, by string, so the result is still deterministic.
    fn contributing_policies<'a>(answer: &Response, policy_set: &'a PolicySet) -> Vec<&'a Policy> {
        let mut policies = answer
            .diagnostics()
            .reason()
            .filter_map(|id| policy_set.policy(id))
            .collect::<Vec<_>>();
        policies.sort_by_key(|policy| declaration_key(policy.id()));
        policies
    }

    fn declaration_key(id: &PolicyId) -> (usize, String) {
        let text = id.to_string();
        let index = text
            .strip_prefix("policy")
            .and_then(|suffix| suffix.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
        (index, text)
    }

    fn load_policy_text(invocation: &CedarPolicyInvocation) -> Result<String, RuntimeError> {
        match (
            invocation.policy_set.as_deref(),
            invocation.policy_path.as_deref(),
        ) {
            (Some(text), None) => Ok(text.to_string()),
            (None, Some(path)) => fs::read_to_string(path).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "cedar builtin dispatcher failed to read policy_path '{path}': {err}"
                ))
            }),
            (Some(_), Some(_)) => Err(RuntimeError::PolicyInvocationFailed(
                "cedar builtin dispatcher received both policy_set and policy_path; manifest validation must reject this earlier".to_string(),
            )),
            (None, None) => Err(RuntimeError::PolicyInvocationFailed(
                "cedar builtin dispatcher requires either policy_set or policy_path".to_string(),
            )),
        }
    }

    fn load_schema(path: Option<&str>) -> Result<Option<Schema>, RuntimeError> {
        let Some(path) = path else {
            return Ok(None);
        };
        let json_text = fs::read_to_string(path).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to read schema_path '{path}': {err}"
            ))
        })?;
        let schema = Schema::from_json_str(&json_text).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse schema_path '{path}': {err}"
            ))
        })?;
        Ok(Some(schema))
    }

    fn validate_policy_set(
        policy_set: &PolicySet,
        schema: Option<&Schema>,
    ) -> Result<(), RuntimeError> {
        let Some(schema) = schema else {
            return Ok(());
        };
        let result = Validator::new(schema.clone()).validate(policy_set, ValidationMode::Strict);
        if result.validation_passed() {
            Ok(())
        } else {
            Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher policy_set failed schema validation: {result}"
            )))
        }
    }

    fn load_entities(
        path: Option<&str>,
        schema: Option<&Schema>,
    ) -> Result<Entities, RuntimeError> {
        let Some(path) = path else {
            return Ok(Entities::empty());
        };
        let json_text = fs::read_to_string(path).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to read entities_path '{path}': {err}"
            ))
        })?;
        Entities::from_json_str(&json_text, schema).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse entities at '{path}': {err}"
            ))
        })
    }

    /// Build the upstream request. The context is built without the
    /// schema, then `Request::new` checks it against the context shape the
    /// schema declares for the action, so a schema that declares none
    /// rejects every request the runtime builds. Building the context
    /// with the schema would turn on Cedar's schema-directed parsing,
    /// which reads a `{"type", "id"}` record as an entity reference and a
    /// string as an extension constructor argument wherever the schema
    /// types an attribute that way. `tool_call.args` is model output, so
    /// that would let a snapshot name any entity in the store without the
    /// `__entity` escape [`build_cedar_request`] rejects.
    fn build_authorizer_request(
        request: &CedarRequest,
        schema: Option<&Schema>,
    ) -> Result<Request, RuntimeError> {
        let principal = entity_uid(&request.principal, "principal")?;
        let action = entity_uid(&request.action, "action")?;
        let resource = entity_uid(&request.resource, "resource")?;
        let context = Context::from_json_value(request.context.clone(), None).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher rejected the request context for {}: {}",
                request.action.as_display(),
                describe_context_json_error(&err)
            ))
        })?;
        Request::new(principal, action, resource, context, schema).map_err(|err| match err {
            // Cedar's own message prints the whole context. That is the
            // snapshot, so keep it out of the error detail.
            RequestValidationError::InvalidContext(_) => {
                RuntimeError::PolicyInvocationFailed(format!(
                    "cedar builtin dispatcher rejected the request context for {}: it does not \
                     match the context shape the schema declares for this action",
                    request.action.as_display()
                ))
            }
            other => RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to build authorizer request: {other}"
            )),
        })
    }

    /// The kind of failure Cedar reports when the context JSON does not
    /// parse. Cedar's own messages quote the offending value, for example
    /// the argument of an extension constructor that did not parse or the
    /// value found where a record was expected, and those are snapshot
    /// values. [`build_cedar_request`] rejects every input that would
    /// reach this today, so the labels are a guard against a change in
    /// Cedar's parser, not a description of a path the runtime takes.
    pub(super) fn describe_context_json_error(error: &ContextJsonError) -> &'static str {
        match error {
            ContextJsonError::JsonDeserialization(error) => json_deserialization_error_kind(error),
            ContextJsonError::ContextCreation(ContextCreationError::NotARecord(_)) => {
                "the context is not a record"
            }
            ContextJsonError::ContextCreation(ContextCreationError::Evaluation(error)) => {
                evaluation_error_kind(error)
            }
            ContextJsonError::ContextCreation(ContextCreationError::ExpressionConstruction(_)) => {
                "a record has a duplicate key"
            }
            ContextJsonError::MissingAction(_) => "the schema does not declare the action",
        }
    }

    fn json_deserialization_error_kind(error: &JsonDeserializationError) -> &'static str {
        match error {
            JsonDeserializationError::Null(_) => "a value is null",
            JsonDeserializationError::TypeMismatch(_) => {
                "a value does not match the type the schema declares"
            }
            JsonDeserializationError::UnexpectedRecordAttr(_) => {
                "a record has an attribute the schema does not declare"
            }
            JsonDeserializationError::MissingRequiredRecordAttr(_) => {
                "a record is missing an attribute the schema requires"
            }
            JsonDeserializationError::ParseEscape(_)
            | JsonDeserializationError::ExpectedLiteralEntityRef(_)
            | JsonDeserializationError::ExprTag(_) => "an escape did not parse",
            JsonDeserializationError::ExpectedExtnValue(_)
            | JsonDeserializationError::MissingImpliedConstructor(_)
            | JsonDeserializationError::IncorrectNumOfArguments(_)
            | JsonDeserializationError::FailedExtensionFunctionLookup(_)
            | JsonDeserializationError::RestrictedExpressionError(_) => {
                "an extension value did not parse"
            }
            JsonDeserializationError::DuplicateKey(_) => "a record has a duplicate key",
            // Serde errors, the entity-only variants, the deprecated
            // entity-tags variant and anything a later Cedar adds.
            _ => "the context did not parse",
        }
    }

    fn entity_uid(entity: &CedarEntity, field: &str) -> Result<EntityUid, RuntimeError> {
        EntityUid::from_str(&entity.as_display()).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse {field} entity '{}': {err}",
                entity.as_display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    //! AGT M2.S2 D3.3 dispatcher behaviour tests. Each test drives the
    //! [`CedarTestDispatcher`] against a hand-crafted policy input whose
    //! snapshot carries the `envelope` block [`build_cedar_request`] reads
    //! and asserts the verdict the runtime would emit after normalizing the
    //! dispatcher's JsonValue through [`crate::normalize_policy_output`].

    use super::*;
    use crate::{normalize_policy_output, Decision};
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn invocation(policy_set: &str, input: JsonValue) -> CedarPolicyInvocation {
        CedarPolicyInvocation {
            policy_set: Some(policy_set.to_string()),
            policy_path: None,
            entities_path: None,
            schema_path: None,
            input: input.clone(),
            canonical_input: serde_json::to_string(&input).unwrap(),
        }
    }

    fn decimal(literal: &str) -> JsonValue {
        json!({"__extn": {"fn": "decimal", "arg": literal}})
    }

    fn tool_input(agent_id: &str, tool_name: &str) -> JsonValue {
        json!({
            "intervention_point": "pre_tool_call",
            "policy_target": {
                "kind": "tool_args",
                "path": "$snap.tool_call.args",
                "value": {"q": "hello"}
            },
            "snapshot": {
                "envelope": {
                    "agent": {"id": agent_id, "version": "1.0", "name": agent_id},
                    "session": {"id": "sess-1", "started_at": "2026-01-01T00:00:00Z"},
                    "intervention_point": "pre_tool_call",
                    "timestamp": "2026-01-01T00:00:01Z",
                    "budgets": {"tool_call_count": 0, "token_count": 0, "elapsed_seconds": 0.0, "cost_usd": 0.0}
                },
                "tool_call": {"name": tool_name, "args": {"q": "hello"}, "id": "call-1"}
            },
            "annotations": {},
            "tool": {"name": tool_name}
        })
    }

    #[cfg(feature = "cedar")]
    fn cedar_test_dir(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("cedar-dispatcher-tests")
            .join(name);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[cfg(feature = "cedar")]
    fn write_cedar_test_file(dir: &Path, name: &str, content: &str) -> String {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    /// A schema for `pre_tool_call` with the resource type given. It
    /// declares the §12.4 context shape for the `tool_input` fixture:
    /// with a schema the request context is type checked, so a schema
    /// that declares no context shape rejects every request.
    #[cfg(feature = "cedar")]
    fn schema_for_resource(resource_type: &str) -> String {
        json!({
            "": {
                "entityTypes": {
                    "Agent": {"shape": {"type": "Record", "attributes": {}}},
                    "Tool": {"shape": {"type": "Record", "attributes": {}}},
                    "PolicyTarget": {"shape": {"type": "Record", "attributes": {}}}
                },
                "actions": {
                    "pre_tool_call": {
                        "appliesTo": {
                            "principalTypes": ["Agent"],
                            "resourceTypes": [resource_type],
                            "context": {"type": "Record", "attributes": {
                                "envelope": {"type": "Record", "attributes": {
                                    "agent": {"type": "Record", "attributes": {
                                        "id": {"type": "String"},
                                        "version": {"type": "String", "required": false},
                                        "name": {"type": "String", "required": false}
                                    }},
                                    "session": {"type": "Record", "required": false, "attributes": {
                                        "id": {"type": "String"},
                                        "started_at": {"type": "String", "required": false}
                                    }},
                                    "intervention_point": {"type": "String", "required": false},
                                    "timestamp": {"type": "String", "required": false},
                                    "budgets": {"type": "Record", "required": false, "attributes": {
                                        "tool_call_count": {"type": "Long", "required": false},
                                        "token_count": {"type": "Long", "required": false},
                                        "elapsed_seconds": {"type": "Extension", "name": "decimal", "required": false},
                                        "cost_usd": {"type": "Extension", "name": "decimal", "required": false}
                                    }}
                                }},
                                "tool_call": {"type": "Record", "attributes": {
                                    "name": {"type": "String"},
                                    "id": {"type": "String", "required": false},
                                    "args": {"type": "Record", "attributes": {
                                        "q": {"type": "String", "required": false}
                                    }}
                                }},
                                "annotations": {"type": "Record", "attributes": {}}
                            }}
                        }
                    }
                }
            }
        })
        .to_string()
    }

    #[cfg(feature = "cedar")]
    fn schema_for_tool_resource() -> String {
        schema_for_resource("Tool")
    }

    #[cfg(feature = "cedar")]
    fn schema_for_policy_target_resource() -> String {
        schema_for_resource("PolicyTarget")
    }

    // ── D3.2 request mapping ──────────────────────────────────────────

    #[test]
    fn build_cedar_request_maps_principal_action_resource_per_d32() {
        let input = tool_input("agent-x", "hello");
        let request = build_cedar_request(&input).expect("request built");
        assert_eq!(request.principal, CedarEntity::new("Agent", "agent-x"));
        assert_eq!(request.action, CedarEntity::new("Action", "pre_tool_call"));
        assert_eq!(request.resource, CedarEntity::new("Tool", "hello"));
        assert_eq!(request.context["tool_call"]["name"], json!("hello"));
    }

    // ── 12.4 context ──────────────────────────────────────────────────

    #[test]
    fn context_is_the_snapshot_with_envelope_plus_nested_annotations() {
        let mut input = tool_input("agent-x", "hello");
        input["annotations"] = json!({"confidence": {"score": 42}, "pii_detected": true});
        let request = build_cedar_request(&input).expect("request built");
        let context = request.context.as_object().expect("context is a record");
        let mut keys = context.keys().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["annotations", "envelope", "tool_call"]);
        assert_eq!(context["envelope"]["agent"]["id"], json!("agent-x"));
        assert_eq!(context["envelope"]["budgets"]["tool_call_count"], json!(0));
        assert_eq!(context["tool_call"]["args"]["q"], json!("hello"));
        assert_eq!(context["annotations"]["confidence"]["score"], json!(42));
        assert_eq!(context["annotations"]["pii_detected"], json!(true));
    }

    #[test]
    fn context_excludes_policy_target_tool_and_intervention_point() {
        let request = build_cedar_request(&tool_input("agent-x", "hello")).unwrap();
        let context = request.context.as_object().unwrap();
        for key in ["policy_target", "tool", "intervention_point"] {
            assert!(!context.contains_key(key), "{key} leaked into the context");
        }
    }

    #[test]
    fn context_always_carries_an_annotations_record() {
        let mut input = tool_input("agent-x", "hello");
        input.as_object_mut().unwrap().remove("annotations");
        let request = build_cedar_request(&input).unwrap();
        assert_eq!(request.context["annotations"], json!({}));
    }

    #[test]
    fn context_rejects_a_snapshot_member_named_annotations() {
        let mut input = tool_input("agent-x", "hello");
        input["snapshot"]["annotations"] = json!({"forged": true});
        let error = build_cedar_request(&input).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(error.detail().contains("context.annotations"), "{error}");
    }

    #[test]
    fn context_floats_become_decimals_rounded_to_four_places() {
        let cases = [
            (json!(12.5), "12.5000"),
            (json!(12.0), "12.0000"),
            (json!(0.0), "0.0000"),
            (json!(-0.0), "0.0000"),
            (json!(0.123456), "0.1235"),
            (json!(0.12345), "0.1234"),
            (json!(0.12355), "0.1236"),
            (json!(100.00004), "100.0000"),
            (json!(100.00006), "100.0001"),
            (json!(-2.00006), "-2.0001"),
            (json!(1e-9), "0.0000"),
            (json!(1e2), "100.0000"),
            (json!(123456789.1234), "123456789.1234"),
        ];
        for (value, literal) in cases {
            let mut input = tool_input("agent-x", "hello");
            input["snapshot"]["tool_call"]["args"]["amount"] = value.clone();
            let request = build_cedar_request(&input).unwrap();
            assert_eq!(
                request.context["tool_call"]["args"]["amount"],
                decimal(literal),
                "{value}"
            );
        }
        let request = build_cedar_request(&tool_input("agent-x", "hello")).unwrap();
        assert_eq!(
            request.context["envelope"]["budgets"]["cost_usd"],
            decimal("0.0000")
        );
    }

    #[test]
    fn context_integers_stay_longs() {
        let mut input = tool_input("agent-x", "hello");
        input["snapshot"]["tool_call"]["args"]["amount"] = json!(i64::MAX);
        input["snapshot"]["tool_call"]["args"]["debit"] = json!(i64::MIN);
        let request = build_cedar_request(&input).unwrap();
        assert_eq!(
            request.context["tool_call"]["args"]["amount"],
            json!(i64::MAX)
        );
        assert_eq!(
            request.context["tool_call"]["args"]["debit"],
            json!(i64::MIN)
        );
    }

    #[test]
    fn context_fails_closed_on_numbers_cedar_cannot_hold_naming_the_key() {
        for (value, range) in [
            (json!(u64::MAX), "Long"),
            (json!(1e300), "decimal"),
            (json!(-1e300), "decimal"),
            (json!(922337203685478.0), "decimal"),
        ] {
            let mut input = tool_input("agent-x", "hello");
            input["snapshot"]["tool_call"]["args"]["amount"] = value.clone();
            let error = build_cedar_request(&input).unwrap_err();
            assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
            assert!(
                error.detail().contains("'context.tool_call.args.amount'"),
                "{value}: {error}"
            );
            assert!(error.detail().contains(range), "{value}: {error}");
            // The value is snapshot data and stays out of the detail.
            assert!(
                !error.detail().contains(&value.to_string()),
                "{value}: {error}"
            );
        }
    }

    #[test]
    fn number_error_details_carry_the_path_and_the_range_only() {
        let error = number_to_cedar(&serde_json::Number::from(u64::MAX), "context.n").unwrap_err();
        assert_eq!(
            error.detail(),
            "cedar context value at 'context.n' is outside the Cedar Long range"
        );
        let below_i64 = serde_json::from_str::<JsonValue>("-9223372036854775809").unwrap();
        let error = number_to_cedar(below_i64.as_number().unwrap(), "context.n").unwrap_err();
        assert_eq!(
            error.detail(),
            "cedar context value at 'context.n' is not a Long and is outside the Cedar decimal range"
        );
    }

    #[test]
    fn context_drops_null_record_members() {
        let mut input = tool_input("agent-x", "hello");
        input["snapshot"]["tool_call"]["args"] = json!({
            "q": "hello",
            "note": null,
            "tags": ["a", "b"],
            "nested": {"inner": null, "kept": 1}
        });
        input["annotations"] = json!({"confidence": null, "judge": {"score": null, "label": "ok"}});
        let request = build_cedar_request(&input).unwrap();
        assert_eq!(
            request.context["tool_call"]["args"],
            json!({"q": "hello", "tags": ["a", "b"], "nested": {"kept": 1}})
        );
        assert_eq!(
            request.context["annotations"],
            json!({"judge": {"label": "ok"}})
        );
    }

    #[test]
    fn context_fails_closed_on_a_null_set_element_naming_the_path() {
        for (args, path) in [
            (
                json!({"tags": ["a", null, "b"]}),
                "context.tool_call.args.tags[1]",
            ),
            (json!({"tags": [null]}), "context.tool_call.args.tags[0]"),
            (
                json!({"rows": [["x"], ["y", null]]}),
                "context.tool_call.args.rows[1][1]",
            ),
            (
                json!({"items": [{"labels": [null]}]}),
                "context.tool_call.args.items[0].labels[0]",
            ),
        ] {
            let mut input = tool_input("agent-x", "hello");
            input["snapshot"]["tool_call"]["args"] = args.clone();
            let error = build_cedar_request(&input).unwrap_err();
            assert_eq!(
                error.reason(),
                "runtime_error:policy_invocation_failed",
                "{args}"
            );
            assert_eq!(
                error.detail(),
                format!("cedar context value at '{path}' is a null set element"),
                "{args}"
            );
        }
        // An annotator's output is held to the same rule.
        let mut input = tool_input("agent-x", "hello");
        input["annotations"] = json!({"judge": {"labels": ["pii", null]}});
        let error = build_cedar_request(&input).unwrap_err();
        assert!(
            error
                .detail()
                .contains("'context.annotations.judge.labels[1]'"),
            "{error}"
        );
    }

    #[test]
    fn context_rejects_a_non_record_annotations_member() {
        for annotations in [json!("str"), json!([1, 2]), json!(3), json!(true)] {
            let mut input = tool_input("agent-x", "hello");
            input["annotations"] = annotations.clone();
            let error = build_cedar_request(&input).unwrap_err();
            assert_eq!(
                error.reason(),
                "runtime_error:policy_invocation_failed",
                "{annotations}"
            );
            assert_eq!(
                error.detail(),
                "cedar context key 'context.annotations' must be a record of annotator outputs",
                "{annotations}"
            );
        }
    }

    #[test]
    fn context_fails_closed_on_reserved_cedar_escape_keys() {
        for key in CEDAR_RESERVED_KEYS {
            let mut input = tool_input("agent-x", "hello");
            input["snapshot"]["tool_call"]["args"][key] = json!({"type": "Agent", "id": "root"});
            let error = build_cedar_request(&input).unwrap_err();
            assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
            assert!(
                error
                    .detail()
                    .contains(&format!("'context.tool_call.args.{key}'")),
                "{error}"
            );
        }
        // Inside an annotation as well: annotator output is untrusted.
        let mut input = tool_input("agent-x", "hello");
        input["annotations"] = json!({"judge": {"__extn": {"fn": "ip", "arg": "10.0.0.1"}}});
        let error = build_cedar_request(&input).unwrap_err();
        assert!(
            error
                .detail()
                .contains("'context.annotations.judge.__extn'"),
            "{error}"
        );
    }

    #[test]
    fn float_to_decimal_rounds_ties_to_even_and_bounds_the_range() {
        // Each tie below scales to an exact half in f64.
        assert_eq!(float_to_decimal(0.00005).as_deref(), Some("0.0000"));
        assert_eq!(float_to_decimal(-0.00005).as_deref(), Some("0.0000"));
        assert_eq!(float_to_decimal(0.00025).as_deref(), Some("0.0002"));
        assert_eq!(float_to_decimal(0.00035).as_deref(), Some("0.0004"));
        assert_eq!(float_to_decimal(-2.00025).as_deref(), Some("-2.0002"));
        assert_eq!(float_to_decimal(2.5).as_deref(), Some("2.5000"));
        assert_eq!(
            float_to_decimal(-123456789.1234).as_deref(),
            Some("-123456789.1234")
        );
        assert_eq!(float_to_decimal(922337203685478.0), None);
        assert_eq!(float_to_decimal(-922337203685478.0), None);
        assert_eq!(float_to_decimal(f64::INFINITY), None);
        assert_eq!(float_to_decimal(f64::NAN), None);
    }

    #[test]
    fn build_cedar_request_uses_policy_target_kind_when_no_tool() {
        let input = json!({
            "intervention_point": "output",
            "policy_target": {"kind": "assistant_output", "path": "$snap.response", "value": {}},
            "snapshot": {
                "envelope": {
                    "agent": {"id": "agent-y"},
                    "session": {"id": "s"},
                    "intervention_point": "output",
                    "timestamp": "t",
                    "budgets": {}
                },
                "response": {"content": ""}
            },
            "annotations": {},
            "tool": null
        });
        let request = build_cedar_request(&input).expect("request built");
        assert_eq!(request.principal, CedarEntity::new("Agent", "agent-y"));
        assert_eq!(request.action, CedarEntity::new("Action", "output"));
        assert_eq!(
            request.resource,
            CedarEntity::new("PolicyTarget", "assistant_output")
        );
    }

    #[test]
    fn build_cedar_request_fails_closed_when_envelope_missing_agent_id() {
        let input = json!({
            "intervention_point": "input",
            "policy_target": {"kind": "user_input", "path": "$snap.input", "value": {}},
            "snapshot": {"envelope": {"agent": {}}},
            "annotations": {},
            "tool": null
        });
        let error = build_cedar_request(&input).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    // ── D3.3 allow / deny ─────────────────────────────────────────────

    #[test]
    fn test_dispatcher_allow_path() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn test_dispatcher_deny_path() {
        let policy_set = r#"{
            "rules": [
                {"effect": "forbid", "principal": "any", "action": "Action::\"pre_tool_call\"", "resource": "Tool::\"banned\"", "reason": "tool_banned"},
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "banned"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("tool_banned"));
    }

    #[test]
    fn test_dispatcher_no_matching_rule_denies() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "Agent::\"alice\"", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("bob", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("no_matching_policy"));
    }

    // ── D3.3 advice translation ───────────────────────────────────────

    #[test]
    fn test_dispatcher_advice_translates_to_transform() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform", "reason": "scrub_pii",
                            "transform": {"path": "$target.value.q", "value": "[REDACTED]"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Transform);
        let transform = verdict.transform.as_ref().expect("transform present");
        assert_eq!(transform.path, "$target.value.q");
        assert_eq!(transform.value, json!("[REDACTED]"));
        assert_eq!(verdict.reason.as_deref(), Some("scrub_pii"));
    }

    #[test]
    fn test_dispatcher_advice_translates_to_escalate() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "escalate", "reason": "human_review", "message": "needs sign-off"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        // The escalate intent is native: a liftable deny.
        assert_eq!(verdict.decision, Decision::Deny);
        assert!(verdict.is_liftable());
        assert_eq!(verdict.reason.as_deref(), Some("human_review"));
        assert_eq!(verdict.message.as_deref(), Some("needs sign-off"));
    }

    #[test]
    fn test_dispatcher_advice_translates_to_warn() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "warn", "reason": "low_confidence"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        // The warn intent is native: allow carrying a warning.
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.warnings.len(), 1);
        assert_eq!(
            verdict.warnings[0].reason.as_deref(),
            Some("low_confidence")
        );
    }

    #[test]
    fn test_dispatcher_picks_the_most_restrictive_advice_over_declaration_order() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "warn", "reason": "noted"}},
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any"},
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "escalate", "reason": "approval_required"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert!(verdict.is_liftable());
        assert_eq!(verdict.reason.as_deref(), Some("approval_required"));
    }

    #[test]
    fn most_restrictive_advice_ranks_escalate_transform_warn_then_declaration_order() {
        let warn = |reason: &str| json!({"decision": "warn", "reason": reason});
        let transform =
            json!({"decision": "transform", "transform": {"path": "$target.value", "value": 1}});
        let escalate = json!({"decision": "escalate"});

        assert_eq!(most_restrictive_advice(vec![]), None);
        assert_eq!(
            most_restrictive_advice(vec![warn("a"), transform.clone(), escalate.clone()]),
            Some(escalate.clone())
        );
        assert_eq!(
            most_restrictive_advice(vec![escalate.clone(), warn("a")]),
            Some(escalate)
        );
        assert_eq!(
            most_restrictive_advice(vec![warn("a"), transform.clone()]),
            Some(transform)
        );
        assert_eq!(
            most_restrictive_advice(vec![warn("first"), warn("second")]),
            Some(warn("first"))
        );
    }

    // ── D3.3 malformed advice ─────────────────────────────────────────

    #[test]
    fn test_dispatcher_malformed_advice_missing_verdict_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"reason": "no_verdict_field"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_malformed_advice_unknown_verdict_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "approve"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_transform_advice_without_body_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_warn_advice_with_transform_body_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "warn",
                            "transform": {"path": "$target.value", "value": "x"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    // ── D1.1 transform target confinement ─────────────────────────────

    #[test]
    fn test_dispatcher_transform_path_outside_policy_target_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform",
                            "transform": {"path": "$snap.tool_call.args.q", "value": "[REDACTED]"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        // The dispatcher emits the verdict JSON verbatim; the runtime's
        // normalize_policy_output is what enforces $target confinement
        // per AGT D1.1, returning runtime_error:transform_target_forbidden.
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let error = normalize_policy_output(output).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:transform_target_forbidden");
    }

    // ── Dispatcher error paths ────────────────────────────────────────

    #[test]
    fn test_dispatcher_requires_inline_policy_set() {
        let inv = CedarPolicyInvocation {
            policy_set: None,
            policy_path: Some("/no/such/file.cedar".to_string()),
            entities_path: None,
            schema_path: None,
            input: tool_input("agent-1", "hello"),
            canonical_input: "{}".to_string(),
        };
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[test]
    fn test_dispatcher_invalid_policy_set_json_fails_closed() {
        let inv = invocation("not json", tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[test]
    fn test_dispatcher_rejects_non_cedar_invocation_through_policy_dispatcher() {
        use crate::{PolicyDispatcher, PreparedPolicyInvocation, TestPolicyInvocation};

        let other = PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: Default::default(),
            input: json!({}),
            canonical_input: "{}".to_string(),
        });
        let error = CedarTestDispatcher::new().evaluate(&other).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    // ── translate_advice unit checks (independent of the dispatcher) ──

    #[test]
    fn translate_advice_rejects_non_object() {
        let error = translate_advice(json!("warn")).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn translate_advice_rejects_non_string_reason() {
        let error = translate_advice(json!({"verdict": "warn", "reason": 7})).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn translate_advice_round_trips_warn() {
        let value = translate_advice(json!({"verdict": "warn"})).unwrap();
        assert_eq!(value["decision"], json!("warn"));
    }

    #[test]
    fn translate_advice_rejects_members_outside_the_schema() {
        // The advice schema closes both objects. A verdict member that
        // only the runtime may set, or a misspelt one, is a mismatch.
        for (advice, member) in [
            (json!({"verdict": "warn", "extra": 1}), "'extra'"),
            (json!({"verdict": "warn", "tranform": {}}), "'tranform'"),
            (
                json!({"verdict": "escalate", "warnings": [{"reason": "smuggled"}]}),
                "'warnings'",
            ),
            (
                json!({"verdict": "warn", "approval": {"x": 1}}),
                "'approval'",
            ),
            (
                json!({"verdict": "transform",
                       "transform": {"path": "$target.value", "value": 1, "extra": true}}),
                "'extra'",
            ),
        ] {
            let error = translate_advice(advice.clone()).unwrap_err();
            assert_eq!(
                error.reason(),
                "runtime_error:policy_output_invalid",
                "{advice}"
            );
            assert!(error.detail().contains(member), "{advice}: {error}");
        }
        let value = translate_advice(json!({
            "verdict": "transform",
            "reason": "r",
            "message": "m",
            "transform": {"path": "$target.value", "value": null}
        }))
        .unwrap();
        assert_eq!(value["decision"], json!("transform"));
    }

    // ── M2.S5 D7 builtin dispatcher (feature `cedar`) ─────────────────

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_allows_trivial_permit_all_policy() {
        let policy_set = "permit(principal, action, resource);";
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("builtin cedar dispatcher returns ok for permit-all");
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_denies_when_no_policy_matches() {
        let policy_set = "permit(principal == Agent::\"alice\", action, resource);";
        let inv = invocation(policy_set, tool_input("bob", "hello"));
        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("builtin cedar dispatcher returns ok for deny");
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("no_matching_policy"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_valid_schema_accepts_conformant_request() {
        let dir = cedar_test_dir("valid-schema-accepts");
        let schema_path = write_cedar_test_file(&dir, "schema.json", &schema_for_tool_resource());
        let mut inv = invocation(
            "permit(principal, action == Action::\"pre_tool_call\", resource == Tool::\"hello\");",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("schema-conformant cedar request should evaluate");
        let verdict = normalize_policy_output(output).unwrap();

        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_valid_schema_rejects_nonconformant_request() {
        let dir = cedar_test_dir("valid-schema-rejects");
        let schema_path =
            write_cedar_test_file(&dir, "schema.json", &schema_for_policy_target_resource());
        let mut inv = invocation(
            "permit(principal, action == Action::\"pre_tool_call\", resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(
            error.detail().contains("authorizer request")
                || error.detail().contains("failed schema validation"),
            "{}",
            error.detail()
        );
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_schema_type_checks_the_context() {
        let dir = cedar_test_dir("schema-context-shape");
        // The schema declares `args.q` as a String; the input carries a Long.
        let schema_path = write_cedar_test_file(&dir, "schema.json", &schema_for_tool_resource());
        let mut input = tool_input("agent-1", "hello");
        input["snapshot"]["tool_call"]["args"]["q"] = json!(7);
        let mut inv = invocation("permit(principal, action, resource);", input);
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(
            error
                .detail()
                .contains("does not match the context shape the schema declares"),
            "{}",
            error.detail()
        );
        // The snapshot content stays out of the error detail.
        assert!(!error.detail().contains("agent-1"), "{}", error.detail());
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_schema_lacking_a_context_shape_fails_closed() {
        let dir = cedar_test_dir("schema-no-context-shape");
        let schema_path = write_cedar_test_file(
            &dir,
            "schema.json",
            r#"{"": {
                "entityTypes": {"Agent": {}, "Tool": {}, "PolicyTarget": {}},
                "actions": {"pre_tool_call": {"appliesTo": {
                    "principalTypes": ["Agent"], "resourceTypes": ["Tool"]}}}
            }}"#,
        );
        let mut inv = invocation(
            "permit(principal, action, resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(
            error.detail().contains("request context"),
            "{}",
            error.detail()
        );
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_deny_reason_is_the_contributing_forbid_id() {
        let policy_set = r#"
            @id("tool_banned")
            forbid(principal, action, resource == Tool::"banned");
            permit(principal, action, resource);
        "#;
        let inv = invocation(policy_set, tool_input("agent-1", "banned"));
        let output = CedarBuiltinDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("tool_banned"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_reads_the_context_it_builds() {
        let policy_set = r#"
            @id("query_blocked")
            forbid(principal, action, resource) when {
                context.tool_call.args.q == "hello" &&
                context.envelope.budgets.cost_usd == decimal("0.0")
            };
            permit(principal, action, resource);
        "#;
        let inv = invocation(policy_set, tool_input("agent-1", "search"));
        let output = CedarBuiltinDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("query_blocked"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_fails_closed_when_schema_path_is_missing() {
        let missing_schema = cedar_test_dir("missing-schema").join("missing-schema.json");
        let mut inv = invocation(
            "permit(principal, action, resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(missing_schema.display().to_string());
        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(error.detail().contains("schema_path"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_fails_closed_when_schema_path_is_malformed() {
        let dir = cedar_test_dir("malformed-schema");
        let schema_path = write_cedar_test_file(&dir, "schema.json", "{not valid schema json");
        let mut inv = invocation(
            "permit(principal, action, resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(error.detail().contains("parse schema_path"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_rejects_non_cedar_invocation_through_policy_dispatcher() {
        use crate::{PolicyDispatcher, PreparedPolicyInvocation, TestPolicyInvocation};

        let other = PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: Default::default(),
            input: json!({}),
            canonical_input: "{}".to_string(),
        });
        let error = CedarBuiltinDispatcher::new().evaluate(&other).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_surfaces_parser_errors_as_policy_invocation_failed() {
        let inv = invocation("not a valid cedar policy", tool_input("agent-1", "hello"));
        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    /// Most of Cedar's context parse errors quote the value they tripped
    /// on. The dispatcher detail carries the kind of failure only. Every
    /// case here is one `build_cedar_request` refuses before Cedar sees
    /// it, so the errors are made by calling Cedar directly.
    #[cfg(feature = "cedar")]
    #[test]
    fn context_parse_error_labels_omit_the_value() {
        use cedar_policy::{Context, EntityUid, Schema};
        use std::str::FromStr;

        let marker = "SECRET";
        // (context, label, whether Cedar's own message quotes the marker)
        let untyped = [
            (json!({"a": marker, "b": null}), "a value is null", false),
            (
                json!({"a": {"__extn": {"fn": "decimal", "arg": marker}}}),
                "an extension function failed",
                true,
            ),
            (
                json!({"a": {"__extn": {"fn": marker, "arg": "1"}}}),
                "an extension function does not exist",
                true,
            ),
            (
                json!({"a": {"__expr": marker}}),
                "an escape did not parse",
                false,
            ),
            (json!(marker), "the context is not a record", true),
        ];
        for (context, label, quotes_the_value) in untyped {
            let error = Context::from_json_value(context.clone(), None).unwrap_err();
            assert_eq!(
                error.to_string().contains(marker),
                quotes_the_value,
                "{context}: {error}"
            );
            assert_eq!(
                builtin::describe_context_json_error(&error),
                label,
                "{context}"
            );
        }

        // With a schema, Cedar's parser also rejects an action the
        // schema does not declare. The dispatcher builds the context
        // without a schema, so this is the parser's rule, not a path
        // the runtime takes.
        let schema = Schema::from_json_str(&schema_for_tool_resource()).unwrap();
        let unknown_action = EntityUid::from_str(&format!("Action::\"{marker}\"")).unwrap();
        let error =
            Context::from_json_value(json!({}), Some((&schema, &unknown_action))).unwrap_err();
        assert_eq!(
            builtin::describe_context_json_error(&error),
            "the schema does not declare the action"
        );
    }
}
