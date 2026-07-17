use crate::{constants::policy_input as pi_key, JsonValue};
use agent_hooks::InterceptionPoint;
use serde_json::Map;

pub fn build_policy_input(
    intervention_point: InterceptionPoint,
    policy_target_path: &str,
    policy_target_kind: Option<&str>,
    policy_target_value: JsonValue,
    snapshot: JsonValue,
    annotations: JsonValue,
    tool: JsonValue,
) -> JsonValue {
    let mut policy_target = Map::new();
    policy_target.insert(
        pi_key::KIND.to_string(),
        policy_target_kind
            .map(|kind| JsonValue::String(kind.to_string()))
            .unwrap_or(JsonValue::Null),
    );
    policy_target.insert(
        pi_key::PATH.to_string(),
        JsonValue::String(policy_target_path.to_string()),
    );
    policy_target.insert(pi_key::VALUE.to_string(), policy_target_value);

    let mut root = Map::new();
    root.insert(
        pi_key::INTERVENTION_POINT.to_string(),
        JsonValue::String(intervention_point.as_str().to_string()),
    );
    root.insert(
        pi_key::POLICY_TARGET.to_string(),
        JsonValue::Object(policy_target),
    );
    root.insert(pi_key::SNAPSHOT.to_string(), snapshot);
    root.insert(pi_key::ANNOTATIONS.to_string(), annotations);
    root.insert(pi_key::TOOL.to_string(), tool);
    JsonValue::Object(root)
}

/// Deterministic serialization (sorted keys) used for size accounting
/// and dispatcher payloads. Not an identity: context identity is owned
/// by agent-hooks (§10).
pub fn canonical_json(value: &JsonValue) -> Result<String, serde_json::Error> {
    fn sort_json(value: &JsonValue) -> JsonValue {
        match value {
            JsonValue::Array(items) => JsonValue::Array(items.iter().map(sort_json).collect()),
            JsonValue::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut sorted = Map::new();
                for key in keys {
                    if let Some(value) = map.get(&key) {
                        sorted.insert(key, sort_json(value));
                    }
                }
                JsonValue::Object(sorted)
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort_json(value))
}
