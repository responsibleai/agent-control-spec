use crate::point_ext::InterceptionPointExt;
use crate::{
    manifest::{InterventionPointConfig, Manifest},
    InterceptionPoint, JsonPath, JsonValue, PathEnv, RuntimeError,
};

pub fn project_tool(
    manifest: &Manifest,
    intervention_point: InterceptionPoint,
    config: &InterventionPointConfig,
    snapshot: &JsonValue,
) -> Result<JsonValue, RuntimeError> {
    let Some(tool_name_from) = &config.tool_name_from else {
        return Ok(JsonValue::Null);
    };

    if !intervention_point.is_tool_point() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "tool_name_from is only valid on tool intervention points, not {}",
            intervention_point
        )));
    }

    let path = JsonPath::parse_with_snapshot_alias(tool_name_from).map_err(|err| {
        RuntimeError::ManifestInvalid(format!(
            "invalid tool_name_from for intervention_point {}: {err}",
            intervention_point
        ))
    })?;
    let value = path.resolve(&PathEnv::with_snap(snapshot))?;
    let tool_name = value.as_str().ok_or_else(|| {
        RuntimeError::PathTypeMismatch(format!(
            "tool_name_from '{tool_name_from}' did not resolve to a string"
        ))
    })?;

    let tool = manifest
        .tools
        .get(tool_name)
        .ok_or_else(|| RuntimeError::ToolUnknown(tool_name.to_string()))?;
    Ok(tool.to_projected_value(tool_name))
}
