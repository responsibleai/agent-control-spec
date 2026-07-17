//! Local extensions over `agent_hooks::InterceptionPoint`.
//!
//! The upstream type carries `Ord` (lifecycle declaration order) and
//! `Display` (wire name) since agent-hooks 0.1.0-alpha.3; only the
//! ACS-specific tool-point predicate remains local.

use agent_hooks::InterceptionPoint;

pub trait InterceptionPointExt {
    /// Whether tool projection applies at this point.
    fn is_tool_point(&self) -> bool;
}

impl InterceptionPointExt for InterceptionPoint {
    fn is_tool_point(&self) -> bool {
        matches!(
            *self,
            InterceptionPoint::PreToolCall | InterceptionPoint::PostToolCall
        )
    }
}
