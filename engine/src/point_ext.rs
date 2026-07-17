//! Local extensions over `agent_hooks::InterceptionPoint`.
//!
//! The upstream type derives `Hash` but not `Ord`/`Display`; the
//! manifest needs deterministic ordered maps and human-readable
//! diagnostics. (Candidate upstream change: derive `Ord` and implement
//! `Display` on `InterceptionPoint`.)

use agent_hooks::InterceptionPoint;
use serde::{Deserialize, Serialize};

/// Ordered map key over an interception point (orders by wire name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PointKey(pub InterceptionPoint);

impl PartialOrd for PointKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PointKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_str().cmp(other.0.as_str())
    }
}

impl std::fmt::Display for PointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

pub trait InterceptionPointExt {
    /// Whether tool projection applies at this point.
    fn is_tool_point(&self) -> bool;
    /// Wire name, for diagnostics.
    fn name(self) -> &'static str;
}

impl InterceptionPointExt for InterceptionPoint {
    fn is_tool_point(&self) -> bool {
        matches!(
            *self,
            InterceptionPoint::PreToolCall | InterceptionPoint::PostToolCall
        )
    }

    fn name(self) -> &'static str {
        self.as_str()
    }
}
