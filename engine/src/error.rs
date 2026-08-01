use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
// Reserved reasons are added as the runtime grows, and a downstream
// exhaustive match should not break each time.
#[non_exhaustive]
pub enum RuntimeError {
    ManifestInvalid(String),
    /// The manifest could not be obtained, so its content was never
    /// judged. Distinct from `ManifestInvalid` because failing to reach
    /// a document says nothing about whether it is well formed, and a
    /// caller that reports one as the other misleads badly.
    ///
    /// Covers the manifest the caller named being absent or unreadable,
    /// a permission denial anywhere in the chain, and a failed fetch of
    /// a URL `extends`.
    ///
    /// A missing `extends` target is *not* here. The including document
    /// was read, and it names a file that is not there, which is a
    /// dangling reference and therefore `ManifestInvalid`. Anything else
    /// that stops an `extends` target being resolved is unreadable,
    /// because the reference itself may be perfectly correct.
    ManifestUnreadable(String),
    InterventionPointUnknown(String),
    PathMissing(String),
    PathTypeMismatch(String),
    ToolUnknown(String),
    AnnotationFailed(String),
    AnnotationTimeout(String),
    PolicyInvocationFailed(String),
    PolicyOutputInvalid(String),
    ResourceLimitExceeded(String),
    /// AGT D6: AGT-side resolution layer detected path traversal. The
    /// resolution layer runs on the host before the engine; this variant
    /// exists so SDKs that materialize manifests through a thin Rust
    /// helper can surface the same reserved reason byte-for-byte.
    ResolutionPathTraversal(String),
    /// AGT D6: cycle in the extends chain detected by the AGT-side
    /// resolution layer.
    ResolutionCycle(String),
    /// AGT D6: invalid governance.yaml encountered by the AGT-side
    /// resolution layer.
    ResolutionInvalidGovernance(String),
    /// AGT D6: non-mergeable section in the AGT-side resolution layer.
    ResolutionMergeConflict(String),
    /// AGT D1.1: a `transform` verdict's `path` is outside `$target`.
    TransformTargetForbidden(String),
    /// AGT D1.1: a `transform` verdict's path did not resolve, or value
    /// could not be set.
    TransformInvalid(String),
}

impl RuntimeError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::ManifestInvalid(_) => "runtime_error:manifest_invalid",
            Self::ManifestUnreadable(_) => "runtime_error:manifest_unreadable",
            Self::InterventionPointUnknown(_) => "runtime_error:intervention_point_unknown",
            Self::PathMissing(_) => "runtime_error:path_missing",
            Self::PathTypeMismatch(_) => "runtime_error:path_type_mismatch",
            Self::ToolUnknown(_) => "runtime_error:tool_unknown",
            Self::AnnotationFailed(_) => "runtime_error:annotation_failed",
            Self::AnnotationTimeout(_) => "runtime_error:annotation_timeout",
            Self::PolicyInvocationFailed(_) => "runtime_error:policy_invocation_failed",
            Self::PolicyOutputInvalid(_) => "runtime_error:policy_output_invalid",
            Self::ResourceLimitExceeded(_) => "runtime_error:resource_limit_exceeded",
            Self::ResolutionPathTraversal(_) => "runtime_error:resolution_path_traversal",
            Self::ResolutionCycle(_) => "runtime_error:resolution_cycle",
            Self::ResolutionInvalidGovernance(_) => "runtime_error:resolution_invalid_governance",
            Self::ResolutionMergeConflict(_) => "runtime_error:resolution_merge_conflict",
            Self::TransformTargetForbidden(_) => "runtime_error:transform_target_forbidden",
            Self::TransformInvalid(_) => "runtime_error:transform_invalid",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::ManifestInvalid(detail)
            | Self::ManifestUnreadable(detail)
            | Self::InterventionPointUnknown(detail)
            | Self::PathMissing(detail)
            | Self::PathTypeMismatch(detail)
            | Self::ToolUnknown(detail)
            | Self::AnnotationFailed(detail)
            | Self::AnnotationTimeout(detail)
            | Self::PolicyInvocationFailed(detail)
            | Self::PolicyOutputInvalid(detail)
            | Self::ResourceLimitExceeded(detail)
            | Self::ResolutionPathTraversal(detail)
            | Self::ResolutionCycle(detail)
            | Self::ResolutionInvalidGovernance(detail)
            | Self::ResolutionMergeConflict(detail)
            | Self::TransformTargetForbidden(detail)
            | Self::TransformInvalid(detail) => detail,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail().is_empty() {
            write!(f, "{}", self.reason())
        } else {
            write!(f, "{}: {}", self.reason(), self.detail())
        }
    }
}

impl Error for RuntimeError {}
