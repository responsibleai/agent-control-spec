//! The agent-hooks interceptor: ACS's integration surface.
//!
//! A host registers [`AcsInterceptor`] with its agent-hooks emitter.
//! On every emission the interceptor resolves the interception point
//! from the context, runs the manifest-bound evaluation pipeline
//! (annotators → policy dispatcher → normalization), and returns the
//! resulting verdict. Every failure path is fail-closed: a `deny`
//! whose reason carries the engine's `runtime_error:*` namespace.
//!
//! The interceptor is pure with respect to the host contract: it
//! applies no transforms, resolves no approvals, and keeps no records
//! — those are host obligations under AGENT-HOOKS-0.1 §6, §9, §10.

use crate::{runtime::Runtime, RuntimeError};
use agent_hooks::{AgentContext, Interceptor, Verdict};
use async_trait::async_trait;
use serde_json::Value as JsonValue;

/// Wraps a [`Runtime`] as an agent-hooks [`Interceptor`].
pub struct AcsInterceptor {
    runtime: RuntimeSource,
    name: String,
}

/// Where an interceptor's runtime came from.
///
/// An interceptor built directly owns its runtime. One built from an
/// [`crate::ActivatedPolicy`] shares that activation instead, so a host
/// on the emitter path gets the readied policy rather than a second copy
/// that would load and compile the bundle again.
enum RuntimeSource {
    Owned(Box<Runtime>),
    Activated(crate::ActivatedPolicy),
}

impl RuntimeSource {
    fn runtime(&self) -> &Runtime {
        match self {
            Self::Owned(runtime) => runtime,
            Self::Activated(policy) => policy.runtime(),
        }
    }
}

impl AcsInterceptor {
    pub fn new(runtime: Runtime) -> Self {
        Self {
            runtime: RuntimeSource::Owned(Box::new(runtime)),
            name: "acs".to_string(),
        }
    }

    /// An interceptor over an already-activated policy version, sharing
    /// its loaded and compiled state.
    pub fn from_activated(policy: crate::ActivatedPolicy) -> Self {
        Self {
            runtime: RuntimeSource::Activated(policy),
            name: "acs".to_string(),
        }
    }

    /// Override the payload-free identifier recorded on
    /// `verdicts[].name`.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn runtime(&self) -> &Runtime {
        self.runtime.runtime()
    }
}

#[async_trait]
impl Interceptor for AcsInterceptor {
    async fn intercept(&self, context: &AgentContext) -> Verdict {
        let snapshot = JsonValue::Object(context.clone());
        self.runtime.runtime().evaluate(&snapshot).verdict
    }

    fn name(&self) -> Option<String> {
        Some(self.name.clone())
    }
}

impl std::fmt::Debug for AcsInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcsInterceptor")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Convenience: an evaluation error that never reaches the host as an
/// error — the interceptor converts every failure into a fail-closed
/// verdict, so this alias documents intent at call sites.
pub type EvaluationError = RuntimeError;
