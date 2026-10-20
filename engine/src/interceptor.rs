// Copyright (c) Microsoft. All rights reserved.

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
use std::sync::Arc;

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
    Owned(Arc<Runtime>),
    Activated(crate::ActivatedPolicy),
}

impl RuntimeSource {
    fn runtime(&self) -> &Runtime {
        match self {
            Self::Owned(runtime) => runtime,
            Self::Activated(policy) => policy.runtime(),
        }
    }

    /// An owned handle for the worker path. Both variants hold an
    /// `Arc`, so this clones a pointer, never the manifest.
    #[cfg(feature = "tokio")]
    fn shared_runtime(&self) -> Arc<Runtime> {
        match self {
            Self::Owned(runtime) => Arc::clone(runtime),
            Self::Activated(policy) => policy.shared_runtime(),
        }
    }
}

impl AcsInterceptor {
    pub fn new(runtime: Runtime) -> Self {
        Self {
            runtime: RuntimeSource::Owned(Arc::new(runtime)),
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

    /// Evaluates off the calling thread when a tokio runtime is on it,
    /// so the future yields and the emitter's timeout can fire. With no
    /// runtime on the thread, such as under a hand-rolled executor,
    /// evaluation runs inline as it does without the feature.
    ///
    /// After the emitter drops this future on timeout the worker keeps
    /// running until the engine returns. It owns its own `Arc` to the
    /// runtime and the snapshot, so nothing it touches is freed early,
    /// and it holds a thread of the runtime's blocking pool, which
    /// `Runtime::drop` waits for; a host that must exit on time uses
    /// `shutdown_timeout` or `shutdown_background`.
    #[cfg(feature = "tokio")]
    async fn evaluate_snapshot(&self, snapshot: JsonValue) -> Verdict {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return self.runtime.runtime().evaluate(&snapshot).verdict;
        };
        let runtime = self.runtime.shared_runtime();
        match handle
            .spawn_blocking(move || runtime.evaluate(&snapshot).verdict)
            .await
        {
            Ok(verdict) => verdict,
            // The engine panicked on the worker. Raise it here so the
            // emitter's panic isolation records
            // `host_error:interceptor_failed`, as it would for an inline
            // panic. The interceptor mints no reason of its own for this:
            // the reserved-reason registry has none for a failed worker.
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            // The runtime is shutting down and dropped the task before it
            // ran. Same treatment: the emitter catches the panic and fails
            // closed.
            Err(_) => panic!("ACS evaluation worker was cancelled by runtime shutdown"),
        }
    }

    #[cfg(not(feature = "tokio"))]
    async fn evaluate_snapshot(&self, snapshot: JsonValue) -> Verdict {
        self.runtime.runtime().evaluate(&snapshot).verdict
    }
}

#[async_trait]
impl Interceptor for AcsInterceptor {
    async fn intercept(&self, context: &AgentContext) -> Verdict {
        let snapshot = JsonValue::Object(context.clone());
        self.evaluate_snapshot(snapshot).await
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
