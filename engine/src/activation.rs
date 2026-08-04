//! One policy version, readied once and evaluated many times.
//!
//! A host that governs an agent evaluates the same policy version at
//! every intervention point, for the life of that version. Splitting
//! that into an explicit activation step and a cheap evaluation step
//! lets the host decide when the expensive part happens, and lets it
//! cache the result under its own versioning scheme rather than relying
//! on the runtime to guess.
//!
//! The example activates through the bundled dispatchers against a Rego
//! policy, so it only compiles when both are available and is skipped
//! otherwise. `--all-targets` does not build doctests, so this gate has
//! to be written out rather than inherited from the item gates below.
#![cfg_attr(
    all(
        feature = "default-dispatchers",
        any(feature = "rego", feature = "opa")
    ),
    doc = "```no_run"
)]
#![cfg_attr(
    not(all(
        feature = "default-dispatchers",
        any(feature = "rego", feature = "opa")
    )),
    doc = "```ignore"
)]
//! use agent_control_spec::{ActivatedPolicy, InterceptionPoint};
//! use serde_json::json;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Once per policy version. Reads the manifest, loads every Rego
//! // module and data document, and compiles the entrypoint each
//! // intervention point queries.
//! let policy = ActivatedPolicy::activate_from_path("manifest.yaml")?;
//!
//! // Many times, on the hot path. No manifest read, no bundle parse,
//! // no compile.
//! let verdict = policy.evaluate(InterceptionPoint::Input, json!({"input": {"text": "hi"}}));
//! # Ok(())
//! # }
//! ```
//!
//! An [`ActivatedPolicy`] is immutable and `Send + Sync`. Share one
//! across threads with [`Clone`], which is a refcount bump, rather than
//! activating per thread. Nothing here re-reads the manifest or the
//! bundle, so a policy edit on disk needs a new activation, which is the
//! point: the host controls when a version changes.

use crate::{
    manifest::Manifest,
    policy::prepare_policy_invocation,
    runtime::{EvaluationResult, PolicyDispatcher, Runtime},
    AnnotatorDispatcher, InterceptionPoint, JsonValue, RuntimeError,
};
use std::sync::Arc;

/// An immutable, ready-to-evaluate policy version.
///
/// Cheap to clone and safe to share; expensive to create, deliberately.
#[derive(Clone)]
pub struct ActivatedPolicy {
    runtime: Arc<Runtime>,
    points: Arc<Vec<InterceptionPoint>>,
}

impl ActivatedPolicy {
    /// Readies `runtime`'s policy for evaluation and returns the
    /// activated version.
    ///
    /// Every intervention point the manifest binds is prepared through
    /// [`PolicyDispatcher::warm`], so the bundle is read and compiled
    /// here rather than on the first agent action.
    ///
    /// Fails only if the manifest binds a policy that cannot be readied
    /// at all, such as a bundle that does not exist. A policy that
    /// merely needs real input to produce a verdict warms fine.
    pub fn activate(runtime: Runtime) -> Result<Self, RuntimeError> {
        let points: Vec<InterceptionPoint> = runtime
            .manifest()
            .intervention_points
            .keys()
            .copied()
            .collect();
        for point in &points {
            warm_point(&runtime, *point)?;
        }
        Ok(Self {
            runtime: Arc::new(runtime),
            points: Arc::new(points),
        })
    }

    /// Activates the manifest at `path` against the bundled dispatchers.
    ///
    /// The zero-config path: bundled annotators, Rego evaluated in
    /// process, Cedar through the built-in evaluator, `test` policies
    /// through their embedded verdict.
    #[cfg(all(
        feature = "default-dispatchers",
        any(feature = "rego", feature = "opa")
    ))]
    pub fn activate_from_path(path: impl AsRef<std::path::Path>) -> Result<Self, RuntimeError> {
        let manifest = Manifest::from_path(path)?;
        Self::activate_manifest(manifest)
    }

    /// Activates an already-parsed `manifest` against the bundled
    /// dispatchers.
    #[cfg(all(
        feature = "default-dispatchers",
        any(feature = "rego", feature = "opa")
    ))]
    pub fn activate_manifest(manifest: Manifest) -> Result<Self, RuntimeError> {
        let annotations = crate::dispatchers::default_annotator_dispatcher();
        let policy = crate::dispatchers::default_policy_dispatcher(&manifest)?;
        Self::activate(Runtime::new(manifest, annotations, policy)?)
    }

    /// Activates against host-supplied dispatchers.
    pub fn activate_with(
        manifest: Manifest,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
    ) -> Result<Self, RuntimeError> {
        Self::activate(Runtime::new(manifest, annotations, policy)?)
    }

    /// Evaluates one intervention point. This is the hot path.
    pub fn evaluate(&self, point: InterceptionPoint, snapshot: JsonValue) -> EvaluationResult {
        self.runtime.evaluate_point(point, snapshot)
    }

    /// The intervention points this policy version binds, in manifest
    /// order. A host can use this to skip emitting points the policy
    /// does not govern.
    pub fn intervention_points(&self) -> &[InterceptionPoint] {
        &self.points
    }

    /// Whether this policy version governs `point`.
    pub fn governs(&self, point: InterceptionPoint) -> bool {
        self.points.contains(&point)
    }

    /// This policy version as an agent-hooks [`Interceptor`], for a host
    /// that drives the runtime through an emitter rather than calling
    /// [`Self::evaluate`] itself.
    ///
    /// Without this the two surfaces would be exclusive: a host on the
    /// emitter path could not use an activated policy at all, which is
    /// the path activation exists to make fast. The returned interceptor
    /// shares this activation, so registering it costs no second load
    /// and no second compile.
    pub fn interceptor(&self) -> crate::AcsInterceptor {
        crate::AcsInterceptor::from_activated(self.clone())
    }

    /// The runtime this policy version evaluates through, for a host
    /// that needs the lower-level surface: telemetry, limits, or the
    /// whole-context [`Runtime::evaluate`] rather than a named point.
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// The manifest this version activated, for a host that reports or
    /// diffs policy versions.
    pub fn manifest(&self) -> &Manifest {
        self.runtime.manifest()
    }
}

impl std::fmt::Debug for ActivatedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivatedPolicy")
            .field("intervention_points", &self.points)
            .finish_non_exhaustive()
    }
}

/// Readies the policy bound to one intervention point.
///
/// The warm-up invocation carries an empty policy input: the dispatcher
/// needs the policy's identity and query to load and compile it, not the
/// data a real decision would carry.
fn warm_point(runtime: &Runtime, point: InterceptionPoint) -> Result<(), RuntimeError> {
    let manifest = runtime.manifest();
    let Some(config) = manifest.intervention_points.get(&point) else {
        return Ok(());
    };
    let binding = &config.policy;
    let Some(policy) = manifest.policies.get(&binding.id) else {
        // A binding naming a policy that is not declared is a manifest
        // error, and `Runtime::new` has already rejected it. Nothing to
        // warm, and not this function's error to raise.
        return Ok(());
    };
    let invocation =
        prepare_policy_invocation(policy, binding, &JsonValue::Object(Default::default()))?;
    runtime.policy_dispatcher().warm(&invocation)
}
