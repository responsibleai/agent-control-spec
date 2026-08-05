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
    /// Fails when readying a bound policy finds it broken, such as a
    /// bundle that does not exist, and when readying cannot be
    /// attempted at all. A policy that merely needs real input to
    /// produce a verdict warms fine.
    ///
    /// The first of those is conditional on readying finishing: a
    /// bundle whose load does not complete inside the deadline is
    /// not reported here, and surfaces at the first decision.
    ///
    /// Readying is bounded by the dispatcher's eval timeout. A policy
    /// too slow to compile inside it is left not necessarily fully readied, and
    /// activation still succeeds: it pays compilation on its first
    /// decision instead, and fails closed there if it cannot finish.
    /// So activation compiles the policy in the ordinary case, but a
    /// successful activation is not a proof that it did.
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

    /// Activates a manifest and its Rego, both supplied as values
    /// rather than read from disk.
    ///
    /// `manifest_yaml` is the manifest text. `bundles` maps a policy id
    /// declared in it to the modules and data documents that policy
    /// evaluates, replacing whatever `bundle` path the manifest names.
    /// A service holding both in a database activates from them
    /// directly, instead of staging a temporary directory per
    /// activation.
    ///
    /// Fails when the manifest does not parse, when a key of `bundles`
    /// names a policy the manifest does not declare as Rego, and when a
    /// Rego policy is left naming a relative `bundle` path. That last
    /// one would otherwise resolve against the process working
    /// directory, since a manifest parsed from a string has no directory
    /// of its own, and would read a policy nobody chose. An absolute
    /// path is left as written, so a manifest can mix policy from the
    /// database with policy from a known location on disk.
    ///
    /// Readying carries the same qualification as
    /// [`Self::activate_from_path`]: it is bounded by the eval timeout.
    #[cfg(all(
        feature = "default-dispatchers",
        any(feature = "rego", feature = "opa")
    ))]
    pub fn activate_from_memory(
        manifest_yaml: &str,
        bundles: std::collections::BTreeMap<String, crate::policy::InMemoryRegoBundle>,
    ) -> Result<Self, RuntimeError> {
        Self::activate_manifest(manifest_from_memory(manifest_yaml, bundles)?)
    }

    /// [`Self::activate_from_memory`] against host-supplied dispatchers,
    /// as [`Self::activate_with`] is to [`Self::activate_from_path`].
    pub fn activate_from_memory_with(
        manifest_yaml: &str,
        bundles: std::collections::BTreeMap<String, crate::policy::InMemoryRegoBundle>,
        annotations: Arc<dyn AnnotatorDispatcher>,
        policy: Arc<dyn PolicyDispatcher>,
    ) -> Result<Self, RuntimeError> {
        Self::activate_with(
            manifest_from_memory(manifest_yaml, bundles)?,
            annotations,
            policy,
        )
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

/// Parses a manifest from text and attaches the modules the host holds
/// for it.
///
/// Refuses to leave a rego policy naming a relative `bundle` path. A
/// manifest parsed from a string has no directory of its own, so such a
/// path resolves against the process working directory and would load a
/// policy nobody chose. An absolute path is a location the host wrote
/// deliberately and is left as it is, so one manifest can mix policy
/// held in memory with policy at a known location on disk.
fn manifest_from_memory(
    manifest_yaml: &str,
    bundles: std::collections::BTreeMap<String, crate::policy::InMemoryRegoBundle>,
) -> Result<Manifest, RuntimeError> {
    let mut manifest = Manifest::parse_yaml_str(manifest_yaml)?;
    for (policy_id, bundle) in bundles {
        manifest.set_rego_bundle_in_memory(&policy_id, bundle)?;
    }
    let unresolved = manifest.unresolved_relative_rego_paths();
    if !unresolved.is_empty() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "activating from memory, but rego {} {} still point at a relative bundle or data \
             path, which has no manifest directory to resolve against. Supply modules for {}, or \
             write the path as absolute",
            if unresolved.len() == 1 {
                "policy"
            } else {
                "policies"
            },
            unresolved
                .iter()
                .map(|id| format!("'{id}'"))
                .collect::<Vec<_>>()
                .join(", "),
            if unresolved.len() == 1 { "it" } else { "them" },
        )));
    }
    Ok(manifest)
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
