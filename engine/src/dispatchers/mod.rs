//! Bundled reference dispatchers for Agent Control Specification.
//!
//! The core defines the annotator contract but leaves execution to hosts. This
//! module provides small synchronous reference dispatchers for HTTP endpoints,
//! generic classifiers, and OpenAI-compatible LLM judges. It is gated behind the
//! `default-dispatchers` feature so the pure deterministic core carries no
//! networking dependency unless a host opts in. These dispatchers back the
//! zero-config defaults surfaced through the FFI builder.

mod binding;
pub mod bundled;
mod classifier;
mod constants;
mod default;
mod endpoint;
mod http;
mod llm;
mod resolve;

pub use binding::BindingPolicyDispatcher;
pub use bundled::{
    fold_score_verdict, BundledClassifierProvider, ClassifierVerdict, HttpTransport,
    ResolvedClassifierConfig, StubHttpTransport, TransportRequest, TransportResponse,
    UreqHttpTransport,
};
pub use classifier::ClassifierAnnotator;
pub use default::DefaultAnnotatorDispatcher;
pub use endpoint::EndpointAnnotator;
pub use llm::LlmAnnotator;

use crate::AnnotatorDispatcher;
#[cfg(any(feature = "rego", feature = "opa"))]
use crate::{Manifest, PolicyDispatcher, RuntimeError};
use std::sync::Arc;

/// The bundled native annotator dispatcher used as the zero-config default. It
/// routes each annotator to the matching reference dispatcher based on its
/// declared `type`, reading endpoint configuration from the manifest.
pub fn default_annotator_dispatcher() -> Arc<dyn AnnotatorDispatcher> {
    Arc::new(DefaultAnnotatorDispatcher::new())
}

/// The bundled native Rego policy dispatcher used as the zero-config default.
///
/// Fails closed if the manifest declares a non-Rego policy because the default
/// dispatcher only evaluates Rego. The runtime normalizes policy evaluation
/// failures into fail-closed verdicts.
///
/// With the default `rego` feature this is the in-process `regorus` backed
/// dispatcher, which needs no external binary and costs no process spawn per
/// evaluation. A build that opts out of `rego` and into the legacy `opa`
/// feature instead gets the dispatcher that shells out to the `opa` CLI.
///
/// AGT M2.S5 D7: gated behind the Rego features. Hosts that build the core
/// without either MUST register their own `PolicyDispatcher` explicitly; the
/// FFI builder surfaces a clear error in that configuration.
#[cfg(any(feature = "rego", feature = "opa"))]
pub fn default_policy_dispatcher(
    manifest: &Manifest,
) -> Result<Arc<dyn PolicyDispatcher>, RuntimeError> {
    for (name, policy) in &manifest.policies {
        let engine = policy.engine_type();
        if engine != "rego" {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "default policy dispatcher supports only Rego policies; policy '{name}' uses engine '{engine}'"
            )));
        }
    }
    #[cfg(feature = "rego")]
    {
        // The cache is on here, unlike the bare `RegorusRegoRunner`
        // default: this dispatcher is built once per manifest and then
        // asked for a verdict at every intervention point, so without it
        // the whole policy set is re-read and re-parsed on every
        // decision. Hosts that hot-reload policy from disk should build
        // their own runner with the cache off.
        Ok(Arc::new(crate::RegorusPolicyDispatcher::with_runner(
            crate::RegorusRegoRunner::from_environment().with_policy_cache(true),
        )))
    }
    #[cfg(all(not(feature = "rego"), feature = "opa"))]
    {
        Ok(Arc::new(crate::OpaPolicyDispatcher::with_runner(
            crate::OpaRegoRunner::from_environment(),
        )))
    }
}
