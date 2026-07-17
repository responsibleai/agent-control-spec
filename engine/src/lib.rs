//! Agent Control Specification: a stateless policy decision runtime
//! implementing the agent-hooks interceptor contract.
//!
//! The interception layer — points, context, verdicts, host
//! obligations, composition, identity — is defined by
//! [AGENT-HOOKS-0.1](https://github.com/responsibleai/agent-hooks) and
//! consumed from the `agent-hooks-sdk` crate. This crate is the policy
//! plane: manifest binding, policy dispatchers (Cedar, Rego, custom),
//! annotators, and the normalization of raw policy output into
//! agent-hooks verdicts. [`AcsInterceptor`] is the integration
//! surface a host registers with its agent-hooks emitter.

pub type JsonValue = serde_json::Value;

pub mod annotation;
pub mod cedar;
mod constants;
pub use constants::reserved_reason;
#[cfg(feature = "default-dispatchers")]
pub mod dispatchers;
pub mod error;
pub mod interceptor;
pub mod limits;
pub mod manifest;
#[cfg(feature = "opa")]
pub mod opa;
pub mod paths;
pub mod perf_telemetry;
pub mod point_ext;
pub mod policy;
pub mod policy_input;
pub mod policy_output;
pub mod runtime;
pub mod telemetry;
pub mod tool_projection;

// The interception contract, re-exported for consumers that want a
// single dependency.
pub use agent_hooks::{
    AgentContext, Decision, EnforcementMode, Evidence, InterceptionPoint, Interceptor, Transform,
    Verdict, Warning,
};

pub use annotation::{
    AnnotationConfig, AnnotatorConfig, AnnotatorDispatcher, AnnotatorInvocation, AnnotatorType,
};
#[cfg(feature = "cedar")]
pub use cedar::CedarBuiltinDispatcher;
pub use cedar::{
    build_cedar_request, translate_advice, CedarEntity, CedarPolicyDispatcher, CedarRequest,
    CedarTestDispatcher,
};
#[cfg(feature = "default-dispatchers")]
pub use dispatchers::{
    ClassifierAnnotator, DefaultAnnotatorDispatcher, EndpointAnnotator, LlmAnnotator,
};
pub use error::RuntimeError;
pub use interceptor::AcsInterceptor;
pub use limits::Limits;
pub use manifest::{InterventionPointConfig, Manifest, ToolConfig};
#[cfg(feature = "opa")]
pub use opa::{OpaPolicyDispatcher, OpaRegoRunner};
pub use paths::{JsonPath, PathEnv, PathParseError, PathRoot, PathSegment};
pub use perf_telemetry::PerfTelemetry;
pub use point_ext::InterceptionPointExt;
pub use policy::{
    CedarPolicyConfig, CedarPolicyInvocation, CustomPolicyConfig, CustomPolicyInvocation,
    PolicyBinding, PolicyConfig, PreparedPolicyInvocation, RegoPolicyConfig, RegoPolicyInvocation,
    TestPolicyConfig, TestPolicyInvocation,
};
pub use policy_input::{build_policy_input, canonical_json};
pub use policy_output::{normalize_policy_output, runtime_error_verdict};
pub use runtime::{EvaluationRequest, EvaluationResult, PolicyDispatcher, Runtime};
pub use telemetry::{NoopTelemetrySink, TelemetryEvent, TelemetryEventType, TelemetrySink};
