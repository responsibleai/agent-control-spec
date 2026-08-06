//! Zero-config policy dispatcher for the language bindings.
//!
//! A host wiring the runtime through a native binding (Node, .NET)
//! cannot supply a Rust [`PolicyDispatcher`], so the binding surface
//! constructs this one: each prepared invocation routes to the bundled
//! evaluator for its engine type. Failures return [`RuntimeError`] and
//! are normalized by the runtime into fail-closed `deny` verdicts with
//! `runtime_error:*` reasons — no error crosses the binding boundary
//! as anything but a verdict.

use crate::policy::PreparedPolicyInvocation;
use crate::runtime::PolicyDispatcher;
use crate::{JsonValue, RuntimeError};

#[cfg(feature = "cedar")]
use crate::cedar::CedarBuiltinDispatcher;
#[cfg(all(not(feature = "rego"), feature = "opa"))]
use crate::opa::{OpaPolicyDispatcher, OpaRegoRunner};
#[cfg(feature = "rego")]
use crate::rego::{RegorusPolicyDispatcher, RegorusRegoRunner};

/// Routes each policy invocation to the bundled evaluator for its
/// engine type: Rego through the in-process `regorus` runner (`rego`
/// feature) or the legacy `opa` CLI runner (`opa` feature), Cedar
/// through the built-in evaluator (`cedar` feature), and `test`
/// policies through their manifest-embedded `verdict` value. Custom
/// policies require a host-supplied dispatcher and fail closed here.
#[derive(Debug, Default)]
pub struct BindingPolicyDispatcher {
    #[cfg(feature = "rego")]
    rego: RegorusPolicyDispatcher,
    #[cfg(all(not(feature = "rego"), feature = "opa"))]
    opa: OpaPolicyDispatcher,
    #[cfg(feature = "cedar")]
    cedar: CedarBuiltinDispatcher,
}

impl BindingPolicyDispatcher {
    pub fn new() -> Self {
        Self {
            // Bindings are long-lived processes evaluating the same
            // manifest repeatedly, so the compiled policy cache is worth
            // its staleness trade here: policy files are read once.
            #[cfg(feature = "rego")]
            rego: RegorusPolicyDispatcher::with_runner(
                RegorusRegoRunner::from_environment().with_policy_cache(true),
            ),
            #[cfg(all(not(feature = "rego"), feature = "opa"))]
            opa: OpaPolicyDispatcher::with_runner(OpaRegoRunner::from_environment()),
            #[cfg(feature = "cedar")]
            cedar: CedarBuiltinDispatcher::new(),
        }
    }
}

impl PolicyDispatcher for BindingPolicyDispatcher {
    /// Forwards warm-up to the bundled evaluator for this invocation's
    /// engine type, so that a policy activated over a binding is
    /// compiled at activation rather than on the first decision. Without
    /// this the trait default would silently make
    /// [`crate::ActivatedPolicy`] eager in Rust and lazy in every
    /// binding.
    fn warm(&self, invocation: &PreparedPolicyInvocation) -> Result<(), RuntimeError> {
        match invocation {
            #[cfg(feature = "rego")]
            PreparedPolicyInvocation::Rego(_) => self.rego.warm(invocation),
            // The remaining engines have nothing to prepare: the `opa`
            // runner shells out per decision, Cedar compiles per
            // evaluation, a `test` policy is a literal verdict, and a
            // custom adapter is not this dispatcher's to ready.
            _ => Ok(()),
        }
    }

    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            #[cfg(feature = "rego")]
            PreparedPolicyInvocation::Rego(_) => self.rego.evaluate(invocation),
            #[cfg(all(not(feature = "rego"), feature = "opa"))]
            PreparedPolicyInvocation::Rego(_) => self.opa.evaluate(invocation),
            #[cfg(not(any(feature = "rego", feature = "opa")))]
            PreparedPolicyInvocation::Rego(_) => Err(RuntimeError::PolicyInvocationFailed(
                "Rego policies require the 'rego' or 'opa' feature or a host dispatcher"
                    .to_string(),
            )),
            #[cfg(feature = "cedar")]
            PreparedPolicyInvocation::Cedar(_) => self.cedar.evaluate(invocation),
            #[cfg(not(feature = "cedar"))]
            PreparedPolicyInvocation::Cedar(_) => Err(RuntimeError::PolicyInvocationFailed(
                "Cedar policies require the 'cedar' feature or a host dispatcher".to_string(),
            )),
            PreparedPolicyInvocation::Test(test) => {
                test.adapter_config.get("verdict").cloned().ok_or_else(|| {
                    RuntimeError::PolicyInvocationFailed(
                        "test policy declares no 'verdict' in its configuration".to_string(),
                    )
                })
            }
            PreparedPolicyInvocation::Custom(custom) => {
                Err(RuntimeError::PolicyInvocationFailed(format!(
                    "custom policy adapter '{}' requires a host-supplied dispatcher; \
                     none is available over this binding",
                    custom.adapter
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TestPolicyInvocation;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn test_invocation(config: BTreeMap<String, JsonValue>) -> PreparedPolicyInvocation {
        PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: config,
            input: json!({}),
            canonical_input: "{}".to_string(),
        })
    }

    #[test]
    fn test_policy_echoes_configured_verdict() {
        let mut config = BTreeMap::new();
        config.insert(
            "verdict".to_string(),
            json!({"decision": "deny", "reason": "blocked"}),
        );
        let out = BindingPolicyDispatcher::new()
            .evaluate(&test_invocation(config))
            .expect("configured verdict");
        assert_eq!(out["decision"], "deny");
    }

    #[test]
    fn test_policy_without_verdict_fails_closed() {
        let err = BindingPolicyDispatcher::new()
            .evaluate(&test_invocation(BTreeMap::new()))
            .expect_err("no verdict configured");
        assert_eq!(err.reason(), "runtime_error:policy_invocation_failed");
    }

    #[test]
    fn custom_policy_fails_closed() {
        let invocation = PreparedPolicyInvocation::Custom(crate::policy::CustomPolicyInvocation {
            adapter: "host-only".to_string(),
            adapter_config: BTreeMap::new(),
            input: json!({}),
            canonical_input: "{}".to_string(),
        });
        let err = BindingPolicyDispatcher::new()
            .evaluate(&invocation)
            .expect_err("custom needs a host dispatcher");
        assert_eq!(err.reason(), "runtime_error:policy_invocation_failed");
    }
}
