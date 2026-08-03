// Node native binding over the Agent Control Specification runtime.
//
// The binding is deliberately thin: construct a runtime from a
// manifest (zero-config dispatchers), evaluate one context, return the
// verdict as wire JSON. Evaluation failures never surface as JS
// exceptions — the runtime normalizes them into fail-closed `deny`
// verdicts with `runtime_error:*` reasons. Exceptions on this boundary
// mean a boundary problem only (unreadable manifest, non-object
// context JSON).

use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::{Manifest, Runtime, RuntimeError, SUPPORTED_VERSIONS};
use napi::bindgen_prelude::{External, Utf16String};
use napi_derive::napi;
use serde_json::Value;
use std::sync::Arc;

pub struct Handle {
    runtime: Runtime,
}

fn err(message: String) -> napi::Error {
    napi::Error::from_reason(message)
}

/// Decode a JS string without losing anything.
///
/// napi's `String` conversion goes through `napi_get_value_string_utf8`,
/// which silently replaces an unpaired surrogate with U+FFFD. That would
/// have the engine judge or evaluate content the caller never supplied,
/// and `binding.js` is published, so a consumer can reach these entry
/// points without the wrapper's guard. Taking UTF-16 code units and
/// converting here makes invalid encoding an explicit error on every
/// path into the engine, matching the C ABI.
///
/// UTF-16 rather than a byte array on purpose: a `Uint8Array` may be
/// backed by a `SharedArrayBuffer`, which another worker can mutate
/// while the engine reads it.
fn decode(what: &str, value: &Utf16String) -> napi::Result<String> {
    String::from_utf16(value).map_err(|_| err(format!("{what} contains an unpaired surrogate")))
}

/// Build a runtime handle from a manifest path using the zero-config
/// dispatchers (bundled annotators; Rego through OPA, Cedar through the
/// built-in evaluator, `test` policies through their embedded verdict).
#[napi]
pub fn interceptor_new(manifest_path: Utf16String) -> napi::Result<External<Handle>> {
    let manifest_path = decode("manifest_path", &manifest_path)?;
    let manifest = Manifest::from_path(&manifest_path).map_err(|e| err(format!("{e}")))?;
    let runtime = Runtime::new(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .map_err(|e| err(format!("{e}")))?;
    Ok(External::new(Handle { runtime }))
}

/// Evaluate one agent context (JSON object per AGENT-HOOKS-0.1 §4) and
/// return the verdict as wire JSON.
#[napi]
pub fn intercept(handle: &External<Handle>, context_json: Utf16String) -> napi::Result<String> {
    let context_json = decode("context_json", &context_json)?;
    let snapshot: Value = serde_json::from_str(&context_json)
        .map_err(|e| err(format!("context_json does not parse: {e}")))?;
    if !snapshot.is_object() {
        return Err(err("context_json must be a JSON object".to_string()));
    }
    let verdict = handle.runtime.evaluate(&snapshot).verdict;
    serde_json::to_string(&verdict).map_err(|e| err(format!("verdict serialization failed: {e}")))
}

/// Validate manifest source against the grammar, without building a
/// runtime.
///
/// Authoring and migration tools need this answer before a policy is
/// runnable, and building a runtime would additionally require the
/// bundled dispatchers and, for Rego, a loadable policy bundle.
///
/// A rejected manifest comes back as `Some(message)` rather than being
/// thrown, so a thrown error from this function always means the call
/// itself failed and never that the manifest is bad. The wrapper relies
/// on that split so it does not relabel boundary failures as grammar
/// failures.
#[napi]
pub fn validate_manifest(source: Utf16String) -> napi::Result<Option<String>> {
    let source = decode("source", &source)?;
    let manifest = match Manifest::parse_yaml_str(&source) {
        Ok(m) => m,
        Err(e) => return Ok(Some(format!("{e}"))),
    };
    if !manifest.extends.is_empty() {
        // Validation checks references across the merged document, so
        // judging this fragment alone would reject it for something its
        // parent defines. Not a verdict, so it is thrown rather than
        // returned as a rejection.
        return Err(err(
            "manifest extends other manifests; validation needs the merged document. \
             Use validateManifestFile, which resolves the chain."
                .to_string(),
        ));
    }
    Ok(manifest.validate().err().map(|e| format!("{e}")))
}

/// Validate a manifest file, resolving `extends` first.
///
/// The entry point for a manifest that inherits. Reads from disk and may
/// fetch URL `extends`, exactly as loading a runtime would.
#[napi]
pub fn validate_manifest_file(path: Utf16String) -> napi::Result<Option<String>> {
    let path = decode("path", &path)?;
    match Manifest::from_path(&path) {
        Ok(_) => Ok(None),
        // Only a grammar rejection is returned as a rejection.
        // Everything else, including a breached resource limit and any
        // variant added later, is thrown as a boundary failure.
        Err(RuntimeError::ManifestInvalid(detail)) => Ok(Some(detail)),
        Err(other) => Err(err(format!("{other}"))),
    }
}

/// The manifest grammar versions this engine accepts.
#[napi]
pub fn supported_manifest_versions() -> Vec<String> {
    SUPPORTED_VERSIONS
        .iter()
        .map(|v| (*v).to_string())
        .collect()
}
