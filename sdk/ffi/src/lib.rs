// C ABI over the Agent Control Specification runtime (language bindings).
//
// Conventions, shared with the .NET binding in `sdk/dotnet`:
// - Every entry point runs under `catch_unwind`; a panic never crosses
//   the C boundary (it becomes an error string).
// - Inbound strings must be valid UTF-8; invalid encoding is an
//   explicit error, never lossily converted.
// - Fallible functions take `err_out: *mut *mut c_char`. On failure the
//   return value is null and `*err_out` carries a message the caller
//   frees with `acs_free_string`. On success `*err_out` is null.
// - Handles from `acs_interceptor_new` are freed exactly once with
//   `acs_interceptor_free`.
//
// Evaluation failures do NOT surface here as errors: the runtime
// normalizes them into fail-closed `deny` verdicts with
// `runtime_error:*` reasons, so `acs_intercept` returns a verdict for
// every schema-valid context. Errors on that path are boundary
// problems only (bad UTF-8, non-object context, poisoned handle).

use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::stream_session::{
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack,
};
use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, Manifest, Runtime, RuntimeError,
    Verdict, SUPPORTED_VERSIONS,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// Opaque interceptor handle: the runtime plus the payload-free name
/// recorded on `verdicts[].name`.
pub struct AcsInterceptor {
    runtime: Runtime,
    name: String,
}

fn set_err(err_out: *mut *mut c_char, message: String) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(message.replace('\0', "\u{fffd}"))
        .unwrap_or_else(|_| CString::new("error message contained NUL").expect("static"));
    unsafe { *err_out = c.into_raw() };
}

fn clear_err(err_out: *mut *mut c_char) {
    if !err_out.is_null() {
        unsafe { *err_out = std::ptr::null_mut() };
    }
}

/// Read a path from a pointer and an explicit length.
///
/// Paths never go through a NUL-terminated parameter here: truncation
/// would name a different file, so the caller would be answered about a
/// document they did not ask about. An interior NUL is rejected rather
/// than accepted, because no such path is meaningful.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null when `len` is 0.
unsafe fn read_path<'a>(ptr: *const u8, len: usize, err_out: *mut *mut c_char) -> Option<&'a str> {
    let bytes: &[u8] = if len == 0 {
        &[]
    } else if ptr.is_null() {
        set_err(err_out, "path must not be null".to_string());
        return None;
    } else {
        std::slice::from_raw_parts(ptr, len)
    };
    let path = match std::str::from_utf8(bytes) {
        Ok(p) => p,
        Err(e) => {
            set_err(err_out, format!("path is not valid UTF-8: {e}"));
            return None;
        }
    };
    if path.contains('\0') {
        set_err(
            err_out,
            "path must not contain an interior NUL byte".to_string(),
        );
        return None;
    }
    Some(path)
}

/// Read a required UTF-8 argument; on failure records the error and
/// returns None.
unsafe fn read_utf8<'a>(
    ptr: *const c_char,
    what: &str,
    err_out: *mut *mut c_char,
) -> Option<&'a str> {
    if ptr.is_null() {
        set_err(err_out, format!("{what} must not be null"));
        return None;
    }
    match CStr::from_ptr(ptr).to_str() {
        Ok(s) => Some(s),
        Err(_) => {
            set_err(err_out, format!("{what} is not valid UTF-8"));
            None
        }
    }
}

fn to_c_string(s: String, err_out: *mut *mut c_char) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => {
            clear_err(err_out);
            c.into_raw()
        }
        Err(_) => {
            set_err(err_out, "output contained an interior NUL byte".to_string());
            std::ptr::null_mut()
        }
    }
}

/// Build an interceptor from a manifest path using the zero-config
/// dispatchers (bundled annotators; Rego in process, Cedar through the
/// built-in evaluator, `test` policies through their embedded verdict).
///
/// # Safety
/// `manifest_path` must be a valid NUL-terminated string; `err_out`,
/// when non-null, must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn acs_interceptor_new(
    manifest_path: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut AcsInterceptor {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = read_utf8(manifest_path, "manifest_path", err_out)?;
        build_interceptor(path, err_out)
    }));
    match result {
        Ok(Some(handle)) => handle,
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            set_err(err_out, "internal panic in acs_interceptor_new".to_string());
            std::ptr::null_mut()
        }
    }
}

/// Outcome of `acs_validate_manifest`. Zero is the only accepting
/// value, so the idiom `if (acs_validate_manifest(...)) { /* problem */ }`
/// fails closed. The predecessor returned `bool`, which invited the
/// opposite reading and treated a boundary failure as a pass.
pub const ACS_MANIFEST_VALID: i32 = 0;
/// The manifest was read and the engine rejected it. `*err_out` carries
/// the engine's message.
pub const ACS_MANIFEST_INVALID: i32 = 1;
/// The call itself failed and the manifest was never judged. `*err_out`
/// carries a boundary message.
pub const ACS_MANIFEST_CALL_FAILED: i32 = -1;

/// Validate manifest source against the grammar, without building a
/// runtime.
///
/// Authoring and migration tools need this answer before a policy is
/// runnable, and `acs_interceptor_new` would additionally require the
/// bundled dispatchers and, for Rego, a loadable policy bundle.
///
/// Returns `ACS_MANIFEST_VALID`, `ACS_MANIFEST_INVALID`, or
/// `ACS_MANIFEST_CALL_FAILED`. A verdict on the manifest and a failure
/// of the call are distinct return values on purpose: `*err_out` is
/// non-null for both, so the return code is the only discriminator, and
/// a caller must not report a boundary failure as a bad manifest.
///
/// `source` is a pointer plus an explicit byte length rather than a
/// NUL-terminated string. Manifest text is arbitrary user input that may
/// contain an interior NUL, and stopping there would validate a prefix
/// and accept a document the engine rejects.
///
/// # Safety
/// `source` must point to `source_len` readable bytes, or be null when
/// `source_len` is 0; `err_out`, when non-null, must point to writable
/// memory.
#[no_mangle]
pub unsafe extern "C" fn acs_validate_manifest(
    source: *const u8,
    source_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if source_len == 0 {
            &[]
        } else if source.is_null() {
            set_err(err_out, "source must not be null".to_string());
            return ACS_MANIFEST_CALL_FAILED;
        } else {
            std::slice::from_raw_parts(source, source_len)
        };
        let source = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("source is not valid UTF-8: {e}"));
                return ACS_MANIFEST_CALL_FAILED;
            }
        };
        let manifest = match Manifest::parse_yaml_str(source) {
            Ok(m) => m,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return ACS_MANIFEST_INVALID;
            }
        };
        if !manifest.extends.is_empty() {
            // Validation checks references across the merged document,
            // so judging this fragment alone would reject it for
            // something its parent defines. Not a verdict, so it must
            // not be reported as one.
            set_err(
                err_out,
                "manifest extends other manifests; validation needs the merged document. \
                 Use acs_validate_manifest_file, which resolves the chain."
                    .to_string(),
            );
            return ACS_MANIFEST_CALL_FAILED;
        }
        match manifest.validate() {
            Ok(()) => ACS_MANIFEST_VALID,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                ACS_MANIFEST_INVALID
            }
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_validate_manifest".to_string(),
            );
            ACS_MANIFEST_CALL_FAILED
        }
    }
}

/// Validate a manifest file, resolving `extends` first.
///
/// The entry point for a manifest that inherits. Reads from disk and may
/// fetch URL `extends`, exactly as loading a runtime would. Returns the
/// same codes as `acs_validate_manifest`.
///
/// `path` is a pointer and an explicit byte length for the same reason
/// as `acs_validate_manifest`: a NUL-terminated parameter truncates, and
/// a truncated path names a different file, so the caller would be told
/// about a document they did not ask about.
///
/// # Safety
/// `path` must point to `path_len` readable bytes, or be null when
/// `path_len` is 0; `err_out`, when non-null, must point to writable
/// memory.
#[no_mangle]
pub unsafe extern "C" fn acs_validate_manifest_file(
    path: *const u8,
    path_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = match read_path(path, path_len, err_out) {
            Some(p) => p,
            None => return ACS_MANIFEST_CALL_FAILED,
        };
        match Manifest::from_path(path) {
            Ok(_) => ACS_MANIFEST_VALID,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                // Only a grammar rejection is a verdict on the document.
                // Everything else, including a breached resource limit
                // and any variant added later, is a failed call. Naming
                // the one accepting variant rather than wildcarding it
                // keeps the default fail-safe.
                match e {
                    RuntimeError::ManifestInvalid(_) => ACS_MANIFEST_INVALID,
                    _ => ACS_MANIFEST_CALL_FAILED,
                }
            }
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_validate_manifest_file".to_string(),
            );
            ACS_MANIFEST_CALL_FAILED
        }
    }
}

/// The manifest grammar versions this engine accepts, as a JSON array
/// of strings. The caller frees the result with `acs_free_string`.
///
/// # Safety
/// `err_out`, when non-null, must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn acs_supported_manifest_versions(err_out: *mut *mut c_char) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        serde_json::to_string(SUPPORTED_VERSIONS)
            .ok()
            .map(|json| to_c_string(json, err_out))
    }));
    match result {
        Ok(Some(ptr)) => ptr,
        Ok(None) => {
            set_err(
                err_out,
                "supported version list is not encodable".to_string(),
            );
            std::ptr::null_mut()
        }
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_supported_manifest_versions".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Shared construction, so both constructors agree on behaviour.
fn build_interceptor(path: &str, err_out: *mut *mut c_char) -> Option<*mut AcsInterceptor> {
    let manifest = match Manifest::from_path(path) {
        Ok(m) => m,
        Err(e) => {
            set_err(err_out, format!("{e}"));
            return None;
        }
    };
    let runtime = match Runtime::new(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    ) {
        Ok(r) => r,
        Err(e) => {
            set_err(err_out, format!("{e}"));
            return None;
        }
    };
    Some(Box::into_raw(Box::new(AcsInterceptor {
        runtime,
        name: "acs".to_string(),
    })))
}

/// Build an interceptor from a manifest path given as a pointer and an
/// explicit length.
///
/// Prefer this over `acs_interceptor_new`, which takes a NUL-terminated
/// path and therefore truncates at an interior NUL, loading a different
/// manifest than the caller named. That signature is kept for existing
/// consumers; this one is additive.
///
/// # Safety
/// `manifest_path` must point to `manifest_path_len` readable bytes, or
/// be null when the length is 0; `err_out`, when non-null, must point to
/// writable memory.
#[no_mangle]
pub unsafe extern "C" fn acs_interceptor_new_ex(
    manifest_path: *const u8,
    manifest_path_len: usize,
    err_out: *mut *mut c_char,
) -> *mut AcsInterceptor {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = read_path(manifest_path, manifest_path_len, err_out)?;
        build_interceptor(path, err_out)
    }));
    match result {
        Ok(Some(handle)) => handle,
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_interceptor_new_ex".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Override the payload-free identifier recorded on `verdicts[].name`.
///
/// # Safety
/// `handle` must be a live pointer from `acs_interceptor_new`; `name`
/// a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_interceptor_set_name(
    handle: *mut AcsInterceptor,
    name: *const c_char,
    err_out: *mut *mut c_char,
) {
    clear_err(err_out);
    if handle.is_null() {
        set_err(err_out, "handle must not be null".to_string());
        return;
    }
    if let Some(n) = read_utf8(name, "name", err_out) {
        (*handle).name = n.to_string();
    }
}

/// Evaluate one agent context (a JSON object per AGENT-HOOKS-0.1 §4)
/// and return the verdict as wire JSON. Evaluation failures return a
/// fail-closed `deny` verdict, not an error.
///
/// # Safety
/// `handle` must be a live pointer from `acs_interceptor_new`;
/// `context_json` a valid NUL-terminated string; the returned string is
/// freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_intercept(
    handle: *const AcsInterceptor,
    context_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let Some(raw) = read_utf8(context_json, "context_json", err_out) else {
            return std::ptr::null_mut();
        };
        let snapshot: Value = match serde_json::from_str(raw) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => {
                set_err(err_out, "context_json must be a JSON object".to_string());
                return std::ptr::null_mut();
            }
            Err(e) => {
                set_err(err_out, format!("context_json does not parse: {e}"));
                return std::ptr::null_mut();
            }
        };
        let verdict = (*handle).runtime.evaluate(&snapshot).verdict;
        match serde_json::to_string(&verdict) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("verdict serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(err_out, "internal panic in acs_intercept".to_string());
            std::ptr::null_mut()
        }
    }
}

/// The interceptor's payload-free name.
///
/// # Safety
/// `handle` must be a live pointer from `acs_interceptor_new`; the
/// returned string is freed with `acs_free_string`.
#[no_mangle]
pub unsafe extern "C" fn acs_interceptor_name(
    handle: *const AcsInterceptor,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    if handle.is_null() {
        set_err(err_out, "handle must not be null".to_string());
        return std::ptr::null_mut();
    }
    to_c_string((*handle).name.clone(), err_out)
}

/// Free a handle from `acs_interceptor_new`. Passing null is a no-op.
///
/// # Safety
/// `handle` must be a pointer from `acs_interceptor_new`, freed at most
/// once.
#[no_mangle]
pub unsafe extern "C" fn acs_interceptor_free(handle: *mut AcsInterceptor) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Free a string returned by any `acs_*` function. Passing null is a
/// no-op.
///
/// # Safety
/// `s` must be a string returned by this library, freed at most once.
#[no_mangle]
pub unsafe extern "C" fn acs_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ---------------------------------------------------------------------
// Activated policy: one policy version, readied once, evaluated many
// times.
//
// `acs_interceptor_*` answers "evaluate this agent context against a
// manifest", and readies the policy lazily on the first call. A host
// that pins a policy version and serves traffic against it wants the
// opposite split: pay for reading and compiling the bundle once, at a
// moment of its choosing, then evaluate a named intervention point with
// nothing left to set up. These entry points are that split.
// ---------------------------------------------------------------------

/// Opaque handle to one activated policy version.
pub struct AcsActivatedPolicy {
    policy: ActivatedPolicy,
}

/// Activate the manifest at `manifest_path`, readying every policy it
/// binds.
///
/// This is the expensive call: it reads the manifest, loads every Rego
/// module and data document, and compiles the entrypoint each
/// intervention point queries. Do it once per policy version and keep
/// the handle; `acs_policy_evaluate` then costs no I/O and no compile.
///
/// Compiling is bounded by the eval timeout. A policy too slow to
/// compile in that window activates anyway, not necessarily fully readied, and
/// pays compilation on its first decision instead.
///
/// Returns NULL and sets `*err_out` on failure. Free with
/// `acs_policy_free`.
///
/// # Safety
/// `manifest_path` must point to `manifest_path_len` readable bytes.
/// `err_out` must be null or point to a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn acs_policy_activate(
    manifest_path: *const u8,
    manifest_path_len: usize,
    err_out: *mut *mut c_char,
) -> *mut AcsActivatedPolicy {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = read_path(manifest_path, manifest_path_len, err_out)?;
        let manifest = match Manifest::from_path(path) {
            Ok(m) => m,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return None;
            }
        };
        let policy = match ActivatedPolicy::activate_with(
            manifest,
            default_annotator_dispatcher(),
            Arc::new(BindingPolicyDispatcher::new()),
        ) {
            Ok(p) => p,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return None;
            }
        };
        Some(Box::into_raw(Box::new(AcsActivatedPolicy { policy })))
    }));
    match result {
        Ok(Some(handle)) => handle,
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            set_err(err_out, "internal panic in acs_policy_activate".to_string());
            std::ptr::null_mut()
        }
    }
}

/// Activate a manifest and its Rego, both supplied as text rather than
/// read from disk.
///
/// `manifest_yaml` is the manifest itself. `bundles_json` maps a policy
/// id declared in it to the modules and data documents that policy
/// evaluates:
///
/// ```json
/// {
///   "gate": {
///     "modules": {"gate.rego": "package gate\n\nverdict := ..."},
///     "data": [{"mount": ["limits"], "document": {"daily": 42}}]
///   }
/// }
/// ```
///
/// `mount` is where the document lands under `data`, outermost segment
/// first; empty puts it at the data root. On disk that comes from the
/// file's directory, and nothing implies it here.
///
/// For a host that keeps policy in a database: activating from these
/// skips staging a temporary directory per activation. `bundles_json`
/// may be NULL or empty, which activates the manifest as written.
///
/// A rego policy left naming a relative `bundle` or data path is an error, not a
/// disk read: a manifest parsed from text has no directory of its own,
/// so the path would resolve against the process working directory and
/// load a policy nobody chose. Write it absolute to keep it.
///
/// Otherwise identical to `acs_policy_activate`, including that
/// compiling is bounded by the eval timeout.
///
/// Returns NULL and sets `*err_out` on failure. Free with
/// `acs_policy_free`.
///
/// # Safety
/// `manifest_yaml` must be a valid NUL-terminated string. `bundles_json`
/// must be NULL or a valid NUL-terminated string. `err_out` must be null
/// or point to a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn acs_policy_activate_from_memory(
    manifest_yaml: *const c_char,
    bundles_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut AcsActivatedPolicy {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let manifest_yaml = read_utf8(manifest_yaml, "manifest_yaml", err_out)?;
        let bundles = match read_in_memory_bundles(bundles_json, err_out) {
            Some(bundles) => bundles,
            None => return None,
        };
        let policy = match ActivatedPolicy::activate_from_memory_with(
            manifest_yaml,
            bundles,
            default_annotator_dispatcher(),
            Arc::new(BindingPolicyDispatcher::new()),
        ) {
            Ok(p) => p,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return None;
            }
        };
        Some(Box::into_raw(Box::new(AcsActivatedPolicy { policy })))
    }));
    match result {
        Ok(Some(handle)) => handle,
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_policy_activate_from_memory".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Reads the `bundles_json` argument, treating NULL and empty as "no
/// bundles supplied" so a host with nothing to override need not build a
/// JSON document to say so.
///
/// Returns `None` only after setting `*err_out`, so a caller can tell an
/// empty map from a rejected one.
unsafe fn read_in_memory_bundles(
    bundles_json: *const c_char,
    err_out: *mut *mut c_char,
) -> Option<BTreeMap<String, InMemoryRegoBundle>> {
    if bundles_json.is_null() {
        return Some(BTreeMap::new());
    }
    let raw = read_utf8(bundles_json, "bundles_json", err_out)?;
    if raw.trim().is_empty() {
        return Some(BTreeMap::new());
    }
    match serde_json::from_str(raw) {
        Ok(bundles) => Some(bundles),
        Err(e) => {
            set_err(err_out, format!("bundles_json is not valid: {e}"));
            None
        }
    }
}

/// Evaluate one intervention point against an activated policy.
///
/// `point` is an agent-hooks intervention point name, such as
/// `"input"` or `"pre_tool_call"`. `context_json` is the agent context
/// object. Returns the verdict as JSON, freed with `acs_free_string`.
///
/// A policy that does not bind `point` is a fail-closed deny carrying
/// reason `runtime_error:intervention_point_unknown`, not a successful
/// call and not a boundary error. Every failure in this runtime reaches
/// a host as a verdict; none is benign.
///
/// # Safety
/// `handle` must be a live pointer from `acs_policy_activate`; `point`
/// and `context_json` valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn acs_policy_evaluate(
    handle: *const AcsActivatedPolicy,
    point: *const c_char,
    context_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let Some(point_raw) = read_utf8(point, "point", err_out) else {
            return std::ptr::null_mut();
        };
        let Ok(point) = point_raw.parse::<InterceptionPoint>() else {
            set_err(err_out, format!("unknown intervention point '{point_raw}'"));
            return std::ptr::null_mut();
        };
        let Some(raw) = read_utf8(context_json, "context_json", err_out) else {
            return std::ptr::null_mut();
        };
        let snapshot: Value = match serde_json::from_str(raw) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => {
                set_err(err_out, "context_json must be a JSON object".to_string());
                return std::ptr::null_mut();
            }
            Err(e) => {
                set_err(err_out, format!("context_json does not parse: {e}"));
                return std::ptr::null_mut();
            }
        };
        let verdict = (*handle).policy.evaluate(point, snapshot).verdict;
        match serde_json::to_string(&verdict) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("verdict serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(err_out, "internal panic in acs_policy_evaluate".to_string());
            std::ptr::null_mut()
        }
    }
}

/// The intervention points this policy version binds, as a JSON array of
/// names. Freed with `acs_free_string`.
///
/// # Safety
/// `handle` must be a live pointer from `acs_policy_activate`.
#[no_mangle]
pub unsafe extern "C" fn acs_policy_intervention_points(
    handle: *const AcsActivatedPolicy,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let names: Vec<String> = (*handle)
            .policy
            .intervention_points()
            .iter()
            .map(|point| point.to_string())
            .collect();
        match serde_json::to_string(&names) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_policy_intervention_points".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Release an activated policy.
///
/// # Safety
/// `handle` must come from `acs_policy_activate` and must not be used
/// afterwards. Passing null is allowed and does nothing.
#[no_mangle]
pub unsafe extern "C" fn acs_policy_free(handle: *mut AcsActivatedPolicy) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

// ---------------------------------------------------------------------
// Incremental stream mediation (specification section 18.1).
//
// A `StreamSession` is stateful, so it follows the handle shape used by
// `AcsActivatedPolicy`: create once, drive it as payloads arrive, free
// exactly once. The runtime underneath stays stateless; the session only
// records what each ordinary evaluation cleared.
//
// Scalar queries return `i64` so an absent value needs no allocation:
// `>= 0` is the value, `-1` is absent (a released offset the caller must
// treat as "release nothing"), and `-2` means the call failed and
// `*err_out` carries why. Absent and failed are distinct because a
// settled session legitimately has no safe offset, which is not an error.
//
// Structured queries return JSON, freed with `acs_free_string`, so the
// wire contract is owned here rather than derived from Rust layout.
// ---------------------------------------------------------------------

/// Opaque handle to one mediated stream.
pub struct AcsStreamSession {
    session: StreamSession,
}

fn parse_track(value: &str, err_out: *mut *mut c_char) -> Option<StreamTrack> {
    match value {
        "request" => Some(StreamTrack::Request),
        "response" => Some(StreamTrack::Response),
        other => {
            set_err(err_out, format!("unknown stream track '{other}'"));
            None
        }
    }
}

fn parse_outcome(value: &str, err_out: *mut *mut c_char) -> Option<SegmentOutcome> {
    match value {
        "cleared" => Some(SegmentOutcome::Cleared),
        "transformed" => Some(SegmentOutcome::Transformed),
        "denied" => Some(SegmentOutcome::Denied),
        other => {
            set_err(err_out, format!("unknown segment outcome '{other}'"));
            None
        }
    }
}

fn end_reason_json(reason: &StreamEndReason) -> Value {
    match reason {
        StreamEndReason::Complete => serde_json::json!({ "kind": "complete" }),
        StreamEndReason::Denied { track, task, range } => serde_json::json!({
            "kind": "denied",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Rewritten { track, task, range } => serde_json::json!({
            "kind": "rewritten",
            "track": track.as_str(),
            "task": task,
            "start": range.start,
            "end": range.end,
        }),
        StreamEndReason::Failed(error) => serde_json::json!({
            "kind": "failed",
            "reason": error.reason(),
            "message": error.to_string(),
        }),
    }
}

/// Open a session from `config_json`.
///
/// The object takes `safety_level` (`blocking`, `complete` or
/// `deferred`), the per track start offsets `request_start_rune_offset`
/// and `response_start_rune_offset`, and the task name arrays
/// `request_tasks` and `response_tasks`. An absent field takes its
/// default; an empty task array means that track is unmediated.
///
/// Returns NULL and sets `*err_out` on failure. Free with
/// `acs_stream_session_free`.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated string. `err_out` must
/// be null or point to a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_new(
    config_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut AcsStreamSession {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(raw) = read_utf8(config_json, "config_json", err_out) else {
            return std::ptr::null_mut();
        };
        let parsed: Value = match serde_json::from_str(raw) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => {
                set_err(err_out, "config_json must be a JSON object".to_string());
                return std::ptr::null_mut();
            }
            Err(e) => {
                set_err(err_out, format!("config_json does not parse: {e}"));
                return std::ptr::null_mut();
            }
        };
        let level_raw = parsed
            .get("safety_level")
            .and_then(Value::as_str)
            .unwrap_or("blocking");
        let safety_level = match SafetyLevel::parse(level_raw) {
            Ok(l) => l,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return std::ptr::null_mut();
            }
        };
        let offset = |key: &str| -> Result<u32, String> {
            match parsed.get(key) {
                None | Some(Value::Null) => Ok(0),
                Some(v) => v
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| format!("{key} must be a rune offset within u32")),
            }
        };
        let request_start_rune_offset = match offset("request_start_rune_offset") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, e);
                return std::ptr::null_mut();
            }
        };
        let response_start_rune_offset = match offset("response_start_rune_offset") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, e);
                return std::ptr::null_mut();
            }
        };
        let tasks = |key: &str| -> Result<Vec<String>, String> {
            match parsed.get(key) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| format!("{key} must contain only task name strings"))
                    })
                    .collect(),
                Some(_) => Err(format!("{key} must be an array of task names")),
            }
        };
        let request_tasks = match tasks("request_tasks") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, e);
                return std::ptr::null_mut();
            }
        };
        let response_tasks = match tasks("response_tasks") {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, e);
                return std::ptr::null_mut();
            }
        };
        let config = StreamSessionConfig {
            safety_level,
            request_start_rune_offset,
            response_start_rune_offset,
            request_tasks,
            response_tasks,
        };
        match StreamSession::new(config) {
            Ok(session) => Box::into_raw(Box::new(AcsStreamSession { session })),
            Err(e) => {
                set_err(err_out, format!("{e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_stream_session_new".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Free a session handle. Freeing NULL is a no-op.
///
/// # Safety
/// `handle` must come from `acs_stream_session_new` and be freed once.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_free(handle: *mut AcsStreamSession) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(handle))));
}

/// Record that `runes` more runes of `source_type` arrived. Returns the
/// track's received offset, or -2 on failure.
///
/// # Safety
/// `handle` must be live; `source_type` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_observe(
    handle: *mut AcsStreamSession,
    source_type: *const c_char,
    runes: u32,
    err_out: *mut *mut c_char,
) -> i64 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -2;
        }
        let Some(raw) = read_utf8(source_type, "source_type", err_out) else {
            return -2;
        };
        let source = match StreamSourceType::parse(raw) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -2;
            }
        };
        match (*handle).session.observe(source, runes) {
            Ok(received) => i64::from(received),
            Err(e) => {
                set_err(err_out, format!("{e}"));
                -2
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_observe".to_string(),
        );
        -2
    })
}

/// Record an arriving payload by its text, counting runes the way the
/// engine does so a host never has to count them itself. Returns the
/// track's received offset, or -2 on failure.
///
/// # Safety
/// `handle` must be live; `source_type` and `text` valid NUL-terminated
/// strings.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_observe_text(
    handle: *mut AcsStreamSession,
    source_type: *const c_char,
    text: *const c_char,
    err_out: *mut *mut c_char,
) -> i64 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -2;
        }
        let Some(raw) = read_utf8(source_type, "source_type", err_out) else {
            return -2;
        };
        let source = match StreamSourceType::parse(raw) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -2;
            }
        };
        let Some(body) = read_utf8(text, "text", err_out) else {
            return -2;
        };
        match (*handle).session.observe_text(source, body) {
            Ok(received) => i64::from(received),
            Err(e) => {
                set_err(err_out, format!("{e}"));
                -2
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_observe_text".to_string(),
        );
        -2
    })
}

/// Record what `task` decided about the span `[start, end)` of
/// `source_type`. `outcome` is `cleared`, `transformed` or `denied`.
/// Returns 0, or -1 on failure.
///
/// # Safety
/// `handle` must be live; `task`, `source_type` and `outcome` valid
/// NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_record_outcome(
    handle: *mut AcsStreamSession,
    task: *const c_char,
    source_type: *const c_char,
    start: u32,
    end: u32,
    outcome: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -1;
        }
        let Some(task_name) = read_utf8(task, "task", err_out) else {
            return -1;
        };
        let Some(source_raw) = read_utf8(source_type, "source_type", err_out) else {
            return -1;
        };
        let source = match StreamSourceType::parse(source_raw) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -1;
            }
        };
        let Some(outcome_raw) = read_utf8(outcome, "outcome", err_out) else {
            return -1;
        };
        let Some(outcome) = parse_outcome(outcome_raw, err_out) else {
            return -1;
        };
        let span = match StreamSpan::new(source, start, end) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -1;
            }
        };
        match (*handle).session.record_outcome(task_name, &span, outcome) {
            Ok(()) => 0,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_record_outcome".to_string(),
        );
        -1
    })
}

/// Record an Agent Control Specification verdict against the span
/// `[start, end)` of `source_type`, mapping its decision onto an
/// outcome. `verdict_json` is a verdict as `acs_policy_evaluate`
/// returns one, so a host feeds a decision straight back without
/// translating it. Returns 0, or -1 on failure.
///
/// # Safety
/// `handle` must be live; `task`, `source_type` and `verdict_json`
/// valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_record_verdict(
    handle: *mut AcsStreamSession,
    task: *const c_char,
    source_type: *const c_char,
    start: u32,
    end: u32,
    verdict_json: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -1;
        }
        let Some(task_name) = read_utf8(task, "task", err_out) else {
            return -1;
        };
        let Some(source_raw) = read_utf8(source_type, "source_type", err_out) else {
            return -1;
        };
        let source = match StreamSourceType::parse(source_raw) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -1;
            }
        };
        let Some(raw) = read_utf8(verdict_json, "verdict_json", err_out) else {
            return -1;
        };
        let verdict: Verdict = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                set_err(err_out, format!("verdict_json does not parse: {e}"));
                return -1;
            }
        };
        let span = match StreamSpan::new(source, start, end) {
            Ok(s) => s,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                return -1;
            }
        };
        match (*handle).session.record_verdict(task_name, &span, &verdict) {
            Ok(()) => 0,
            Err(e) => {
                set_err(err_out, format!("{e}"));
                -1
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_record_verdict".to_string(),
        );
        -1
    })
}

/// Recompute `track`'s watermark and return the offset it advanced to,
/// -1 when it did not advance or the session has ended, -2 on failure.
///
/// # Safety
/// `handle` must be live; `track` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_advance(
    handle: *mut AcsStreamSession,
    track: *const c_char,
    err_out: *mut *mut c_char,
) -> i64 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -2;
        }
        let Some(raw) = read_utf8(track, "track", err_out) else {
            return -2;
        };
        let Some(track) = parse_track(raw, err_out) else {
            return -2;
        };
        match (*handle).session.advance(track) {
            Some(offset) => i64::from(offset),
            None => -1,
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_advance".to_string(),
        );
        -2
    })
}

/// The offset of `track` safe to release, -1 once the session has ended,
/// -2 on failure. A settled session has no safe offset, which is not an
/// error: it means release nothing further.
///
/// # Safety
/// `handle` must be live; `track` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_safe_offset(
    handle: *const AcsStreamSession,
    track: *const c_char,
    err_out: *mut *mut c_char,
) -> i64 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -2;
        }
        let Some(raw) = read_utf8(track, "track", err_out) else {
            return -2;
        };
        let Some(track) = parse_track(raw, err_out) else {
            return -2;
        };
        match (*handle).session.safe_offset(track) {
            Some(offset) => i64::from(offset),
            None => -1,
        }
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_safe_offset".to_string(),
        );
        -2
    })
}

/// The rune count of `track` observed but not yet released, or -2 on
/// failure.
///
/// # Safety
/// `handle` must be live; `track` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_pending(
    handle: *const AcsStreamSession,
    track: *const c_char,
    err_out: *mut *mut c_char,
) -> i64 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -2;
        }
        let Some(raw) = read_utf8(track, "track", err_out) else {
            return -2;
        };
        let Some(track) = parse_track(raw, err_out) else {
            return -2;
        };
        i64::from((*handle).session.pending(track))
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_pending".to_string(),
        );
        -2
    })
}

/// `track`'s watermark as JSON, carrying `track`, `confirmed`,
/// `received`, `pending` and the `tasks` that must clear it. The
/// confirmed offset stays readable after settlement, so an audit record
/// can still say how far the stream got. Freed with `acs_free_string`.
///
/// # Safety
/// `handle` must be live; `track` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_watermark(
    handle: *const AcsStreamSession,
    track: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let Some(raw) = read_utf8(track, "track", err_out) else {
            return std::ptr::null_mut();
        };
        let Some(track) = parse_track(raw, err_out) else {
            return std::ptr::null_mut();
        };
        let watermark = (*handle).session.watermark(track);
        let payload = serde_json::json!({
            "track": track.as_str(),
            "confirmed": watermark.confirmed(),
            "received": watermark.received(),
            "pending": watermark.pending(),
            "tasks": watermark.tasks().collect::<Vec<_>>(),
        });
        match serde_json::to_string(&payload) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("watermark serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_stream_session_watermark".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Session state as JSON: `is_ended`, `transformed`, `end_reason` and
/// the effective `config`. `end_reason` is null while the session is
/// live. Freed with `acs_free_string`.
///
/// # Safety
/// `handle` must be a live pointer from `acs_stream_session_new`.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_state(
    handle: *const AcsStreamSession,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let session = &(*handle).session;
        let config = session.config();
        let payload = serde_json::json!({
            "is_ended": session.is_ended(),
            "transformed": session.transformed(),
            "end_reason": session.end_reason().map(end_reason_json),
            "config": {
                "safety_level": config.safety_level.as_str(),
                "request_start_rune_offset": config.request_start_rune_offset,
                "response_start_rune_offset": config.response_start_rune_offset,
                "request_tasks": config.request_tasks,
                "response_tasks": config.response_tasks,
            },
        });
        match serde_json::to_string(&payload) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("state serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_stream_session_state".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

/// Declare that no further payload will arrive. Returns 0, or -1 on
/// failure.
///
/// # Safety
/// `handle` must be a live pointer from `acs_stream_session_new`.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_end_of_payloads(
    handle: *mut AcsStreamSession,
    err_out: *mut *mut c_char,
) -> i32 {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return -1;
        }
        (*handle).session.end_of_payloads();
        0
    }));
    result.unwrap_or_else(|_| {
        set_err(
            err_out,
            "internal panic in acs_stream_session_end_of_payloads".to_string(),
        );
        -1
    })
}

/// Settle the session and return the completion as JSON, carrying
/// `reason`, `transformed` and `is_clean`. Freed with
/// `acs_free_string`. Settling twice returns the same completion.
///
/// # Safety
/// `handle` must be a live pointer from `acs_stream_session_new`.
#[no_mangle]
pub unsafe extern "C" fn acs_stream_session_finish(
    handle: *mut AcsStreamSession,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    clear_err(err_out);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_err(err_out, "handle must not be null".to_string());
            return std::ptr::null_mut();
        }
        let completion = (*handle).session.finish();
        let payload = serde_json::json!({
            "reason": end_reason_json(&completion.reason),
            "transformed": completion.transformed,
            "is_clean": completion.reason.is_clean(),
        });
        match serde_json::to_string(&payload) {
            Ok(json) => to_c_string(json, err_out),
            Err(e) => {
                set_err(err_out, format!("completion serialization failed: {e}"));
                std::ptr::null_mut()
            }
        }
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err(
                err_out,
                "internal panic in acs_stream_session_finish".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;

    fn manifest_file(dir: &std::path::Path) -> CString {
        let path = dir.join("manifest.yaml");
        let mut f = std::fs::File::create(&path).expect("create manifest");
        f.write_all(
            br#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: ffi-test
policies:
  allow_all:
    type: test
    verdict:
      decision: allow
  block:
    type: test
    verdict:
      decision: deny
      reason: blocked_by_test
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy:
      id: block
  input:
    policy_target: "$.input"
    policy:
      id: allow_all
"#,
        )
        .expect("write manifest");
        CString::new(path.to_str().expect("utf8 path")).expect("no NUL")
    }

    fn intercept(handle: *const AcsInterceptor, ctx: &str) -> Value {
        let ctx = CString::new(ctx).unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let out = unsafe { acs_intercept(handle, ctx.as_ptr(), &mut err) };
        assert!(err.is_null(), "unexpected boundary error");
        let verdict: Value =
            serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        unsafe { acs_free_string(out) };
        verdict
    }

    fn valid_manifest_source() -> String {
        concat!(
            "agent_control_specification_version: \"0.4.0-alpha.1\"\n",
            "policies:\n  p:\n    type: test\n    verdict:\n      decision: allow\n",
            "intervention_points:\n  input:\n    policy_target: \"$.input\"\n",
            "    policy:\n      id: p\n"
        )
        .to_string()
    }

    fn validate(bytes: &[u8]) -> (i32, Option<String>) {
        let mut err: *mut c_char = std::ptr::null_mut();
        let code = unsafe { acs_validate_manifest(bytes.as_ptr(), bytes.len(), &mut err) };
        let message = if err.is_null() {
            None
        } else {
            let m = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
            unsafe { acs_free_string(err) };
            Some(m)
        };
        (code, message)
    }

    #[test]
    fn validate_reports_a_valid_manifest_with_no_error() {
        let (code, message) = validate(valid_manifest_source().as_bytes());
        assert_eq!(code, ACS_MANIFEST_VALID);
        assert!(message.is_none(), "success must leave err_out null");
    }

    #[test]
    fn validate_separates_a_bad_manifest_from_a_failed_call() {
        // Both set err_out, so the return code is the only thing telling
        // a caller whether the manifest was actually judged.
        let rejected = valid_manifest_source().replace("0.4.0-alpha.1", "0.3.1-beta");
        let (code, message) = validate(rejected.as_bytes());
        assert_eq!(code, ACS_MANIFEST_INVALID);
        assert!(message.unwrap().contains("0.3.1-beta"));

        let (code, message) = validate(&[0xff, 0xfe]);
        assert_eq!(
            code, ACS_MANIFEST_CALL_FAILED,
            "a non-UTF-8 buffer is a boundary failure, not a bad manifest"
        );
        assert!(message.unwrap().contains("UTF-8"));
    }

    #[test]
    fn validate_rejects_a_null_source_as_a_failed_call() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let code = unsafe { acs_validate_manifest(std::ptr::null(), 7, &mut err) };
        assert_eq!(code, ACS_MANIFEST_CALL_FAILED);
        assert!(!err.is_null());
        unsafe { acs_free_string(err) };
    }

    #[test]
    fn validate_does_not_truncate_at_an_interior_nul() {
        // A NUL-terminated parameter would validate only the prefix and
        // accept this document, a fail-open in a fail-closed surface.
        let mut source = valid_manifest_source().into_bytes();
        source.push(0);
        source.extend_from_slice(b"garbage: [");
        let (code, _) = validate(&source);
        assert_eq!(
            code, ACS_MANIFEST_INVALID,
            "everything after an interior NUL must still be read"
        );
    }

    #[test]
    fn any_non_zero_code_means_the_action_must_not_proceed() {
        // The C idiom `if (acs_validate_manifest(...))` must fail closed,
        // so zero has to be the only accepting value.
        assert_eq!(ACS_MANIFEST_VALID, 0);
        assert_ne!(ACS_MANIFEST_INVALID, 0);
        assert_ne!(ACS_MANIFEST_CALL_FAILED, 0);
    }

    #[test]
    fn interceptor_new_ex_rejects_a_path_with_an_interior_nul() {
        // The NUL-terminated constructor would load the prefix, which is
        // a different manifest than the caller named.
        let mut err: *mut c_char = std::ptr::null_mut();
        let probe = b"examples/coding_agent/manifest.yaml\0/not/this/path.yaml";
        let handle = unsafe { acs_interceptor_new_ex(probe.as_ptr(), probe.len(), &mut err) };
        assert!(handle.is_null());
        assert!(!err.is_null());
        unsafe { acs_free_string(err) };
    }

    #[test]
    fn validate_file_treats_a_breached_limit_as_a_failed_call() {
        // A depth breach is not a grammar rejection, and the default
        // arm must not label it as one. Guards the whole class,
        // including variants added later.
        let dir = std::env::temp_dir().join(format!("acs-depth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let depth = 20;
        for i in 0..depth {
            let body = if i == depth - 1 {
                concat!(
                    "agent_control_specification_version: \"0.4.0-alpha.1\"\n",
                    "policies:\n  p:\n    type: test\n    verdict:\n      decision: allow\n",
                    "intervention_points:\n  input:\n    policy_target: \"$.input\"\n",
                    "    policy:\n      id: p\n"
                )
                .to_string()
            } else {
                format!("agent_control_specification_version: \"0.4.0-alpha.1\"\nextends:\n  - ./m{}.yaml\n", i + 1)
            };
            std::fs::write(dir.join(format!("m{i}.yaml")), body).unwrap();
        }
        let path = dir.join("m0.yaml");
        let path = path.to_str().unwrap().as_bytes();
        let mut err: *mut c_char = std::ptr::null_mut();
        let code = unsafe { acs_validate_manifest_file(path.as_ptr(), path.len(), &mut err) };
        let message = if err.is_null() {
            String::new()
        } else {
            let m = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
            unsafe { acs_free_string(err) };
            m
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(code, ACS_MANIFEST_CALL_FAILED, "message was: {message}");
        assert!(message.contains("depth"), "message was: {message}");
    }

    #[test]
    fn validate_file_rejects_a_path_with_an_interior_nul() {
        // A truncated path names a different file, so answering about it
        // would answer a question the caller did not ask.
        let mut err: *mut c_char = std::ptr::null_mut();
        let probe = b"examples/coding_agent/manifest.yaml\0/not/this/path.yaml";
        let code = unsafe { acs_validate_manifest_file(probe.as_ptr(), probe.len(), &mut err) };
        assert_eq!(code, ACS_MANIFEST_CALL_FAILED);
        assert!(!err.is_null());
        unsafe { acs_free_string(err) };
    }

    #[test]
    fn validate_file_separates_an_unreadable_path_from_a_bad_manifest() {
        // `acs_interceptor_new` already treats a missing file as a
        // boundary failure; the file validator must agree with it.
        let mut err: *mut c_char = std::ptr::null_mut();
        let path = b"/nonexistent/typo.yaml";
        let code = unsafe { acs_validate_manifest_file(path.as_ptr(), path.len(), &mut err) };
        assert_eq!(code, ACS_MANIFEST_CALL_FAILED);
        assert!(!err.is_null());
        unsafe { acs_free_string(err) };
    }

    #[test]
    fn validate_treats_empty_source_as_a_rejected_manifest() {
        let (code, message) = validate(&[]);
        assert_eq!(code, ACS_MANIFEST_INVALID);
        assert!(message.is_some());
    }

    #[test]
    fn supported_versions_round_trips_as_json_and_frees_cleanly() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let out = unsafe { acs_supported_manifest_versions(&mut err) };
        assert!(err.is_null());
        assert!(!out.is_null());
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
        unsafe { acs_free_string(out) };
        let versions: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(versions, agent_control_spec::SUPPORTED_VERSIONS.to_vec());
    }

    #[test]
    fn end_to_end_allow_deny_and_fail_closed() {
        let dir = std::env::temp_dir().join(format!("acs-ffi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = manifest_file(&dir);
        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe { acs_interceptor_new(manifest.as_ptr(), &mut err) };
        if !err.is_null() {
            let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
            unsafe { acs_free_string(err) };
            panic!("constructor failed: {msg}");
        }
        assert!(!handle.is_null(), "constructor returned no handle");

        let allow = intercept(
            handle,
            r#"{"interception_point":"input","input":{"content":"hi","role":"user"}}"#,
        );
        assert_eq!(allow["decision"], "allow");

        let deny = intercept(
            handle,
            r#"{"interception_point":"pre_tool_call","tool_call":{"id":"t1","name":"x","args":{"a":1}}}"#,
        );
        assert_eq!(deny["decision"], "deny");
        assert_eq!(deny["reason"], "blocked_by_test");

        // Unknown interception point fails closed as a verdict, not an
        // FFI error.
        let closed = intercept(handle, r#"{"interception_point":"nope"}"#);
        assert_eq!(closed["decision"], "deny");
        assert!(closed["reason"]
            .as_str()
            .unwrap()
            .starts_with("runtime_error:"));

        unsafe { acs_interceptor_free(handle) };
    }

    #[test]
    fn boundary_errors_are_explicit() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let bad = CString::new("/nonexistent/manifest.yaml").unwrap();
        let handle = unsafe { acs_interceptor_new(bad.as_ptr(), &mut err) };
        assert!(handle.is_null() && !err.is_null());
        unsafe { acs_free_string(err) };

        let out = unsafe { acs_intercept(std::ptr::null(), std::ptr::null(), &mut err) };
        assert!(out.is_null() && !err.is_null());
        unsafe { acs_free_string(err) };
    }

    /// The manifest and its Rego cross this boundary as text, so a host
    /// keeping both in a database needs no temporary directory.
    #[test]
    fn policy_activates_from_memory() {
        let manifest = CString::new(
            r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: ffi-in-memory
policies:
  gate:
    type: rego
    query: data.gate.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"#,
        )
        .unwrap();
        let bundles = CString::new(
            r#"{"gate": {"modules": {"gate.rego": "package gate\n\nverdict := {\"decision\": \"allow\", \"reason\": \"from-memory\"}\n"}}}"#,
        )
        .unwrap();

        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe {
            acs_policy_activate_from_memory(manifest.as_ptr(), bundles.as_ptr(), &mut err)
        };
        assert!(
            err.is_null(),
            "{}",
            unsafe { CStr::from_ptr(err) }.to_string_lossy()
        );
        assert!(!handle.is_null());

        let point = CString::new("input").unwrap();
        let context = CString::new(r#"{"input": {"text": "hello"}}"#).unwrap();
        let out =
            unsafe { acs_policy_evaluate(handle, point.as_ptr(), context.as_ptr(), &mut err) };
        assert!(err.is_null());
        let verdict: Value =
            serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        unsafe { acs_free_string(out) };
        unsafe { acs_policy_free(handle) };

        assert_eq!(verdict["decision"], "allow");
        assert_eq!(verdict["reason"], "from-memory");
    }

    /// A relative bundle or data path has no manifest directory to resolve
    /// against here, so it must be refused rather than read from
    /// wherever the process happens to be running.
    #[test]
    fn activating_from_memory_refuses_a_relative_bundle_path() {
        let manifest = CString::new(
            r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: ffi-in-memory-relative
policies:
  gate:
    type: rego
    bundle: ./policy
    query: data.gate.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"#,
        )
        .unwrap();

        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe {
            acs_policy_activate_from_memory(manifest.as_ptr(), std::ptr::null(), &mut err)
        };

        assert!(handle.is_null());
        assert!(!err.is_null());
        let message = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe { acs_free_string(err) };
        assert!(
            message.contains("relative bundle or data path"),
            "{message}"
        );
    }

    /// Malformed JSON is a boundary error, not a policy that quietly
    /// activates without the modules the host meant to supply.
    #[test]
    fn activating_from_memory_rejects_malformed_bundles_json() {
        let manifest =
            CString::new("agent_control_specification_version: \"0.4.0-alpha.1\"\n").unwrap();
        let bundles = CString::new("{not json").unwrap();

        let mut err: *mut c_char = std::ptr::null_mut();
        let handle = unsafe {
            acs_policy_activate_from_memory(manifest.as_ptr(), bundles.as_ptr(), &mut err)
        };

        assert!(handle.is_null());
        assert!(!err.is_null());
        let message = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe { acs_free_string(err) };
        assert!(message.contains("bundles_json is not valid"), "{message}");
    }
}
