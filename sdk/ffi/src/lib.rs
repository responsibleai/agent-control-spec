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
use agent_control_spec::{Manifest, Runtime, RuntimeError, SUPPORTED_VERSIONS};
use serde_json::Value;
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
/// dispatchers (bundled annotators; Rego through OPA, Cedar through the
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
}
