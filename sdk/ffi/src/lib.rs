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
use agent_control_spec::{Manifest, Runtime};
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
