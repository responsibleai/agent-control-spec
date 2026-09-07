//! Legacy Rego policy dispatcher that shells out to the `opa` CLI.
//!
//! Gated behind the opt-in `opa` feature. The bundled default is
//! [`crate::rego`], which evaluates Rego in process and so costs no
//! process spawn per decision. This dispatcher stays available for two
//! cases: a host that needs OPA's exact CLI semantics, most visibly the
//! packaged `.tar.gz` bundles the in-process dispatcher does not read,
//! and a host that must pin evaluation to a specific `opa` build.

use crate::{
    policy::rego_adapter_data_paths, runtime::PolicyDispatcher, JsonValue, Limits,
    PreparedPolicyInvocation, RegoPolicyInvocation, RuntimeError,
};
use serde::Deserialize;
use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const OPA_PATH_ENV: &str = "ACS_OPA_PATH";
pub const OPA_TIMEOUT_ENV: &str = "ACS_OPA_TIMEOUT_MS";
const DEFAULT_OPA_TIMEOUT: Duration = Duration::from_secs(5);
const ERROR_OUTPUT_LIMIT: usize = 4096;
const BUNDLE_CLEANUP_ATTEMPTS: usize = 3;
const BUNDLE_CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaRegoRunner {
    executable: PathBuf,
    data_paths: Vec<PathBuf>,
    eval_timeout: Duration,
    limits: Limits,
}

impl OpaRegoRunner {
    pub fn new() -> Self {
        Self {
            executable: PathBuf::from("opa"),
            data_paths: Vec::new(),
            eval_timeout: DEFAULT_OPA_TIMEOUT,
            limits: Limits::default(),
        }
    }

    pub fn from_environment() -> Self {
        let mut runner = match env::var_os(OPA_PATH_ENV) {
            Some(value) if !value.is_empty() => {
                Self::new().with_executable(Self::resolve_opa_executable_hint(PathBuf::from(value)))
            }
            _ => Self::new(),
        };
        if let Some(timeout) = eval_timeout_from_environment() {
            runner = runner.with_eval_timeout(timeout);
        }
        runner
    }

    pub fn with_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.executable = executable.into();
        self
    }

    pub fn with_eval_timeout(mut self, timeout: Duration) -> Self {
        self.eval_timeout = timeout;
        self
    }

    /// Sets the existing manifest URL budgets for pinned remote bundle fetches.
    /// This does not change the OPA subprocess evaluation timeout.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn eval_timeout(&self) -> Duration {
        self.eval_timeout
    }

    fn resolve_opa_executable_hint(hint: PathBuf) -> PathBuf {
        if hint.is_dir() {
            hint.join(Self::opa_binary_name())
        } else {
            hint
        }
    }

    #[cfg(windows)]
    fn opa_binary_name() -> &'static str {
        "opa.exe"
    }

    #[cfg(not(windows))]
    fn opa_binary_name() -> &'static str {
        "opa"
    }

    pub fn with_data_path(mut self, data_path: impl Into<PathBuf>) -> Self {
        self.data_paths.push(data_path.into());
        self
    }

    pub fn with_data_paths<I, P>(mut self, data_paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.data_paths
            .extend(data_paths.into_iter().map(Into::into));
        self
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn data_paths(&self) -> &[PathBuf] {
        &self.data_paths
    }

    pub fn is_available(&self) -> bool {
        Command::new(&self.executable)
            .arg("version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    pub fn evaluate(&self, invocation: &RegoPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        reject_in_memory_bundle(invocation)?;
        let output = self.run_opa_eval(invocation)?;
        if !output.status.success() {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "opa eval failed with {}: {}",
                output.status,
                process_error_output(&output)
            )));
        }
        parse_opa_eval_output(&output.stdout)
    }

    fn run_opa_eval(&self, invocation: &RegoPolicyInvocation) -> Result<Output, RuntimeError> {
        let adapter_data_paths = rego_adapter_data_paths(&invocation.adapter_config)?;
        let mut remote_bundle = invocation
            .bundle_url()?
            .map(|source| {
                let bytes = crate::manifest::fetch_pinned_https_bytes(&source, self.limits)
                    .map_err(|err| {
                        RuntimeError::PolicyInvocationFailed(err.detail().to_string())
                    })?;
                StagedBundle::new(&bytes)
            })
            .transpose()?;
        let mut command = Command::new(&self.executable);
        command
            .arg("eval")
            .arg("--format")
            .arg("json")
            .arg("--stdin-input");

        if let Some(bundle) = &invocation.bundle {
            command.arg("--bundle").arg(opa_command_path_arg(bundle));
        }
        if let Some(bundle) = &remote_bundle {
            command
                .arg("--bundle")
                .arg(opa_command_path_arg(bundle.path()));
        }
        for data_path in &self.data_paths {
            command.arg("--data").arg(opa_command_path_arg(data_path));
        }
        for data_path in adapter_data_paths {
            command.arg("--data").arg(opa_command_path_arg(&data_path));
        }
        command
            .arg(&invocation.query)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| opa_spawn_error(&self.executable, err))?;

        match child.stdin.take() {
            Some(mut stdin) => stdin
                .write_all(invocation.canonical_input.as_bytes())
                .map_err(|err| {
                    let _ = child.wait();
                    RuntimeError::PolicyInvocationFailed(format!(
                        "failed to write OPA stdin input: {err}"
                    ))
                })?,
            None => {
                let _ = child.wait();
                return Err(RuntimeError::PolicyInvocationFailed(
                    "failed to open OPA stdin input pipe".to_string(),
                ));
            }
        }

        let result = wait_with_timeout(child, self.eval_timeout).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!("failed to read OPA output: {err}"))
        });
        if let Some(bundle) = remote_bundle.as_mut() {
            bundle.cleanup();
        }
        result
    }
}

/// OPA needs a filename. Own a unique directory under the OS temporary root
/// until the subprocess exits. Cleanup is bounded and best-effort; Drop covers
/// early returns without changing the policy result.
struct StagedBundle {
    directory: PathBuf,
    cleanup_attempted: bool,
}

impl StagedBundle {
    fn new(bytes: &[u8]) -> Result<Self, RuntimeError> {
        let stage = || -> io::Result<Self> {
            let mut builder = tempfile::Builder::new();
            builder.prefix("acs-opa-bundle-");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(fs::Permissions::from_mode(0o700));
            }
            let directory = builder.tempdir()?.keep();
            let bundle = Self {
                directory,
                cleanup_attempted: false,
            };
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(bundle.path())?;
            file.write_all(bytes)?;
            Ok(bundle)
        };
        stage().map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "failed to stage pinned OPA bundle in the temporary directory: {err}"
            ))
        })
    }

    fn path(&self) -> PathBuf {
        self.directory.join("bundle.tar.gz")
    }

    fn cleanup(&mut self) {
        if self.cleanup_attempted {
            return;
        }
        self.cleanup_attempted = true;
        cleanup_bundle_directory(
            &self.directory,
            |path| fs::remove_dir_all(path),
            thread::sleep,
            &mut io::stderr().lock(),
        );
    }
}

impl Drop for StagedBundle {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn cleanup_bundle_directory(
    directory: &Path,
    mut remove: impl FnMut(&Path) -> io::Result<()>,
    mut wait: impl FnMut(Duration),
    diagnostics: &mut impl Write,
) {
    for attempt in 1..=BUNDLE_CLEANUP_ATTEMPTS {
        match remove(directory) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) if attempt == BUNDLE_CLEANUP_ATTEMPTS => {
                // A failed diagnostic write must not replace the policy result either.
                let _ = writeln!(
                    diagnostics,
                    "ACS warning: failed to remove staged OPA bundle directory '{}' after \
                     {attempt} attempts: {error}. The policy result is unchanged; \
                     the host must reclaim this directory when it is no longer in use.",
                    directory.display(),
                );
            }
            Err(_) => wait(BUNDLE_CLEANUP_RETRY_DELAY),
        }
    }
}

fn eval_timeout_from_environment() -> Option<Duration> {
    let value = env::var(OPA_TIMEOUT_ENV).ok()?;
    let millis = value.parse::<u64>().ok()?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> io::Result<Output> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to open OPA stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to open OPA stderr pipe"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });

    let status = wait_for_exit_or_timeout(&mut child, timeout)?;
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_exit_or_timeout(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("OPA eval exceeded timeout of {} ms", timeout.as_millis()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn join_reader(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other("OPA output reader thread panicked"))?
}

/// Refuses an in-memory bundle rather than evaluating without it.
///
/// `opa eval` takes policy as paths, so this dispatcher has nothing to
/// pass the modules to. Ignoring them would evaluate whatever the
/// manifest's `bundle` still pointed at, or nothing at all, and either
/// way would return a verdict for a policy the host did not supply.
fn reject_in_memory_bundle(invocation: &RegoPolicyInvocation) -> Result<(), RuntimeError> {
    invocation.bundle_url()?;
    if invocation.inline_bundle.is_some() {
        return Err(RuntimeError::PolicyInvocationFailed(
            "this policy supplies Rego modules in memory, which the `opa` CLI dispatcher cannot \
             evaluate because it passes policy to a subprocess as paths. Use the in-process Rego \
             dispatcher, or stage the modules to a directory and point `bundle` at it"
                .to_string(),
        ));
    }
    Ok(())
}

fn opa_command_path_arg(path: impl AsRef<Path>) -> OsString {
    strip_windows_verbatim_prefix(path.as_ref())
}

fn strip_windows_verbatim_prefix(path: &Path) -> OsString {
    let value = path.to_string_lossy();
    if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
        OsString::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = value.strip_prefix(r"\\?\") {
        OsString::from(stripped)
    } else {
        path.as_os_str().to_os_string()
    }
}

impl Default for OpaRegoRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpaPolicyDispatcher {
    runner: OpaRegoRunner,
}

impl OpaPolicyDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runner(runner: OpaRegoRunner) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &OpaRegoRunner {
        &self.runner
    }
}

impl PolicyDispatcher for OpaPolicyDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Rego(invocation) => self.runner.evaluate(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "OPA policy dispatcher only supports Rego invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OpaEvalResponse {
    #[serde(default)]
    result: Vec<OpaEvalResult>,
    #[serde(default)]
    errors: Vec<OpaEvalError>,
}

#[derive(Debug, Deserialize)]
struct OpaEvalResult {
    #[serde(default)]
    expressions: Vec<OpaEvalExpression>,
}

#[derive(Debug, Deserialize)]
struct OpaEvalExpression {
    value: JsonValue,
}

#[derive(Debug, Deserialize)]
struct OpaEvalError {
    code: Option<String>,
    message: String,
}

fn opa_spawn_error(executable: &Path, err: io::Error) -> RuntimeError {
    if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(2) {
        let message = match env::var_os(OPA_PATH_ENV) {
            Some(value) if !value.is_empty() => format!(
                "default policy dispatcher could not execute OPA from ${OPA_PATH_ENV}: '{}'; explicit OPA paths do not fall back to PATH",
                executable.display()
            ),
            _ => format!(
                "OPA executable '{}' was not found; install OPA or configure OpaRegoRunner::with_executable(...)",
                executable.display()
            ),
        };
        RuntimeError::PolicyInvocationFailed(message)
    } else {
        RuntimeError::PolicyInvocationFailed(format!(
            "failed to start OPA executable '{}': {err}",
            executable.display()
        ))
    }
}

fn parse_opa_eval_output(stdout: &[u8]) -> Result<JsonValue, RuntimeError> {
    let response: OpaEvalResponse = serde_json::from_slice(stdout).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!("failed to parse OPA JSON output: {err}"))
    })?;

    if !response.errors.is_empty() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "OPA returned errors: {}",
            format_opa_errors(&response.errors)
        )));
    }

    let result = match response.result.as_slice() {
        [] => {
            return Err(RuntimeError::PolicyInvocationFailed(
                "OPA query returned no result".to_string(),
            ))
        }
        [result] => result,
        _ => {
            return Err(RuntimeError::PolicyInvocationFailed(
                "OPA query returned multiple results; policy query must resolve to one verdict"
                    .to_string(),
            ))
        }
    };

    match result.expressions.as_slice() {
        [expression] => Ok(expression.value.clone()),
        [] => Err(RuntimeError::PolicyInvocationFailed(
            "OPA query returned a result with no expression value".to_string(),
        )),
        _ => Err(RuntimeError::PolicyInvocationFailed(
            "OPA query returned multiple expression values; policy query must resolve to one verdict"
                .to_string(),
        )),
    }
}

fn format_opa_errors(errors: &[OpaEvalError]) -> String {
    errors
        .iter()
        .map(|error| match &error.code {
            Some(code) => format!("{code}: {}", error.message),
            None => error.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn process_error_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    };
    if detail.is_empty() {
        "OPA produced no error output".to_string()
    } else {
        truncate(&detail)
    }
}

fn truncate(value: &str) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(ERROR_OUTPUT_LIMIT).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_bundle_directory, opa_command_path_arg, OpaRegoRunner, StagedBundle,
        BUNDLE_CLEANUP_ATTEMPTS, BUNDLE_CLEANUP_RETRY_DELAY,
    };
    use crate::artifact_tests::{rego, source, with_test_ca, Response, Server};
    use base64::Engine;
    use std::{io, path::Path};

    fn archive() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(
            "H4sIAAAAAAACCu3SsQrDIBSFYWefQnyA4qAJBPowYkQkoRZj26H03StZCt1bCv2/5VzOcpabfIuHGlMRn2O6wdo9u/c0xo2ve+9HZ51QRnzBZWu+9knxn84+LD5FlfofSHmNdc6hqemo7nqOIW+5nPSktF/XctMPKQAAAAAAAAAAAAAAAAAAv+EJiUDVRQAoAAA="
        ).unwrap()
    }

    #[test]
    fn explicit_default_url_limits_preserve_runner_configuration() {
        assert_eq!(
            OpaRegoRunner::new(),
            OpaRegoRunner::new().with_limits(crate::Limits::default())
        );
    }

    #[test]
    fn staged_bundle_keeps_bytes_until_dropped_and_cleans_up_on_error() {
        let bytes = archive();
        let bundle = StagedBundle::new(&bytes).unwrap();
        let path = bundle.path();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let directory = path.parent().unwrap().to_owned();
        drop(bundle);
        assert!(!directory.exists());

        let mut staged = None;
        let fail = |staged: &mut Option<std::path::PathBuf>| -> Result<(), &'static str> {
            let bundle = StagedBundle::new(b"test").unwrap();
            *staged = Some(bundle.directory.clone());
            Err("simulated subprocess failure")
        };
        assert!(fail(&mut staged).is_err());
        assert!(!staged.unwrap().exists());
    }

    #[test]
    fn staged_bundle_uses_a_unique_temporary_directory() {
        let mut first = StagedBundle::new(b"first").unwrap();
        let second = StagedBundle::new(b"second").unwrap();
        assert_ne!(first.directory, second.directory);
        assert_eq!(
            first.directory.parent().unwrap().canonicalize().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&first.directory)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let path = first.directory.clone();
        first.cleanup();
        assert!(first.cleanup_attempted);
        assert!(!path.exists());
        drop(first);
        assert_eq!(std::fs::read(second.path()).unwrap(), b"second");
    }

    #[test]
    fn bundle_cleanup_retries_transient_errors() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let mut diagnostics = Vec::new();
        cleanup_bundle_directory(
            Path::new("owned-bundle"),
            |_| {
                attempts += 1;
                if attempts < BUNDLE_CLEANUP_ATTEMPTS {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "file locked",
                    ))
                } else {
                    Ok(())
                }
            },
            |delay| delays.push(delay),
            &mut diagnostics,
        );
        assert_eq!(attempts, BUNDLE_CLEANUP_ATTEMPTS);
        assert_eq!(delays, vec![BUNDLE_CLEANUP_RETRY_DELAY; 2]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn bundle_cleanup_reports_exhausted_retries() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let mut diagnostics = Vec::new();
        cleanup_bundle_directory(
            Path::new("owned-bundle"),
            |_| {
                attempts += 1;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file locked",
                ))
            },
            |delay| delays.push(delay),
            &mut diagnostics,
        );
        assert_eq!(attempts, BUNDLE_CLEANUP_ATTEMPTS);
        assert_eq!(delays.len(), BUNDLE_CLEANUP_ATTEMPTS - 1);
        let message = String::from_utf8(diagnostics).unwrap();
        assert!(message.contains("owned-bundle"));
        assert!(message.contains("file locked"));
        assert!(message.contains("policy result is unchanged"));
    }

    #[test]
    fn bundle_cleanup_accepts_an_already_removed_directory() {
        let mut attempts = 0;
        let mut diagnostics = Vec::new();
        cleanup_bundle_directory(
            Path::new("owned-bundle"),
            |_| {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::NotFound))
            },
            |_| panic!("a missing directory needs no retry"),
            &mut diagnostics,
        );
        assert_eq!(attempts, 1);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn pinned_bundle_runs_with_real_opa_when_installed() {
        let runner = OpaRegoRunner::new();
        if !runner.is_available() {
            assert_ne!(
                std::env::var("AGENT_CONTROL_REQUIRE_OPA").as_deref(),
                Ok("1"),
                "AGENT_CONTROL_REQUIRE_OPA=1 but the 'opa' executable is not available on PATH"
            );
            eprintln!("skipping OPA integration; set AGENT_CONTROL_REQUIRE_OPA=1 to require OPA");
            return;
        }
        with_test_ca(|| {
            let bytes = archive();
            let response = bytes.clone();
            let server = Server::https(move |_, _| Response::ok(response.clone()));
            let value = runner
                .evaluate(&rego(&source(server.url.clone(), &bytes)))
                .unwrap();
            assert_eq!(value["decision"], "allow");
        });
    }

    #[cfg(unix)]
    #[test]
    fn pinned_bundle_lives_through_subprocess_and_is_removed_after_success_or_failure() {
        use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
        with_test_ca(|| {
            // This separate guard owns only the fake executable and its observation
            // file, not the runner's downloaded bundle.
            let harness = StagedBundle::new(b"test harness").unwrap();
            let script = harness.directory.join("opa-test");
            let observed = harness.directory.join("observed");
            let bytes = archive();
            let response = bytes.clone();
            let server = Server::https(move |_, _| Response::ok(response.clone()));
            let invocation = rego(&source(server.url.clone(), &bytes));
            for ending in [
                "printf '%s\\n' '{\"result\":[{\"expressions\":[{\"value\":{\"decision\":\"allow\"}}]}]}'",
                "exit 7",
                "printf '%s\\n' 'not json'",
                "exec sleep 2",
            ] {
                let body = format!(
                    "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n\
                     if [ \"$1\" = --bundle ]; then shift; bundle=\"$1\"; fi\n\
                     shift\ndone\ncat >/dev/null\n[ -s \"$bundle\" ] || exit 9\n\
                     printf '%s' \"$bundle\" > \"$(dirname \"$0\")/observed\"\n{ending}\n"
                );
                fs::write(&script, body).unwrap();
                fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
                let runner = OpaRegoRunner::new().with_executable(&script)
                    .with_eval_timeout(Duration::from_millis(250));
                let result = runner.evaluate(&invocation);
                if ending.contains("expressions") {
                    assert_eq!(result.unwrap()["decision"], "allow");
                } else {
                    assert!(result.is_err());
                }
                let downloaded = fs::read_to_string(&observed).unwrap();
                assert!(!Path::new(&downloaded).exists(), "staged archive leaked");
                assert!(!Path::new(&downloaded).parent().unwrap().exists());
                fs::remove_file(&observed).unwrap();
            }
        });
    }

    #[test]
    fn opa_command_path_arg_strips_windows_verbatim_disk_prefix() {
        assert_eq!(
            opa_command_path_arg(Path::new(r"\\?\C:\Temp\acs\policy")).to_string_lossy(),
            r"C:\Temp\acs\policy"
        );
    }

    #[test]
    fn opa_command_path_arg_strips_windows_verbatim_unc_prefix() {
        assert_eq!(
            opa_command_path_arg(Path::new(r"\\?\UNC\server\share\policy")).to_string_lossy(),
            r"\\server\share\policy"
        );
    }
}
