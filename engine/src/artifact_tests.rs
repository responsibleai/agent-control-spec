//! Real loopback HTTPS tests. Only this test thread trusts the fixture CA;
//! certificate/hostname verification and the production HTTP path stay enabled.

use crate::manifest::{fetch_pinned_https_bytes, fetch_pinned_https_text, PinnedHttpsSource};
use crate::{JsonValue, Limits, Manifest, RuntimeError};
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const FETCH_TIMEOUT_MS: u64 = 1_000;

// Public, deterministic TEST-ONLY key (P-256 scalar 123456789), never a credential.
// The CA and localhost certificate are valid from 2020 through 2120.
const ROOT: &str = "MIIBRzCB7qADAgECAgEBMAoGCCqGSM49BAMCMCIxIDAeBgNVBAMMF0FDUyBsb2NhbGhvc3QgVEVTVCBPTkxZMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAiMSAwHgYDVQQDDBdBQ1MgbG9jYWxob3N0IFRFU1QgT05MWTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPtQOI8pSY0Kk60l7Ew0A3udPMPMpHh+tv7aviswA+rIn3dlyp1iiOb/c09c0I86WSHPVLIbs5i1CsDSV3+gdHKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIwO3HEQw1Agsq48fAd92dpT+lWen4M2dD1DILocYdltAiA/bS0kqprB++EYbIfsS6I2jxwKZi37aqCnJouSoX3J1w==";
const LEAF: &str = "MIIBYTCCAQigAwIBAgIBAjAKBggqhkjOPQQDAjAiMSAwHgYDVQQDDBdBQ1MgbG9jYWxob3N0IFRFU1QgT05MWTAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+1A4jylJjQqTrSXsTDQDe508w8ykeH62/tq+KzAD6sifd2XKnWKI5v9zT1zQjzpZIc9UshuzmLUKwNJXf6B0cqM7MDkwDAYDVR0TAQH/BAIwADAUBgNVHREEDTALgglsb2NhbGhvc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgMBLWRg6txz8CryFoV8obeVcA0TmP5ryoPBbclQhk9nsCIE6UwJZOAziIC++oZsssITKXHa89O7gzQzOQCnWisVyd";
const TEST_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdbzRWhRANCAAT7UDiPKUmNCpOtJexMNAN7nTzDzKR4frb+2r4rMAPqyJ93ZcqdYojm/3NPXNCPOlkhz1SyG7OYtQrA0ld/oHRy";

thread_local! {
    static TRUST_TEST_CA: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn trust_test_ca() -> bool {
    TRUST_TEST_CA.with(Cell::get)
}

pub(crate) fn tls_config() -> ureq::tls::TlsConfig {
    let pem = format!("-----BEGIN CERTIFICATE-----\n{ROOT}\n-----END CERTIFICATE-----\n");
    let certificate = ureq::tls::Certificate::from_pem(pem.as_bytes()).unwrap();
    ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::Specific(Arc::new(vec![certificate])))
        .build()
}

pub(crate) fn with_test_ca<T>(test: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            TRUST_TEST_CA.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(TRUST_TEST_CA.with(|cell| cell.replace(true)));
    test()
}

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

pub(crate) struct Response {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    delay: Duration,
    chunked: bool,
}

impl Response {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            location: None,
            body: body.into(),
            delay: Duration::ZERO,
            chunked: false,
        }
    }

    fn redirect(url: String) -> Self {
        Self {
            status: 302,
            location: Some(url),
            ..Self::ok(Vec::new())
        }
    }
}

pub(crate) struct Server {
    pub(crate) url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Server {
    pub(crate) fn https(respond: impl Fn(&str, &str) -> Response + Send + Sync + 'static) -> Self {
        Self::start(true, respond)
    }

    fn start(tls: bool, respond: impl Fn(&str, &str) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "{}://localhost:{}",
            if tls { "https" } else { "http" },
            listener.local_addr().unwrap().port()
        );
        let server_url = url.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(decode(LEAF))],
            rustls::pki_types::PrivatePkcs8KeyDer::from(decode(TEST_KEY)).into(),
        )
        .unwrap();
        let config = Arc::new(config);
        let respond = Arc::new(respond);
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopped.load(Ordering::Relaxed) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(err) => panic!("loopback accept: {err}"),
                };
                // Accepted sockets inherit the listener's nonblocking mode on Windows.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let (config, respond, seen, base) = (
                    config.clone(),
                    respond.clone(),
                    seen.clone(),
                    server_url.clone(),
                );
                workers.push(thread::spawn(move || {
                    if tls {
                        let conn = rustls::ServerConnection::new(config).unwrap();
                        serve(
                            rustls::StreamOwned::new(conn, stream),
                            &base,
                            &*respond,
                            &seen,
                        );
                    } else {
                        serve(stream, &base, &*respond, &seen);
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            url,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn source(&self, path: &str, body: &[u8]) -> PinnedHttpsSource {
        source(format!("{}{path}", self.url), body)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap();
    }
}

fn serve(
    mut stream: impl Read + Write,
    base: &str,
    respond: &impl Fn(&str, &str) -> Response,
    seen: &Mutex<Vec<String>>,
) {
    let mut request = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        request.extend_from_slice(&buffer[..read]);
        if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let length = String::from_utf8_lossy(&request[..end])
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                break;
            }
        }
        assert!(request.len() < 65536, "unexpectedly large test request");
    }
    let request = String::from_utf8_lossy(&request).into_owned();
    let path = request.split_whitespace().nth(1).unwrap().to_string();
    seen.lock().unwrap().push(request);
    let response = respond(base, &path);
    let mut header = format!("HTTP/1.1 {} Test\r\nConnection: close\r\n", response.status);
    if let Some(location) = response.location {
        header.push_str(&format!("Location: {location}\r\n"));
    }
    if response.chunked {
        header.push_str("Transfer-Encoding: chunked\r\n\r\n");
    } else {
        header.push_str(&format!("Content-Length: {}\r\n\r\n", response.body.len()));
    }
    if stream.write_all(header.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }
    thread::sleep(response.delay);
    if response.chunked {
        let _ = write!(stream, "{:x}\r\n", response.body.len());
        let _ = stream.write_all(&response.body);
        let _ = stream.write_all(b"\r\n0\r\n\r\n");
    } else {
        let _ = stream.write_all(&response.body);
    }
    let _ = stream.flush();
}

fn artifact_server(body: &[u8]) -> Server {
    let body = body.to_vec();
    Server::https(move |base, path| {
        let mut response = Response::ok(body.clone());
        match path {
            "/redirect" => return Response::redirect(format!("{base}/middle")),
            "/middle" => return Response::redirect(format!("{base}/body")),
            "/downgrade" => return Response::redirect(base.replace("https:", "http:")),
            "/slow" => response.delay = Duration::from_millis(FETCH_TIMEOUT_MS * 3),
            "/chunked" => response.chunked = true,
            "/error" => response.status = 404,
            "/utf8" => response.body = vec![0xff],
            _ => {}
        }
        response
    })
}

fn expect_error<T: std::fmt::Debug>(result: Result<T, RuntimeError>, detail: &str) -> RuntimeError {
    let error = result.unwrap_err();
    assert!(error.detail().contains(detail), "{error}");
    error
}

fn byte_limit(max_manifest_url_bytes: usize) -> Limits {
    Limits {
        max_manifest_url_bytes,
        ..Limits::default()
    }
}

fn timeout_limit(manifest_url_timeout_ms: u64) -> Limits {
    Limits {
        manifest_url_timeout_ms,
        ..Limits::default()
    }
}

fn redirect_limit(max_manifest_url_redirects: usize) -> Limits {
    Limits {
        max_manifest_url_redirects,
        ..Limits::default()
    }
}

#[cfg(feature = "default-dispatchers")]
fn budget_cases(body_len: usize) -> [(&'static str, Limits, &'static str); 3] {
    [
        ("", byte_limit(body_len - 1), "exceeds limit"),
        ("/slow", timeout_limit(FETCH_TIMEOUT_MS), "timeout"),
        ("/redirect", redirect_limit(0), "redirect"),
    ]
}

pub(crate) fn source(url: String, body: &[u8]) -> PinnedHttpsSource {
    PinnedHttpsSource {
        url,
        sha256: Some(crate::hex::lower(&Sha256::digest(body))),
        integrity: None,
    }
}

pub(crate) fn manifest() -> Manifest {
    Manifest::from_yaml_str(
        "agent_control_specification_version: 0.4.0-alpha.1\n\
         policies:\n  p:\n    type: rego\n    query: data.gate.verdict\n\
         intervention_points:\n  input:\n    policy_target: $.input\n    policy:\n      id: p\n",
    )
    .unwrap()
}

#[cfg(feature = "default-dispatchers")]
fn annotator(pinned: &PinnedHttpsSource, endpoint: &str) -> crate::AnnotatorInvocation {
    crate::AnnotatorInvocation {
        fields: BTreeMap::from([
            ("type".into(), json!("llm")),
            ("provider".into(), json!("openai_compatible")),
            ("from".into(), json!("$.input.text")),
            ("endpoint".into(), json!(endpoint)),
            ("system_prompt_url".into(), json!(pinned)),
        ]),
    }
}

#[cfg(any(
    feature = "opa",
    all(feature = "rego", feature = "default-dispatchers")
))]
pub(crate) fn rego(pinned: &PinnedHttpsSource) -> crate::RegoPolicyInvocation {
    crate::RegoPolicyInvocation {
        query: "data.gate.verdict".into(),
        bundle: None,
        inline_bundle: None,
        adapter_config: BTreeMap::from([("bundle_url".into(), json!(pinned))]),
        input: json!({}),
        canonical_input: "{}".into(),
    }
}

#[test]
fn pinned_sources_reject_invalid_configuration_before_fetch() {
    for (detail, values) in [
        (
            "invalid pinned HTTPS source",
            vec![
                json!("https://localhost:1/prompt"),
                json!({"url": "https://localhost:1/prompt", "sha256": "0".repeat(64), "integrity": null}),
                json!({"url": "https://localhost:1/prompt", "sha256": null, "integrity": format!("sha256-{}", "A".repeat(43))}),
            ],
        ),
        (
            "exactly one",
            vec![
                json!({"url": "https://localhost:1/prompt"}),
                json!({"url": "https://localhost:1/prompt", "sha256": "0".repeat(64), "integrity": "sha256-AAAA"}),
            ],
        ),
        (
            "artifact",
            vec![
                json!({"url": "https://localhost:1/prompt", "sha256": "bad"}),
                json!({"url": "https://localhost:1/prompt", "integrity": "sha512-AAAA"}),
                json!({"url": "https://localhost:1/prompt", "integrity": "sha256-AAAA"}),
                json!({"url": "http://localhost:1/prompt", "sha256": "0".repeat(64)}),
            ],
        ),
    ] {
        for value in values {
            let error = expect_error(PinnedHttpsSource::from_value(&value), detail);
            assert!(!error.detail().contains("extends"), "{error}");
        }
    }
}

#[test]
fn pinned_https_verifies_pins_utf8_and_exact_byte_boundary() {
    with_test_ca(|| {
        let server = artifact_server(b"hello");
        let limits = byte_limit(5);
        let mut pinned = server.source("", b"hello");
        assert_eq!(fetch_pinned_https_text(&pinned, limits).unwrap(), "hello");
        pinned.sha256 = pinned.sha256.map(|hash| hash.to_uppercase());
        assert_eq!(fetch_pinned_https_text(&pinned, limits).unwrap(), "hello");
        pinned.sha256 = None;
        pinned.integrity = Some(format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"hello"))
        ));
        assert_eq!(fetch_pinned_https_text(&pinned, limits).unwrap(), "hello");
        expect_error(
            fetch_pinned_https_text(&pinned, byte_limit(4)),
            "exceeds limit 4",
        );
        expect_error(
            fetch_pinned_https_bytes(&server.source("", b"wrong"), limits),
            "pin mismatch",
        );
        expect_error(
            fetch_pinned_https_text(&server.source("/utf8", &[0xff]), limits),
            "UTF-8",
        );
        assert_eq!(
            fetch_pinned_https_bytes(
                &pinned,
                Limits {
                    max_manifest_url_bytes: usize::MAX,
                    max_manifest_url_redirects: usize::MAX,
                    ..limits
                }
            )
            .unwrap(),
            b"hello"
        );
        match fetch_pinned_https_bytes(&pinned, timeout_limit(u64::MAX)) {
            Ok(body) => assert_eq!(body, b"hello"),
            Err(err) => assert!(matches!(
                err,
                crate::RuntimeError::ResourceLimitExceeded(_)
                    | crate::RuntimeError::ManifestUnreadable(_)
            )),
        }
    });
}

#[test]
fn pinned_https_enforces_streaming_timeout_and_redirect_budgets() {
    with_test_ca(|| {
        let server = artifact_server(b"hello");
        let fetch = |path, limits| fetch_pinned_https_bytes(&server.source(path, b"hello"), limits);
        expect_error(fetch("/chunked", byte_limit(4)), "exceeds limit 4");
        for redirects in [0, 1] {
            assert!(fetch("/redirect", redirect_limit(redirects)).is_err());
        }
        assert_eq!(fetch("/redirect", redirect_limit(2)).unwrap(), b"hello");
        assert!(fetch("/downgrade", Limits::default()).is_err());
        expect_error(fetch("/error", Limits::default()), "404");
        let count = server.requests().len();
        expect_error(fetch("/body", timeout_limit(0)), "timeout of 0");
        assert_eq!(server.requests().len(), count);
        let timed = timeout_limit(FETCH_TIMEOUT_MS);
        assert_eq!(fetch("/body", timed).unwrap(), b"hello");
        let requests = server.requests().len();
        expect_error(fetch("/slow", timed), "timeout");
        assert_eq!(server.requests().len(), requests + 1);
        assert!(server.requests().last().unwrap().starts_with("GET /slow "));
    });
}

#[test]
fn pinned_https_zero_byte_budget_allows_only_empty_body() {
    with_test_ca(|| {
        let server = Server::https(|_, path| {
            Response::ok(if path == "/nonempty" {
                vec![1]
            } else {
                Vec::new()
            })
        });
        assert!(
            fetch_pinned_https_bytes(&server.source("", b""), byte_limit(0))
                .unwrap()
                .is_empty()
        );
        expect_error(
            fetch_pinned_https_bytes(&server.source("/nonempty", &[1]), byte_limit(0)),
            "exceeds limit 0",
        );
    });
}

#[test]
fn production_tls_does_not_trust_test_ca() {
    let server = artifact_server(b"hello");
    let pinned = server.source("", b"hello");
    with_test_ca(|| {
        assert_eq!(
            fetch_pinned_https_bytes(&pinned, Limits::default()).unwrap(),
            b"hello"
        );
    });
    expect_error(
        fetch_pinned_https_bytes(&pinned, Limits::default()),
        "invalid peer certificate",
    );
    assert_eq!(
        server.requests().len(),
        1,
        "untrusted TLS must not send an HTTP request"
    );
}

#[cfg(feature = "default-dispatchers")]
#[test]
fn annotator_factories_consume_url_limits_and_preserve_default_constructors() {
    use crate::dispatchers::{
        default_annotator_dispatcher, default_annotator_dispatcher_for,
        default_annotator_dispatcher_with_limits, DefaultAnnotatorDispatcher, LlmAnnotator,
    };
    use crate::AnnotatorDispatcher;
    with_test_ca(|| {
        let prompts = artifact_server(b"remote prompt");
        let inference = Server::start(false, |_, _| {
            Response::ok(br#"{"choices":[{"message":{"content":"{\"label\":\"safe\"}"}}]}"#)
        });
        let pinned = prompts.source("", b"remote prompt");
        let invocation = annotator(&pinned, &inference.url);
        let input = json!({"snapshot": {"input": {"text": "judge this"}}});
        let exact = byte_limit(13);
        let dispatchers: Vec<Arc<dyn AnnotatorDispatcher>> = vec![
            default_annotator_dispatcher(),
            default_annotator_dispatcher_with_limits(Limits::default()),
            default_annotator_dispatcher_for(&manifest(), exact).unwrap(),
            Arc::new(DefaultAnnotatorDispatcher),
            Arc::new(LlmAnnotator),
        ];
        for dispatcher in dispatchers {
            assert_eq!(
                dispatcher.dispatch("judge", &invocation, &input).unwrap()["label"],
                "safe"
            );
        }
        for request in inference.requests() {
            let body: JsonValue =
                serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
            assert_eq!(body["messages"][0]["content"], "remote prompt");
        }
        let sent = inference.requests().len();
        for (path, limits, expected) in budget_cases(b"remote prompt".len()) {
            let invocation = annotator(&prompts.source(path, b"remote prompt"), &inference.url);
            let err = default_annotator_dispatcher_for(&manifest(), limits)
                .unwrap()
                .dispatch("judge", &invocation, &input)
                .unwrap_err();
            assert_eq!(err.reason(), "runtime_error:annotation_failed");
            let detail = err.detail().to_lowercase();
            assert!(detail.contains("artifact"), "{err}");
            assert!(
                detail.contains(expected)
                    || (expected == "redirect" && detail.contains("http 302")),
                "{err}"
            );
        }
        for (path, expected_bytes, detail) in [
            ("/utf8", &[0xff][..], "UTF-8"),
            ("", &b"incorrect pin"[..], "pin mismatch"),
        ] {
            let invocation = annotator(&prompts.source(path, expected_bytes), &inference.url);
            expect_error(
                default_annotator_dispatcher_for(&manifest(), exact)
                    .unwrap()
                    .dispatch("judge", &invocation, &input),
                detail,
            );
        }
        assert_eq!(
            inference.requests().len(),
            sent,
            "no inference after failed prompt fetch"
        );
    });
}

#[cfg(feature = "default-dispatchers")]
#[test]
fn prompt_overrides_and_invalid_urls_never_fall_back() {
    use crate::dispatchers::{default_annotator_dispatcher_for, LlmAnnotator, StubHttpTransport};
    use crate::{AnnotatorDispatcher, AnnotatorInvocation};
    let pinned = source("https://localhost:1/prompt".into(), b"prompt");
    let input = json!({"snapshot": {"input": {"text": "judge this"}}});
    for field in ["prompt", "system_prompt"] {
        let mut invocation = annotator(&pinned, "http://localhost:1/inference");
        invocation.fields.insert(field.into(), json!("inline"));
        expect_error(
            LlmAnnotator.dispatch("judge", &invocation, &input),
            "must not be combined",
        );
    }
    for url in [
        JsonValue::Null,
        json!("https://localhost:1"),
        json!({"url":"https://localhost:1"}),
    ] {
        let transport = StubHttpTransport::with_response(200, "{}");
        let mut invocation = annotator(&pinned, "http://localhost:1/inference");
        invocation.fields.insert("system_prompt_url".into(), url);
        assert!(LlmAnnotator
            .dispatch_with_transport("judge", &invocation, &input, &transport)
            .is_err());
        assert!(transport.last_request().is_none());
    }
    let mut manifest = manifest();
    let config = crate::annotation::AnnotatorConfig {
        annotator_type: crate::annotation::AnnotatorType::Llm,
        fields: BTreeMap::from([("system_prompt".into(), json!("inline"))]),
    };
    let annotation = crate::annotation::AnnotationConfig {
        from: "$target.text".into(),
        fields: BTreeMap::from([("system_prompt_url".into(), json!(pinned))]),
    };
    let overridden = AnnotatorInvocation::from_annotation(&config, &annotation);
    assert!(LlmAnnotator.dispatch("judge", &overridden, &input).is_err());
    manifest.annotators.insert("judge".into(), config);
    manifest
        .intervention_points
        .values_mut()
        .next()
        .unwrap()
        .annotations
        .insert("judge".into(), annotation);
    assert!(manifest.validate().is_err());
    assert!(default_annotator_dispatcher_for(&manifest, Limits::default()).is_err());
}

#[test]
fn bundle_url_validation_preserves_struct_literals_and_detects_binding_conflicts() {
    use crate::policy::{prepare_policy_invocation, validate_policy_binding};
    use crate::{
        InMemoryRegoBundle, InterceptionPoint, PolicyBinding, PolicyConfig, RegoPolicyConfig,
    };
    let remote = json!(source("https://localhost:1/bundle".into(), b"bundle"));
    let config = RegoPolicyConfig {
        query: Some("data.gate.verdict".into()),
        bundle: None,
        inline_bundle: None,
        adapter_config: BTreeMap::from([("bundle_url".into(), remote.clone())]),
    };
    assert!(config.bundle_url().unwrap().is_some());
    let mut conflict = config.clone();
    conflict.bundle = Some("local".into());
    expect_error(conflict.bundle_url(), "must not combine");
    conflict.bundle = None;
    conflict.inline_bundle = Some(Arc::new(
        InMemoryRegoBundle::new(BTreeMap::new(), vec![]).unwrap(),
    ));
    assert!(conflict.bundle_url().is_err());
    let local = PolicyConfig::Rego(RegoPolicyConfig {
        bundle: Some("local".into()),
        adapter_config: BTreeMap::new(),
        ..config.clone()
    });
    let binding = PolicyBinding {
        id: "p".into(),
        query: None,
        adapter_config: BTreeMap::from([("bundle_url".into(), remote)]),
    };
    assert!(validate_policy_binding(InterceptionPoint::Input, &binding, &local).is_err());
    assert!(prepare_policy_invocation(&local, &binding, &json!({})).is_err());
    let mut manifest = manifest();
    manifest
        .policies
        .insert("p".into(), PolicyConfig::Rego(config));
    manifest
        .set_rego_bundle_in_memory(
            "p",
            InMemoryRegoBundle::new(BTreeMap::new(), vec![]).unwrap(),
        )
        .unwrap();
    assert!(manifest.validate().is_ok());
}

#[test]
fn in_memory_replacement_rejects_binding_urls_without_mutating_manifest() {
    use crate::InMemoryRegoBundle;
    let mut manifest = manifest();
    let remote = json!(source("https://localhost:1/bundle".into(), b"bundle"));
    manifest
        .intervention_points
        .values_mut()
        .next()
        .unwrap()
        .policy
        .adapter_config
        .insert("bundle_url".into(), remote);
    assert!(manifest.validate().is_ok());
    let before = manifest.clone();

    let error = manifest
        .set_rego_bundle_in_memory(
            "p",
            InMemoryRegoBundle::new(BTreeMap::new(), vec![]).unwrap(),
        )
        .unwrap_err();
    assert!(error.detail().contains("remove the binding override first"));
    assert_eq!(manifest, before);
    assert!(manifest.validate().is_ok());

    manifest
        .intervention_points
        .values_mut()
        .next()
        .unwrap()
        .policy
        .adapter_config
        .remove("bundle_url");
    manifest
        .set_rego_bundle_in_memory(
            "p",
            InMemoryRegoBundle::new(BTreeMap::new(), vec![]).unwrap(),
        )
        .unwrap();
    assert!(manifest.validate().is_ok());
}

#[test]
fn artifact_schema_agrees_on_pin_and_source_conflicts() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spec")
        .join("schema");
    let load = |name| -> JsonValue {
        serde_json::from_reader(std::fs::File::open(directory.join(name)).unwrap()).unwrap()
    };
    let schema = load("manifest.schema.json");
    let approval = load("approval.schema.json");
    let registry = jsonschema::Registry::new()
        .add(approval["$id"].as_str().unwrap(), &approval)
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let mut document = serde_json::to_value(manifest()).unwrap();
    let pinned = json!(source("https://example.org/artifact".into(), b"data"));
    document["policies"]["p"]["bundle_url"] = pinned.clone();
    assert!(validator.is_valid(&document));
    document["policies"]["p"]["bundle"] = json!("local");
    assert!(!validator.is_valid(&document));
    document["policies"]["p"]
        .as_object_mut()
        .unwrap()
        .remove("bundle");
    document["annotators"]["judge"] = json!({"type":"llm", "system_prompt_url": pinned});
    assert!(validator.is_valid(&document));
    document["annotators"]["judge"]["system_prompt"] = json!("inline");
    assert!(!validator.is_valid(&document));
    document["annotators"]["judge"]
        .as_object_mut()
        .unwrap()
        .remove("system_prompt");
    let url = "https://example.org/artifact";
    for pin in [
        json!({"url": url}),
        json!({"url": url, "sha256": "0".repeat(64), "integrity": null}),
        json!({"url": url, "integrity": format!("sha256-+_{}", "A".repeat(41))}),
    ] {
        assert!(PinnedHttpsSource::from_value(&pin).is_err());
        document["annotators"]["judge"]["system_prompt_url"] = pin;
        assert!(!validator.is_valid(&document));
    }

    for encoded in [
        base64::engine::general_purpose::STANDARD.encode([255u8; 32]),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode([255u8; 32]),
        base64::engine::general_purpose::URL_SAFE.encode([255u8; 32]),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([255u8; 32]),
    ] {
        let pin = json!({"url": url, "integrity": format!("sha256-{encoded}")});
        assert!(PinnedHttpsSource::from_value(&pin).is_ok());
        document["annotators"]["judge"]["system_prompt_url"] = pin;
        assert!(validator.is_valid(&document));
    }
}

#[cfg(all(feature = "rego", feature = "default-dispatchers"))]
#[test]
fn regorus_rejects_remote_bundles_in_evaluate_warm_and_activation() {
    use crate::dispatchers::{default_policy_dispatcher_with_limits, BindingPolicyDispatcher};
    use crate::{
        ActivatedPolicy, PolicyConfig, PolicyDispatcher, PreparedPolicyInvocation,
        RegorusRegoRunner,
    };
    let invocation = rego(&source("https://localhost:1/bundle".into(), b"bundle"));
    for cached in [false, true] {
        let runner = RegorusRegoRunner::new().with_policy_cache(cached);
        expect_error(runner.evaluate(&invocation), "bundle_url");
        expect_error(runner.warm(&invocation), "bundle_url");
    }
    let prepared = PreparedPolicyInvocation::Rego(invocation.clone());
    let mut manifest = manifest();
    let PolicyConfig::Rego(config) = manifest.policies.get_mut("p").unwrap() else {
        unreachable!()
    };
    config.adapter_config = invocation.adapter_config;
    let defaults = default_policy_dispatcher_with_limits(&manifest, Limits::default()).unwrap();
    assert!(defaults.evaluate(&prepared).is_err());
    assert!(defaults.warm(&prepared).is_err());
    let binding = BindingPolicyDispatcher::with_limits(Limits::default());
    assert!(binding.warm(&prepared).is_err());
    assert!(binding.evaluate(&prepared).is_err());
    assert!(ActivatedPolicy::activate_with(
        manifest,
        crate::dispatchers::default_annotator_dispatcher(),
        Arc::new(binding),
    )
    .is_err());
}

#[cfg(all(
    feature = "opa",
    not(feature = "rego"),
    feature = "default-dispatchers"
))]
#[test]
fn opa_default_and_binding_factories_consume_url_budgets() {
    use crate::dispatchers::{default_policy_dispatcher_with_limits, BindingPolicyDispatcher};
    use crate::{PolicyDispatcher, PreparedPolicyInvocation};
    with_test_ca(|| {
        let server = artifact_server(b"bundle");
        for (path, limits, detail) in budget_cases(b"bundle".len()) {
            let invocation = PreparedPolicyInvocation::Rego(rego(&server.source(path, b"bundle")));
            let dispatchers: Vec<Arc<dyn PolicyDispatcher>> = vec![
                default_policy_dispatcher_with_limits(&manifest(), limits).unwrap(),
                Arc::new(BindingPolicyDispatcher::with_limits(limits)),
            ];
            for dispatcher in dispatchers {
                let err = dispatcher.evaluate(&invocation).unwrap_err();
                assert_eq!(err.reason(), "runtime_error:policy_invocation_failed");
                let message = err.detail().to_lowercase();
                assert!(message.contains("artifact"), "{err}");
                assert!(
                    message.contains(detail)
                        || (detail == "redirect" && message.contains("http 302")),
                    "{err}"
                );
            }
        }
    });
}
