// Copyright (c) Microsoft. All rights reserved.

use crate::dispatchers::{
    bundled::{TransportRequest, TransportResponse},
    constants::*,
    host_env,
    resolve::failed,
};
use crate::{AnnotatorInvocation, JsonValue, RuntimeError};
use serde_json::json;
use sha2::Digest;
use std::{
    collections::BTreeMap,
    error::Error,
    io::{self, Read},
    time::Duration,
};

/// An authorization header to attach to an annotator HTTP request.
///
/// Defaults to `Authorization: Bearer <key>` (OpenAI-style), but the header
/// name can be overridden via the `api_key_header` field so Azure-family
/// services work too (`api-key` for Azure OpenAI, `Ocp-Apim-Subscription-Key`
/// for Azure AI Content Safety).
pub struct Authorization {
    pub header: String,
    pub value: String,
}

pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// The `http::Response` shape ureq 3 hands back for a completed exchange.
type HttpResponse = ureq::http::Response<ureq::Body>;

/// Builds a one-shot agent: one end-to-end timeout for the whole call, no
/// redirects, and every status returned as `Ok` so the caller reads the
/// code and fails closed on anything outside 2xx (ureq 3 would otherwise
/// collapse 4xx/5xx into `Error::StatusCode`).
///
/// Redirects are off because the request carries the annotator's
/// credential, under `Authorization` or under a custom header such as
/// `api-key`. ureq strips only `Authorization` and `Cookie` on a
/// cross-host redirect, so following one would hand the key to an origin
/// the manifest never named and accept that origin's body as the
/// annotation. A 3xx now comes back as a response and the caller
/// rejects it: annotator credentials go to the configured URL only.
fn http_agent(timeout_ms: u64) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(timeout_ms)))
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    )
}

/// Sums up a non-2xx response body without quoting it. An annotator
/// error body is remote text, and a provider that echoes invalid input
/// would put the policy target in it, so only its size and a digest
/// prefix reach the error detail. An operator matches the digest
/// against the provider's own log.
pub fn describe_error_body(body: &str) -> String {
    if body.is_empty() {
        return "empty body".to_string();
    }
    let digest = sha2::Sha256::digest(body.as_bytes());
    let prefix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{} byte body, sha256 {prefix}", body.len())
}

/// The error detail for a response outside 2xx: status code, canonical
/// reason and [`describe_error_body`], never the body itself.
pub fn describe_http_failure(status: u16, body: &str) -> String {
    let reason = ureq::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or_default();
    format!(
        "HTTP request failed with status {status} ({reason}); {}",
        describe_error_body(body)
    )
}

pub fn post_json(
    annotator_name: &str,
    url: &str,
    payload: JsonValue,
    authorization: Option<Authorization>,
    timeout_ms: u64,
) -> Result<JsonValue, RuntimeError> {
    let agent = http_agent(timeout_ms);
    let mut request = agent
        .post(url)
        .header(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON)
        .header(HEADER_ACCEPT, CONTENT_TYPE_JSON);
    if let Some(authorization) = &authorization {
        request = request.header(authorization.header.as_str(), authorization.value.as_str());
    }
    // Serialize eagerly and send a buffered body: ureq 3's `send_json`
    // streams with chunked transfer encoding, while ureq 2 sent a
    // content-length framed body. Sending the serialized string keeps the
    // wire shape identical for endpoints that do not support chunked
    // requests.
    let response = request
        .send(payload.to_string())
        .map_err(|error| transport_error(annotator_name, error))?;
    let status = response.status().as_u16();
    // 3xx included: the agent does not follow redirects, so one is a
    // response the configured origin gave instead of an annotation.
    if !(200..300).contains(&status) {
        let body = read_error_body(response);
        return Err(failed(annotator_name, describe_http_failure(status, &body)));
    }
    parse_response(annotator_name, response)
}

fn transport_error(annotator_name: &str, error: ureq::Error) -> RuntimeError {
    if is_timeout_error(&error) {
        RuntimeError::AnnotationTimeout(format!("HTTP request timed out: {error}"))
    } else {
        failed(annotator_name, format!("HTTP request failed: {error}"))
    }
}

fn is_timeout_error(error: &ureq::Error) -> bool {
    if matches!(error, ureq::Error::Timeout(_)) {
        return true;
    }
    if let ureq::Error::Io(io_error) = error {
        if io_error.kind() == io::ErrorKind::TimedOut {
            return true;
        }
    }
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            return io_error.kind() == io::ErrorKind::TimedOut;
        }
        source = error.source();
    }
    false
}

/// Reads a bounded slice of an error response body for
/// [`describe_error_body`]. The text itself goes no further.
fn read_error_body(response: HttpResponse) -> String {
    let mut body = String::new();
    let _ = response
        .into_body()
        .into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_string(&mut body);
    body.trim().to_string()
}

fn parse_response(annotator_name: &str, response: HttpResponse) -> Result<JsonValue, RuntimeError> {
    let body = read_response_body(response).map_err(|error| failed(annotator_name, error))?;
    serde_json::from_str(&body).map_err(|error| {
        failed(
            annotator_name,
            format!("HTTP response was not valid JSON: {error}"),
        )
    })
}

pub fn read_response_body(response: HttpResponse) -> Result<String, String> {
    let mut body = String::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|error| format!("HTTP response read failed: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("HTTP response exceeded size limit".to_string());
    }
    Ok(body)
}

pub fn send_transport_request(request: TransportRequest) -> Result<TransportResponse, String> {
    if request.method != "POST" {
        return Err(format!("unsupported HTTP method '{}'", request.method));
    }
    let agent = http_agent(request.timeout_ms);
    let mut outbound = agent.post(&request.url);
    for (name, value) in &request.headers {
        outbound = outbound.header(name.as_str(), value.as_str());
    }
    // 4xx/5xx come back as `Ok` (see `http_agent`), matching the ureq 2 arm
    // that surfaced status errors as a `TransportResponse`. The body is
    // serialized eagerly so the request stays content-length framed (ureq 3's
    // `send_json` would switch to chunked transfer encoding).
    match outbound.send(request.body.to_string()) {
        Ok(response) => Ok(TransportResponse {
            status: response.status().as_u16(),
            body: read_response_body(response)?,
        }),
        Err(error) => Err(format!("HTTP request failed: {error}")),
    }
}

pub fn required_string_field<'a>(
    annotator_name: &str,
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, RuntimeError> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failed(annotator_name, format!("missing required field '{name}'")))
}

pub fn optional_string_field<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
}

pub fn timeout_ms(
    annotator_name: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<u64, RuntimeError> {
    match fields.get(FIELD_TIMEOUT_MS) {
        None | Some(JsonValue::Null) => Ok(DEFAULT_TIMEOUT_MS),
        Some(value) => value
            .as_u64()
            .filter(|timeout| *timeout > 0)
            .ok_or_else(|| failed(annotator_name, "timeout_ms must be a positive integer")),
    }
}

pub fn env_api_key(
    annotator_name: &str,
    annotator: &AnnotatorInvocation,
) -> Result<Option<Authorization>, RuntimeError> {
    let fields = &annotator.fields;
    let Some(env_name) = optional_string_field(fields, FIELD_API_KEY_ENV) else {
        return Ok(None);
    };
    let key = host_env::read(annotator.url_sourced, env_name)
        .map_err(|message| failed(annotator_name, message))?
        .ok_or_else(|| {
            failed(
                annotator_name,
                format!("API key environment variable '{env_name}' is not set"),
            )
        })?;
    Ok(Some(authorization(fields, key)))
}

/// Builds the authorization header for a request. Uses `api_key_header` when
/// present (raw key value), otherwise the OpenAI-style `Authorization: Bearer`.
fn authorization(fields: &BTreeMap<String, JsonValue>, key: String) -> Authorization {
    match optional_string_field(fields, FIELD_API_KEY_HEADER) {
        Some(header) => Authorization {
            header: header.to_string(),
            value: key,
        },
        None => Authorization {
            header: HEADER_AUTHORIZATION.to_string(),
            value: format!("{AUTH_BEARER_PREFIX}{key}"),
        },
    }
}

pub fn configured_fields(
    fields: &BTreeMap<String, JsonValue>,
    transport_fields: &[&str],
) -> JsonValue {
    let mut config = serde_json::Map::new();
    for (key, value) in fields {
        if !transport_fields.contains(&key.as_str()) {
            config.insert(key.clone(), value.clone());
        }
    }
    JsonValue::Object(config)
}

pub fn endpoint_payload(input: String, fields: &BTreeMap<String, JsonValue>) -> JsonValue {
    json!({
        REQUEST_INPUT: input,
        REQUEST_FIELDS: configured_fields(fields, &[
            ANNOTATOR_TYPE,
            FIELD_FROM,
            FIELD_INPUT_FROM,
            FIELD_ENDPOINT,
            FIELD_URL,
            FIELD_TIMEOUT_MS,
            FIELD_API_KEY_ENV,
            FIELD_API_KEY,
            FIELD_API_KEY_HEADER,
            FIELD_HEADERS,
            FIELD_PROVIDER_CONFIG,
            FIELD_AWS_ACCESS_KEY_ID,
            FIELD_AWS_SECRET_ACCESS_KEY,
            FIELD_AWS_SESSION_TOKEN,
            FIELD_AWS_ACCESS_KEY_ID_ENV,
            FIELD_AWS_SECRET_ACCESS_KEY_ENV,
            FIELD_AWS_SESSION_TOKEN_ENV,
        ]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
    };

    /// Serves one request with the given status line, extra headers and
    /// body, then returns the request text.
    fn one_shot_server(
        status_line: &'static str,
        extra_headers: String,
        body: Arc<String>,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buffer.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let head = format!(
                "HTTP/1.1 {status_line}\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            // The client may stop reading a large body once it has what
            // it needs, so a short write here is not a test failure.
            let _ = stream.write_all(body.as_bytes());
            String::from_utf8_lossy(&buffer).into_owned()
        });
        (url, handle)
    }

    /// A listener that records whether anyone ever connected.
    fn canary_listener() -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let contacted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&contacted);
        let handle = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline {
                if listener.accept().is_ok() {
                    flag.store(true, Ordering::SeqCst);
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        (url, contacted, handle)
    }

    /// A 1 MiB 5xx body that echoes the request stays out of the error
    /// detail: the detail is short and names the status and a digest.
    #[test]
    fn oversized_error_body_is_summarised_not_echoed() {
        let marker = "ATTACKER_INJECTED_TEXT my SSN is 123-45-6789";
        let mut body = marker.to_string();
        body.push_str(&"\u{7}x\n".repeat(400_000));
        assert!(body.len() >= 1_048_576);
        let (url, request) =
            one_shot_server("500 Internal Server Error", String::new(), Arc::new(body));

        let error = post_json(
            "scan",
            &url,
            json!({"input": "my SSN is 123-45-6789"}),
            None,
            5_000,
        )
        .unwrap_err();
        request.join().unwrap();

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        let detail = error.detail();
        assert!(
            detail.contains("HTTP request failed with status 500 (Internal Server Error)"),
            "{detail}"
        );
        assert!(detail.contains("sha256 "), "{detail}");
        assert!(!detail.contains(marker), "{detail}");
        assert!(!detail.contains("SSN"), "{detail}");
        assert!(!detail.chars().any(char::is_control), "{detail}");
        assert!(detail.len() < 200, "{} bytes: {detail}", detail.len());
    }

    #[test]
    fn describe_error_body_is_bounded_and_content_free() {
        assert_eq!(describe_error_body(""), "empty body");
        let summary = describe_error_body("{\"error\":\"secret text\"}");
        assert!(!summary.contains("secret"), "{summary}");
        assert!(summary.starts_with("23 byte body, sha256 "), "{summary}");
        assert_eq!(summary.len(), "23 byte body, sha256 ".len() + 16);
        assert_eq!(
            describe_http_failure(418, "x"),
            "HTTP request failed with status 418 (I'm a teapot); 1 byte body, sha256 2d711642b726b044"
        );
    }

    /// A 302 from the configured endpoint is not followed: the second
    /// host never sees the request or the credential header, and the
    /// dispatch fails closed.
    #[test]
    fn post_json_does_not_follow_redirects() {
        let (elsewhere, contacted, canary) = canary_listener();
        let (url, request) = one_shot_server(
            "302 Found",
            format!("location: {elsewhere}/elsewhere\r\n"),
            Arc::new(String::new()),
        );

        let error = post_json(
            "classifier",
            &url,
            json!({"input": "hello"}),
            Some(Authorization {
                header: "X-Api-Key".to_string(),
                value: "probe-secret-value".to_string(),
            }),
            5_000,
        )
        .unwrap_err();
        let first_request = request.join().unwrap();
        canary.join().unwrap();

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        assert!(error.detail().contains("status 302"), "{}", error.detail());
        assert!(first_request
            .to_lowercase()
            .contains("x-api-key: probe-secret-value"));
        assert!(
            !contacted.load(Ordering::SeqCst),
            "the redirect target was contacted"
        );
    }

    /// The same for the provider transport the bundled classifiers use.
    #[test]
    fn send_transport_request_does_not_follow_redirects() {
        let (elsewhere, contacted, canary) = canary_listener();
        let (url, request) = one_shot_server(
            "301 Moved Permanently",
            format!("location: {elsewhere}/\r\n"),
            Arc::new(String::new()),
        );

        let response = send_transport_request(
            TransportRequest::post(url)
                .header("api-key", "probe-secret-value")
                .json(json!({"input": "hello"}))
                .timeout_ms(5_000),
        )
        .unwrap();
        request.join().unwrap();
        canary.join().unwrap();

        assert_eq!(response.status, 301);
        assert!(!contacted.load(Ordering::SeqCst));
    }

    #[test]
    fn timeout_io_error_maps_to_annotation_timeout() {
        let io_error = io::Error::new(io::ErrorKind::TimedOut, "too slow");

        let error = transport_error("endpoint", ureq::Error::Io(io_error));

        assert!(matches!(error, RuntimeError::AnnotationTimeout(_)));
    }

    #[test]
    fn ureq_timeout_maps_to_annotation_timeout() {
        let error = transport_error("endpoint", ureq::Error::Timeout(ureq::Timeout::Global));

        assert!(matches!(error, RuntimeError::AnnotationTimeout(_)));
    }

    #[test]
    fn non_timeout_error_fails_closed_as_annotation_failed() {
        let error = transport_error("endpoint", ureq::Error::ConnectionFailed);

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        assert!(error.detail().contains("HTTP request failed"));
    }

    #[test]
    fn env_api_key_refuses_url_sourced() {
        let annotator = AnnotatorInvocation {
            url_sourced: true,
            fields: BTreeMap::from([(
                FIELD_API_KEY_ENV.to_string(),
                json!("ACS_URL_SOURCED_CLASSIFIER_KEY"),
            )]),
        };

        let error = match env_api_key("classifier", &annotator) {
            Ok(_) => panic!("URL sourced credential read must be refused"),
            Err(error) => error,
        };

        assert_eq!(error.reason(), "runtime_error:annotation_failed");
        assert!(error.detail().contains("URL sourced manifest"), "{error}");
        assert!(
            error.detail().contains("ACS_URL_SOURCED_CLASSIFIER_KEY"),
            "{error}"
        );
    }

    #[test]
    fn env_api_key_without_field_is_none_even_when_url_sourced() {
        let annotator = AnnotatorInvocation {
            url_sourced: true,
            fields: BTreeMap::new(),
        };

        assert!(matches!(env_api_key("classifier", &annotator), Ok(None)));
    }

    /// The flag rides the invocation in process only. It is neither in the
    /// JSON a host dispatcher receives nor in the payload an endpoint
    /// annotator posts.
    #[test]
    fn invocation_json_and_endpoint_payload_have_no_provenance_key() {
        let annotator = AnnotatorInvocation {
            url_sourced: true,
            fields: BTreeMap::from([
                (ANNOTATOR_TYPE.to_string(), json!(TYPE_ENDPOINT)),
                ("purpose".to_string(), json!("probe")),
            ]),
        };

        let wire = serde_json::to_value(&annotator).unwrap();
        assert_eq!(wire, json!({"type": "endpoint", "purpose": "probe"}));

        let payload = endpoint_payload("hello".to_string(), &annotator.fields);
        assert_eq!(
            payload,
            json!({"input": "hello", "fields": {"purpose": "probe"}})
        );
        assert!(!payload.to_string().contains("url_sourced"));
    }
}
