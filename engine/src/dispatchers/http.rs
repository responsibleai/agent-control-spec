use crate::dispatchers::{
    bundled::{TransportRequest, TransportResponse},
    constants::*,
    resolve::failed,
};
use crate::{JsonValue, RuntimeError};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
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

/// Builds a one-shot agent matching the ureq 2 dispatcher behavior: one
/// end-to-end timeout for the whole call, and 4xx/5xx responses returned as
/// `Ok` so the status plus a bounded body slice stay readable for the
/// fail-closed error text (ureq 3 would otherwise collapse them into
/// `Error::StatusCode`, which discards the body).
fn http_agent(timeout_ms: u64) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(timeout_ms)))
            .http_status_as_error(false)
            .build(),
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
    let status = response.status();
    if status.as_u16() >= 400 {
        let code = status.as_u16();
        let status_text = status.canonical_reason().unwrap_or_default().to_string();
        let body = read_error_body(response);
        return Err(if body.is_empty() {
            failed(
                annotator_name,
                format!("HTTP request failed with status {code}: {status_text}"),
            )
        } else {
            failed(
                annotator_name,
                format!("HTTP request failed with status {code} ({status_text}): {body}"),
            )
        });
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

/// Reads a bounded slice of an error response body so failures stay diagnosable
/// (e.g. an Azure `content_filter` rejection carries its reason in the body).
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
    fields: &BTreeMap<String, JsonValue>,
) -> Result<Option<Authorization>, RuntimeError> {
    let Some(env_name) = optional_string_field(fields, FIELD_API_KEY_ENV) else {
        return Ok(None);
    };
    let key = env::var(env_name).map_err(|_| {
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
}
