pub(crate) mod annotation {
    pub(crate) const FROM: &str = "from";
    pub(crate) const INPUT_FROM: &str = "input_from";
    pub(crate) const TYPE: &str = "type";
}

/// SHA-256 digest sizes shared by the `extends` integrity validators so the
/// raw-byte and hex-encoded length checks stay in lockstep with their error
/// messages.
pub(crate) mod sha256 {
    pub(crate) const DIGEST_BYTES: usize = 32;
    pub(crate) const HEX_LEN: usize = 64;
}

/// Reserved deny reasons that cross the dispatcher boundary, where a host
/// supplied annotator dispatcher signals the outcome back to the runtime. These
/// are the single source of truth for the sentinel strings, so the FFI boundary
/// and the language bridges compare and emit the same values without duplicating
/// string literals that could drift apart.
pub mod reserved_reason {
    pub const ANNOTATION_TIMEOUT: &str = "runtime_error:annotation_timeout";
    pub const ANNOTATION_FAILED: &str = "runtime_error:annotation_failed";
}

pub(crate) mod manifest_version {
    pub(crate) const SUPPORTED: [&str; 1] = ["0.4.0-alpha.1"];
}

pub(crate) mod engine {
    pub(crate) const CEDAR: &str = "cedar";
    pub(crate) const CUSTOM: &str = "custom";
    pub(crate) const REGO: &str = "rego";
    pub(crate) const TEST: &str = "test";
}

/// Field names reserved for the `cedar` policy type, per AGT delta D3.1.
/// These are rejected when they appear on a `rego` policy's flattened
/// `adapter_config` so that mixed-language manifests are caught early.
pub(crate) mod cedar_field {
    pub(crate) const POLICY_SET: &str = "policy_set";
    pub(crate) const POLICY_PATH: &str = "policy_path";
    pub(crate) const ENTITIES_PATH: &str = "entities_path";
    pub(crate) const SCHEMA_PATH: &str = "schema_path";

    pub(crate) const ALL: [&str; 4] = [POLICY_SET, POLICY_PATH, ENTITIES_PATH, SCHEMA_PATH];
}

/// Annotator fields that name a host environment variable holding a
/// credential. A manifest that folded in a fetched document may not use
/// them: the fetched document can also pick the endpoint that receives
/// the value. The bundled dispatcher constants alias these so the load
/// time gate and the dispatch time sink agree on one list.
pub(crate) mod host_env_secret_field {
    pub(crate) const API_KEY_ENV: &str = "api_key_env";
    pub(crate) const AWS_ACCESS_KEY_ID_ENV: &str = "aws_access_key_id_env";
    pub(crate) const AWS_SECRET_ACCESS_KEY_ENV: &str = "aws_secret_access_key_env";
    pub(crate) const AWS_SESSION_TOKEN_ENV: &str = "aws_session_token_env";

    pub(crate) const ALL: [&str; 4] = [
        API_KEY_ENV,
        AWS_ACCESS_KEY_ID_ENV,
        AWS_SECRET_ACCESS_KEY_ENV,
        AWS_SESSION_TOKEN_ENV,
    ];
}

/// Adapter config key that names a remote Rego bundle. Inert data to the
/// core today; a fetched document may name it only when every URL hop
/// from the root manifest to that document carries a pin.
pub(crate) mod remote_bundle {
    pub(crate) const BUNDLE_URL: &str = "bundle_url";
}

/// Manifest provenance markers.
pub(crate) mod provenance {
    /// Stable substring in every provenance refusal, at load or at
    /// dispatch, so a host can recognise the class from the text.
    pub(crate) const MARKER: &str = "URL sourced manifest";
    /// Recorded as the source when a host marks a manifest it fetched
    /// itself through `Manifest::mark_url_sourced`.
    pub(crate) const HOST_MARKED_SOURCE: &str = "host-marked remote content";
}

pub(crate) mod policy_input {
    pub(crate) const ANNOTATIONS: &str = "annotations";
    pub(crate) const INTERVENTION_POINT: &str = "intervention_point";
    pub(crate) const KIND: &str = "kind";
    pub(crate) const PATH: &str = "path";
    pub(crate) const SNAPSHOT: &str = "snapshot";
    pub(crate) const POLICY_TARGET: &str = "policy_target";
    pub(crate) const TOOL: &str = "tool";
    pub(crate) const VALUE: &str = "value";
}
