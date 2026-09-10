//! Every read of the host process environment by a bundled dispatcher
//! goes through this module. Review invariant:
//! `rg -n 'env::var' engine/src/dispatchers` hits only this file.
//!
//! A manifest that folded in a fetched document is URL sourced, and a
//! fetched document can choose both the environment variable name and
//! the endpoint that receives its value. So a URL sourced invocation
//! may not read the host environment at all: not a name the manifest
//! gave, and not a provider default such as `OPENAI_API_KEY`. The
//! refusal comes before the lookup, so the message never says whether
//! the variable exists.

/// Reads `env_name` for a host authored invocation; refuses for a URL
/// sourced one. `Ok(None)` means host authored and unset.
pub(super) fn read(url_sourced: bool, env_name: &str) -> Result<Option<String>, String> {
    read_with(url_sourced, env_name, |name| std::env::var(name).ok())
}

/// For the Bedrock session token only: absent without an error when the
/// manifest is URL sourced, so inline long-term keys still sign without
/// borrowing the host's session token.
pub(super) fn read_optional(url_sourced: bool, env_name: &str) -> Option<String> {
    read_with(url_sourced, env_name, |name| std::env::var(name).ok()).unwrap_or(None)
}

/// The lookup is a parameter so a test can prove the short-circuit
/// precedes it without touching process environment.
fn read_with<F: Fn(&str) -> Option<String>>(
    url_sourced: bool,
    env_name: &str,
    lookup: F,
) -> Result<Option<String>, String> {
    if url_sourced {
        return Err(format!(
            "{} must not read host environment credential '{env_name}'; supply the credential \
             inline or declare this annotator in a manifest chain with no URL extends",
            crate::constants::provenance::MARKER
        ));
    }
    Ok(lookup(env_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_called(name: &str) -> Option<String> {
        panic!("host environment lookup for '{name}' must not run for a URL sourced manifest")
    }

    #[test]
    fn read_with_short_circuits_before_lookup_when_url_sourced() {
        let error = read_with(true, "X", never_called).unwrap_err();

        assert!(error.contains("URL sourced manifest"), "{error}");
        assert!(error.contains("'X'"), "{error}");
    }

    #[test]
    fn read_with_reads_when_host_authored() {
        let value = read_with(false, "X", |name| {
            assert_eq!(name, "X");
            Some("v".to_string())
        })
        .unwrap();

        assert_eq!(value.as_deref(), Some("v"));
    }

    #[test]
    fn read_optional_is_none_when_url_sourced() {
        // Same short-circuit as `read_optional`, through the seam that
        // takes a lookup, so the assertion does not depend on what the
        // process environment happens to hold.
        let value = read_with(true, "AWS_SESSION_TOKEN", never_called).unwrap_or(None);

        assert_eq!(value, None);
    }
}
