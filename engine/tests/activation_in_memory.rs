//! Activating a policy whose manifest and Rego are held in memory.
//!
//! A host that keeps both in a database has no directory to point a
//! manifest at, so these pin that a bundle supplied as values evaluates,
//! that two such bundles stay apart in the policy cache, and that the
//! same policy activated from disk and from memory decides alike.
#![cfg(all(feature = "rego", feature = "default-dispatchers"))]

use agent_control_spec::{
    ActivatedPolicy, InMemoryRegoBundle, InterceptionPoint, JsonValue, MountedRegoData,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const MANIFEST: &str = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: in-memory
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
"#;

fn module(allow: bool) -> String {
    format!(
        r#"package gate

verdict := {{"decision": "{}", "reason": "{}"}}
"#,
        if allow { "allow" } else { "deny" },
        if allow { "permitted" } else { "refused" }
    )
}

fn bundle(allow: bool) -> InMemoryRegoBundle {
    InMemoryRegoBundle::new(
        BTreeMap::from([("gate.rego".to_string(), module(allow))]),
        Vec::new(),
    )
    .expect("bundle")
}

fn activate(bundle: InMemoryRegoBundle) -> ActivatedPolicy {
    ActivatedPolicy::activate_from_memory(MANIFEST, BTreeMap::from([("gate".to_string(), bundle)]))
        .expect("activate from memory")
}

fn snapshot() -> JsonValue {
    json!({"input": {"text": "hello"}})
}

fn verdict(policy: &ActivatedPolicy) -> JsonValue {
    let result = policy.evaluate(InterceptionPoint::Input, snapshot());
    let verdict = serde_json::to_value(&result.verdict).expect("verdict as json");
    assert!(
        !result
            .verdict
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("runtime_error:")),
        "policy failed rather than decided: {verdict}"
    );
    verdict
}

fn test_artifact_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("activation-in-memory-tests")
        .join(format!("{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

/// Nothing is written to disk anywhere in this test, so a decision here
/// proves the policy came from the supplied strings.
#[test]
fn a_bundle_held_only_in_memory_decides() {
    let policy = activate(bundle(true));

    let verdict = verdict(&policy);
    assert_eq!(verdict["decision"], json!("allow"));
    assert_eq!(verdict["reason"], json!("permitted"));
}

/// Data documents mount where the caller says, since no directory
/// implies it in memory.
#[test]
fn data_documents_mount_where_the_caller_puts_them() {
    let manifest = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: in-memory-data
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
"#;
    let bundle = InMemoryRegoBundle::new(
        BTreeMap::from([(
            "gate.rego".to_string(),
            r#"package gate

verdict := {
    "decision": "allow",
    "reason": sprintf("limit=%v root=%v", [data.limits.daily, data.at_root]),
}
"#
            .to_string(),
        )]),
        vec![
            MountedRegoData {
                mount: vec!["limits".to_string()],
                document: json!({"daily": 42}),
            },
            MountedRegoData {
                mount: Vec::new(),
                document: json!({"at_root": "yes"}),
            },
        ],
    )
    .expect("bundle");

    let policy = ActivatedPolicy::activate_from_memory(
        manifest,
        BTreeMap::from([("gate".to_string(), bundle)]),
    )
    .expect("activate");

    // Both documents reach the policy at the mount points the caller
    // gave, which the policy reports back through its reason.
    let verdict = verdict(&policy);
    assert_eq!(verdict["decision"], json!("allow"));
    assert_eq!(verdict["reason"], json!("limit=42 root=yes"));
}

/// The policy cache is keyed on a bundle path, and an in-memory bundle
/// has none. Two of them under one manifest share a dispatcher and so
/// share a cache, and must still be told apart: without the content
/// digest the second lookup is served the first one's engine, its own
/// query is undefined there, and it fails closed.
///
/// Two separate activations would not detect this. Each builds its own
/// dispatcher with its own cache, so nothing they do can collide.
#[test]
fn two_in_memory_bundles_under_one_manifest_do_not_share_an_engine() {
    let manifest = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: two-policies
policies:
  first:
    type: rego
    query: data.first.verdict
  second:
    type: rego
    query: data.second.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: first
  output:
    policy_target: "$.output"
    policy_target_kind: model_response
    policy:
      id: second
"#;
    let named = |package: &str, reason: &str| {
        InMemoryRegoBundle::new(
            BTreeMap::from([(
                format!("{package}.rego"),
                format!(
                    "package {package}\n\nverdict := {{\"decision\": \"allow\", \"reason\": \"{reason}\"}}\n"
                ),
            )]),
            Vec::new(),
        )
        .expect("bundle")
    };

    let policy = ActivatedPolicy::activate_from_memory(
        manifest,
        BTreeMap::from([
            ("first".to_string(), named("first", "from-first")),
            ("second".to_string(), named("second", "from-second")),
        ]),
    )
    .expect("activate");

    let first = policy
        .evaluate(InterceptionPoint::Input, json!({"input": {"text": "x"}}))
        .verdict;
    let second = policy
        .evaluate(InterceptionPoint::Output, json!({"output": {"text": "y"}}))
        .verdict;

    assert_eq!(first.reason.as_deref(), Some("from-first"));
    assert_eq!(second.reason.as_deref(), Some("from-second"));
}

/// Two activations of different bundles decide as their own policy says.
/// Weaker than the test above, and kept because it is the shape a host
/// actually writes: one activation per policy version.
#[test]
fn separate_activations_of_different_bundles_keep_their_own_verdicts() {
    let permissive = activate(bundle(true));
    let restrictive = activate(bundle(false));

    assert_eq!(verdict(&permissive)["reason"], json!("permitted"));
    assert_eq!(verdict(&restrictive)["reason"], json!("refused"));
}

/// Two bundles holding the same modules are the same policy, so they
/// should share the prepared engine rather than compile twice.
#[test]
fn identical_bundles_share_a_digest() {
    assert_eq!(bundle(true).digest(), bundle(true).digest());
    assert_ne!(bundle(true).digest(), bundle(false).digest());
}

/// Length-prefixing in the digest exists for this: without it a module
/// named `ab` with body `c` would hash like one named `a` with body
/// `bc`, and the two would collide in the cache.
#[test]
fn a_moved_boundary_between_name_and_body_changes_the_digest() {
    let left = InMemoryRegoBundle::new(
        BTreeMap::from([("ab".to_string(), "c".to_string())]),
        Vec::new(),
    )
    .unwrap();
    let right = InMemoryRegoBundle::new(
        BTreeMap::from([("a".to_string(), "bc".to_string())]),
        Vec::new(),
    )
    .unwrap();

    assert_ne!(left.digest(), right.digest());
}

/// A mount point is part of what a bundle is, so moving a document must
/// change the digest even though the document did not.
#[test]
fn moving_a_data_document_changes_the_digest() {
    let make = |mount: Vec<String>| {
        InMemoryRegoBundle::new(
            BTreeMap::new(),
            vec![MountedRegoData {
                mount,
                document: json!({"n": 1}),
            }],
        )
        .unwrap()
    };

    assert_ne!(
        make(vec!["a".to_string()]).digest(),
        make(vec!["b".to_string()]).digest()
    );
    assert_ne!(
        make(vec!["a".to_string(), "b".to_string()]).digest(),
        make(vec!["a.b".to_string()]).digest()
    );
}

/// The same policy from either source must decide identically, or the
/// in-memory path is a second implementation rather than the same one
/// without the read.
#[test]
fn a_policy_decides_the_same_from_disk_and_from_memory() {
    let dir = test_artifact_dir("parity");
    let bundle_dir = dir.join("policy");
    fs::create_dir_all(&bundle_dir).unwrap();
    fs::write(bundle_dir.join("gate.rego"), module(true)).unwrap();
    fs::write(bundle_dir.join("data.json"), r#"{"tier": "gold"}"#).unwrap();

    let manifest_yaml = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: parity
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
"#;
    fs::write(dir.join("manifest.yaml"), manifest_yaml).unwrap();

    let from_disk = ActivatedPolicy::activate_from_path(dir.join("manifest.yaml")).expect("disk");

    // The same two files, as values. `data.json` sits at the bundle
    // root, which OPA mounts at the data root, so the mount is empty.
    let from_memory = ActivatedPolicy::activate_from_memory(
        manifest_yaml,
        BTreeMap::from([(
            "gate".to_string(),
            InMemoryRegoBundle::new(
                BTreeMap::from([("gate.rego".to_string(), module(true))]),
                vec![MountedRegoData {
                    mount: Vec::new(),
                    document: json!({"tier": "gold"}),
                }],
            )
            .unwrap(),
        )]),
    )
    .expect("memory");

    assert_eq!(verdict(&from_disk), verdict(&from_memory));
    assert_eq!(verdict(&from_disk)["decision"], json!("allow"));
}

/// A manifest parsed from a string has no directory of its own, so a
/// leftover relative path would resolve against the process working
/// directory and read a policy nobody chose.
#[test]
fn a_leftover_relative_bundle_path_is_refused() {
    let error = ActivatedPolicy::activate_from_memory(MANIFEST, BTreeMap::new()).unwrap_err();

    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("'gate'") && error.detail().contains("relative bundle or data"),
        "{}",
        error.detail()
    );
}

/// A relative data path resolves against the working directory exactly
/// as a relative bundle path does, so refusing one and reading the other
/// would be an inconsistency the host pays for.
#[test]
fn a_leftover_relative_data_path_is_refused() {
    let manifest = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: relative-data
policies:
  gate:
    type: rego
    query: data.gate.verdict
    data_paths:
      - ./config.json
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"#;

    let error = ActivatedPolicy::activate_from_memory(
        manifest,
        BTreeMap::from([("gate".to_string(), bundle(true))]),
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("'gate'") && error.detail().contains("relative bundle or data"),
        "{}",
        error.detail()
    );
}

/// A binding can carry data paths of its own, and they reach the same
/// loader as the policy's, so they need the same refusal.
#[test]
fn a_leftover_relative_data_path_on_a_binding_is_refused() {
    let manifest = r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: relative-binding-data
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
      data_paths:
        - ./binding.json
"#;

    let error = ActivatedPolicy::activate_from_memory(
        manifest,
        BTreeMap::from([("gate".to_string(), bundle(true))]),
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("'gate'") && error.detail().contains("relative bundle or data"),
        "{}",
        error.detail()
    );
}

/// An absolute data path is a location the host wrote deliberately, so
/// supplying modules in memory must not start refusing it.
#[test]
fn an_absolute_data_path_survives_an_in_memory_activation() {
    let dir = test_artifact_dir("absolute-data");
    let data = dir.join("config.json");
    fs::write(&data, r#"{"tier": "gold"}"#).unwrap();

    let manifest = format!(
        r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: absolute-data
policies:
  gate:
    type: rego
    query: data.gate.verdict
    data_paths:
      - {}
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"#,
        data.display()
    );

    let policy = ActivatedPolicy::activate_from_memory(
        &manifest,
        BTreeMap::from([("gate".to_string(), bundle(true))]),
    )
    .expect("absolute data path");

    assert_eq!(verdict(&policy)["decision"], json!("allow"));
}

/// Naming a policy the manifest does not declare is a host mistake worth
/// reporting, not modules to drop on the floor.
#[test]
fn supplying_modules_for_an_undeclared_policy_is_refused() {
    let error = ActivatedPolicy::activate_from_memory(
        MANIFEST,
        BTreeMap::from([("nope".to_string(), bundle(true))]),
    )
    .unwrap_err();

    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("no such policy"),
        "{}",
        error.detail()
    );
}

/// An absolute path is a location the host chose, not one inferred from
/// a manifest directory that does not exist, so it is left alone.
#[test]
fn an_absolute_bundle_path_survives_an_in_memory_activation() {
    let dir = test_artifact_dir("absolute");
    let bundle_dir = dir.join("policy");
    fs::create_dir_all(&bundle_dir).unwrap();
    fs::write(bundle_dir.join("gate.rego"), module(true)).unwrap();

    let manifest = format!(
        r#"
agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: absolute
policies:
  gate:
    type: rego
    bundle: {}
    query: data.gate.verdict
intervention_points:
  input:
    policy_target: "$.input"
    policy_target_kind: user_input
    policy:
      id: gate
"#,
        bundle_dir.display()
    );

    let policy =
        ActivatedPolicy::activate_from_memory(&manifest, BTreeMap::new()).expect("absolute");

    assert_eq!(verdict(&policy)["decision"], json!("allow"));
}
