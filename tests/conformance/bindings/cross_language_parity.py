#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run the whole public surface in every supported language and diff.

ACS reaches Rust, Python, Node and .NET through four different binding
mechanisms: a direct crate dependency, pyo3, napi, and a C ABI with
P/Invoke over it. Each one converts enums, offsets, absent values and
error text at its own boundary, so agreement between them is not
structural and cannot be assumed. This asserts it, for streaming and for
everything else.

Every language answers the same questions against the same manifest and
prints one JSON object. The objects must be identical.

The scenario deliberately covers the places a binding is most likely to
drift:

* a rune count that differs from the UTF-16 length, which is where a
  .NET or Node binding silently releases twice what was evaluated
* an absent safe offset after settlement, which must not arrive as 0 or
  as -1 in any language, because both read as permission
* a fail-closed deny, which every binding must surface as a verdict
  rather than as an exception
* a rejected manifest, which must fail rather than return
* versioned dependencies and legacy host fields driving policy decisions

Run it from the repository root. Every language builds from this
checkout, so it answers for the code under review rather than for
whatever happens to be installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = Path(__file__).resolve().parent / "manifest.yaml"
HOOKS_MANIFEST = Path(__file__).resolve().parent / "host-hooks-manifest.yaml"
DEPENDENCIES_MANIFEST = Path(__file__).resolve().parent / "dependencies-manifest.yaml"
DEPENDENCY_VERSION = "0.5.0-alpha.1"
LEGACY_VERSION = "0.4.0-alpha.1"

# "hi" plus one astral-plane scalar: 3 runes, 4 UTF-16 code units.
TEXT = "hi\U0001f600"
RUNES = 3

# A pre_tool_call context the fixture manifest denies.
DENY_CONTEXT = {
    "interception_point": "pre_tool_call",
    "tool_call": {"name": "shell", "args": {"cmd": "rm -rf /"}},
}

# An input context the fixture manifest allows.
ALLOW_CONTEXT = {"interception_point": "input", "input": "hello"}

# Built rather than written literally. A repo guard scans committed files
# for the version key and validates whatever follows it, and a Python
# string literal carries quotes it cannot strip.
_VERSION_KEY = "agent_control_specification_version"

# Names a supported version, then omits policies and intervention_points,
# so the grammar refuses it. Every language must fail rather than return.
BAD_MANIFEST = f'{_VERSION_KEY}: "0.4.0-alpha.1"\nmetadata: {{}}\n'

# A sound manifest that names Rego. The document check passes it whatever
# the Rego says, so it is the only way to see artifact validation work.
REGO_MANIFEST = (
    f'{_VERSION_KEY}: "0.4.0-alpha.1"\n'
    "policies:\n  gate:\n    type: rego\n    bundle: ./b\n"
    'intervention_points:\n  input:\n    policy_target: "$.input"\n'
    "    policy:\n      id: gate\n      query: data.acs.decision\n"
)
GOOD_BUNDLES = {
    "gate": {"modules": {"p.rego": 'package acs\ndecision := {"decision":"allow"}\n'}}
}
BAD_BUNDLES = {"gate": {"modules": {"p.rego": "package acs\nthis is not rego ***\n"}}}

EXPECTED = {
    # Manifest surface
    "supported_versions_nonempty": True,
    "supports_dependency_version": True,
    "supports_legacy_version": True,
    "validate_good": "ok",
    "validate_bad": "rejected",
    # Interceptor surface
    "interceptor_name": "acs",
    "allow_decision": "allow",
    "deny_decision": "deny",
    "deny_reason": "blocked_by_policy",
    # Activated policy surface
    "binds_input": True,
    "activated_allow_decision": "allow",
    # Streaming surface
    "received": RUNES,
    "safe_offset_before": 0,
    "advanced": RUNES,
    "safe_offset_after": RUNES,
    "confirmed": RUNES,
    "is_clean": True,
    "transformed": False,
    # Absent, never 0 and never -1. Each language spells it natively.
    "safe_offset_settled": None,
    # Host extension points. The classifier's answer must decide the
    # verdict, and a classifier that could not be reached must deny
    # rather than read as one that found nothing.
    "hook_benign_decision": "allow",
    "hook_harmful_decision": "deny",
    "hook_harmful_reason": "unsafe_content",
    "hook_failure_decision": "deny",
    "hook_failure_reason": "runtime_error:annotation_failed",
    "hook_dispatcher_calls": 1,
    # Manifest tooling.
    "parsed_has_points": True,
    "diagnostics_on_bad": 1,
    "diagnostics_on_good": 0,
    # The shape, not only the count. Asserting the count alone let three
    # bindings return three different diagnostic shapes for one call.
    "diagnostic_keys": ["code", "field", "message", "severity"],
    "diagnostic_code": "runtime_error:manifest_invalid",
    "diagnostic_field": "intervention point",
    # Settlement with uncleared residue, the fail-closed core of the
    # profile. Every scenario above settles clean, so without this no
    # binding is pinned to refusing text nothing evaluated.
    "residue_kind": "failed",
    "residue_reason": "host_error:streaming_unsupported",
    "residue_clean": False,
    # Artifact validation. The manifest is sound either way, so only
    # compiling the Rego tells the two bundles apart.
    #
    # With no bundles the manifest still names ./b, which is not on disk,
    # so activation reports the missing bundle. That is the answer a host
    # wants: validating a manifest that names Rego without supplying the
    # Rego cannot be a pass.
    "artifacts_manifest_only": 1,
    "artifacts_good_rego": 0,
    "artifacts_bad_rego": 1,
    "artifacts_bad_rego_code": "runtime_error:policy_invocation_failed",
    # Resource caps. The same context must pass under the defaults and
    # fail closed under a cap smaller than it, or the cap was accepted
    # and dropped.
    "limits_default_decision": "allow",
    "limits_capped_decision": "deny",
    "limits_capped_reason": "runtime_error:resource_limit_exceeded",
    "dependency_new_blocked": {
        "calls": [
            {
                "name": "source", "from": "$target", "input": {"blocked": True},
                "annotations": {}, "needs_present": False, "needs": None,
            },
            {
                "name": "judge", "from": "$target", "input": {"blocked": True},
                "annotations": {"source": {"blocked": True}},
                "needs_present": False, "needs": None,
            },
        ],
        "judge": {"blocked": True, "basis": "source_blocked"},
        "decision": "deny",
        "reason": "source_blocked",
    },
    "dependency_new_clear": {
        "calls": [
            {
                "name": "source", "from": "$target", "input": {"blocked": False},
                "annotations": {}, "needs_present": False, "needs": None,
            },
            {
                "name": "judge", "from": "$target", "input": {"blocked": False},
                "annotations": {"source": {"blocked": False}},
                "needs_present": False, "needs": None,
            },
        ],
        "judge": {"blocked": False, "basis": "clear"},
        "decision": "allow",
        "reason": "clear",
    },
    "dependency_legacy": {
        "calls": [
            {
                "name": "judge", "from": "$target", "input": {"blocked": False},
                "annotations": {}, "needs_present": True, "needs": ["source"],
            },
            {
                "name": "source", "from": "$target", "input": {"blocked": False},
                "annotations": {}, "needs_present": False, "needs": None,
            },
        ],
        "judge": {"blocked": True, "basis": "legacy_needs"},
        "decision": "deny",
        "reason": "legacy_needs",
    },
}

# Larger than the capped bound below, smaller than the default one.
BIG_INPUT = "x" * 4096
SMALL_CAP = {"max_snapshot_bytes": 64}


def _run(cmd: list[str], **kw) -> dict:
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)
    return json.loads(out.stdout.strip().splitlines()[-1])


RUST_MAIN = r"""
use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::stream_session::*;
use agent_control_spec::{ActivatedPolicy, InterceptionPoint, Limits, Manifest, Runtime};
use std::sync::Arc;

struct Classifier {
    severity: i64,
    calls: std::sync::atomic::AtomicUsize,
}

impl agent_control_spec::annotation::AnnotatorDispatcher for Classifier {
    fn dispatch(
        &self,
        _name: &str,
        _annotator: &agent_control_spec::annotation::AnnotatorInvocation,
        _prelim: &serde_json::Value,
    ) -> Result<serde_json::Value, agent_control_spec::RuntimeError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({ "severity": self.severity }))
    }
}

struct Broken;

impl agent_control_spec::annotation::AnnotatorDispatcher for Broken {
    fn dispatch(
        &self,
        _name: &str,
        _annotator: &agent_control_spec::annotation::AnnotatorInvocation,
        _prelim: &serde_json::Value,
    ) -> Result<serde_json::Value, agent_control_spec::RuntimeError> {
        Err(agent_control_spec::RuntimeError::AnnotationFailed(
            "classifier unreachable".to_string(),
        ))
    }
}

fn hook(
    hooks_manifest: &str,
    dispatcher: Arc<dyn agent_control_spec::annotation::AnnotatorDispatcher>,
) -> (String, Option<String>) {
    let manifest = Manifest::from_path(hooks_manifest).expect("hooks manifest");
    let runtime = Runtime::new(manifest, dispatcher, Arc::new(BindingPolicyDispatcher::new()))
        .expect("hooks runtime");
    let ctx: serde_json::Value =
        serde_json::from_str(r#"{"interception_point":"input","input":"hello"}"#).expect("ctx");
    let verdict = runtime.evaluate(&ctx).verdict;
    (
        format!("{:?}", verdict.decision).to_lowercase(),
        verdict.reason.clone(),
    )
}

struct DependencyAnnotator {
    calls: std::sync::Mutex<Vec<serde_json::Value>>,
}

impl agent_control_spec::AnnotatorDispatcher for DependencyAnnotator {
    fn dispatch(
        &self,
        name: &str,
        invocation: &agent_control_spec::AnnotatorInvocation,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, agent_control_spec::RuntimeError> {
        let annotations = &input["annotations"];
        let target = &input["policy_target"]["value"];
        let needs = invocation.field("needs");
        self.calls.lock().expect("calls").push(serde_json::json!({
            "name": name,
            "from": invocation.input_from(),
            "input": target,
            "annotations": annotations,
            "needs_present": needs.is_some(),
            "needs": needs,
        }));
        match name {
            "source" => Ok(serde_json::json!({ "blocked": target["blocked"] })),
            "judge" => {
                let source_blocked = annotations.get("source")
                    .map(|source| source["blocked"].as_bool().expect("source blocked"))
                    .unwrap_or(false);
                let basis = if needs.is_some() { "legacy_needs" }
                    else if source_blocked { "source_blocked" } else { "clear" };
                Ok(serde_json::json!({
                    "blocked": needs.is_some() || source_blocked,
                    "basis": basis,
                }))
            }
            _ => Err(agent_control_spec::RuntimeError::AnnotationFailed(
                format!("unexpected annotator: {name}"),
            )),
        }
    }
}

struct DependencyPolicy {
    judge: std::sync::Mutex<Option<serde_json::Value>>,
}

impl agent_control_spec::PolicyDispatcher for DependencyPolicy {
    fn evaluate(
        &self,
        invocation: &agent_control_spec::PreparedPolicyInvocation,
    ) -> Result<serde_json::Value, agent_control_spec::RuntimeError> {
        let judge = &invocation.policy_input().expect("policy input")["annotations"]["judge"];
        *self.judge.lock().expect("judge") = Some(judge.clone());
        Ok(serde_json::json!({
            "decision": if judge["blocked"].as_bool().expect("judge blocked") {
                "deny"
            } else {
                "allow"
            },
            "reason": judge["basis"],
        }))
    }
}

fn dependency_case(path: &str, blocked: bool) -> serde_json::Value {
    let annotator = Arc::new(DependencyAnnotator {
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let policy = Arc::new(DependencyPolicy {
        judge: std::sync::Mutex::new(None),
    });
    let runtime = Runtime::new(
        Manifest::from_path(path).expect("dependency manifest"),
        annotator.clone(),
        policy.clone(),
    ).expect("dependency runtime");
    let verdict = runtime.evaluate(&serde_json::json!({
        "interception_point": "input", "input": { "blocked": blocked },
    })).verdict;
    let calls = annotator.calls.lock().expect("calls").clone();
    let judge = policy.judge.lock().expect("judge").clone();
    serde_json::json!({
        "calls": calls,
        "judge": judge,
        "decision": format!("{:?}", verdict.decision).to_lowercase(),
        "reason": verdict.reason,
    })
}

fn main() {
    let manifest_path = std::env::args().nth(1).expect("manifest path");
    let text = std::env::args().nth(2).expect("text");
    let hooks_manifest = std::env::args().nth(3).expect("hooks manifest");
    let dependencies_manifest = std::env::args().nth(4).expect("dependencies manifest");
    let legacy_manifest = std::env::args().nth(5).expect("legacy manifest");

    let validate_good = match Manifest::from_path(&manifest_path) {
        Ok(_) => "ok",
        Err(_) => "rejected",
    };
    let validate_bad = match Manifest::from_yaml_str(BAD_MANIFEST) {
        Ok(_) => "ok",
        Err(_) => "rejected",
    };

    let manifest = Manifest::from_path(&manifest_path).expect("manifest");
    let runtime = Runtime::new(
        manifest.clone(),
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .expect("runtime");

    let allow: serde_json::Value = serde_json::from_str(ALLOW_CONTEXT).expect("allow ctx");
    let deny: serde_json::Value = serde_json::from_str(DENY_CONTEXT).expect("deny ctx");
    let allow_verdict = runtime.evaluate(&allow).verdict;
    let deny_verdict = runtime.evaluate(&deny).verdict;

    let policy = ActivatedPolicy::activate_with(
        manifest,
        default_annotator_dispatcher(),
        Arc::new(BindingPolicyDispatcher::new()),
    )
    .expect("activate");
    let binds_input = policy
        .intervention_points()
        .iter()
        .any(|p| format!("{p:?}").to_lowercase() == "input");
    let activated = policy
        .evaluate(InterceptionPoint::Input, allow.clone())
        .verdict;

    let mut session = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec![],
        response_tasks: vec!["pii".to_string()],
    })
    .expect("session");
    let received = session
        .observe_text(StreamSourceType::ModelGenerated, &text)
        .expect("observe");
    let before = session.safe_offset(StreamTrack::Response);
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, received).expect("span");
    session
        .record_outcome("pii", &span, SegmentOutcome::Cleared)
        .expect("outcome");
    let advanced = session.advance(StreamTrack::Response);
    let after = session.safe_offset(StreamTrack::Response);
    let confirmed = session.watermark(StreamTrack::Response).confirmed();
    let completion = session.finish();

    let benign = Arc::new(Classifier {
        severity: 1,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let b = hook(&hooks_manifest, benign.clone());
    let hh = hook(
        &hooks_manifest,
        Arc::new(Classifier {
            severity: 7,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }),
    );
    let f = hook(&hooks_manifest, Arc::new(Broken));
    let parsed = Manifest::from_yaml_str(&std::fs::read_to_string(&manifest_path).expect("read"))
        .expect("parse");
    let parsed_json = serde_json::to_value(&parsed).expect("parsed json");
    let art = |bundles: &str| -> (usize, Option<String>) {
        let parsed: std::collections::BTreeMap<String, agent_control_spec::InMemoryRegoBundle> =
            serde_json::from_str(bundles).expect("bundles");
        match ActivatedPolicy::activate_from_memory(REGO_MANIFEST, parsed) {
            Ok(_) => (0, None),
            Err(e) => (1, Some(e.reason().to_string())),
        }
    };
    let mut residue = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec![],
        response_tasks: vec!["pii".into()],
    })
    .expect("residue session");
    residue
        .observe_text(StreamSourceType::ModelGenerated, "hello")
        .expect("observe");
    let residue_done = residue.finish();
    let residue_json = agent_control_spec::wire::completion_json(&residue_done);

    let big_ctx: serde_json::Value =
        serde_json::from_str(BIG_CTX).expect("big ctx");
    let lim = |limits: Limits| -> (String, Option<String>) {
        let manifest = Manifest::from_path(&hooks_manifest).expect("hooks manifest");
        let rt = Runtime::with_limits(
            manifest,
            Arc::new(Classifier { severity: 1, calls: std::sync::atomic::AtomicUsize::new(0) }),
            Arc::new(BindingPolicyDispatcher::new()),
            limits,
        )
        .expect("limited runtime");
        let v = rt.evaluate(&big_ctx).verdict;
        (format!("{:?}", v.decision).to_lowercase(), v.reason.clone())
    };
    let lim_default = lim(Limits::default());
    let lim_capped = lim(Limits { max_snapshot_bytes: 64, ..Limits::default() });

    let art_only = art("{}");
    let art_good = art(GOOD_BUNDLES);
    let art_bad = art(BAD_BUNDLES);
    let bad_diag_value = match Manifest::from_yaml_str(BAD_MANIFEST) {
        Err(e) => Some(agent_control_spec::wire::diagnostic_json(&e)),
        Ok(m) => m.validate().err().map(|e| agent_control_spec::wire::diagnostic_json(&e)),
    };
    let mut bad_diag_keys: Vec<String> = bad_diag_value
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    bad_diag_keys.sort();
    let bad_diag_code = bad_diag_value
        .as_ref()
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let bad_diag_field = bad_diag_value
        .as_ref()
        .and_then(|v| v.get("field"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let bad_diags = usize::from(bad_diag_value.is_some());
    let good_diags = usize::from(
        Manifest::from_yaml_str(&std::fs::read_to_string(&manifest_path).expect("read"))
            .and_then(|m| m.validate())
            .is_err(),
    );

    let mut output = serde_json::json!({
            "hook_benign_decision": b.0,
            "hook_harmful_decision": hh.0,
            "hook_harmful_reason": hh.1,
            "hook_failure_decision": f.0,
            "hook_failure_reason": f.1,
            "hook_dispatcher_calls": benign.calls.load(std::sync::atomic::Ordering::SeqCst),
            "parsed_has_points": parsed_json.get("intervention_points").is_some(),
            "diagnostics_on_bad": bad_diags,
            "diagnostic_keys": bad_diag_keys,
            "diagnostic_code": bad_diag_code,
            "diagnostic_field": bad_diag_field,
            "diagnostics_on_good": good_diags,
            "artifacts_manifest_only": art_only.0,
            "artifacts_good_rego": art_good.0,
            "artifacts_bad_rego": art_bad.0,
            "artifacts_bad_rego_code": art_bad.1,
            "limits_default_decision": lim_default.0,
            "limits_capped_decision": lim_capped.0,
            "limits_capped_reason": lim_capped.1,
            "residue_kind": residue_json["reason"]["kind"],
            "residue_reason": residue_json["reason"]["reason"],
            "residue_clean": residue_json["is_clean"],
            "supported_versions_nonempty": !agent_control_spec::SUPPORTED_VERSIONS.is_empty(),
            "validate_good": validate_good,
            "validate_bad": validate_bad,
            "interceptor_name": "acs",
            "allow_decision": format!("{:?}", allow_verdict.decision).to_lowercase(),
            "deny_decision": format!("{:?}", deny_verdict.decision).to_lowercase(),
            "deny_reason": deny_verdict.reason.clone(),
            "binds_input": binds_input,
            "activated_allow_decision": format!("{:?}", activated.decision).to_lowercase(),
            "received": received,
            "safe_offset_before": before,
            "advanced": advanced,
            "safe_offset_after": after,
            "confirmed": confirmed,
            "is_clean": completion.reason.is_clean(),
            "transformed": completion.transformed,
            "safe_offset_settled": session.safe_offset(StreamTrack::Response),
        });
    output["supports_dependency_version"] =
        agent_control_spec::SUPPORTED_VERSIONS.contains(&DEPENDENCY_VERSION).into();
    output["supports_legacy_version"] =
        agent_control_spec::SUPPORTED_VERSIONS.contains(&LEGACY_VERSION).into();
    output["dependency_new_blocked"] = dependency_case(&dependencies_manifest, true);
    output["dependency_new_clear"] = dependency_case(&dependencies_manifest, false);
    output["dependency_legacy"] = dependency_case(&legacy_manifest, false);
    let mut supported_versions = agent_control_spec::SUPPORTED_VERSIONS.to_vec();
    supported_versions.sort_unstable();
    let source = std::fs::read_to_string(&dependencies_manifest).expect("dependency fixture");
    let work = std::path::Path::new(&legacy_manifest).parent().expect("temporary workspace");
    let mut version_cases = serde_json::Map::new();
    for (index, version) in supported_versions.iter().enumerate() {
        let path = work.join(format!("rust-{index}.yaml"));
        std::fs::write(&path, source.replacen(DEPENDENCY_VERSION, version, 1))
            .expect("versioned dependency fixture");
        let path = path.to_str().expect("fixture path");
        version_cases.insert((*version).to_string(), serde_json::json!({
            "blocked": dependency_case(path, true),
            "clear": dependency_case(path, false),
        }));
    }
    output["supported_versions"] = serde_json::json!(supported_versions);
    output["dependency_by_version"] = version_cases.into();
    println!("{output}");
}
"""


def rust(legacy_manifest: Path) -> dict:
    work = ROOT / "target" / "parity-rs"
    work.mkdir(parents=True, exist_ok=True)
    (work / "main.rs").write_text(
        RUST_MAIN.replace("BAD_MANIFEST", json.dumps(BAD_MANIFEST))
        .replace("ALLOW_CONTEXT", json.dumps(json.dumps(ALLOW_CONTEXT)))
        .replace("DENY_CONTEXT", json.dumps(json.dumps(DENY_CONTEXT)))
        .replace("REGO_MANIFEST", json.dumps(REGO_MANIFEST))
        .replace("GOOD_BUNDLES", json.dumps(json.dumps(GOOD_BUNDLES)))
        .replace("BAD_BUNDLES", json.dumps(json.dumps(BAD_BUNDLES)))
        .replace("DEPENDENCY_VERSION", json.dumps(DEPENDENCY_VERSION))
        .replace("LEGACY_VERSION", json.dumps(LEGACY_VERSION))
        .replace(
            "BIG_CTX",
            json.dumps(json.dumps({"interception_point": "input", "input": BIG_INPUT})),
        )
    )
    (work / "Cargo.toml").write_text(
        f"""
[package]
name = "acs-parity"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "acs-parity"
path = "main.rs"

[dependencies]
agent-control-spec = {{ path = "{ROOT / "engine"}", features = ["default-dispatchers", "streaming"] }}
serde_json = "1"

[workspace]
"""
    )
    return _run(
        [
            "cargo",
            "run",
            "--quiet",
            "--release",
            "--manifest-path",
            str(work / "Cargo.toml"),
            "--",
            str(MANIFEST),
            TEXT,
            str(HOOKS_MANIFEST),
            str(DEPENDENCIES_MANIFEST),
            str(legacy_manifest),
        ]
    )


def python_binding(legacy_manifest: Path) -> dict:
    script = f"""
import json
from pathlib import Path
from agent_control_spec import (
    AcsInterceptor, ActivatedPolicy, StreamSession,
    supported_manifest_versions, validate_manifest,
    parse_manifest, validate_manifest_detailed, validate_artifacts,
)

def check(source):
    try:
        validate_manifest(source)
        return "ok"
    except Exception:
        return "rejected"

interceptor = AcsInterceptor({str(MANIFEST)!r})
allow = interceptor.intercept({ALLOW_CONTEXT!r})
deny = interceptor.intercept({DENY_CONTEXT!r})

policy = ActivatedPolicy({str(MANIFEST)!r})
points = [str(p).lower() for p in policy.intervention_points]
activated = policy.evaluate("input", {ALLOW_CONTEXT!r})

session = StreamSession(safety_level="blocking", response_tasks=["pii"])
received = session.observe_text("model_generated", {TEXT!r})
before = session.safe_offset("response")
session.record_outcome("pii", "model_generated", 0, received, "cleared")
advanced = session.advance("response")
after = session.safe_offset("response")
confirmed = session.watermark("response")["confirmed"]
completion = session.finish()

def decision(v):
    d = getattr(v, "decision", None)
    return str(getattr(d, "value", d)).lower()


class _Classifier:
    def __init__(self, sev): self.sev = sev; self.calls = 0
    def dispatch(self, name, annotator, prelim):
        self.calls += 1
        return {{"severity": self.sev}}

class _Broken:
    def dispatch(self, *a, **k):
        raise RuntimeError("classifier unreachable")

def _hook(dispatcher):
    i = AcsInterceptor({str(HOOKS_MANIFEST)!r}, annotator_dispatcher=dispatcher)
    v = i.intercept({{"interception_point": "input", "input": "hello"}})
    return (str(getattr(v.decision, "value", v.decision)).lower(), v.reason)

def dependency_case(path, blocked):
    calls = []
    seen_judge = None

    def annotate(name, invocation, policy_input):
        annotations = policy_input["annotations"]
        target = policy_input["policy_target"]["value"]
        has_needs = "needs" in invocation
        calls.append({{
            "name": name, "from": invocation["from"], "input": target,
            "annotations": annotations, "needs_present": has_needs,
            "needs": invocation.get("needs"),
        }})
        if name == "source":
            return {{"blocked": target["blocked"]}}
        if name != "judge":
            raise ValueError(f"unexpected annotator: {{name}}")
        source_blocked = annotations["source"]["blocked"] if "source" in annotations else False
        basis = "legacy_needs" if has_needs else ("source_blocked" if source_blocked else "clear")
        return {{"blocked": has_needs or source_blocked, "basis": basis}}

    def evaluate(invocation):
        nonlocal seen_judge
        seen_judge = invocation["input"]["annotations"]["judge"]
        return {{
            "decision": "deny" if seen_judge["blocked"] else "allow",
            "reason": seen_judge["basis"],
        }}

    runtime = AcsInterceptor(path, annotator_dispatcher=annotate, policy_dispatcher=evaluate)
    verdict = runtime.intercept({{"interception_point": "input", "input": {{"blocked": blocked}}}})
    return {{"calls": calls, "judge": seen_judge, "decision": decision(verdict), "reason": verdict.reason}}

_supported_versions = sorted(supported_manifest_versions())
_dependency_source = Path({str(DEPENDENCIES_MANIFEST)!r}).read_text()
_dependency_by_version = {{}}
for _index, _version in enumerate(_supported_versions):
    _path = Path({str(legacy_manifest.parent)!r}) / f"python-{{_index}}.yaml"
    _path.write_text(_dependency_source.replace({DEPENDENCY_VERSION!r}, _version, 1))
    _dependency_by_version[_version] = {{
        "blocked": dependency_case(str(_path), True),
        "clear": dependency_case(str(_path), False),
    }}

_benign = _Classifier(1)
_b = _hook(_benign)
_h = _hook(_Classifier(7))
_f = _hook(_Broken())
_parsed = parse_manifest(open({str(MANIFEST)!r}).read())
_bad_diags = validate_manifest_detailed({BAD_MANIFEST!r})
_good_diags = validate_manifest_detailed(open({str(MANIFEST)!r}).read())
_art_only = validate_artifacts({REGO_MANIFEST!r})
_art_good = validate_artifacts({REGO_MANIFEST!r}, {GOOD_BUNDLES!r})
_art_bad = validate_artifacts({REGO_MANIFEST!r}, {BAD_BUNDLES!r})

_big_ctx = {{"interception_point": "input", "input": {BIG_INPUT!r}}}
_lim_default = AcsInterceptor({str(HOOKS_MANIFEST)!r}, annotator_dispatcher=_Classifier(1)).intercept(_big_ctx)
_res = StreamSession(safety_level="blocking", response_tasks=["pii"])
_res.observe_text("model_generated", "hello")
_res_done = _res.finish()

_lim_capped = AcsInterceptor(
    {str(HOOKS_MANIFEST)!r}, annotator_dispatcher=_Classifier(1), limits={SMALL_CAP!r}
).intercept(_big_ctx)

print(json.dumps({{
    "hook_benign_decision": _b[0],
    "hook_harmful_decision": _h[0],
    "hook_harmful_reason": _h[1],
    "hook_failure_decision": _f[0],
    "hook_failure_reason": _f[1],
    "hook_dispatcher_calls": _benign.calls,
    "parsed_has_points": "intervention_points" in _parsed,
    "diagnostics_on_bad": len(_bad_diags),
    "diagnostic_keys": sorted(_bad_diags[0]) if _bad_diags else [],
    "diagnostic_code": _bad_diags[0].get("code") if _bad_diags else None,
    "diagnostic_field": _bad_diags[0].get("field") if _bad_diags else None,
    "diagnostics_on_good": len(_good_diags),
    "artifacts_manifest_only": len(_art_only),
    "artifacts_good_rego": len(_art_good),
    "artifacts_bad_rego": len(_art_bad),
    "artifacts_bad_rego_code": _art_bad[0]["code"] if _art_bad else None,
    "limits_default_decision": decision(_lim_default),
    "limits_capped_decision": decision(_lim_capped),
    "limits_capped_reason": _lim_capped.reason,
    "residue_kind": _res_done["reason"]["kind"],
    "residue_reason": _res_done["reason"].get("reason"),
    "residue_clean": _res_done["is_clean"],
    "supported_versions_nonempty": len(_supported_versions) > 0,
    "supports_dependency_version": {DEPENDENCY_VERSION!r} in _supported_versions,
    "supports_legacy_version": {LEGACY_VERSION!r} in _supported_versions,
    "supported_versions": _supported_versions,
    "dependency_by_version": _dependency_by_version,
    "dependency_new_blocked": dependency_case({str(DEPENDENCIES_MANIFEST)!r}, True),
    "dependency_new_clear": dependency_case({str(DEPENDENCIES_MANIFEST)!r}, False),
    "dependency_legacy": dependency_case({str(legacy_manifest)!r}, False),
    "validate_good": check(open({str(MANIFEST)!r}).read()),
    "validate_bad": check({BAD_MANIFEST!r}),
    "interceptor_name": interceptor.name,
    "allow_decision": decision(allow),
    "deny_decision": decision(deny),
    "deny_reason": deny.reason,
    "binds_input": "input" in points,
    "activated_allow_decision": decision(activated),
    "received": received,
    "safe_offset_before": before,
    "advanced": advanced,
    "safe_offset_after": after,
    "confirmed": confirmed,
    "is_clean": completion["is_clean"],
    "transformed": completion["transformed"],
    "safe_offset_settled": session.safe_offset("response"),
}}))
"""
    return _run([sys.executable, "-c", script])


def node(legacy_manifest: Path) -> dict:
    script = f"""
const fs = require('fs');
const acs = require('./dist/index.js');

function check(source) {{
  try {{ acs.validateManifest(source); return 'ok'; }}
  catch (e) {{ return 'rejected'; }}
}}

const interceptor = acs.AcsInterceptor.fromPath({json.dumps(str(MANIFEST))});
const allow = interceptor.intercept({json.dumps(ALLOW_CONTEXT)});
const deny = interceptor.intercept({json.dumps(DENY_CONTEXT)});

const policy = acs.ActivatedPolicy.activate({json.dumps(str(MANIFEST))});
const points = policy.interventionPoints().map((p) => String(p).toLowerCase());
const activated = policy.evaluate('input', {json.dumps(ALLOW_CONTEXT)});

const session = new acs.StreamSession({{ safetyLevel: 'blocking', responseTasks: ['pii'] }});
const received = session.observeText('model_generated', {json.dumps(TEXT)});
const before = session.safeOffset('response');
session.recordOutcome('pii', 'model_generated', 0, received, 'cleared');
const advanced = session.advance('response');
const after = session.safeOffset('response');
const confirmed = session.watermark('response').confirmed;
const completion = session.finish();

function hook(d) {{
  const i = acs.AcsInterceptor.fromPath({json.dumps(str(HOOKS_MANIFEST))}, {{ annotatorDispatcher: d }});
  const v = i.intercept({{ interception_point: 'input', input: 'hello' }});
  return [String(v.decision).toLowerCase(), v.reason ?? null];
}}
function dependencyCase(path, blocked) {{
  const calls = [];
  let judge = null;
  const annotatorDispatcher = (name, invocation, policyInput) => {{
    const annotations = policyInput.annotations;
    const target = policyInput.policy_target.value;
    const hasNeeds = Object.prototype.hasOwnProperty.call(invocation, 'needs');
    calls.push({{
      name, from: invocation.from, input: target, annotations,
      needs_present: hasNeeds, needs: hasNeeds ? invocation.needs : null,
    }});
    if (name === 'source') return {{ blocked: target.blocked }};
    if (name !== 'judge') throw new Error(`unexpected annotator: ${{name}}`);
    const sourceBlocked = Object.prototype.hasOwnProperty.call(annotations, 'source')
      ? annotations.source.blocked : false;
    return {{
      blocked: hasNeeds || sourceBlocked,
      basis: hasNeeds ? 'legacy_needs' : (sourceBlocked ? 'source_blocked' : 'clear'),
    }};
  }};
  const policyDispatcher = (invocation) => {{
    judge = invocation.input.annotations.judge;
    return {{ decision: judge.blocked ? 'deny' : 'allow', reason: judge.basis }};
  }};
  const runtime = acs.AcsInterceptor.fromPath(path, {{ annotatorDispatcher, policyDispatcher }});
  const verdict = runtime.intercept({{ interception_point: 'input', input: {{ blocked }} }});
  return {{ calls, judge, decision: String(verdict.decision).toLowerCase(), reason: verdict.reason ?? null }};
}}
const supportedVersions = [...acs.supportedManifestVersions()].sort();
const dependencySource = fs.readFileSync({json.dumps(str(DEPENDENCIES_MANIFEST))}, 'utf8');
const dependencyByVersion = {{}};
for (const [index, version] of supportedVersions.entries()) {{
  const path = require('path').join({json.dumps(str(legacy_manifest.parent))}, `node-${{index}}.yaml`);
  fs.writeFileSync(path, dependencySource.replace({json.dumps(DEPENDENCY_VERSION)}, () => version));
  dependencyByVersion[version] = {{
    blocked: dependencyCase(path, true),
    clear: dependencyCase(path, false),
  }};
}}
let hookCalls = 0;
const b = hook(() => {{ hookCalls++; return {{ severity: 1 }}; }});
const hh = hook(() => ({{ severity: 7 }}));
const f = hook(() => {{ throw new Error('classifier unreachable'); }});
const parsed = acs.parseManifest(fs.readFileSync({json.dumps(str(MANIFEST))}, 'utf8'));
const badDiags = acs.validateManifestDetailed({json.dumps(BAD_MANIFEST)});
const goodDiags = acs.validateManifestDetailed(fs.readFileSync({json.dumps(str(MANIFEST))}, 'utf8'));
const artOnly = acs.validateArtifacts({json.dumps(REGO_MANIFEST)});
const artGood = acs.validateArtifacts({json.dumps(REGO_MANIFEST)}, {json.dumps(GOOD_BUNDLES)});
const artBad = acs.validateArtifacts({json.dumps(REGO_MANIFEST)}, {json.dumps(BAD_BUNDLES)});

const res = new acs.StreamSession({{ safetyLevel: 'blocking', responseTasks: ['pii'] }});
res.observeText('model_generated', 'hello');
const resDone = res.finish();

const bigCtx = {{ interception_point: 'input', input: {json.dumps(BIG_INPUT)} }};
const limDefault = acs.AcsInterceptor
  .fromPath({json.dumps(str(HOOKS_MANIFEST))}, {{ annotatorDispatcher: () => ({{ severity: 1 }}) }})
  .intercept(bigCtx);
const limCapped = acs.AcsInterceptor
  .fromPath({json.dumps(str(HOOKS_MANIFEST))}, {{ annotatorDispatcher: () => ({{ severity: 1 }}), limits: {json.dumps(SMALL_CAP)} }})
  .intercept(bigCtx);

console.log(JSON.stringify({{
  hook_benign_decision: b[0],
  hook_harmful_decision: hh[0],
  hook_harmful_reason: hh[1],
  hook_failure_decision: f[0],
  hook_failure_reason: f[1],
  hook_dispatcher_calls: hookCalls,
  parsed_has_points: Object.prototype.hasOwnProperty.call(parsed, 'intervention_points'),
  diagnostics_on_bad: badDiags.length,
  diagnostic_keys: badDiags.length ? Object.keys(badDiags[0]).sort() : [],
  diagnostic_code: badDiags.length ? badDiags[0].code : null,
  diagnostic_field: badDiags.length ? badDiags[0].field : null,
  diagnostics_on_good: goodDiags.length,
  artifacts_manifest_only: artOnly.length,
  artifacts_good_rego: artGood.length,
  artifacts_bad_rego: artBad.length,
  artifacts_bad_rego_code: artBad.length ? artBad[0].code : null,
  limits_default_decision: String(limDefault.decision).toLowerCase(),
  limits_capped_decision: String(limCapped.decision).toLowerCase(),
  limits_capped_reason: limCapped.reason ?? null,
  residue_kind: resDone.reason.kind,
  residue_reason: resDone.reason.reason ?? null,
  residue_clean: resDone.isClean,
  supported_versions_nonempty: supportedVersions.length > 0,
  supports_dependency_version: supportedVersions.includes({json.dumps(DEPENDENCY_VERSION)}),
  supports_legacy_version: supportedVersions.includes({json.dumps(LEGACY_VERSION)}),
  supported_versions: supportedVersions,
  dependency_by_version: dependencyByVersion,
  dependency_new_blocked: dependencyCase({json.dumps(str(DEPENDENCIES_MANIFEST))}, true),
  dependency_new_clear: dependencyCase({json.dumps(str(DEPENDENCIES_MANIFEST))}, false),
  dependency_legacy: dependencyCase({json.dumps(str(legacy_manifest))}, false),
  validate_good: check(fs.readFileSync({json.dumps(str(MANIFEST))}, 'utf8')),
  validate_bad: check({json.dumps(BAD_MANIFEST)}),
  interceptor_name: interceptor.name,
  allow_decision: String(allow.decision).toLowerCase(),
  deny_decision: String(deny.decision).toLowerCase(),
  deny_reason: deny.reason ?? null,
  binds_input: points.includes('input'),
  activated_allow_decision: String(activated.decision).toLowerCase(),
  received,
  safe_offset_before: before,
  advanced,
  safe_offset_after: after,
  confirmed,
  is_clean: completion.isClean,
  transformed: completion.transformed,
  safe_offset_settled: session.safeOffset('response'),
}}));
"""
    return _run(["node", "-e", script], cwd=ROOT / "sdk" / "node")


DOTNET_PROGRAM = """
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentControlSpec;
using AgentHooks;

static string Check(Action f)
{
    try { f(); return "ok"; } catch { return "rejected"; }
}

var manifest = MANIFEST_PATH;
using var interceptor = AcsInterceptor.FromPath(manifest);
var allowCtx = new AgentContext(JsonNode.Parse(ALLOW_JSON)!.AsObject());
var denyCtx = new AgentContext(JsonNode.Parse(DENY_JSON)!.AsObject());
var allow = await interceptor.InterceptAsync(allowCtx);
var deny = await interceptor.InterceptAsync(denyCtx);

using var policy = AcsPolicy.Activate(manifest);
var points = policy.InterventionPoints.Select(p => p.ToString().ToLowerInvariant()).ToList();
var activated = policy.Evaluate(InterceptionPoint.Input, ALLOW_JSON);

using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
var received = session.ObserveText(StreamSourceType.ModelGenerated, TEXT_LITERAL);
var before = session.SafeOffset(StreamTrack.Response);
session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, received, SegmentOutcome.Cleared);
var advanced = session.Advance(StreamTrack.Response);
var after = session.SafeOffset(StreamTrack.Response);
var confirmed = session.Watermark(StreamTrack.Response).Confirmed;
var completion = session.Finish();

static (string, string?) Hook(AnnotatorDispatcher d)
{
    using var i = AcsHostInterceptor.FromPath(HOOKS_MANIFEST, annotator: d);
    var v = i.InterceptAsync(new AgentContext(JsonNode.Parse(ALLOW_JSON)!.AsObject())).AsTask().Result;
    return (v.Decision.ToString().ToLowerInvariant(), v.Reason);
}

static object DependencyCase(string path, bool blocked)
{
    var calls = new List<object>();
    JsonElement? judge = null;
    using var runtime = AcsHostInterceptor.FromPath(
        path,
        annotator: (name, invocationJson, policyInputJson) =>
        {
            using var invocation = JsonDocument.Parse(invocationJson);
            using var input = JsonDocument.Parse(policyInputJson);
            var annotations = input.RootElement.GetProperty("annotations");
            var target = input.RootElement.GetProperty("policy_target").GetProperty("value");
            var hasNeeds = invocation.RootElement.TryGetProperty("needs", out var needs);
            calls.Add(new Dictionary<string, object?>
            {
                ["name"] = name,
                ["from"] = invocation.RootElement.GetProperty("from").GetString(),
                ["input"] = target.Clone(),
                ["annotations"] = annotations.Clone(),
                ["needs_present"] = hasNeeds,
                ["needs"] = hasNeeds ? needs.Clone() : (object?)null,
            });
            if (name == "source")
                return JsonSerializer.Serialize(new { blocked = target.GetProperty("blocked").GetBoolean() });
            if (name != "judge")
                throw new InvalidOperationException($"unexpected annotator: {name}");
            var sourceBlocked = annotations.TryGetProperty("source", out var source)
                && source.GetProperty("blocked").GetBoolean();
            return JsonSerializer.Serialize(new
            {
                blocked = hasNeeds || sourceBlocked,
                basis = hasNeeds ? "legacy_needs" : (sourceBlocked ? "source_blocked" : "clear"),
            });
        },
        policy: invocationJson =>
        {
            using var invocation = JsonDocument.Parse(invocationJson);
            var output = invocation.RootElement.GetProperty("input").GetProperty("annotations").GetProperty("judge");
            judge = output.Clone();
            return JsonSerializer.Serialize(new
            {
                decision = output.GetProperty("blocked").GetBoolean() ? "deny" : "allow",
                reason = output.GetProperty("basis").GetString(),
            });
        });
    var context = new AgentContext(JsonNode.Parse(JsonSerializer.Serialize(new
    {
        interception_point = "input", input = new { blocked },
    }))!.AsObject());
    var verdict = runtime.InterceptAsync(context).AsTask().Result;
    return new { calls, judge, decision = verdict.Decision.ToString().ToLowerInvariant(), reason = verdict.Reason };
}

var supportedVersions = AcsManifest.SupportedVersions().OrderBy(v => v, StringComparer.Ordinal).ToList();
var dependencySource = File.ReadAllText(DEPENDENCIES_MANIFEST);
var dependencyByVersion = new Dictionary<string, object>();
for (var index = 0; index < supportedVersions.Count; index++)
{
    var version = supportedVersions[index];
    var path = Path.Combine(Path.GetDirectoryName(LEGACY_MANIFEST)!, $"dotnet-{index}.yaml");
    File.WriteAllText(path, dependencySource.Replace(DEPENDENCY_VERSION, version));
    dependencyByVersion[version] = new
    {
        blocked = DependencyCase(path, true),
        clear = DependencyCase(path, false),
    };
}

var hookCalls = 0;
var b = Hook((_, _, _) => { hookCalls++; return SEV1; });
var hh = Hook((_, _, _) => SEV7);
var f = Hook((_, _, _) => throw new InvalidOperationException("classifier unreachable"));
var parsed = AcsManifestTools.Parse(File.ReadAllText(manifest));
var badDiags = AcsManifestTools.Diagnostics(BAD_JSON);
var goodDiags = AcsManifestTools.Diagnostics(File.ReadAllText(manifest));
var artOnly = AcsManifestTools.ValidateArtifacts(REGO_MANIFEST, null);
var artGood = AcsManifestTools.ValidateArtifacts(REGO_MANIFEST, GOOD_BUNDLES);
var artBad = AcsManifestTools.ValidateArtifacts(REGO_MANIFEST, BAD_BUNDLES);

using var residue = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
residue.ObserveText(StreamSourceType.ModelGenerated, "hello");
var residueDone = residue.Finish();

var bigCtx = new AgentContext(JsonNode.Parse(BIG_CTX)!.AsObject());
using var limDefault = AcsHostInterceptor.FromPath(HOOKS_MANIFEST, annotator: (_, _, _) => SEV1);
using var limCapped = AcsHostInterceptor.FromPath(
    HOOKS_MANIFEST, annotator: (_, _, _) => SEV1, limits: SMALL_CAP);
var limDefaultVerdict = limDefault.InterceptAsync(bigCtx).AsTask().Result;
var limCappedVerdict = limCapped.InterceptAsync(bigCtx).AsTask().Result;

Console.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
{
    ["hook_benign_decision"] = b.Item1,
    ["hook_harmful_decision"] = hh.Item1,
    ["hook_harmful_reason"] = hh.Item2,
    ["hook_failure_decision"] = f.Item1,
    ["hook_failure_reason"] = f.Item2,
    ["hook_dispatcher_calls"] = hookCalls,
    ["parsed_has_points"] = parsed.Contains("intervention_points"),
    ["diagnostics_on_bad"] = badDiags.Count,
    ["diagnostic_keys"] = badDiags.Count > 0
        ? JsonSerializer.Deserialize<Dictionary<string, object?>>(
            JsonSerializer.Serialize(badDiags[0]))!.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList()
        : new List<string>(),
    ["diagnostic_code"] = badDiags.Count > 0 ? badDiags[0].Code : null,
    ["diagnostic_field"] = badDiags.Count > 0 ? badDiags[0].Field : null,
    ["diagnostics_on_good"] = goodDiags.Count,
    ["artifacts_manifest_only"] = artOnly.Count,
    ["artifacts_good_rego"] = artGood.Count,
    ["artifacts_bad_rego"] = artBad.Count,
    ["artifacts_bad_rego_code"] = artBad.Count > 0 ? artBad[0].Code : null,
    ["limits_default_decision"] = limDefaultVerdict.Decision.ToString().ToLowerInvariant(),
    ["limits_capped_decision"] = limCappedVerdict.Decision.ToString().ToLowerInvariant(),
    ["limits_capped_reason"] = limCappedVerdict.Reason,
    ["residue_kind"] = residueDone.Reason.Kind,
    ["residue_reason"] = residueDone.Reason.Reason,
    ["residue_clean"] = residueDone.IsClean,
    ["supported_versions_nonempty"] = supportedVersions.Count > 0,
    ["supports_dependency_version"] = supportedVersions.Contains(DEPENDENCY_VERSION),
    ["supports_legacy_version"] = supportedVersions.Contains(LEGACY_VERSION),
    ["supported_versions"] = supportedVersions,
    ["dependency_by_version"] = dependencyByVersion,
    ["dependency_new_blocked"] = DependencyCase(DEPENDENCIES_MANIFEST, true),
    ["dependency_new_clear"] = DependencyCase(DEPENDENCIES_MANIFEST, false),
    ["dependency_legacy"] = DependencyCase(LEGACY_MANIFEST, false),
    ["validate_good"] = Check(() => AcsManifest.Validate(File.ReadAllText(manifest))),
    ["validate_bad"] = Check(() => AcsManifest.Validate(BAD_JSON)),
    ["interceptor_name"] = interceptor.Name,
    ["allow_decision"] = allow.Decision.ToString().ToLowerInvariant(),
    ["deny_decision"] = deny.Decision.ToString().ToLowerInvariant(),
    ["deny_reason"] = deny.Reason,
    ["binds_input"] = points.Contains("input"),
    ["activated_allow_decision"] = activated.Decision.ToString().ToLowerInvariant(),
    ["received"] = received,
    ["safe_offset_before"] = before,
    ["advanced"] = advanced,
    ["safe_offset_after"] = after,
    ["confirmed"] = confirmed,
    ["is_clean"] = completion.IsClean,
    ["transformed"] = completion.Transformed,
    ["safe_offset_settled"] = session.SafeOffset(StreamTrack.Response),
}));
"""


def dotnet(legacy_manifest: Path) -> dict:
    work = Path(tempfile.mkdtemp())
    try:
        app = work / "app"
        subprocess.run(
            ["dotnet", "new", "console", "-o", str(app)],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "dotnet",
                "add",
                str(app),
                "reference",
                str(ROOT / "sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj"),
            ],
            capture_output=True,
            check=True,
        )
        program = (
            DOTNET_PROGRAM.replace("MANIFEST_PATH", json.dumps(str(MANIFEST)))
            .replace("HOOKS_MANIFEST", json.dumps(str(HOOKS_MANIFEST)))
            .replace("DEPENDENCIES_MANIFEST", json.dumps(str(DEPENDENCIES_MANIFEST)))
            .replace("LEGACY_MANIFEST", json.dumps(str(legacy_manifest)))
            .replace("DEPENDENCY_VERSION", json.dumps(DEPENDENCY_VERSION))
            .replace("LEGACY_VERSION", json.dumps(LEGACY_VERSION))
            .replace("SEV1", json.dumps(json.dumps({"severity": 1})))
            .replace("SEV7", json.dumps(json.dumps({"severity": 7})))
            .replace("REGO_MANIFEST", json.dumps(REGO_MANIFEST))
            .replace("GOOD_BUNDLES", json.dumps(json.dumps(GOOD_BUNDLES)))
            .replace("BAD_BUNDLES", json.dumps(json.dumps(BAD_BUNDLES)))
            .replace(
                "BIG_CTX",
                json.dumps(
                    json.dumps({"interception_point": "input", "input": BIG_INPUT})
                ),
            )
            .replace("SMALL_CAP", json.dumps(json.dumps(SMALL_CAP)))
            .replace(
                "__BIGCTX__",
                json.dumps(
                    json.dumps({"interception_point": "input", "input": BIG_INPUT})
                ),
            )
            .replace("__SMALLCAP__", json.dumps(json.dumps(SMALL_CAP)))
            .replace("ALLOW_JSON", json.dumps(json.dumps(ALLOW_CONTEXT)))
            .replace("DENY_JSON", json.dumps(json.dumps(DENY_CONTEXT)))
            .replace("BAD_JSON", json.dumps(BAD_MANIFEST))
            .replace("TEXT_LITERAL", json.dumps(TEXT))
        )
        (app / "Program.cs").write_text(program)
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = str(ROOT / "target" / "release")
        return _run(["dotnet", "run", "--project", str(app), "--nologo"], env=env)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    languages = {
        "rust": rust,
        "python": python_binding,
        "node": node,
        "dotnet": dotnet,
    }

    results: dict[str, dict] = {}
    failed = False
    with tempfile.TemporaryDirectory(prefix="acs-parity-dependencies-") as work:
        legacy_manifest = Path(work) / "legacy-manifest.yaml"
        source = DEPENDENCIES_MANIFEST.read_text()
        if source.count(DEPENDENCY_VERSION) != 1:
            raise ValueError("dependency fixture must declare the new version exactly once")
        legacy_manifest.write_text(source.replace(DEPENDENCY_VERSION, LEGACY_VERSION, 1))
        for name, run in languages.items():
            try:
                results[name] = run(legacy_manifest)
            except subprocess.CalledProcessError as e:
                print(f"{name}: FAILED TO RUN\n{e.stdout}\n{e.stderr}", file=sys.stderr)
                failed = True

    if failed:
        return 1

    # Rust's registry defines parity for every exported version; the fixed
    # goldens above independently pin the current legacy/chaining semantics.
    expected = {
        **EXPECTED,
        "supported_versions": results["rust"]["supported_versions"],
        "dependency_by_version": results["rust"]["dependency_by_version"],
    }
    for name, got in results.items():
        mismatches = {
            k: (expected[k], got.get(k)) for k in expected if got.get(k) != expected[k]
        }
        print(f"{name:8} {'ok' if not mismatches else 'MISMATCH'}")
        print(f"         supported_versions: {got.get('supported_versions')!r}")
        for key, (want, actual) in sorted(mismatches.items()):
            print(f"         {key}: expected {want!r}, got {actual!r}", file=sys.stderr)
            failed = True

    if failed:
        print("\nlanguages disagree about the same inputs", file=sys.stderr)
        return 1

    print(
        f"\nall {len(results)} languages agree across {len(expected)} assertions"
        f" ({len(expected['dependency_by_version'])} supported versions, blocked and clear)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
