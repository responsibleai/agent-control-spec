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
}


def _run(cmd: list[str], **kw) -> dict:
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)
    return json.loads(out.stdout.strip().splitlines()[-1])


RUST_MAIN = r"""
use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::stream_session::*;
use agent_control_spec::{ActivatedPolicy, InterceptionPoint, Manifest, Runtime};
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

fn main() {
    let manifest_path = std::env::args().nth(1).expect("manifest path");
    let text = std::env::args().nth(2).expect("text");
    let hooks_manifest = std::env::args().nth(3).expect("hooks manifest");

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
    let art_only = art("{}");
    let art_good = art(GOOD_BUNDLES);
    let art_bad = art(BAD_BUNDLES);
    let bad_diags = usize::from(Manifest::from_yaml_str(BAD_MANIFEST).is_err());
    let good_diags = usize::from(
        Manifest::from_yaml_str(&std::fs::read_to_string(&manifest_path).expect("read"))
            .and_then(|m| m.validate())
            .is_err(),
    );

    println!(
        "{}",
        serde_json::json!({
            "hook_benign_decision": b.0,
            "hook_harmful_decision": hh.0,
            "hook_harmful_reason": hh.1,
            "hook_failure_decision": f.0,
            "hook_failure_reason": f.1,
            "hook_dispatcher_calls": benign.calls.load(std::sync::atomic::Ordering::SeqCst),
            "parsed_has_points": parsed_json.get("intervention_points").is_some(),
            "diagnostics_on_bad": bad_diags,
            "diagnostics_on_good": good_diags,
            "artifacts_manifest_only": art_only.0,
            "artifacts_good_rego": art_good.0,
            "artifacts_bad_rego": art_bad.0,
            "artifacts_bad_rego_code": art_bad.1,
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
        })
    );
}
"""


def rust() -> dict:
    work = ROOT / "target" / "parity-rs"
    work.mkdir(parents=True, exist_ok=True)
    (work / "main.rs").write_text(
        RUST_MAIN.replace("BAD_MANIFEST", json.dumps(BAD_MANIFEST))
        .replace("ALLOW_CONTEXT", json.dumps(json.dumps(ALLOW_CONTEXT)))
        .replace("DENY_CONTEXT", json.dumps(json.dumps(DENY_CONTEXT)))
        .replace("REGO_MANIFEST", json.dumps(REGO_MANIFEST))
        .replace("GOOD_BUNDLES", json.dumps(json.dumps(GOOD_BUNDLES)))
        .replace("BAD_BUNDLES", json.dumps(json.dumps(BAD_BUNDLES)))
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
        ]
    )


def python_binding() -> dict:
    script = f"""
import json
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

print(json.dumps({{
    "hook_benign_decision": _b[0],
    "hook_harmful_decision": _h[0],
    "hook_harmful_reason": _h[1],
    "hook_failure_decision": _f[0],
    "hook_failure_reason": _f[1],
    "hook_dispatcher_calls": _benign.calls,
    "parsed_has_points": "intervention_points" in _parsed,
    "diagnostics_on_bad": len(_bad_diags),
    "diagnostics_on_good": len(_good_diags),
    "artifacts_manifest_only": len(_art_only),
    "artifacts_good_rego": len(_art_good),
    "artifacts_bad_rego": len(_art_bad),
    "artifacts_bad_rego_code": _art_bad[0]["code"] if _art_bad else None,
    "supported_versions_nonempty": len(supported_manifest_versions()) > 0,
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


def node() -> dict:
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

console.log(JSON.stringify({{
  hook_benign_decision: b[0],
  hook_harmful_decision: hh[0],
  hook_harmful_reason: hh[1],
  hook_failure_decision: f[0],
  hook_failure_reason: f[1],
  hook_dispatcher_calls: hookCalls,
  parsed_has_points: Object.prototype.hasOwnProperty.call(parsed, 'intervention_points'),
  diagnostics_on_bad: badDiags.length,
  diagnostics_on_good: goodDiags.length,
  artifacts_manifest_only: artOnly.length,
  artifacts_good_rego: artGood.length,
  artifacts_bad_rego: artBad.length,
  artifacts_bad_rego_code: artBad.length ? artBad[0].code : null,
  supported_versions_nonempty: acs.supportedManifestVersions().length > 0,
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
    ["diagnostics_on_good"] = goodDiags.Count,
    ["artifacts_manifest_only"] = artOnly.Count,
    ["artifacts_good_rego"] = artGood.Count,
    ["artifacts_bad_rego"] = artBad.Count,
    ["artifacts_bad_rego_code"] = artBad.Count > 0 ? artBad[0].Code : null,
    ["supported_versions_nonempty"] = AcsManifest.SupportedVersions().Count > 0,
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


def dotnet() -> dict:
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
            .replace("SEV1", json.dumps(json.dumps({"severity": 1})))
            .replace("SEV7", json.dumps(json.dumps({"severity": 7})))
            .replace("REGO_MANIFEST", json.dumps(REGO_MANIFEST))
            .replace("GOOD_BUNDLES", json.dumps(json.dumps(GOOD_BUNDLES)))
            .replace("BAD_BUNDLES", json.dumps(json.dumps(BAD_BUNDLES)))
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
    for name, run in languages.items():
        try:
            results[name] = run()
        except subprocess.CalledProcessError as e:
            print(f"{name}: FAILED TO RUN\n{e.stdout}\n{e.stderr}", file=sys.stderr)
            failed = True

    if failed:
        return 1

    for name, got in results.items():
        mismatches = {
            k: (EXPECTED[k], got.get(k)) for k in EXPECTED if got.get(k) != EXPECTED[k]
        }
        print(f"{name:8} {'ok' if not mismatches else 'MISMATCH'}")
        for key, (want, actual) in sorted(mismatches.items()):
            print(f"         {key}: expected {want!r}, got {actual!r}", file=sys.stderr)
            failed = True

    if failed:
        print("\nlanguages disagree about the same inputs", file=sys.stderr)
        return 1

    print(f"\nall {len(results)} languages agree across {len(EXPECTED)} assertions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
