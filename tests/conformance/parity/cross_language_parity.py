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
}


def _run(cmd: list[str], **kw) -> dict:
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)
    return json.loads(out.stdout.strip().splitlines()[-1])


RUST_MAIN = r"""
use agent_control_spec::dispatchers::{default_annotator_dispatcher, BindingPolicyDispatcher};
use agent_control_spec::stream_session::*;
use agent_control_spec::{ActivatedPolicy, InterceptionPoint, Manifest, Runtime};
use std::sync::Arc;

fn main() {
    let manifest_path = std::env::args().nth(1).expect("manifest path");
    let text = std::env::args().nth(2).expect("text");

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

    println!(
        "{}",
        serde_json::json!({
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
        ]
    )


def python_binding() -> dict:
    script = f"""
import json
from agent_control_spec import (
    AcsInterceptor, ActivatedPolicy, StreamSession,
    supported_manifest_versions, validate_manifest,
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


print(json.dumps({{
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

console.log(JSON.stringify({{
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

Console.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
{
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
