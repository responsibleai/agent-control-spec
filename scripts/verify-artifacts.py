#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Build every published artifact and exercise it from a clean install.

The test suites and the parity harness run against this checkout, where
the engine is on the loader path, the TypeScript is in `dist/`, and the
Python package is importable from source. A consumer has none of that.
They have a crate, a wheel, a tarball and a nupkg.

The difference is not theoretical. `ResponsibleAI.AgentControlSpec`
0.4.0-alpha.2 passed its whole suite and threw `DllNotFoundException` on
the first call any consumer made, because the package carried no native
library and CI supplied one through `LD_LIBRARY_PATH`. No test that
imports from the checkout can catch that class of defect.

So this builds the four artifacts the release workflow builds, installs
each into a throwaway project outside the repository, and runs the whole
public surface there: manifest tooling, the host extension points, and
streaming. Every language must answer identically.

Node is packed as two artifacts because napi splits it that way: the
JavaScript package and a per-platform binary package. The published
package.json gains its `optionalDependencies` at publish time, so a
locally packed main tarball cannot resolve the binary on its own and
both halves are installed explicitly here.

Usage: python scripts/verify-artifacts.py [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# NuGet caches by id and version, so a fixed version would let a stale
# package from an earlier run satisfy a later one and report a pass for
# code the artifact does not contain. Stamp each run instead.
CHECK_VERSION = f"0.0.0-artifactcheck{os.getpid()}{int(time.time())}"
HOOKS_MANIFEST = ROOT / "tests" / "conformance" / "parity" / "host-hooks-manifest.yaml"
BAD_MANIFEST = 'agent_control_specification_version: "0.4.0-alpha.1"\nmetadata: {}\n'

REGO_MANIFEST = (
    'agent_control_specification_version: "0.4.0-alpha.1"\n'
    "policies:\n  gate:\n    type: rego\n    bundle: ./b\n"
    'intervention_points:\n  input:\n    policy_target: "$.input"\n'
    "    policy:\n      id: gate\n      query: data.acs.decision\n"
)
BAD_BUNDLES = {"gate": {"modules": {"p.rego": "package acs\nthis is not rego ***\n"}}}

EXPECTED = {
    "non_streaming": True,
    "hook_benign": "allow",
    "hook_harmful": "deny",
    "hook_harmful_reason": "unsafe_content",
    "hook_failure": "deny",
    "hook_failure_reason": "runtime_error:annotation_failed",
    "hook_calls": 1,
    "parse_ok": True,
    "streaming_offset": 5,
    "streaming_clean": True,
    "streaming_settled": None,
    # A manifest the document check passes whose Rego does not compile.
    "artifacts_bad_rego": 1,
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)


def last_json(out: str) -> dict:
    return json.loads(out.strip().splitlines()[-1])


def build(stage: Path) -> dict[str, Path]:
    """Build every artifact the release workflow publishes."""
    art = stage / "artifacts"
    art.mkdir(parents=True, exist_ok=True)

    run(
        [
            "maturin",
            "build",
            "--release",
            "-m",
            str(ROOT / "sdk/python/Cargo.toml"),
            "-o",
            str(art / "py"),
        ]
    )

    run(["npm", "run", "build"], cwd=ROOT / "sdk/node")
    run(
        [
            "npx",
            "napi",
            "build",
            "--release",
            "--platform",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--manifest-path",
            "native/Cargo.toml",
            "--cwd",
            ".",
            "--output-dir",
            ".",
        ],
        cwd=ROOT / "sdk/node",
    )
    for node_binary in (ROOT / "sdk/node").glob("*.node"):
        shutil.copy(node_binary, ROOT / "sdk/node/npm/linux-x64-gnu")
    run(
        ["npm", "pack", "--pack-destination", str(art)],
        cwd=ROOT / "sdk/node",
    )
    run(
        ["npm", "pack", "--pack-destination", str(art)],
        cwd=ROOT / "sdk/node/npm/linux-x64-gnu",
    )

    run(["cargo", "build", "--release", "-p", "agent-control-spec-ffi"], cwd=ROOT)
    native = ROOT / "sdk/dotnet/native/runtimes/linux-x64/native"
    native.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "target/release/libagent_control_spec_ffi.so", native)
    run(
        [
            "dotnet",
            "pack",
            str(ROOT / "sdk/dotnet/src/AgentControlSpec"),
            "-c",
            "Release",
            "-o",
            str(art / "nuget"),
            "--nologo",
            "-p:AcsNativeAssetsRequired=true",
            f"-p:Version={CHECK_VERSION}",
        ]
    )

    run(
        [
            "cargo",
            "package",
            "-p",
            "agent-control-spec",
            "--allow-dirty",
            "--no-verify",
        ],
        cwd=ROOT,
    )
    crate = next((ROOT / "target/package").glob("agent-control-spec-*.crate"))
    unpacked = art / "crate"
    unpacked.mkdir(exist_ok=True)
    run(["tar", "xzf", str(crate), "-C", str(unpacked)])

    return {
        "wheel": next((art / "py").glob("*.whl")),
        "npm_main": next(art.glob("responsibleai-agent-control-spec-[0-9]*.tgz")),
        "npm_native": next(
            art.glob("responsibleai-agent-control-spec-linux-x64-gnu-*.tgz")
        ),
        "nuget_feed": art / "nuget",
        "crate": next(unpacked.glob("agent-control-spec-*")),
    }


PY_PROGRAM = """
import json
from agent_control_spec import (
    AcsInterceptor, StreamSession, supported_manifest_versions,
    parse_manifest, validate_manifest_detailed, validate_artifacts,
)
M = {manifest!r}
class C:
    def __init__(s, v): s.v = v; s.calls = 0
    def dispatch(s, *a): s.calls += 1; return {{"severity": s.v}}
class B:
    def dispatch(s, *a): raise RuntimeError("classifier unreachable")
def hook(d):
    v = AcsInterceptor(M, annotator_dispatcher=d).intercept(
        {{"interception_point": "input", "input": "hi"}})
    return (str(getattr(v.decision, "value", v.decision)).lower(), v.reason)
c = C(1); b = hook(c); h = hook(C(7)); f = hook(B())
s = StreamSession(safety_level="blocking", response_tasks=["pii"])
r = s.observe_text("model_generated", "hello")
s.record_outcome("pii", "model_generated", 0, r, "cleared"); s.advance("response")
off = s.safe_offset("response"); clean = s.finish()["is_clean"]
print(json.dumps({{
    "non_streaming": len(supported_manifest_versions()) > 0,
    "hook_benign": b[0], "hook_harmful": h[0], "hook_harmful_reason": h[1],
    "hook_failure": f[0], "hook_failure_reason": f[1], "hook_calls": c.calls,
    "parse_ok": "intervention_points" in parse_manifest(open(M).read()),
    "streaming_offset": off, "streaming_clean": clean,
    "streaming_settled": s.safe_offset("response"),
    "artifacts_bad_rego": len(validate_artifacts({rego!r}, {bad!r})),
}}))
"""


def check_python(art: dict, stage: Path) -> dict:
    venv = stage / "venv-py"
    run([sys.executable, "-m", "venv", str(venv)])
    run([str(venv / "bin/pip"), "install", "-q", str(art["wheel"])])
    out = run(
        [
            str(venv / "bin/python"),
            "-c",
            PY_PROGRAM.format(
                manifest=str(HOOKS_MANIFEST), rego=REGO_MANIFEST, bad=BAD_BUNDLES
            ),
        ]
    )
    return last_json(out.stdout)


NODE_PROGRAM = """
const acs = require('@responsibleai/agent-control-spec');
const fs = require('fs');
const M = %s;
function hook(d) {
  const i = acs.AcsInterceptor.fromPath(M, { annotatorDispatcher: d });
  const v = i.intercept({ interception_point: 'input', input: 'hi' });
  return [String(v.decision).toLowerCase(), v.reason ?? null];
}
let calls = 0;
const b = hook(() => { calls++; return { severity: 1 }; });
const h = hook(() => ({ severity: 7 }));
const f = hook(() => { throw new Error('classifier unreachable'); });
const s = new acs.StreamSession({ safetyLevel: 'blocking', responseTasks: ['pii'] });
const r = s.observeText('model_generated', 'hello');
s.recordOutcome('pii', 'model_generated', 0, r, 'cleared');
s.advance('response');
const off = s.safeOffset('response');
const clean = s.finish().isClean;
console.log(JSON.stringify({
  non_streaming: acs.supportedManifestVersions().length > 0,
  hook_benign: b[0], hook_harmful: h[0], hook_harmful_reason: h[1],
  hook_failure: f[0], hook_failure_reason: f[1], hook_calls: calls,
  parse_ok: Object.prototype.hasOwnProperty.call(
      acs.parseManifest(fs.readFileSync(M, 'utf8')), 'intervention_points'),
  streaming_offset: off, streaming_clean: clean,
  streaming_settled: s.safeOffset('response'),
  artifacts_bad_rego: acs.validateArtifacts(%s, %s).length,
}));
"""


def check_node(art: dict, stage: Path) -> dict:
    app = stage / "app-node"
    app.mkdir()
    run(["npm", "init", "-y"], cwd=app)
    run(
        ["npm", "install", str(art["npm_native"]), str(art["npm_main"])],
        cwd=app,
    )
    out = run(
        [
            "node",
            "-e",
            NODE_PROGRAM
            % (
                json.dumps(str(HOOKS_MANIFEST)),
                json.dumps(REGO_MANIFEST),
                json.dumps(BAD_BUNDLES),
            ),
        ],
        cwd=app,
    )
    return last_json(out.stdout)


DOTNET_PROGRAM = """
using AgentControlSpec;
using AgentHooks;
using System.Text.Json;
using System.Text.Json.Nodes;

var M = __MANIFEST__;
AgentContext Ctx() => new(JsonNode.Parse(CTX_JSON)!.AsObject());
async Task<(string, string?)> Hook(AnnotatorDispatcher d)
{
    using var i = AcsHostInterceptor.FromPath(M, annotator: d);
    var v = await i.InterceptAsync(Ctx());
    return (v.Decision.ToString().ToLowerInvariant(), v.Reason);
}
var calls = 0;
var b = await Hook((_, _, _) => { calls++; return SEV1; });
var h = await Hook((_, _, _) => SEV7);
var f = await Hook((_, _, _) => throw new InvalidOperationException("classifier unreachable"));
using var s = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
var r = s.ObserveText(StreamSourceType.ModelGenerated, "hello");
s.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, r, SegmentOutcome.Cleared);
s.Advance(StreamTrack.Response);
var off = s.SafeOffset(StreamTrack.Response);
var clean = s.Finish().IsClean;
Console.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
{
    ["non_streaming"] = AcsManifest.SupportedVersions().Count > 0,
    ["hook_benign"] = b.Item1,
    ["hook_harmful"] = h.Item1,
    ["hook_harmful_reason"] = h.Item2,
    ["hook_failure"] = f.Item1,
    ["hook_failure_reason"] = f.Item2,
    ["hook_calls"] = calls,
    ["parse_ok"] = AcsManifestTools.Parse(File.ReadAllText(M)).Contains("intervention_points"),
    ["streaming_offset"] = off,
    ["streaming_clean"] = clean,
    ["streaming_settled"] = s.SafeOffset(StreamTrack.Response),
    ["artifacts_bad_rego"] = AcsManifestTools.ValidateArtifacts(__REGO__, __BADB__).Count,
}));
"""


def check_dotnet(art: dict, stage: Path) -> dict:
    app = stage / "app-net"
    app.mkdir()
    (app / "NuGet.config").write_text(
        f"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="{art["nuget_feed"]}" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
</configuration>
"""
    )
    run(["dotnet", "new", "console", "-o", str(app), "--force"])
    run(
        [
            "dotnet",
            "add",
            str(app),
            "package",
            "ResponsibleAI.AgentControlSpec",
            "--version",
            CHECK_VERSION,
        ]
    )
    program = (
        DOTNET_PROGRAM.replace("__MANIFEST__", json.dumps(str(HOOKS_MANIFEST)))
        .replace(
            "CTX_JSON",
            json.dumps(json.dumps({"interception_point": "input", "input": "hi"})),
        )
        .replace("SEV1", json.dumps(json.dumps({"severity": 1})))
        .replace("SEV7", json.dumps(json.dumps({"severity": 7})))
        .replace("__REGO__", json.dumps(REGO_MANIFEST))
        .replace("__BADB__", json.dumps(json.dumps(BAD_BUNDLES)))
    )
    (app / "Program.cs").write_text(program)
    out = run(["dotnet", "run", "--project", str(app), "--nologo"])
    return last_json(out.stdout)


RUST_MAIN = """
use agent_control_spec::annotation::{AnnotatorDispatcher, AnnotatorInvocation};
use agent_control_spec::dispatchers::BindingPolicyDispatcher;
use agent_control_spec::stream_session::*;
use agent_control_spec::{Manifest, Runtime, RuntimeError};
use std::sync::Arc;

struct C(i64, std::sync::atomic::AtomicUsize);
impl AnnotatorDispatcher for C {
    fn dispatch(&self, _n: &str, _a: &AnnotatorInvocation, _p: &serde_json::Value)
        -> Result<serde_json::Value, RuntimeError> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({"severity": self.0}))
    }
}
struct B;
impl AnnotatorDispatcher for B {
    fn dispatch(&self, _n: &str, _a: &AnnotatorInvocation, _p: &serde_json::Value)
        -> Result<serde_json::Value, RuntimeError> {
        Err(RuntimeError::AnnotationFailed("classifier unreachable".into()))
    }
}
fn hook(m: &str, d: Arc<dyn AnnotatorDispatcher>) -> (String, Option<String>) {
    let manifest = Manifest::from_path(m).expect("manifest");
    let rt = Runtime::new(manifest, d, Arc::new(BindingPolicyDispatcher::new())).expect("runtime");
    let ctx: serde_json::Value =
        serde_json::from_str(r#"{"interception_point":"input","input":"hi"}"#).unwrap();
    let v = rt.evaluate(&ctx).verdict;
    (format!("{:?}", v.decision).to_lowercase(), v.reason.clone())
}
fn main() {
    let m = std::env::args().nth(1).expect("manifest");
    let benign = Arc::new(C(1, std::sync::atomic::AtomicUsize::new(0)));
    let b = hook(&m, benign.clone());
    let h = hook(&m, Arc::new(C(7, std::sync::atomic::AtomicUsize::new(0))));
    let f = hook(&m, Arc::new(B));
    let mut s = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec![],
        response_tasks: vec!["pii".into()],
    }).unwrap();
    let r = s.observe_text(StreamSourceType::ModelGenerated, "hello").unwrap();
    let sp = StreamSpan::new(StreamSourceType::ModelGenerated, 0, r).unwrap();
    s.record_outcome("pii", &sp, SegmentOutcome::Cleared).unwrap();
    s.advance(StreamTrack::Response);
    let off = s.safe_offset(StreamTrack::Response);
    let clean = s.finish().reason.is_clean();
    let bad_bundles: std::collections::BTreeMap<String, agent_control_spec::InMemoryRegoBundle> =
        serde_json::from_str(BAD_BUNDLES).expect("bundles");
    let artifacts_bad_rego = usize::from(
        agent_control_spec::ActivatedPolicy::activate_from_memory(REGO_MANIFEST, bad_bundles)
            .is_err(),
    );
    println!("{}", serde_json::json!({
        "non_streaming": !agent_control_spec::SUPPORTED_VERSIONS.is_empty(),
        "hook_benign": b.0, "hook_harmful": h.0, "hook_harmful_reason": h.1,
        "hook_failure": f.0, "hook_failure_reason": f.1,
        "hook_calls": benign.1.load(std::sync::atomic::Ordering::SeqCst),
        "parse_ok": Manifest::from_yaml_str(&std::fs::read_to_string(&m).unwrap()).is_ok(),
        "streaming_offset": off, "streaming_clean": clean,
        "streaming_settled": s.safe_offset(StreamTrack::Response),
        "artifacts_bad_rego": artifacts_bad_rego,
    }));
}
"""


def check_rust(art: dict, stage: Path) -> dict:
    app = stage / "app-rs"
    (app / "src").mkdir(parents=True)
    (app / "Cargo.toml").write_text(
        f"""[package]
name = "acs-artifact-check"
version = "0.0.0"
edition = "2021"

[dependencies]
agent-control-spec = {{ path = "{art["crate"]}", features = ["default-dispatchers", "streaming"] }}
serde_json = "1"

[workspace]
"""
    )
    (app / "src/main.rs").write_text(
        RUST_MAIN.replace("REGO_MANIFEST", json.dumps(REGO_MANIFEST)).replace(
            "BAD_BUNDLES", json.dumps(json.dumps(BAD_BUNDLES))
        )
    )
    out = run(
        ["cargo", "run", "--quiet", "--release", "--", str(HOOKS_MANIFEST)], cwd=app
    )
    return last_json(out.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--keep", action="store_true", help="keep the staging directory"
    )
    args = parser.parse_args()

    stage = Path(tempfile.mkdtemp(prefix="acs-artifacts-"))
    failed = False
    try:
        print("building artifacts", flush=True)
        try:
            art = build(stage)
        except subprocess.CalledProcessError as e:
            # A build that refuses is a result, not a crash. The pack-time
            # guard against a native-less package reports itself this way.
            print(
                f"building artifacts FAILED\n{' '.join(str(c) for c in e.cmd)}\n"
                f"{e.stdout}\n{e.stderr}",
                file=sys.stderr,
            )
            return 1
        for name, path in art.items():
            print(f"  {name}: {path.name}")

        checks = {
            "rust": check_rust,
            "python": check_python,
            "node": check_node,
            "dotnet": check_dotnet,
        }
        print("\nrunning the public surface from each installed artifact")
        for name, check in checks.items():
            try:
                got = check(art, stage)
            except subprocess.CalledProcessError as e:
                print(
                    f"{name:8} FAILED TO RUN\n{e.stdout}\n{e.stderr}", file=sys.stderr
                )
                failed = True
                continue
            mismatches = {
                k: (EXPECTED[k], got.get(k))
                for k in EXPECTED
                if got.get(k) != EXPECTED[k]
            }
            print(f"  {name:8} {'ok' if not mismatches else 'MISMATCH'}")
            for key, (want, actual) in sorted(mismatches.items()):
                print(
                    f"           {key}: expected {want!r}, got {actual!r}",
                    file=sys.stderr,
                )
                failed = True
    finally:
        if args.keep:
            print(f"\nstaging kept at {stage}")
        else:
            shutil.rmtree(stage, ignore_errors=True)

    if failed:
        print(
            "\na published artifact does not carry what the checkout does",
            file=sys.stderr,
        )
        return 1
    print(
        f"\nevery artifact carries the whole surface, across {len(EXPECTED)} assertions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
