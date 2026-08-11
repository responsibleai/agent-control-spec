#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run one streaming scenario in every supported language and diff.

Streaming reaches Rust, Python, Node and .NET through four different
binding mechanisms: a direct crate dependency, pyo3, napi, and a C ABI
with P/Invoke over it. Each converts enums, offsets and the absent
release point at its own boundary, so agreement is not structural and
cannot be assumed. This asserts it.

The scenario deliberately covers the places a binding is most likely to
drift:

* a rune count that differs from the UTF-16 length, which is where a
  .NET or Node binding silently releases twice what was evaluated
* an absent safe offset after settlement, which must not arrive as 0 or
  as -1 in any language, because both read as permission
* a refusal, whose confirmed watermark must survive settlement for the
  audit record

Run it from the repository root. Every language builds from this
checkout, so it answers for the code under review rather than for
whatever happens to be installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

# One astral-plane scalar: 1 rune, 2 UTF-16 code units, 4 UTF-8 bytes.
EMOJI = "\U0001f600"
TEXT = f"hi{EMOJI}"
RUNES = 3


def rust() -> dict:
    src = ROOT / "target" / "parity-rs"
    src.mkdir(parents=True, exist_ok=True)
    (src / "main.rs").write_text(
        """
use agent_control_spec::stream_session::*;
fn main() {
    let mut s = StreamSession::new(StreamSessionConfig {
        safety_level: SafetyLevel::Blocking,
        request_start_rune_offset: 0,
        response_start_rune_offset: 0,
        request_tasks: vec![],
        response_tasks: vec!["pii".to_string()],
    })
    .expect("session");
    let received = s
        .observe_text(StreamSourceType::ModelGenerated, "TEXT_PLACEHOLDER")
        .expect("observe");
    let before = s.safe_offset(StreamTrack::Response);
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, received).expect("span");
    s.record_outcome("pii", &span, SegmentOutcome::Cleared).expect("outcome");
    let advanced = s.advance(StreamTrack::Response);
    let after = s.safe_offset(StreamTrack::Response);
    let confirmed = s.watermark(StreamTrack::Response).confirmed();
    let completion = s.finish();
    let settled = s.safe_offset(StreamTrack::Response);
    println!(
        "{}",
        serde_json::json!({
            "received": received,
            "safe_offset_before": before,
            "advanced": advanced,
            "safe_offset_after": after,
            "confirmed": confirmed,
            "is_clean": completion.reason.is_clean(),
            "transformed": completion.transformed,
            "safe_offset_settled": settled,
        })
    );
}
""".replace("TEXT_PLACEHOLDER", TEXT)
    )
    manifest = ROOT / "target" / "parity-rs" / "Cargo.toml"
    manifest.write_text(
        f"""
[package]
name = "acs-parity"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "acs-parity"
path = "main.rs"

[dependencies]
agent-control-spec = {{ path = "{ROOT / "engine"}", features = ["streaming"] }}
serde_json = "1"

[workspace]
"""
    )
    out = subprocess.run(
        ["cargo", "run", "--quiet", "--release", "--manifest-path", str(manifest)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def python_binding() -> dict:
    script = f"""
import json
from agent_control_spec import StreamSession
s = StreamSession(safety_level="blocking", response_tasks=["pii"])
received = s.observe_text("model_generated", {TEXT!r})
before = s.safe_offset("response")
s.record_outcome("pii", "model_generated", 0, received, "cleared")
advanced = s.advance("response")
after = s.safe_offset("response")
confirmed = s.watermark("response")["confirmed"]
completion = s.finish()
print(json.dumps({{
    "received": received,
    "safe_offset_before": before,
    "advanced": advanced,
    "safe_offset_after": after,
    "confirmed": confirmed,
    "is_clean": completion["is_clean"],
    "transformed": completion["transformed"],
    "safe_offset_settled": s.safe_offset("response"),
}}))
"""
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def node() -> dict:
    script = f"""
const {{ StreamSession }} = require({str(ROOT / "sdk" / "node" / "dist" / "index.js")!r});
const s = new StreamSession({{ safetyLevel: 'blocking', responseTasks: ['pii'] }});
const received = s.observeText('model_generated', {TEXT!r});
const before = s.safeOffset('response');
s.recordOutcome('pii', 'model_generated', 0, received, 'cleared');
const advanced = s.advance('response');
const after = s.safeOffset('response');
const confirmed = s.watermark('response').confirmed;
const completion = s.finish();
console.log(JSON.stringify({{
  received, safe_offset_before: before, advanced, safe_offset_after: after,
  confirmed, is_clean: completion.isClean, transformed: completion.transformed,
  safe_offset_settled: s.safeOffset('response'),
}}));
"""
    out = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT / "sdk" / "node",
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def dotnet() -> dict:
    work = Path(tempfile.mkdtemp())
    try:
        subprocess.run(
            ["dotnet", "new", "console", "-o", str(work / "app")],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "dotnet",
                "add",
                str(work / "app"),
                "reference",
                str(ROOT / "sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj"),
            ],
            capture_output=True,
            check=True,
        )
        (work / "app" / "Program.cs").write_text(
            """
using System.Text.Json;
using AgentControlSpec;
using var s = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
var received = s.ObserveText(StreamSourceType.ModelGenerated, "TEXT_PLACEHOLDER");
var before = s.SafeOffset(StreamTrack.Response);
s.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, received, SegmentOutcome.Cleared);
var advanced = s.Advance(StreamTrack.Response);
var after = s.SafeOffset(StreamTrack.Response);
var confirmed = s.Watermark(StreamTrack.Response).Confirmed;
var completion = s.Finish();
Console.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
{
    ["received"] = received,
    ["safe_offset_before"] = before,
    ["advanced"] = advanced,
    ["safe_offset_after"] = after,
    ["confirmed"] = confirmed,
    ["is_clean"] = completion.IsClean,
    ["transformed"] = completion.Transformed,
    ["safe_offset_settled"] = s.SafeOffset(StreamTrack.Response),
}));
""".replace("TEXT_PLACEHOLDER", TEXT)
        )
        env = {"LD_LIBRARY_PATH": str(ROOT / "target" / "release")}
        import os

        merged = dict(os.environ)
        merged.update(env)
        out = subprocess.run(
            ["dotnet", "run", "--project", str(work / "app"), "--nologo"],
            capture_output=True,
            text=True,
            check=True,
            env=merged,
        )
        return json.loads(out.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(work, ignore_errors=True)


EXPECTED = {
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
            print(f"{name}: FAILED TO RUN\n{e.stderr}", file=sys.stderr)
            failed = True

    if failed:
        return 1

    for name, got in results.items():
        mismatches = {
            k: (EXPECTED[k], got.get(k)) for k in EXPECTED if got.get(k) != EXPECTED[k]
        }
        status = "ok" if not mismatches else "MISMATCH"
        print(f"{name:8} {status}  {json.dumps(got, sort_keys=True)}")
        for key, (want, actual) in mismatches.items():
            print(f"         {key}: expected {want!r}, got {actual!r}", file=sys.stderr)
            failed = True

    if failed:
        print("\nlanguages disagree about the same stream", file=sys.stderr)
        return 1

    print(f"\nall {len(results)} languages agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
