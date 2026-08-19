#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail when an engine capability is reachable from fewer than four bindings.

Cross-language comparison proves the bindings agree about the calls it
makes. It cannot notice a capability none of them expose, because a
surface absent everywhere is consistent everywhere.

So this reads the engine's public re-exports and requires every one to
be either a capability with the token each binding exposes, or a
non-capability with a written reason. A symbol that is neither fails,
which forces the question to be answered when the symbol is added
rather than when a consumer cannot find it.

Writing the reason down is the point. An unexplained omission and a
deliberate one look identical six months later.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

# Symbols that need no entry point, each with why. Anything not listed
# here and not matched below is treated as an unbound capability.
NOT_A_CAPABILITY = {
    # Types that cross the boundary as JSON rather than as objects. A
    # binding never constructs one, so there is nothing to bind.
    "AgentContext": "crosses as JSON",
    "Verdict": "crosses as JSON",
    "Decision": "crosses as JSON",
    "Warning": "crosses as JSON",
    "Transform": "crosses as JSON",
    "Evidence": "crosses as JSON",
    "EnforcementMode": "crosses as JSON",
    "InterceptionPoint": "crosses as JSON",
    "EvaluationRequest": "crosses as JSON",
    "EvaluationResult": "crosses as JSON",
    "AnnotatorInvocation": "crosses as JSON to a host dispatcher",
    "PreparedPolicyInvocation": "crosses as JSON to a host dispatcher",
    "RegoPolicyInvocation": "variant of PreparedPolicyInvocation",
    "CedarPolicyInvocation": "variant of PreparedPolicyInvocation",
    "TestPolicyInvocation": "variant of PreparedPolicyInvocation",
    "CustomPolicyInvocation": "variant of PreparedPolicyInvocation",
    "CedarRequest": "crosses as JSON",
    "CedarEntity": "crosses as JSON",
    "TelemetryEvent": "crosses as JSON to a host sink",
    "TelemetryEventType": "field of TelemetryEvent",
    "RuntimeError": "surfaces as an error message or a diagnostic",
    "StreamError": "surfaces as an end reason",
    # Manifest grammar, reached by parsing a manifest rather than by
    # constructing the node.
    "Manifest": "reached through parse and validate",
    "InterventionPointConfig": "manifest grammar",
    "AnnotationConfig": "manifest grammar",
    "AnnotatorConfig": "manifest grammar",
    "AnnotatorType": "manifest grammar",
    "PolicyConfig": "manifest grammar",
    "PolicyBinding": "manifest grammar",
    "RegoPolicyConfig": "manifest grammar",
    "CedarPolicyConfig": "manifest grammar",
    "TestPolicyConfig": "manifest grammar",
    "CustomPolicyConfig": "manifest grammar",
    "ToolConfig": "manifest grammar",
    "MountedRegoData": "field of InMemoryRegoBundle",
    # Dispatchers the manifest selects by policy type. A host picks one
    # by writing a manifest, not by naming the Rust type.
    "RegorusPolicyDispatcher": "selected by manifest policy type",
    "RegorusRegoRunner": "selected by manifest policy type",
    "OpaPolicyDispatcher": "selected by manifest policy type",
    "OpaRegoRunner": "selected by manifest policy type",
    "CedarBuiltinDispatcher": "selected by manifest policy type",
    "CedarPolicyDispatcher": "selected by manifest policy type",
    "CedarTestDispatcher": "test double",
    "DefaultAnnotatorDispatcher": "the default when a host supplies none",
    "NoopTelemetrySink": "the default when a host supplies none",
    "ClassifierAnnotator": "selected by manifest annotator type",
    "EndpointAnnotator": "selected by manifest annotator type",
    "LlmAnnotator": "selected by manifest annotator type",
    "Interceptor": "the trait AcsInterceptor implements",
    "AcsInterceptor": "bound as the interceptor entry point itself",
    "Runtime": "bound as the interceptor entry point itself",
    # Internals of building a policy input. A host supplies the context;
    # the engine builds the input from it.
    "JsonPath": "internal to policy input construction",
    "PathEnv": "internal to policy input construction",
    "PathRoot": "internal to policy input construction",
    "PathSegment": "internal to policy input construction",
    "PathParseError": "internal to policy input construction",
    "build_policy_input": "internal to policy input construction",
    "build_cedar_request": "internal to Cedar dispatch",
    "normalize_policy_output": "internal to verdict normalization",
    "runtime_error_verdict": "internal to verdict normalization",
    "translate_advice": "internal to Cedar dispatch",
    "InterceptionPointExt": "Rust ergonomics on a foreign enum",
    "canonical_json": "agent-hooks owns identity and canonicalization",
    # Constants, readable from a verdict or a spec document.
    "SUPPORTED_VERSIONS": "bound through supported_manifest_versions",
    "MAX_RUNE_OFFSET": "constant",
    "STREAMING_FAIL_CLOSED_REASON": "constant, appears in a verdict",
    "VERDICT_INVALID_REASON": "constant, appears in a verdict",
    "reserved_reason": "constants, appear in a verdict",
}

# A capability is reachable when each binding names it or the entry
# point that carries it. Matching by name alone would miss the cases
# where a binding renames on the way out, so state the token to look for.
CAPABILITIES = {
    "ActivatedPolicy": (
        "acs_policy_activate",
        "policy_activate",
        "policy_activate",
        "PolicyActivate",
    ),
    "InMemoryRegoBundle": ("bundles_json", "bundles", "bundles", "bundlesJson"),
    "AnnotatorDispatcher": (
        "AcsAnnotatorFn",
        "annotator_dispatcher",
        "annotatorDispatcher",
        "AnnotatorDispatcher",
    ),
    "PolicyDispatcher": (
        "AcsPolicyFn",
        "policy_dispatcher",
        "policyDispatcher",
        "PolicyDispatcher",
    ),
    "TelemetrySink": (
        "AcsTelemetryFn",
        "telemetry_sink",
        "telemetrySink",
        "TelemetrySink",
    ),
    "PerfTelemetry": (
        "perf_telemetry",
        "perf_telemetry",
        "perfTelemetry",
        "PerfTelemetry",
    ),
    "Limits": ("limits_json", "limits", "limits", "limits"),
    "StreamSession": (
        "acs_stream_session_new",
        "stream_session_new",
        "stream_session_new",
        "StreamSession",
    ),
    "StreamSessionConfig": (
        "acs_stream_session_new",
        "stream_session_new",
        "stream_session_new",
        "StreamSession",
    ),
    "StreamWatermark": (
        "acs_stream_session_watermark",
        "stream_watermark",
        "stream_session_watermark",
        "Watermark",
    ),
    "StreamCompletion": (
        "acs_stream_session_finish",
        "stream_finish",
        "stream_session_finish",
        "Finish",
    ),
    "StreamEndReason": ("end_reason", "end_reason", "endReason", "EndReason"),
    "StreamSpan": (
        "acs_stream_session_record_outcome",
        "stream_record_outcome",
        "stream_session_record_outcome",
        "RecordOutcome",
    ),
    "SegmentOutcome": (
        "acs_stream_session_record_outcome",
        "stream_record_outcome",
        "stream_session_record_outcome",
        "SegmentOutcome",
    ),
    "SafetyLevel": ("safety_level", "safety_level", "safetyLevel", "SafetyLevel"),
    "StreamSourceType": (
        "source_type",
        "source_type",
        "sourceType",
        "StreamSourceType",
    ),
    "StreamTrack": (
        "acs_stream_session_advance",
        "stream_advance",
        "stream_session_advance",
        "StreamTrack",
    ),
    "RuneRange": (
        "acs_stream_session_record_outcome",
        "stream_record_outcome",
        "stream_session_record_outcome",
        "RecordOutcome",
    ),
}

BINDINGS = (
    ("ffi", [ROOT / "sdk/ffi/src/lib.rs"]),
    (
        "python",
        [
            ROOT / "sdk/python/src/lib.rs",
            ROOT / "sdk/python/agent_control_spec/__init__.py",
        ],
    ),
    ("node", [ROOT / "sdk/node/native/src/lib.rs", ROOT / "sdk/node/src/index.ts"]),
    ("dotnet", list((ROOT / "sdk/dotnet/src/AgentControlSpec").glob("*.cs"))),
)


def ffi_entry_points() -> set[str]:
    """Every `acs_*` function the C ABI exports."""
    src = (ROOT / "sdk/ffi/src/lib.rs").read_text(encoding="utf-8")
    return set(re.findall(r"pub unsafe extern \"C\" fn (acs_\w+)", src))


def unbound_from_dotnet() -> list[str]:
    """C ABI entry points the .NET binding never declares.

    .NET is the only binding that goes through the C ABI rather than
    linking the engine directly, so an entry point added there and not
    declared here is reachable from every language except .NET. The
    token scan above cannot see it, because the capability it belongs to
    may already be covered by a sibling entry point.
    """
    declared = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "sdk/dotnet/src/AgentControlSpec").glob("*.cs")
    )
    # Freeing and string ownership are called by the SafeHandle and the
    # marshaller, not declared as separate imports.
    internal = {"acs_free_string"}
    # Whole-word, because `acs_interceptor_new` is a substring of
    # `acs_interceptor_new_ex`: a substring test would call the shorter
    # one declared on the strength of the longer one.
    return sorted(
        name
        for name in ffi_entry_points()
        if name not in internal and not re.search(rf"\b{re.escape(name)}\b", declared)
    )


def engine_symbols() -> set[str]:
    src = (ROOT / "engine/src/lib.rs").read_text(encoding="utf-8")
    found: set[str] = set()
    for match in re.finditer(r"pub use ([^;]+);", src, re.DOTALL):
        body = re.sub(r"^\s*[\w:]+::", "", match.group(1))
        groups = re.findall(r"\{([^}]*)\}", body) or [body]
        for group in groups:
            for name in group.split(","):
                name = name.strip().split(" as ")[-1].strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""):
                    found.add(name)
    return found


def main() -> int:
    sources = {
        name: "\n".join(p.read_text(encoding="utf-8") for p in paths if p.exists())
        for name, paths in BINDINGS
    }

    symbols = engine_symbols()
    unexplained = sorted(
        s for s in symbols if s not in NOT_A_CAPABILITY and s not in CAPABILITIES
    )

    failed = False
    if unexplained:
        print(
            "engine symbols that are neither a declared capability nor an "
            "explained non-capability:",
            file=sys.stderr,
        )
        for name in unexplained:
            print(f"  {name}", file=sys.stderr)
        print(
            "\nAdd each to CAPABILITIES with the token every binding exposes, "
            "or to NOT_A_CAPABILITY with the reason it needs none.",
            file=sys.stderr,
        )
        failed = True

    orphans = unbound_from_dotnet()
    if orphans:
        print("C ABI entry points the .NET binding does not declare:", file=sys.stderr)
        for name in orphans:
            print(f"  {name}", file=sys.stderr)
        failed = True

    for symbol, tokens in sorted(CAPABILITIES.items()):
        missing = [
            lang
            for (lang, _), token in zip(BINDINGS, tokens)
            if token not in sources[lang]
        ]
        if missing:
            print(
                f"  {symbol:24} UNREACHABLE from {', '.join(missing)}", file=sys.stderr
            )
            failed = True

    if failed:
        return 1

    print(
        f"every one of {len(CAPABILITIES)} engine capabilities is reachable from "
        f"all {len(BINDINGS)} bindings"
    )
    print(
        f"{len(NOT_A_CAPABILITY)} further symbols are data or internals, each with a stated reason"
    )
    print(
        f"all {len(ffi_entry_points())} C ABI entry points are declared by the .NET binding"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
