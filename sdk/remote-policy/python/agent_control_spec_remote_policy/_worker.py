# Copyright (c) Microsoft. All rights reserved.
"""Private, credential-free subprocess entry point for remote ACS evaluation."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from agent_control_spec import ActivatedPolicy

from .poller import (
    MAX_EVALUATION_BYTES,
    PolicyError,
    decode_json,
    validate_acs_artifacts,
)


def _apply_resource_limits() -> None:
    if os.name != "posix":
        return

    import resource

    memory_bytes = 1024**3
    if sys.platform == "darwin":
        # Darwin rejects a cap below mappings already reserved by its runtime.
        usage = subprocess.run(
            ["/bin/ps", "-o", "vsz=", "-p", str(os.getpid())],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="ascii",
            env={},
            timeout=1,
        )
        mapped_bytes = int(usage.stdout.strip()) * 1024
        if mapped_bytes <= 0:
            raise ValueError("Invalid worker address-space measurement")
        memory_bytes += mapped_bytes
    for kind, soft, hard in (
        (resource.RLIMIT_AS, memory_bytes, memory_bytes),
        (resource.RLIMIT_CPU, 5, 6),
    ):
        inherited_soft, inherited_hard = resource.getrlimit(kind)
        if inherited_hard != resource.RLIM_INFINITY:
            hard = min(hard, inherited_hard)
        if inherited_soft != resource.RLIM_INFINITY:
            soft = min(soft, inherited_soft)
        resource.setrlimit(kind, (min(soft, hard), hard))


def main() -> int:
    """Evaluate one bounded request and emit the existing agent-hooks verdict wire."""
    try:
        _apply_resource_limits()
    except (OSError, ValueError, subprocess.SubprocessError):
        print('{"error":"resource_limit_failed"}')
        return 2
    try:
        request = decode_json(
            sys.stdin.buffer.read(MAX_EVALUATION_BYTES + 1),
            max_bytes=MAX_EVALUATION_BYTES,
        )
        if not isinstance(request, dict) or request.keys() != {
            "manifest",
            "bundles",
            "point",
            "context",
        }:
            raise TypeError("Invalid policy evaluation request")
        manifest, point, context = (
            request["manifest"],
            request["point"],
            request["context"],
        )
        if (
            not isinstance(manifest, str)
            or not isinstance(point, str)
            or not isinstance(context, dict)
        ):
            raise TypeError("Invalid policy evaluation request")
        bundles = validate_acs_artifacts(manifest, request["bundles"])
        policy = ActivatedPolicy.from_memory(manifest, bundles)
        verdict = policy.evaluate(point, context)
        print(json.dumps(verdict.to_wire(), allow_nan=False))
        return 0
    except (PolicyError, ValueError, TypeError, RuntimeError):
        print('{"error":"evaluation_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
