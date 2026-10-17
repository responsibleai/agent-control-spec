# Copyright (c) Microsoft. All rights reserved.
"""Private, credential-free subprocess entry point for remote ACS evaluation."""

from __future__ import annotations

import json
import os
import sys

from agent_control_spec import ActivatedPolicy

from .poller import (
    MAX_EVALUATION_BYTES,
    PolicyError,
    decode_json,
    validate_acs_artifacts,
)


def main() -> int:
    """Evaluate one bounded request and emit the existing agent-hooks verdict wire."""
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
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
