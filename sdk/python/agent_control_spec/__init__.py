# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Control Specification: a policy decision runtime behind the
agent-hooks interceptor contract.

The runtime evaluates the policy bound in a manifest against each
:class:`agent_hooks` context and returns a verdict. Evaluation failures
never raise into the host: the runtime normalizes them into fail-closed
``deny`` verdicts with ``runtime_error:*`` reasons (the engine's own
reason namespace; the ``host_error:*`` namespace stays reserved for
hosts, per AGENT-HOOKS-0.1 §5/§11).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agent_hooks import Verdict

from agent_control_spec import _native

__all__ = ["AcsInterceptor", "__version__"]

__version__ = "0.4.0a1"


class AcsInterceptor:
    """agent-hooks interceptor over the Agent Control Specification runtime.

    Register an instance with any agent-hooks host emitter. The manifest
    is loaded once at construction with the zero-config dispatchers
    (bundled annotators; Rego through OPA, Cedar through the built-in
    evaluator, ``test`` policies through their embedded verdict).
    """

    def __init__(self, manifest_path: str) -> None:
        self._handle = _native.interceptor_new(manifest_path)

    def intercept(self, context: Mapping[str, Any]) -> Verdict:
        wire = _native.intercept(self._handle, json.dumps(context, allow_nan=False))
        return Verdict.from_wire(json.loads(wire))
