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

__all__ = [
    "AcsInterceptor",
    "ManifestInvalidError",
    "__version__",
    "supported_manifest_versions",
    "validate_manifest",
    "validate_manifest_file",
]

__version__ = "0.4.0a1"


class AcsInterceptor:
    """agent-hooks interceptor over the Agent Control Specification runtime.

    Register an instance with any agent-hooks host emitter. The manifest
    is loaded once at construction with the zero-config dispatchers
    (bundled annotators; Rego in process, Cedar through the built-in
    evaluator, ``test`` policies through their embedded verdict).
    """

    def __init__(self, manifest_path: str) -> None:
        self._handle = _native.interceptor_new(manifest_path)

    def intercept(self, context: Mapping[str, Any]) -> Verdict:
        wire = _native.intercept(self._handle, json.dumps(context, allow_nan=False))
        return Verdict.from_wire(json.loads(wire))


#: A manifest failed grammar validation. Raised by
#: :func:`validate_manifest`, carrying the engine's own message, which
#: names the offending field. Subclasses :class:`ValueError`.
ManifestInvalidError = _native.ManifestInvalid


def validate_manifest(source: str) -> None:
    """Validate manifest source against the grammar.

    Raises :class:`ManifestInvalidError` when the manifest is rejected,
    and returns ``None`` when it is accepted. Nothing is evaluated and no
    runtime is built, so this works before a policy is runnable and
    without resolving a policy bundle.

    Anything else the call raises is a boundary problem rather than a
    verdict on the manifest, and propagates unchanged.

    A manifest that uses ``extends`` cannot be judged from its own source,
    because validation checks references across the merged document. That
    raises :class:`ValueError` rather than
    :class:`ManifestInvalidError`; use :func:`validate_manifest_file`.
    """
    _native.validate_manifest(source)


def validate_manifest_file(path: str) -> None:
    """Validate a manifest file, resolving ``extends`` first.

    Use this for a manifest that inherits. It reads from disk and may
    fetch URL ``extends``, exactly as loading a runtime would.
    """
    _native.validate_manifest_file(path)


def supported_manifest_versions() -> tuple[str, ...]:
    """The manifest grammar versions this engine accepts.

    Read it rather than hardcoding the set; it moves with the engine.
    """
    return tuple(_native.supported_manifest_versions())
