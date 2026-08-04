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
    "ActivatedPolicy",
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


class ActivatedPolicy:
    """One policy version, readied once and evaluated many times.

    :class:`AcsInterceptor` answers "evaluate this agent context against
    a manifest" and readies the policy lazily on the first call. This
    class is the other split: :meth:`activate` pays for reading the
    manifest, loading every Rego module and data document, and compiling
    the entrypoint each intervention point queries, so that every later
    :meth:`evaluate` costs no I/O and no compile.

    Activate once per policy version and keep the instance. A policy edit
    on disk needs a new activation, which is the point: the host controls
    when a version changes. The handle is immutable and evaluation
    releases the GIL, so one instance serves concurrent threads.

    A manifest names its bundle relative to itself, so an absolute
    manifest path is enough and the working directory does not matter.
    """

    __slots__ = ("_handle",)

    def __init__(self, manifest_path: str) -> None:
        """Activate the manifest at ``manifest_path`` with the
        zero-config dispatchers (bundled annotators; Rego in process,
        Cedar through the built-in evaluator, ``test`` policies through
        their embedded verdict).

        Raises :class:`ValueError` when the manifest cannot be read or is
        rejected, and :class:`RuntimeError` when it binds a policy that
        cannot be readied at all, such as a missing bundle. A policy that
        merely needs real input to produce a verdict activates fine.
        """
        self._handle = _native.policy_activate(manifest_path)

    @classmethod
    def activate(cls, manifest_path: str) -> ActivatedPolicy:
        """Activate the manifest at ``manifest_path``.

        Same as the constructor, named for the lifecycle it belongs to.
        """
        return cls(manifest_path)

    def evaluate(self, point: str, context: Mapping[str, Any]) -> Verdict:
        """Evaluate one intervention point. This is the hot path.

        ``point`` is an agent-hooks intervention point name, such as
        ``"input"`` or ``"pre_tool_call"``.

        Evaluation failures return a fail-closed ``deny`` verdict
        (``runtime_error:*`` reason), including a point this policy
        version does not bind. Raises only on boundary problems: an
        unknown point name or a context that will not serialize.
        """
        wire = _native.policy_evaluate(
            self._handle, point, json.dumps(context, allow_nan=False)
        )
        return Verdict.from_wire(json.loads(wire))

    @property
    def intervention_points(self) -> tuple[str, ...]:
        """The intervention points this policy version binds, in manifest
        order. Read it to skip emitting points the policy does not
        govern.
        """
        return tuple(_native.policy_intervention_points(self._handle))

    def governs(self, point: str) -> bool:
        """Whether this policy version governs ``point``."""
        return point in self.intervention_points


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
