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
from collections.abc import Callable, Iterable, Mapping
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from types import MappingProxyType as _MappingProxyType
from typing import Any, Self

from agent_hooks import Verdict

from agent_control_spec import _native

__all__ = [
    "DEFAULT_LIMITS",
    "PERF_TELEMETRY_LEVELS",
    "AcsInterceptor",
    "ActivatedPolicy",
    "ArtifactDiagnostic",
    "ManifestInvalidError",
    "RegoBundle",
    "StreamSession",
    "TelemetryEvent",
    "ValidationDiagnostic",
    "__version__",
    "merge_manifests",
    "parse_manifest",
    "supported_manifest_versions",
    "validate_artifacts",
    "validate_manifest",
    "validate_manifest_detailed",
    "validate_manifest_file",
]

#: Read from the installed distribution rather than written here. A
#: literal is a seventh version surface, and it is the one surface
#: neither ``scripts/check-version-consistency.py`` nor RELEASING.md
#: covers, so it silently kept a stale value across two releases. The
#: fallback covers an import from a source tree that was never installed.
try:
    __version__ = _distribution_version("agent-control-spec")
except PackageNotFoundError:  # pragma: no cover - source tree, not installed
    __version__ = "0.0.0.dev0"

#: One Rego policy's sources, held in memory rather than on disk:
#: ``{"modules": {name: source}, "data": [{"mount": [...], "document":
#: {...}}]}``. Both keys default to empty and nothing else is accepted.
RegoBundle = Mapping[str, Any]

#: The `perf_telemetry` levels the runtime accepts. Kept explicit rather
#: than a Rust-side enum: the constructor argument is a string, so the
#: allowed values are the vocabulary a Python host reads.
PERF_TELEMETRY_LEVELS: tuple[str, ...] = ("off", "external", "full")

#: The engine's shipped resource caps, as a read-only mapping. A host
#: passing ``limits=`` to :class:`AcsInterceptor` reads this to see what
#: it is overriding — a shipping change to another default cannot then
#: be silently absorbed. Frozen at import time so a caller cannot mutate
#: a shared default. Fields:
#:
#: - ``max_snapshot_bytes``: cap on the canonicalized context snapshot.
#: - ``max_policy_input_depth``: JSON nesting depth accepted anywhere.
#: - ``max_annotators_per_point``: annotators the engine will dispatch.
#: - ``max_annotator_output_bytes``: per-annotator serialized output.
#: - ``max_policy_output_bytes``: policy-decision serialized output.
#: - ``max_extends_depth``: manifest ``extends`` chain length.
#: - ``max_merged_manifest_bytes``: composed manifest total size.
#: - ``max_manifest_url_bytes``: per-URL fetch body cap.
#: - ``manifest_url_timeout_ms``: per-URL fetch deadline.
#: - ``max_manifest_url_redirects``: per-URL fetch redirect count.
DEFAULT_LIMITS: Mapping[str, int] = _MappingProxyType(_native.default_limits())

#: A telemetry event a host-supplied sink receives from the engine.
#:
#: The dict is populated by the native layer and mirrors
#: :class:`agent_control_spec.telemetry.TelemetryEvent` on the Rust side.
#: Its shape is documented rather than typed as a ``TypedDict`` to keep
#: the Python surface stable while the engine grows fields, which it has
#: done twice already in 0.4 (evidence artefacts, transformed-event).
#: Keys:
#:
#: - ``event_type``: one of ``"decision"``, ``"annotator_dispatch"``,
#:   ``"policy_evaluation"``, ``"evaluation_timing"``,
#:   ``"intervention_point.transformed"``, ``"annotator_failed"``, or
#:   ``"policy_failed"``.
#: - ``intervention_point``: agent-hooks wire name.
#: - ``decision``: ``"allow"`` / ``"deny"`` / ``"transform"`` or ``None``.
#: - ``reason_code``: ``str`` or ``None``.
#: - ``error_class``: ``str`` or ``None``.
#: - ``policy_id``: ``str`` or ``None``.
#: - ``annotators``: ``list[str]``.
#: - ``enforcement_mode``: ``"enforce"`` / ``"evaluate_only"`` or ``None``.
#: - ``duration_ms``: ``float`` or ``None``.
#: - ``evidence_artefact``: ``str`` or ``None``.
#: - ``evidence_verification_pointer_keys``: ``list[str]``.
#: - ``action_identity``: ``str`` or ``None``.
#: - ``metadata``: ``dict[str, str]``.
TelemetryEvent = Mapping[str, Any]

#: One entry produced by :func:`validate_manifest_detailed`. Shape:
#:
#: - ``code``: ``str`` (the engine's ``runtime_error:*`` reason).
#: - ``message``: ``str`` (the engine's own message text).
#: - ``severity``: always ``"error"``.
#: - ``field``: ``str | None`` (best-effort field name extracted from
#:   the message; ``None`` when the message names no known field).
#:
#: Matches :data:`ArtifactDiagnostic` on ``code``, ``message``, and
#: ``severity``, so a diagnostic-consuming tool can key off ``code``
#: across surfaces. Wrapped as a mapping rather than a dataclass to
#: keep it JSON-safe for tools that shuttle diagnostics through IPC.
ValidationDiagnostic = Mapping[str, Any]

#: One entry produced by :func:`validate_artifacts`. Shape:
#:
#: - ``code``: ``str`` (the engine's ``runtime_error:*`` reason).
#: - ``message``: ``str`` (the engine's own detail text).
#: - ``severity``: always ``"error"``.
#:
#: Matches the C ABI's ``acs_artifact_diagnostics`` wire shape, so a
#: diagnostic-consuming tool can key off ``code`` across languages.
ArtifactDiagnostic = Mapping[str, Any]


def _normalize_perf_telemetry(value: str | None) -> str:
    """Reject unknown perf-telemetry levels on the Python side.

    The Rust binding does its own check, but doing this here means the
    error is raised without paying for a manifest load first, which
    matches how the rest of the wrapper preserves cheap-to-fail
    ordering. The engine's own vocabulary is preserved verbatim.
    """
    if value is None:
        return "off"
    if value not in PERF_TELEMETRY_LEVELS:
        raise ValueError(
            f"unknown perf_telemetry level {value!r}; "
            f"expected one of {PERF_TELEMETRY_LEVELS}"
        )
    return value


class AcsInterceptor:
    """agent-hooks interceptor over the Agent Control Specification runtime.

    Register an instance with any agent-hooks host emitter. The manifest
    is loaded once at construction.

    Zero-config path (the default): bundled annotators; Rego in process,
    Cedar through the built-in evaluator, ``test`` policies through
    their embedded verdict; no-op telemetry; the engine's default
    resource caps.

    Host hooks are supplied by keyword:

    - ``annotator_dispatcher``: object with a ``dispatch(annotator_name,
      annotator, preliminary_policy_input)`` method or a plain callable
      with the same signature. Return value is the annotation payload
      that reaches the policy under ``input.annotations[<name>]``.
    - ``policy_dispatcher``: object with an ``evaluate(invocation)``
      method (and optionally a ``warm(invocation)`` method) or a plain
      callable. Return value is the raw policy output normalized into a
      verdict by the engine.
    - ``telemetry_sink``: object with an ``emit(event)`` method
      (optionally a ``shutdown()`` method) or a plain callable. The
      engine emits one event per decision plus optional stage events.
    - ``perf_telemetry``: ``"off"`` (default), ``"external"``, or
      ``"full"``, gating whether external and per-stage timing events
      are emitted.
    - ``limits``: a mapping of resource caps that overrides the engine's
      defaults field by field. Absent means keep every default; each
      field is individually optional, so a host raising one cap does
      not restate the other nine. A host feeding large payloads raises
      ``max_snapshot_bytes``; one hardening against a hostile manifest
      lowers ``max_extends_depth`` or ``manifest_url_timeout_ms``. Read
      :data:`DEFAULT_LIMITS` to see the shipped values.

    A dispatcher that raises does not silently no-op: the engine
    normalizes the failure into a fail-closed ``deny`` verdict with a
    ``runtime_error:*`` reason.
    """

    def __init__(
        self,
        manifest_path: str,
        name: str = "acs",
        *,
        annotator_dispatcher: object | None = None,
        policy_dispatcher: object | None = None,
        telemetry_sink: object | Callable[[TelemetryEvent], None] | None = None,
        perf_telemetry: str = "off",
        limits: Mapping[str, int] | None = None,
    ) -> None:
        perf = _normalize_perf_telemetry(perf_telemetry)
        self._handle = _native.interceptor_new(
            manifest_path,
            annotator_dispatcher,
            policy_dispatcher,
            telemetry_sink,
            perf,
            limits,
        )
        self._name = name

    @property
    def name(self) -> str:
        """Payload-free identifier for the record's ``verdicts[].name``.

        The engine does not stamp this onto a verdict. A host that runs
        more than one interceptor records it alongside the verdict so the
        entry says which one decided.
        """
        return self._name

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

    Compiling is bounded by the eval timeout: a policy too slow to
    compile in that window activates anyway, not necessarily fully readied, and
    pays compilation on its first evaluation instead.

    Activate once per policy version and keep the instance. A policy edit
    on disk needs a new activation, which is the point: the host controls
    when a version changes. The handle is immutable and evaluation
    releases the GIL, so one instance serves concurrent threads.

    A manifest names its bundle relative to itself, so an absolute
    manifest path is enough and the working directory does not matter.
    :meth:`from_memory` is the other source: manifest text and Rego
    sources held by the host, with no file to read.

    Host dispatchers are supplied by the same keyword arguments as
    :class:`AcsInterceptor`. Passing them here is exactly how the
    consumer-facing ``AgentControl.from_native(...,
    annotator_dispatcher=ContentSafetyDispatcher())`` shape composed:
    activation carries the dispatcher, evaluation calls it, and readying
    warms it.
    """

    __slots__ = ("_handle",)

    def __init__(
        self,
        manifest_path: str,
        *,
        annotator_dispatcher: object | None = None,
        policy_dispatcher: object | None = None,
    ) -> None:
        """Activate the manifest at ``manifest_path``.

        Passing no host arguments preserves the zero-config path (bundled
        annotators; Rego in process, Cedar through the built-in
        evaluator, ``test`` policies through their embedded verdict).

        Raises :class:`ValueError` when the manifest cannot be read or is
        rejected, and :class:`RuntimeError` when it binds a policy that
        readying finds broken, such as a missing bundle, and only when
        readying finished: a bundle whose load does not complete inside
        the deadline surfaces at the first decision instead. A policy that
        merely needs real input to produce a verdict activates fine.
        """
        self._handle = _native.policy_activate(
            manifest_path, annotator_dispatcher, policy_dispatcher
        )

    @classmethod
    def activate(
        cls,
        manifest_path: str,
        *,
        annotator_dispatcher: object | None = None,
        policy_dispatcher: object | None = None,
    ) -> ActivatedPolicy:
        """Activate the manifest at ``manifest_path``.

        Same as the constructor, named for the lifecycle it belongs to.
        """
        return cls(
            manifest_path,
            annotator_dispatcher=annotator_dispatcher,
            policy_dispatcher=policy_dispatcher,
        )

    @classmethod
    def from_memory(
        cls,
        manifest_yaml: str,
        bundles: Mapping[str, RegoBundle],
        *,
        annotator_dispatcher: object | None = None,
        policy_dispatcher: object | None = None,
    ) -> ActivatedPolicy:
        """Activate a manifest and its Rego supplied as values.

        ``manifest_yaml`` is the manifest text. ``bundles`` maps a policy
        id declared in it to that policy's sources, replacing whatever
        ``bundle`` path the manifest names. A service that keeps
        manifests and Rego in a database activates from them directly,
        rather than staging a temporary directory per activation.

        Raises :class:`ManifestInvalidError` when the manifest is
        rejected, when a key of ``bundles`` names a policy the manifest
        does not declare as Rego, and when a Rego policy is left naming a
        *relative* bundle path: a manifest parsed from a string has no
        directory of its own, so that path would resolve against the
        process working directory. Absolute paths are left as written, so
        one manifest can mix policy from a database with policy from a
        known location on disk.
        """
        policy = cls.__new__(cls)
        policy._handle = _native.policy_activate_from_memory(
            manifest_yaml,
            json.dumps(bundles, allow_nan=False),
            annotator_dispatcher,
            policy_dispatcher,
        )
        return policy

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


def validate_manifest_detailed(source: str) -> list[ValidationDiagnostic]:
    """Return structured validation diagnostics for a manifest source.

    Each diagnostic is ``{"code": str, "message": str, "severity":
    "error", "field": str | None}`` — the same wire shape
    :func:`validate_artifacts` and every other binding return. An
    accepted manifest returns ``[]``. A rejected one returns one entry
    naming the failed field where the engine's message permits
    extraction, and ``None`` for ``field`` when it does not: the
    ``message`` is the engine's own text either way, so a tool that
    cannot map ``field`` back to a location still has the verbatim
    reason.

    Use this for authoring tools, migration linting, and CI checks that
    want per-field feedback. :func:`validate_manifest` is the boolean
    shortcut for callers that only care whether validation passed.
    """
    return json.loads(_native.validate_manifest_diagnostics(source))


def validate_artifacts(
    manifest_source: str,
    bundles: Mapping[str, RegoBundle] | None = None,
) -> list[ArtifactDiagnostic]:
    """Validate a manifest AND the Rego it names, returning findings.

    Each diagnostic is ``{"code": str, "message": str, "severity":
    "error"}`` and matches the C ABI's ``acs_artifact_diagnostics``
    wire shape. An empty list means both halves are sound.

    :func:`validate_manifest_detailed` answers only for the document.
    A manifest can satisfy the grammar, name a Rego bundle, and still
    fail at activation because the Rego does not compile — compilation
    happens at activation time, so a validation surface that stops at
    the document turns that failure into a host's first agent action
    rather than a CI signal. This activates against the supplied
    bundles in memory and reports what that surfaced, closing the gap.

    ``bundles`` has the same shape :meth:`ActivatedPolicy.from_memory`
    takes: a mapping from policy id to a ``{"modules": {...}, "data":
    [...]}`` object. ``None`` or an empty mapping means the manifest
    names no Rego, and the result then equals the manifest-only
    diagnostics: a document that does not parse is reported as a
    manifest problem, not an activation problem, because that names
    the wrong half.
    """
    payload = "" if bundles is None else json.dumps(bundles, allow_nan=False)
    return json.loads(_native.validate_artifacts_diagnostics(manifest_source, payload))


def parse_manifest(source: str) -> dict[str, Any]:
    """Parse manifest source into a ``dict`` without validating.

    An authoring tool that needs to inspect a fragment before deciding
    what to do with it, such as reading an ``extends`` child's
    ``metadata`` before resolving the chain, calls this. No policy
    engine is put on-path.

    Raises :class:`ManifestInvalidError` when the source is not
    well-formed YAML or the manifest grammar rejects it structurally.
    """
    return json.loads(_native.parse_manifest(source))


def merge_manifests(sources: Iterable[str]) -> dict[str, Any]:
    """Compose an ordered chain of manifest sources into one ``dict``.

    Later sources overlay earlier ones under the same merge grammar
    ``extends`` uses on disk. Every entry must be a fully-formed manifest
    fragment: no chain entry may itself carry unresolved ``extends``.
    The resulting document is validated before it is returned, so a
    chain that would fail as an on-disk ``extends`` fails here too.

    Use this when the manifests come from memory (database rows,
    process-supplied overlays) rather than disk; use ``extends`` in the
    manifest itself when they come from disk and their layout is fixed.

    Raises :class:`ManifestInvalidError` when the chain is empty or an
    entry does not parse.
    """
    materialized = list(sources)
    return json.loads(_native.merge_manifests(materialized))


def supported_manifest_versions() -> tuple[str, ...]:
    """The manifest grammar versions this engine accepts.

    Read it rather than hardcoding the set; it moves with the engine.
    """
    return tuple(_native.supported_manifest_versions())


class StreamSession:
    """Host side accounting for one streamed policy target.

    A session holds no policy, performs no evaluation, and stores no
    stream text. The host drives it: it reports how much text arrived,
    declares the spans its segmenter produced, evaluates those spans
    through the ordinary interceptor path, records each outcome, and
    reads :meth:`safe_offset` to see how far it may release the track.
    This is the incremental profile in specification section 18.1.

    A track with no tasks is unmediated. Payload on such a track fails
    closed, which matches the behavior of a host guarding only the model
    stream and receiving text on the wrong track. A configuration that
    mediates neither track is rejected at construction: it would gate
    nothing.

    ``safety_level`` is one of ``"blocking"``, ``"complete"``, or
    ``"deferred"``. ``"blocking"`` and ``"complete"`` hold each span
    until the watermark covers it. ``"deferred"`` emits payload as it
    arrives and evaluates behind the stream, and cannot recall what has
    already been emitted.

    The session settles in two steps. :meth:`end_of_payloads` says no
    more text is coming while outcomes are still in flight, which is
    what a ``"deferred"`` host needs so a late denial can still land.
    :meth:`finish` returns the terminal :class:`dict` and marks the
    session ended. After :meth:`finish`, :meth:`safe_offset` is
    ``None``: a terminated session has no offset a host may emit
    through, whatever the reason. The confirmed offset stays available
    through :meth:`watermark` for the audit record.
    """

    __slots__ = ("_handle",)

    def __init__(
        self,
        safety_level: str = "blocking",
        *,
        request_tasks: Iterable[str] | None = None,
        response_tasks: Iterable[str] | None = None,
        request_start_rune_offset: int = 0,
        response_start_rune_offset: int = 0,
    ) -> None:
        request_tasks_list = list(request_tasks) if request_tasks is not None else []
        response_tasks_list = list(response_tasks) if response_tasks is not None else []
        self._handle = _native.stream_session_new(
            safety_level,
            int(request_start_rune_offset),
            int(response_start_rune_offset),
            request_tasks_list,
            response_tasks_list,
        )

    def observe(self, source_type: str, runes: int) -> int:
        """Report that ``runes`` more runes arrived on this role's
        track. Returns the track's new end offset.
        """
        return _native.stream_observe(self._handle, source_type, int(runes))

    def observe_text(self, source_type: str, text: str) -> int:
        """Report arriving text and let the engine count its runes,
        so a host does not reach for a length that measures UTF-16 code
        units or bytes. Neither is interchangeable with a rune offset.
        The text itself is not retained.
        """
        return _native.stream_observe_text(self._handle, source_type, text)

    def record_outcome(
        self,
        task: str,
        source_type: str,
        start: int,
        end: int,
        outcome: str,
    ) -> None:
        """Record what a host decided for the half-open rune range
        ``[start, end)`` on ``source_type``'s track, under ``task``.

        ``outcome`` is one of ``"cleared"``, ``"transformed"``, or
        ``"denied"``. A denial or transform ends the session. Every
        engine rejection raises :class:`ValueError` with the engine's
        own message; nothing silently no-ops.
        """
        _native.stream_record_outcome(
            self._handle,
            task,
            source_type,
            int(start),
            int(end),
            outcome,
        )

    def record_verdict(
        self,
        task: str,
        source_type: str,
        start: int,
        end: int,
        verdict: Verdict | Mapping[str, Any],
    ) -> None:
        """Map an agent-hooks verdict onto an outcome and record it.

        ``verdict`` may be a :class:`agent_hooks.Verdict` or the same
        wire dict :meth:`agent_hooks.Verdict.to_wire` produces. A shape
        the section 5 contract does not admit fails the stream closed
        with :class:`ValueError` before its decision is read.
        """
        if isinstance(verdict, Verdict):
            wire = verdict.to_wire()
        elif isinstance(verdict, Mapping):
            wire = verdict
        else:
            raise TypeError("verdict must be an agent_hooks.Verdict or a wire dict")
        _native.stream_record_verdict(
            self._handle,
            task,
            source_type,
            int(start),
            int(end),
            json.dumps(wire, allow_nan=False),
        )

    def advance(self, track: str) -> int | None:
        """Recompute the watermark for ``track`` and return the new
        confirmed offset when it advanced. Returns ``None`` when it did
        not, so a host emits a watermark event only on real progress.
        Returns ``None`` once the session has ended.
        """
        return _native.stream_advance(self._handle, track)

    def safe_offset(self, track: str) -> int | None:
        """Offset through which the host may emit ``track``, or ``None``
        once the session has ended.

        A denial withholds every rune the host has not already emitted,
        including runes a task had cleared, so a terminated session has
        no offset anyone may emit through. Returning ``None`` says that
        in the type, which a host cannot read as permission by
        accident.
        """
        return _native.stream_safe_offset(self._handle, track)

    def pending(self, track: str) -> int:
        """Runes observed but not yet cleared by every task on
        ``track``, as of the last :meth:`advance`.
        """
        return _native.stream_pending(self._handle, track)

    def watermark(self, track: str) -> dict[str, Any]:
        """Watermark snapshot for one track:
        ``{"track", "confirmed", "received", "pending", "tasks"}``.
        Reads without moving anything.
        """
        return json.loads(_native.stream_watermark(self._handle, track))

    def end_of_payloads(self) -> None:
        """Stop accepting payloads while outcomes are still in flight.
        A ``"deferred"`` host calls this at payload EOF so a classifier
        running behind the stream can still record a denial before
        :meth:`finish`.
        """
        _native.stream_end_of_payloads(self._handle)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        """Settle on the way out.

        A host owes an outcome for every session it opens, including one
        it abandons, and nothing can make that automatic. A context
        manager makes it the shape of least resistance instead. Settling
        twice returns the same completion, so an explicit ``finish``
        inside the block stays correct.
        """
        self.finish()

    def finish(self) -> dict[str, Any]:
        """Settle the session and return the terminal record:
        ``{"reason": <end_reason>, "transformed": bool, "is_clean":
        bool}``.

        ``reason`` is one of ``{"kind": "complete"}``, ``{"kind":
        "denied", "track", "task", "start", "end"}``, ``{"kind":
        "rewritten", "track", "task", "start", "end"}``, or ``{"kind":
        "failed", "reason", "message"}``. Any rune no task cleared
        settles the session ``failed`` under every safety level.
        """
        return json.loads(_native.stream_finish(self._handle))

    @property
    def is_ended(self) -> bool:
        """Whether the session has reached its terminal state."""
        return _native.stream_is_ended(self._handle)

    @property
    def transformed(self) -> bool:
        """Whether a ``transformed`` outcome ended this session, meaning
        the host emits a substitute rather than verbatim model output.
        A transform clears nothing, so this says nothing about what was
        released.
        """
        return _native.stream_transformed(self._handle)

    @property
    def end_reason(self) -> dict[str, Any] | None:
        """Terminal reason as a wire dict, or ``None`` when the session
        has not ended. The same schema :meth:`finish` returns under
        ``reason``.
        """
        raw = _native.stream_end_reason(self._handle)
        return None if raw is None else json.loads(raw)

    @property
    def config(self) -> dict[str, Any]:
        """Streaming parameters this session was opened with:
        ``{"safety_level", "request_start_rune_offset",
        "response_start_rune_offset", "request_tasks",
        "response_tasks"}``.
        """
        return json.loads(_native.stream_config(self._handle))
