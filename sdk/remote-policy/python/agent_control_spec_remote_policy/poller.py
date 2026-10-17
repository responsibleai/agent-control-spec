# Copyright (c) Microsoft. All rights reserved.
"""Opt-in remote ACS artifact polling; downloaded does not mean evaluator-ready."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
import uuid
from collections.abc import Hashable, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import (
    Literal,
    NotRequired,
    Protocol,
    Self,
    TypeAlias,
    TypedDict,
    TypeGuard,
    cast,
)
from urllib.parse import urlsplit

import yaml
from agent_control_spec import (
    parse_manifest,
    supported_manifest_versions,
    validate_manifest,
)
from yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    DocumentStartEvent,
    ScalarEvent,
)

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
CredentialOption: TypeAlias = None | bool | int | float | str
_POLICY_REQUEST_ID: ContextVar[str | None] = ContextVar(
    "acs_policy_request_id", default=None
)


def current_policy_request_id() -> str | None:
    """Return the current source-call audit ID, not an authorization identity."""
    return _POLICY_REQUEST_ID.get()


SourceErrorKind: TypeAlias = Literal["transient", "authoritative", "protocol"]
ValidationCode: TypeAlias = Literal[
    "config",
    "json",
    "schema",
    "scope",
    "etag",
    "clock_skew",
    "lease",
    "manifest",
    "rego",
    "revision",
]
State: TypeAlias = Literal[
    "pending",
    "active",
    "unavailable",
    "expired",
    "closed",
    "failed",
]
MAX_POLICY_BYTES = 1024 * 1024
MAX_EVALUATION_BYTES = 2 * MAX_POLICY_BYTES
MAX_YAML_BYTES = 64 * 1024
MAX_AGENTS = 32
MAX_CONCURRENT_FETCHES = 4
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_QUERY = re.compile(r"data(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_ETAG = re.compile(r'"[0-9a-f]{64}"')
_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)
_SOURCE_CODES = frozenset(
    {
        "transport",
        "timeout",
        "unauthorized",
        "forbidden",
        "not_found",
        "gone",
        "throttled",
        "service",
        "unexpected_status",
        "redirect",
        "headers",
        "body_too_large",
        "credential",
        "busy",
        "closed",
        "source_failure",
    }
)
_LOG = logging.getLogger(__name__)


class PolicyError(Exception):
    """Base for safe, operator-visible remote policy failures."""


class PolicyValidationError(PolicyError, ValueError):
    """Rejected configuration or artifact; never includes fetched content."""

    def __init__(self, code: ValidationCode) -> None:
        if code not in (
            "config",
            "json",
            "schema",
            "scope",
            "etag",
            "clock_skew",
            "lease",
            "manifest",
            "rego",
            "revision",
        ):
            raise ValueError("Unknown remote policy validation code")
        self.code = code
        super().__init__(f"Remote policy validation failed: {code}")


class PolicySourceError(PolicyError):
    """Typed transport/auth failure; authoritative failures fence the agent."""

    def __init__(self, kind: SourceErrorKind, code: str) -> None:
        if kind not in ("transient", "authoritative", "protocol"):
            raise ValueError("Unknown policy source error kind")
        if code not in _SOURCE_CODES:
            raise ValueError("Unknown policy source error code")
        self.kind = kind
        self.code = code
        super().__init__(f"Remote policy source failed: {code}")


class PolicyUnavailable(PolicyError):
    """No current authorized, unexpired snapshot; the host must block."""


class PolicyCapacityError(PolicyUnavailable):
    """Immediate bounded-worker admission failed; no work was queued."""


class PolicyUsageError(PolicyError, RuntimeError):
    """Unknown registration, lifecycle misuse, or event-loop mismatch."""


class PolicyCloseError(PolicyError):
    """Cleanup failed; retained work is not reported as successfully closed."""

    def __init__(self, retained_tasks: int) -> None:
        self.retained_tasks = retained_tasks
        super().__init__(
            f"Remote policy source did not close cleanly; retained tasks: {retained_tasks}"
        )


class StartupError(PolicyError):
    """All-required startup failed; inspect the immutable per-agent failures."""

    def __init__(self, failures: Mapping[str, PolicyError]) -> None:
        self.failures = MappingProxyType(dict(failures))
        super().__init__(f"Remote policy startup failed for {len(failures)} agent(s)")


def _is_object(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _is_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def _object(value: object, code: ValidationCode) -> dict[str, object]:
    if not _is_object(value):
        raise PolicyValidationError(code)
    result: dict[str, object] = {}
    for key, child in value.items():
        if not isinstance(key, str):
            raise PolicyValidationError(code)
        try:
            key.encode("utf-8")
        except UnicodeEncodeError:
            raise PolicyValidationError(code) from None
        result[key] = child
    return result


def _keys(
    value: Mapping[str, object],
    required: set[str],
    optional: set[str],
    code: ValidationCode,
) -> None:
    if not required <= value.keys() or value.keys() - required - optional:
        raise PolicyValidationError(code)


def _identifier(value: object, code: ValidationCode) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise PolicyValidationError(code)
    return value


def _number(value: object, code: ValidationCode) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyValidationError(code)
    number = float(value)
    if not math.isfinite(number):
        raise PolicyValidationError(code)
    return number


class _YamlReader(Protocol):
    """Narrow incomplete PyYAML stubs at the supported SafeLoader boundary."""

    def get_event(self) -> object: ...

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object: ...

    def dispose(self) -> None: ...


def _preflight_yaml(text: str, code: ValidationCode) -> None:
    try:
        if len(text.encode("utf-8")) > MAX_YAML_BYTES:
            raise PolicyValidationError(code)
    except UnicodeEncodeError:
        raise PolicyValidationError(code) from None
    depth = documents = events = 0
    loader: _YamlReader | None = None
    try:
        loader = cast(_YamlReader, yaml.SafeLoader(text))
        while (event := loader.get_event()) is not None:
            events += 1
            if events > 10000:
                raise PolicyValidationError(code)
            if isinstance(event, AliasEvent):
                raise PolicyValidationError(code)
            if isinstance(event, (CollectionStartEvent, ScalarEvent)) and (
                event.anchor is not None or event.tag is not None
            ):
                raise PolicyValidationError(code)
            if isinstance(event, ScalarEvent) and event.value == "<<":
                raise PolicyValidationError(code)
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > 32:
                    raise PolicyValidationError(code)
            if isinstance(event, CollectionEndEvent):
                depth -= 1
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise PolicyValidationError(code)
    except yaml.YAMLError:
        raise PolicyValidationError(code) from None
    finally:
        if loader is not None:
            loader.dispose()


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Hashable, object]:
        result: dict[Hashable, object] = {}
        constructor = cast(_YamlReader, self)
        for key_node, value_node in node.value:
            key = constructor.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise PolicyValidationError("config")
            result[key] = constructor.construct_object(value_node, deep=deep)
        return result


@dataclass(frozen=True, slots=True)
class AgentPolicy:
    """Host-owned flat selection; remote/model content cannot change these IDs."""

    agent_id: str
    tenant_id: str
    policy_id: str

    def __post_init__(self) -> None:
        for value in (self.agent_id, self.tenant_id, self.policy_id):
            _identifier(value, "config")


def _credential_options(
    value: Mapping[str, CredentialOption],
) -> Mapping[str, CredentialOption]:
    raw: object = value
    if not isinstance(raw, Mapping) or len(raw) > 32:
        raise PolicyValidationError("config")
    options: dict[str, CredentialOption] = {}
    for key, child in cast(Mapping[object, object], raw).items():
        name = _identifier(key, "config")
        if name in options or len(options) >= 32:
            raise PolicyValidationError("config")
        if child is not None and not isinstance(child, (bool, int, float, str)):
            raise PolicyValidationError("config")
        if isinstance(child, float) and not math.isfinite(child):
            raise PolicyValidationError("config")
        if isinstance(child, str):
            try:
                if len(child.encode("utf-8")) > 16384:
                    raise PolicyValidationError("config")
            except UnicodeEncodeError:
                raise PolicyValidationError("config") from None
        options[name] = child
    try:
        encoded = json.dumps(
            options,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (ValueError, UnicodeEncodeError):
        raise PolicyValidationError("config") from None
    if len(encoded) > 16384:
        raise PolicyValidationError("config")
    return MappingProxyType(options)


@dataclass(frozen=True, slots=True)
class CredentialConfig:
    """Non-secret provider settings; reject mutable, invalid or oversized options."""

    provider: str
    options: Mapping[str, CredentialOption] = field(
        default_factory=lambda: dict[str, CredentialOption](), repr=False, hash=False
    )

    def __post_init__(self) -> None:
        _identifier(self.provider, "config")
        object.__setattr__(self, "options", _credential_options(self.options))


def _parse_credentials(value: object) -> dict[str, CredentialConfig]:
    definitions = _object(value, "config")
    if len(definitions) > 32:
        raise PolicyValidationError("config")
    result: dict[str, CredentialConfig] = {}
    for reference, raw in definitions.items():
        _identifier(reference, "config")
        definition = _object(raw, "config")
        _keys(definition, {"provider"}, {"options"}, "config")
        options = _object(definition.get("options", {}), "config")
        # CredentialConfig validates scalar types even for untyped callers.
        result[reference] = CredentialConfig(
            _identifier(definition["provider"], "config"),
            cast(Mapping[str, CredentialOption], options),
        )
    return result


@dataclass(frozen=True, slots=True)
class PollerConfig:
    """Bounded registrations, 300-second default, optional HTTP configuration."""

    agents: tuple[AgentPolicy, ...]
    poll_interval_seconds: float = 300.0
    request_timeout_seconds: float = 10.0
    endpoint: str | None = None
    credential_ref: str | None = None
    allow_insecure_localhost: bool = False
    credentials: Mapping[str, CredentialConfig] = field(
        default_factory=lambda: dict[str, CredentialConfig](), repr=False, hash=False
    )

    def __post_init__(self) -> None:
        agents_value: object = self.agents
        if not _is_tuple(agents_value) or any(
            not isinstance(agent, AgentPolicy) for agent in agents_value
        ):
            raise PolicyValidationError("config")
        if not 1 <= len(self.agents) <= MAX_AGENTS:
            raise PolicyValidationError("config")
        if len({agent.agent_id for agent in self.agents}) != len(self.agents):
            raise PolicyValidationError("config")
        interval = _number(self.poll_interval_seconds, "config")
        timeout = _number(self.request_timeout_seconds, "config")
        if not 0 < timeout <= 120 or not timeout < interval <= 3600:
            raise PolicyValidationError("config")
        endpoint_value: object = self.endpoint
        if endpoint_value is not None and not isinstance(endpoint_value, str):
            raise PolicyValidationError("config")
        if self.credential_ref is not None:
            _identifier(self.credential_ref, "config")
        insecure_value: object = self.allow_insecure_localhost
        if not isinstance(insecure_value, bool):
            raise PolicyValidationError("config")
        definitions: object = self.credentials
        if not isinstance(definitions, Mapping) or len(definitions) > 32:
            raise PolicyValidationError("config")
        copied: dict[str, CredentialConfig] = {}
        for reference, definition in cast(Mapping[object, object], definitions).items():
            name = _identifier(reference, "config")
            if (
                not isinstance(definition, CredentialConfig)
                or name in copied
                or len(copied) >= 32
            ):
                raise PolicyValidationError("config")
            copied[name] = definition
        object.__setattr__(self, "credentials", MappingProxyType(copied))

    @classmethod
    def from_yaml(cls, text: str) -> PollerConfig:
        """Parse non-secret YAML; duplicates, aliases and unknown fields fail."""
        _preflight_yaml(text, "config")
        loader = _UniqueSafeLoader(text)
        try:
            raw: object = loader.get_single_data()
        except yaml.YAMLError:
            raise PolicyValidationError("config") from None
        finally:
            loader.dispose()
        root = _object(raw, "config")
        _keys(root, {"remote_policy"}, set(), "config")
        config = _object(root["remote_policy"], "config")
        _keys(
            config,
            {"agents"},
            {
                "poll_interval_seconds",
                "request_timeout_seconds",
                "endpoint",
                "credential_ref",
                "allow_insecure_localhost",
                "credentials",
            },
            "config",
        )
        agents_raw = config["agents"]
        if not _is_list(agents_raw):
            raise PolicyValidationError("config")
        agents: list[AgentPolicy] = []
        for raw_agent in agents_raw:
            agent = _object(raw_agent, "config")
            _keys(agent, {"agent_id", "tenant_id", "policy_id"}, set(), "config")
            agents.append(
                AgentPolicy(
                    _identifier(agent["agent_id"], "config"),
                    _identifier(agent["tenant_id"], "config"),
                    _identifier(agent["policy_id"], "config"),
                )
            )
        interval = _number(config.get("poll_interval_seconds", 300), "config")
        if not 5 <= interval <= 3600:
            raise PolicyValidationError("config")
        endpoint = config.get("endpoint")
        if endpoint is not None and not isinstance(endpoint, str):
            raise PolicyValidationError("config")
        if endpoint is not None:
            try:
                url = urlsplit(endpoint)
                if (
                    url.scheme not in ("http", "https")
                    or not url.hostname
                    or url.username is not None
                    or url.password is not None
                    or url.query
                    or url.fragment
                ):
                    raise PolicyValidationError("config")
            except ValueError:
                raise PolicyValidationError("config") from None
        credential_ref = config.get("credential_ref")
        if credential_ref is not None:
            credential_ref = _identifier(credential_ref, "config")
        insecure = config.get("allow_insecure_localhost", False)
        if not isinstance(insecure, bool):
            raise PolicyValidationError("config")
        return cls(
            tuple(agents),
            interval,
            _number(config.get("request_timeout_seconds", 10), "config"),
            endpoint,
            credential_ref,
            insecure,
            _parse_credentials(config.get("credentials", {})),
        )


def remote_configuration_note(source: str) -> str | None:
    """Give a payload-free validation note only for an established remote root."""
    try:
        _preflight_yaml(source, "config")
        loader = _UniqueSafeLoader(source)
        try:
            raw: object = loader.get_single_data()
        finally:
            loader.dispose()
    except (PolicyValidationError, yaml.YAMLError):
        return None
    if _is_object(raw) and "remote_policy" in raw:
        return "Remote configuration rejected (code=config; path=remote_policy)."
    return None


@dataclass(frozen=True, slots=True)
class Changed:
    """Complete exact-byte envelope, not a delta; ETag authenticates consistency."""

    body: bytes = field(repr=False)
    etag: str


@dataclass(frozen=True, slots=True)
class NotModified:
    """Conditional response; cannot renew the cached absolute lease."""

    etag: str


class PolicySource(Protocol):
    """Host adapter owned by one poller; cancellation and aclose must drain IO."""

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified: ...

    async def aclose(self) -> None: ...


class Clock(Protocol):
    """Trusted host clock, injectable for deterministic lease tests."""

    def utcnow(self) -> datetime: ...

    def monotonic(self) -> float: ...


class _SystemClock:
    def utcnow(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class MountedData(TypedDict):
    """Inline Rego data only; mount is a logical data path, not a file path."""

    mount: list[str]
    document: JsonValue


class EmbeddedRegoBundle(TypedDict):
    """One declared logical Rego key's in-memory sources and optional data."""

    modules: dict[str, str]
    data: NotRequired[list[MountedData]]


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyValidationError("json")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PolicyValidationError("json")


def _json_value(value: object, depth: int = 0) -> JsonValue:
    if depth > 32:
        raise PolicyValidationError("json")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise PolicyValidationError("json") from None
        return value
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise PolicyValidationError("json")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PolicyValidationError("json")
        return value
    if _is_list(value):
        return [_json_value(child, depth + 1) for child in value]
    mapping = _object(value, "json")
    return {key: _json_value(child, depth + 1) for key, child in mapping.items()}


def decode_json(body: bytes, *, max_bytes: int = MAX_POLICY_BYTES) -> JsonValue:
    """Bounded strict JSON decoder, also usable by custom sources/examples."""
    if len(body) > max_bytes:
        raise PolicyValidationError("json")
    depth = 0
    quoted = escaped = False
    for byte in body:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                raise PolicyValidationError("json")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise PolicyValidationError("json")
    try:
        raw: object = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise PolicyValidationError("json") from None
    return _json_value(raw)


def _rego_preflight(source: str) -> None:
    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > 64 * 1024:
        raise PolicyValidationError("rego")
    quote: int | None = None
    escaped = comment = word = False
    depth = operations = work = 0
    # Mirror native authoring admission without parsing untrusted Rego in-process.
    for byte in encoded:
        work += 1 << depth
        if work > 262144:
            raise PolicyValidationError("rego")
        if comment:
            comment = byte != 10
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif quote == 34 and byte == 92:
                escaped = True
            elif byte == quote:
                quote = None
            continue
        word_byte = (
            48 <= byte <= 57
            or 65 <= byte <= 90
            or 97 <= byte <= 122
            or byte == 95
            or byte >= 128
        )
        if word_byte and not word:
            operations += 1
        word = word_byte
        if byte == 35:
            comment = True
        elif byte in (34, 96):
            quote = byte
        elif byte in (91, 123, 40):
            depth += 1
            operations += 1
            if depth > 12:
                raise PolicyValidationError("rego")
        elif byte in (93, 125, 41):
            depth = max(0, depth - 1)
        elif byte in b".+-*/%&|!<>=:":
            operations += 1
        if operations > 1024:
            raise PolicyValidationError("rego")


def _embedded_bundles(value: object) -> dict[str, EmbeddedRegoBundle]:
    raw = _object(value, "schema")
    if not 1 <= len(raw) <= 64:
        raise PolicyValidationError("schema")
    result: dict[str, EmbeddedRegoBundle] = {}
    module_count = 0
    for key, raw_bundle in raw.items():
        _identifier(key, "schema")
        bundle = _object(raw_bundle, "schema")
        _keys(bundle, {"modules"}, {"data"}, "schema")
        raw_modules = _object(bundle["modules"], "schema")
        if not raw_modules:
            raise PolicyValidationError("schema")
        modules: dict[str, str] = {}
        for name, source in raw_modules.items():
            _identifier(name, "schema")
            if not name.endswith(".rego") or not isinstance(source, str):
                raise PolicyValidationError("schema")
            _rego_preflight(source)
            modules[name] = source
            module_count += 1
            if module_count > 64:
                raise PolicyValidationError("schema")
        embedded: EmbeddedRegoBundle = {"modules": modules}
        if "data" in bundle:
            raw_data = bundle["data"]
            if not _is_list(raw_data):
                raise PolicyValidationError("schema")
            data: list[MountedData] = []
            for raw_item in raw_data:
                item = _object(raw_item, "schema")
                _keys(item, {"mount", "document"}, set(), "schema")
                mount = item["mount"]
                if not _is_list(mount) or len(mount) > 32:
                    raise PolicyValidationError("schema")
                data.append(
                    {
                        "mount": [_identifier(part, "schema") for part in mount],
                        "document": _json_value(item["document"]),
                    }
                )
            embedded["data"] = data
        result[key] = embedded
    return result


def validate_acs_artifacts(
    manifest: str, bundles: object
) -> dict[str, EmbeddedRegoBundle]:
    """Validate the closed remote Rego profile; does not compile/evaluate code."""
    _preflight_yaml(manifest, "manifest")
    try:
        normalized: object = parse_manifest(manifest)
        validate_manifest(manifest)
    except (ValueError, RuntimeError):
        raise PolicyValidationError("manifest") from None
    root = _object(normalized, "manifest")
    _keys(
        root,
        {"agent_control_specification_version", "policies", "intervention_points"},
        {"metadata", "tools", "extends", "annotators"},
        "manifest",
    )
    if root["agent_control_specification_version"] not in supported_manifest_versions():
        raise PolicyValidationError("manifest")
    if root.get("extends", []) != [] or root.get("annotators", {}) != {}:
        raise PolicyValidationError("manifest")
    policies = _object(root["policies"], "manifest")
    points = _object(root["intervention_points"], "manifest")
    if not policies or not points:
        raise PolicyValidationError("manifest")
    embedded = _embedded_bundles(bundles)
    if embedded.keys() != policies.keys():
        raise PolicyValidationError("manifest")
    for key, raw_policy in policies.items():
        _identifier(key, "manifest")
        policy = _object(raw_policy, "manifest")
        _keys(policy, {"type", "query"}, set(), "manifest")
        if policy["type"] != "rego":
            raise PolicyValidationError("manifest")
        _rule_query(policy["query"])
    for raw_point in points.values():
        point = _object(raw_point, "manifest")
        _keys(
            point,
            {"policy"},
            {"policy_target", "policy_target_kind", "tool_name_from", "annotations"},
            "manifest",
        )
        if point.get("annotations", {}) != {}:
            raise PolicyValidationError("manifest")
        binding = _object(point["policy"], "manifest")
        _keys(binding, {"id"}, {"query"}, "manifest")
        if _identifier(binding["id"], "manifest") not in policies:
            raise PolicyValidationError("manifest")
        if "query" in binding:
            _rule_query(binding["query"])
    for raw_tool in _object(root.get("tools", {}), "manifest").values():
        tool = _object(raw_tool, "manifest")
        _keys(tool, {"type", "id"}, set(), "manifest")
        if tool["type"] != "Tool":
            raise PolicyValidationError("manifest")
        _identifier(tool["id"], "manifest")
    return embedded


def _rule_query(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 256
        or _QUERY.fullmatch(value) is None
    ):
        raise PolicyValidationError("manifest")


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise PolicyValidationError("schema")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise PolicyValidationError("schema") from None


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Immutable downloaded artifacts; retrieve and gate through the poller."""

    selection: AgentPolicy
    revision: int
    issued_at: datetime
    expires_at: datetime
    etag: str
    manifest_yaml: str = field(repr=False)
    _document_bytes: bytes = field(repr=False)
    monotonic_deadline: float = field(repr=False)

    def bundles(self) -> dict[str, EmbeddedRegoBundle]:
        """Return a fresh mutable copy; callers cannot mutate the memory cache."""
        document = _object(decode_json(self._document_bytes), "schema")
        return _embedded_bundles(document["bundles"])


@dataclass(frozen=True, slots=True)
class PolicyStatus:
    """Safe per-agent observability; metadata is never taken from model context."""

    state: State
    revision: int
    last_success_at: datetime | None
    error_kind: str | None


@dataclass(slots=True)
class _Entry:
    selection: AgentPolicy
    snapshot: PolicySnapshot | None = None
    revision: int = 0
    etag: str | None = None
    deadline: float = 0
    state: State = "pending"
    last_success: datetime | None = None
    error: str | None = None
    request_id: str = ""
    expires_at: datetime | None = None


class PolicyPoller:
    """Own a source and bounded per-agent memory cache on one event loop."""

    def __init__(
        self,
        config: PollerConfig,
        source: PolicySource,
        *,
        clock: Clock | None = None,
        close_timeout_seconds: float = 5.0,
    ) -> None:
        self.config = config
        self._source = source
        self._clock: Clock = clock if clock is not None else _SystemClock()
        close_timeout = _number(close_timeout_seconds, "config")
        if not 0 < close_timeout <= 30:
            raise PolicyValidationError("config")
        self._close_timeout = close_timeout
        self._entries = {a.agent_id: _Entry(a) for a in config.agents}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._phase: Literal[
            "created",
            "starting",
            "running",
            "closing",
            "closed",
            "failed",
            "close_failed",
        ] = "created"
        self._slots = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
        self._flights: dict[str, asyncio.Task[PolicySnapshot]] = {}
        self._requests: dict[str, asyncio.Task[Changed | NotModified]] = {}
        self._scheduler: asyncio.Task[None] | None = None
        self._closing: asyncio.Task[None] | None = None
        self._source_closing: asyncio.Task[None] | None = None

    def _bind(self) -> asyncio.AbstractEventLoop:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise PolicyUsageError(
                "Remote policy access requires its running loop"
            ) from None
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise PolicyUsageError("Remote policy poller belongs to a different loop")
        return loop

    def _entry(self, agent_id: str) -> _Entry:
        if agent_id not in self._entries:
            raise PolicyUsageError("Agent has no trusted policy registration")
        return self._entries[agent_id]

    def _audit(self, event: str, entry: _Entry, *, error: bool = False) -> None:
        expires_at = (
            entry.expires_at.isoformat() if entry.expires_at is not None else None
        )
        _LOG.log(
            logging.WARNING if error else logging.INFO,
            "%s agent=%s tenant=%s policy=%s revision=%d etag=%s "
            "expires_at=%s error=%s request_id=%s",
            event,
            entry.selection.agent_id,
            entry.selection.tenant_id,
            entry.selection.policy_id,
            entry.revision,
            entry.etag,
            expires_at,
            entry.error,
            entry.request_id,
            extra={
                "event": event,
                "agent_id": entry.selection.agent_id,
                "tenant_id": entry.selection.tenant_id,
                "policy_id": entry.selection.policy_id,
                "revision": entry.revision,
                "etag": entry.etag,
                "expires_at": expires_at,
                "error_kind": entry.error,
                "request_id": entry.request_id,
            },
        )

    def _expire(self, entry: _Entry) -> None:
        snapshot = entry.snapshot
        if snapshot is not None and (
            self._clock.utcnow() >= snapshot.expires_at
            or self._clock.monotonic() >= snapshot.monotonic_deadline
        ):
            entry.snapshot = None
            entry.state, entry.error = "expired", "expired"
            self._audit("policy_expired", entry, error=True)

    def get_policy(self, agent_id: str) -> PolicySnapshot:
        """Get a valid artifact snapshot; absence/expiry/close raises, never allows."""
        self._bind()
        entry = self._entry(agent_id)
        if self._phase != "running":
            raise PolicyUnavailable("Remote policy poller is not running")
        self._expire(entry)
        if entry.snapshot is None:
            raise PolicyUnavailable("Agent policy is unavailable or expired")
        return entry.snapshot

    def assert_current(self, agent_id: str, snapshot: PolicySnapshot) -> None:
        """Final synchronous action gate; changed or expired selection blocks."""
        if self.get_policy(agent_id) is not snapshot:
            raise PolicyUnavailable("Agent policy changed during evaluation")

    def status(self, agent_id: str) -> PolicyStatus:
        """Read safe state and last-success metadata on the poller's event loop."""
        self._bind()
        entry = self._entry(agent_id)
        self._expire(entry)
        return PolicyStatus(
            entry.state, entry.revision, entry.last_success, entry.error
        )

    async def start(self) -> None:
        """Download all required policies before starting the fixed-rate scheduler."""
        loop = self._bind()
        if self._phase != "created":
            raise PolicyUsageError("Remote policy poller is single-use")
        self._phase = "starting"
        try:
            failures = await self._refresh_all()
        except asyncio.CancelledError:
            await self.aclose()
            raise
        if failures:
            await self.aclose()
            raise StartupError(failures)
        if self._phase != "starting":
            raise PolicyUnavailable("Remote policy startup was closed")
        self._phase = "running"
        self._scheduler = loop.create_task(self._run(), name="acs-policy-polling")
        self._scheduler.add_done_callback(self._scheduler_finished)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def refresh(self, agent_id: str) -> PolicySnapshot:
        """Explicit shared refresh; cancellation leaves bounded work owned here."""
        self._bind()
        self._entry(agent_id)
        if self._phase != "running":
            raise PolicyUnavailable("Remote policy poller is not running")
        return await asyncio.shield(self._flight(agent_id))

    def _flight(self, agent_id: str) -> asyncio.Task[PolicySnapshot]:
        existing = self._flights.get(agent_id)
        if existing is not None:
            return existing
        loop = self._bind()
        task = loop.create_task(self._refresh(agent_id), name="acs-policy-refresh")
        self._flights[agent_id] = task
        task.add_done_callback(lambda done: self._flight_finished(agent_id, done))
        return task

    def _flight_finished(
        self, agent_id: str, task: asyncio.Task[PolicySnapshot]
    ) -> None:
        if self._flights.get(agent_id) is task:
            del self._flights[agent_id]
        if not task.cancelled():
            failure = task.exception()
            if failure is not None and not isinstance(failure, PolicyError):
                entry = self._entries[agent_id]
                entry.snapshot = None
                entry.state, entry.error = "failed", "internal"
                self._audit("policy_internal_failure", entry, error=True)

    async def _refresh_all(self) -> dict[str, PolicyError]:
        agents = tuple(self._entries)
        results = await asyncio.gather(
            *(asyncio.shield(self._flight(agent)) for agent in agents),
            return_exceptions=True,
        )
        failures: dict[str, PolicyError] = {}
        for agent_id, result in zip(agents, results, strict=True):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, PolicyError):
                failures[agent_id] = result
            elif isinstance(result, BaseException):
                failures[agent_id] = PolicyUsageError(
                    "Unexpected policy refresh failure"
                )
        return failures

    async def _run(self) -> None:
        loop = self._bind()
        interval = self.config.poll_interval_seconds
        next_poll = loop.time() + interval
        while True:
            await asyncio.sleep(max(0, next_poll - loop.time()))
            await self._refresh_all()
            next_poll += interval
            now = loop.time()
            if next_poll <= now:
                next_poll += (math.floor((now - next_poll) / interval) + 1) * interval

    def _scheduler_finished(self, task: asyncio.Task[None]) -> None:
        if (
            task.cancelled() or task.exception() is not None
        ) and self._phase == "running":
            self._phase = "failed"
            for entry in self._entries.values():
                entry.snapshot = None
                entry.state, entry.error = "failed", "internal"
                self._audit("policy_scheduler_failed", entry, error=True)

    async def _call_source(
        self, selection: AgentPolicy, etag: str | None
    ) -> Changed | NotModified:
        async with self._slots:
            return await self._source.fetch(selection, etag)

    def _request_finished(
        self, agent_id: str, task: asyncio.Task[Changed | NotModified]
    ) -> None:
        if self._requests.get(agent_id) is task:
            del self._requests[agent_id]
        if not task.cancelled():
            failure = task.exception()
            if (
                isinstance(failure, PolicySourceError)
                and failure.kind == "authoritative"
                and self._phase in ("starting", "running")
            ):
                self._fence(self._entries[agent_id], failure.code)

    def _fence(self, entry: _Entry, code: str) -> None:
        changed = entry.snapshot is not None or entry.error != code
        entry.snapshot = None
        entry.state, entry.error = "unavailable", code
        if changed:
            self._audit("policy_fenced", entry, error=True)

    async def _refresh(self, agent_id: str) -> PolicySnapshot:
        entry = self._entries[agent_id]
        self._expire(entry)
        etag = entry.snapshot.etag if entry.snapshot is not None else None
        context: Token[str | None] | None = None
        try:
            if agent_id in self._requests:
                raise PolicySourceError("transient", "busy")
            loop = self._bind()
            entry.request_id = uuid.uuid4().hex
            context = _POLICY_REQUEST_ID.set(entry.request_id)
            request = loop.create_task(
                self._call_source(entry.selection, etag), name="acs-policy-fetch"
            )
            self._requests[agent_id] = request
            request.add_done_callback(
                lambda done: self._request_finished(agent_id, done)
            )
            done, _ = await asyncio.wait(
                (request,), timeout=self.config.request_timeout_seconds
            )
            if not done:
                request.cancel()
                raise PolicySourceError("transient", "timeout")
            if self._phase not in ("starting", "running"):
                raise PolicyUnavailable("Remote policy refresh was closed")
            if request.cancelled():
                raise PolicySourceError("transient", "source_failure")
            failure = request.exception()
            if failure is not None:
                if isinstance(failure, PolicyError):
                    raise failure
                raise PolicySourceError("transient", "source_failure") from None
            response: object = request.result()
            self._expire(entry)
            if (
                isinstance(response, Changed)
                and entry.snapshot is not None
                and response.etag == etag
            ):
                if (
                    not isinstance(response.body, bytes)
                    or len(response.body) > MAX_POLICY_BYTES
                    or f'"{hashlib.sha256(response.body).hexdigest()}"' != response.etag
                ):
                    raise PolicyValidationError("etag")
                response = NotModified(response.etag)
            if isinstance(response, NotModified):
                if entry.snapshot is None or etag is None or response.etag != etag:
                    raise PolicyValidationError("etag")
                entry.last_success, entry.error = self._clock.utcnow(), None
                self._audit("policy_not_modified", entry)
                return entry.snapshot
            if not isinstance(response, Changed):
                raise PolicyValidationError("schema")
            candidate = self._decode(entry.selection, response)
            if candidate.revision < entry.revision:
                raise PolicyValidationError("revision")
            if candidate.revision == entry.revision:
                if candidate.etag != entry.etag:
                    raise PolicyValidationError("revision")
                candidate = replace(
                    candidate,
                    monotonic_deadline=min(
                        candidate.monotonic_deadline, entry.deadline
                    ),
                )
                if self._clock.monotonic() >= candidate.monotonic_deadline:
                    raise PolicyValidationError("lease")
                self._expire(entry)
                if entry.snapshot is not None:
                    entry.last_success, entry.error = self._clock.utcnow(), None
                    self._audit("policy_not_modified", entry)
                    return entry.snapshot
            entry.snapshot = candidate
            entry.expires_at = candidate.expires_at
            entry.revision, entry.etag, entry.deadline = (
                candidate.revision,
                candidate.etag,
                candidate.monotonic_deadline,
            )
            entry.state, entry.error = "active", None
            entry.last_success = self._clock.utcnow()
            self._audit("policy_installed", entry)
            return candidate
        except (PolicySourceError, PolicyValidationError, PolicyUnavailable) as failure:
            if (
                isinstance(failure, PolicySourceError)
                and failure.kind == "authoritative"
            ):
                self._fence(entry, failure.code)
            else:
                entry.error = (
                    failure.code
                    if not isinstance(failure, PolicyUnavailable)
                    else "closed"
                )
                self._expire(entry)
                self._audit("policy_refresh_failed", entry, error=True)
            raise
        finally:
            if context is not None:
                _POLICY_REQUEST_ID.reset(context)

    def _decode(self, selection: AgentPolicy, response: Changed) -> PolicySnapshot:
        body_value: object = response.body
        etag_value: object = response.etag
        if not isinstance(body_value, bytes) or not isinstance(etag_value, str):
            raise PolicyValidationError("schema")
        if len(body_value) > MAX_POLICY_BYTES:
            raise PolicyValidationError("json")
        if (
            _ETAG.fullmatch(response.etag) is None
            or hashlib.sha256(response.body).hexdigest() != response.etag[1:-1]
        ):
            raise PolicyValidationError("etag")
        body = _object(decode_json(response.body), "schema")
        _keys(
            body,
            {
                "schema_version",
                "tenant_id",
                "policy_id",
                "revision",
                "issued_at",
                "expires_at",
                "manifest",
                "bundles",
            },
            set(),
            "schema",
        )
        if type(body["schema_version"]) is not int or body["schema_version"] != 1:
            raise PolicyValidationError("schema")
        if (
            _identifier(body["tenant_id"], "scope") != selection.tenant_id
            or _identifier(body["policy_id"], "scope") != selection.policy_id
        ):
            raise PolicyValidationError("scope")
        revision = body["revision"]
        if type(revision) is not int or not 1 <= revision < 2**63:
            raise PolicyValidationError("revision")
        issued, expires = _utc(body["issued_at"]), _utc(body["expires_at"])
        now = self._clock.utcnow()
        if issued > now + timedelta(seconds=60):
            raise PolicyValidationError("clock_skew")
        duration = (expires - issued).total_seconds()
        minimum = (
            2 * self.config.poll_interval_seconds + self.config.request_timeout_seconds
        )
        if not minimum <= duration <= 86400 or expires <= now:
            raise PolicyValidationError("lease")
        manifest = body["manifest"]
        if not isinstance(manifest, str):
            raise PolicyValidationError("manifest")
        validate_acs_artifacts(manifest, body["bundles"])
        return PolicySnapshot(
            selection,
            revision,
            issued,
            expires,
            response.etag,
            manifest,
            response.body,
            self._clock.monotonic() + (expires - now).total_seconds(),
        )

    async def aclose(self) -> None:
        """Fence immediately, cancel/drain owned work and close the owned source."""
        loop = self._bind()
        if self._phase == "closed":
            return
        if self._closing is None or (
            self._closing.done() and self._phase == "close_failed"
        ):
            self._phase = "closing"
            for entry in self._entries.values():
                entry.snapshot = None
                entry.state, entry.error = "closed", "closed"
            self._closing = loop.create_task(self._close(), name="acs-policy-close")
            self._closing.add_done_callback(self._close_finished)
        await asyncio.shield(self._closing)

    def _close_finished(self, task: asyncio.Task[None]) -> None:
        if task.cancelled() or task.exception() is not None:
            self._phase = "close_failed"
            for entry in self._entries.values():
                entry.state, entry.error = "failed", "close_failed"
            _LOG.error("policy_close_failed", extra={"event": "policy_close_failed"})

    async def _close(self) -> None:
        tasks: set[asyncio.Task[object]] = set()
        tasks.update(self._flights.values())
        tasks.update(self._requests.values())
        if self._scheduler is not None:
            tasks.add(self._scheduler)
        for task in tasks:
            task.cancel()
        pending: set[asyncio.Task[object]] = set()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=self._close_timeout)
        if self._source_closing is None or self._source_closing.cancelled():
            self._source_closing = self._bind().create_task(
                self._source.aclose(), name="acs-policy-source-close"
            )
            self._source_closing.add_done_callback(self._source_close_finished)
        source_close = self._source_closing
        done, _ = await asyncio.wait((source_close,), timeout=self._close_timeout)
        if not done:
            source_close.cancel()
        failed = (
            not done
            or source_close.cancelled()
            or (source_close.done() and source_close.exception() is not None)
        )
        if pending or failed:
            self._phase = "close_failed"
            raise PolicyCloseError(len(pending) + int(not done))
        self._phase = "closed"
        for entry in self._entries.values():
            self._audit("policy_closed", entry)

    @staticmethod
    def _source_close_finished(task: asyncio.Task[None]) -> None:
        if not task.cancelled() and task.exception() is not None:
            _LOG.error(
                "policy_source_close_failed",
                extra={"event": "policy_source_close_failed"},
            )
