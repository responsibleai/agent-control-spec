# Copyright (c) Microsoft. All rights reserved.
"""Contract, tenancy, leases, atomic installation and owned-task lifecycle."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from agent_control_spec_remote_policy.poller import (
    MAX_POLICY_BYTES,
    AgentPolicy,
    Changed,
    CredentialConfig,
    CredentialOption,
    JsonValue,
    NotModified,
    PolicyCloseError,
    PolicyError,
    PolicyPoller,
    PolicySnapshot,
    PolicySourceError,
    PolicyUnavailable,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
    StartupError,
    current_policy_request_id,
    decode_json,
    validate_acs_artifacts,
)

NOW = datetime(2026, 10, 12, tzinfo=UTC)
FIXTURE = Path(__file__).parent.joinpath("fixtures", "remote_policy_v1.json")


class FakeClock:
    """UTC and elapsed time are independent to expose wall-clock rollback."""

    def __init__(self) -> None:
        self.wall = NOW
        self.elapsed = 100.0

    def utcnow(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.elapsed

    def advance(self, seconds: float, *, wall_seconds: float | None = None) -> None:
        self.elapsed += seconds
        self.wall += timedelta(
            seconds=seconds if wall_seconds is None else wall_seconds
        )


def configuration(
    count: int = 2, *, interval: float = 300, timeout: float = 10
) -> PollerConfig:
    return PollerConfig(
        tuple(
            AgentPolicy(f"agent{n}", "demo-tenant", f"policy{n}") for n in range(count)
        ),
        poll_interval_seconds=interval,
        request_timeout_seconds=timeout,
    )


def test_credential_definitions_are_immutable_replaceable_hashable_and_private() -> (
    None
):
    options: dict[str, CredentialOption] = {"scope": "non-secret-private-setting"}
    definition = CredentialConfig("custom", options)
    definitions = {"reader": definition}
    config = replace(configuration(1), credential_ref="reader", credentials=definitions)
    options["scope"] = "changed"
    definitions.clear()
    assert definition.options["scope"] == "non-secret-private-setting"
    assert config.credentials["reader"] == definition
    assert replace(config) == config
    assert replace(definition) == definition
    assert hash(config) == hash(replace(config))
    assert hash(definition) == hash(replace(definition))
    assert "non-secret-private-setting" not in repr(config) + repr(definition)
    with pytest.raises(TypeError):
        cast(dict[str, CredentialOption], definition.options)["scope"] = "changed"
    with pytest.raises(TypeError):
        cast(dict[str, CredentialConfig], config.credentials)["other"] = definition
    assert definition != CredentialConfig("custom", {"scope": "different"})


@pytest.mark.parametrize(
    "options",
    [
        {"nested": {}},
        {"array": []},
        {"bad/name": "value"},
        {1: "value"},
        {"number": float("nan")},
        {"number": float("inf")},
        {"text": "\ud800"},
        {"value": object()},
    ],
)
def test_programmatic_credential_options_reject_non_scalars_and_invalid_values(
    options: dict[object, object],
) -> None:
    with pytest.raises(PolicyValidationError, match="config"):
        CredentialConfig("custom", cast(Mapping[str, CredentialOption], options))


@pytest.mark.parametrize("count", [32, 33])
def test_credential_definition_and_option_count_limits(count: int) -> None:
    options = {f"k{n}": n for n in range(count)}
    definitions = {f"r{n}": CredentialConfig("custom") for n in range(count)}
    if count == 32:
        assert len(CredentialConfig("custom", options).options) == count
        assert (
            len(replace(configuration(1), credentials=definitions).credentials) == count
        )
    else:
        with pytest.raises(PolicyValidationError):
            CredentialConfig("custom", options)
        with pytest.raises(PolicyValidationError):
            replace(configuration(1), credentials=definitions)


@pytest.mark.parametrize("size", [16384, 16385])
def test_credential_option_canonical_json_byte_limit(size: int) -> None:
    # {"x":""} occupies eight bytes; non-ASCII is encoded as UTF-8, not escapes.
    options = {"x": "a" * (size - 8)}
    assert len(json.dumps(options, separators=(",", ":")).encode()) == size
    if size == 16384:
        assert CredentialConfig("custom", options).options == options
    else:
        with pytest.raises(PolicyValidationError):
            CredentialConfig("custom", options)


def test_strict_credential_yaml_and_programmatic_mapping_guards() -> None:
    base = (
        "remote_policy:\n  agents:\n    - {agent_id: a, tenant_id: t, policy_id: p}\n"
    )
    config = PollerConfig.from_yaml(
        base + "  credential_ref: reader\n  credentials:\n"
        "    reader:\n      provider: azure_cli\n      options:\n"
        "        scope: api://policy/.default\n        process_timeout_seconds: 5\n"
    )
    assert config.credentials["reader"] == CredentialConfig(
        "azure_cli", {"scope": "api://policy/.default", "process_timeout_seconds": 5}
    )
    for invalid in (
        "[]",
        "{reader: {provider: custom, unknown: value}}",
        "{reader: {options: {}}}",
        "{reader: {provider: custom, options: []}}",
        "{reader: {provider: custom, options: {x: [1]}}}",
        "{reader: {provider: custom}, reader: {provider: other}}",
        "{reader: {provider: custom, options: {x: 1, x: 2}}}",
        "{1: {provider: custom}}",
        "{bad/name: {provider: custom}}",
        "{reader: {provider: bad/name}}",
        "{reader: {provider: custom, options: {x: .nan}}}",
    ):
        with pytest.raises(PolicyValidationError, match="config"):
            PollerConfig.from_yaml(base + "  credentials: " + invalid)
    invalid_mappings: tuple[object, ...] = (
        [],
        {"reader": "not a definition"},
        {1: CredentialConfig("custom")},
    )
    for raw in invalid_mappings:
        with pytest.raises(PolicyValidationError):
            replace(
                configuration(1), credentials=cast(Mapping[str, CredentialConfig], raw)
            )
    with pytest.raises(PolicyValidationError):
        CredentialConfig("bad/name")


def document(
    selection: AgentPolicy,
    *,
    revision: int = 1,
    issued_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(seconds=900),
) -> dict[str, JsonValue]:
    raw = decode_json(FIXTURE.read_bytes())
    assert isinstance(raw, dict)
    raw.update(
        {
            "tenant_id": selection.tenant_id,
            "policy_id": selection.policy_id,
            "revision": revision,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        }
    )
    return raw


def raw_reply(body: bytes) -> Changed:
    return Changed(body, f'"{hashlib.sha256(body).hexdigest()}"')


def reply(value: dict[str, JsonValue]) -> Changed:
    return raw_reply(json.dumps(value, allow_nan=False).encode("utf-8"))


class MemorySource:
    """Deterministic source with real cancellation/admission barriers."""

    def __init__(self, config: PollerConfig) -> None:
        self.responses: dict[str, Changed | NotModified | PolicySourceError] = {
            agent.agent_id: reply(document(agent)) for agent in config.agents
        }
        self.calls: list[tuple[str, str | None]] = []
        self.closed = False
        self.active = self.peak = 0
        self.gate: asyncio.Event | None = None
        self.entered = asyncio.Event()
        self.at_capacity = asyncio.Event()
        self.polled = asyncio.Event()
        self.ignore_cancellation = False
        self.conditional = True

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        self.calls.append((selection.agent_id, if_none_match))
        self.active += 1
        self.peak = max(self.peak, self.active)
        self.entered.set()
        if self.active == 4:
            self.at_capacity.set()
        if len(self.calls) > len(self.responses):
            self.polled.set()
        try:
            if self.gate is not None:
                while not self.gate.is_set():
                    try:
                        await self.gate.wait()
                    except asyncio.CancelledError:
                        if not self.ignore_cancellation:
                            raise
            response = self.responses[selection.agent_id]
            if isinstance(response, PolicySourceError):
                raise response
            if (
                isinstance(response, Changed)
                and self.conditional
                and if_none_match == response.etag
            ):
                return NotModified(response.etag)
            return response
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        self.closed = True


def test_default_interval_yaml_and_snapshot_copy() -> None:
    config = PollerConfig.from_yaml(
        "remote_policy:\n  agents:\n"
        "    - agent_id: a\n      tenant_id: t\n      policy_id: p\n"
    )
    assert config.poll_interval_seconds == 300

    async def scenario() -> None:
        source = MemorySource(config)
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            snapshot = poller.get_policy("a")
            assert snapshot.revision == 1
            changed = snapshot.bundles()
            changed["gate"]["modules"]["limits.rego"] = "mutated"
            assert "mutated" not in snapshot.bundles()["gate"]["modules"]["limits.rego"]
            assert poller.status("a").state == "active"
        assert source.closed and source.active == 0
        assert not poller._flights and not poller._requests
        with pytest.raises(PolicyUnavailable):
            poller.get_policy("a")

    asyncio.run(scenario())


@pytest.mark.parametrize("encoding", ["unicode", "compact_exponents"])
def test_large_bundle_copies_preserve_wire_size_bound(encoding: str) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        value = document(config.agents[0])
        bundles = value["bundles"]
        assert isinstance(bundles, dict)
        bundle = bundles["gate"]
        assert isinstance(bundle, dict)
        payload: JsonValue = (
            "\u4e2d" * 200_000
            if encoding == "unicode"
            else [1e99 for _ in range(180_000)]
        )
        bundle["data"] = [{"mount": ["large"], "document": payload}]
        body = (
            json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("1e+99", "1e99")
            .encode("utf-8")
        )
        assert len(body) <= MAX_POLICY_BYTES
        source.responses["agent0"] = raw_reply(body)
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            snapshot = poller.get_policy("agent0")
            copy = snapshot.bundles()["gate"]
            assert "data" in copy
            assert copy["data"][0]["document"] == payload
            copy["data"][0]["document"] = None
            unchanged = snapshot.bundles()["gate"]
            assert "data" in unchanged
            assert unchanged["data"][0]["document"] == payload
        assert source.closed and source.active == 0
        assert not poller._flights and not poller._requests

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "text",
    [
        "remote_policy:\n  agents: []",
        "remote_policy:\n  agents: []\n  extra: secret",
        "remote_policy:\n  agents: []\n  agents: []",
        "remote_policy: &x\n  agents: []",
        "remote_policy:\n  agents: *x",
        "remote_policy: !thing {}",
        "remote_policy: {}\n---\nremote_policy: {}",
        "remote_policy:\n  <<: {}\n  agents: []",
        "remote_policy:\n  agents:\n    - agent_id: no\n      tenant_id: t\n      policy_id: p",
        "remote_policy:\n  agents:\n    - agent_id: on\n      tenant_id: t\n      policy_id: p",
        "remote_policy:\n  agents:\n    - agent_id: 010\n      tenant_id: t\n      policy_id: p",
        "remote_policy:\n  agents:\n    - agent_id: a\n      tenant_id: ..\n      policy_id: p",
        "remote_policy:\n  agents:\n    - agent_id: a\n      tenant_id: t\n      policy_id: x/y",
    ],
)
def test_invalid_yaml_fails_without_coercion(text: str) -> None:
    with pytest.raises(PolicyValidationError):
        PollerConfig.from_yaml(text)


@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), 0, -1])
def test_numeric_config_is_not_bool_or_nonfinite(value: float) -> None:
    with pytest.raises(PolicyValidationError):
        replace(configuration(), poll_interval_seconds=value)


def test_duplicate_agent_but_shared_policy_selection() -> None:
    selection = AgentPolicy("a", "t", "p")
    with pytest.raises(PolicyValidationError):
        PollerConfig((selection, selection))
    shared = PollerConfig((selection, AgentPolicy("b", "t", "p")))
    assert len(shared.agents) == 2
    with pytest.raises(PolicyValidationError):
        configuration(33)


def test_identical_200_skips_decoding_and_logs_safe_policy_summary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class CountingPoller(PolicyPoller):
        decodes = 0

        def _decode(self, selection: AgentPolicy, response: Changed) -> PolicySnapshot:
            self.decodes += 1
            return super()._decode(selection, response)

    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        source.conditional = False
        clock = FakeClock()
        with caplog.at_level(
            logging.INFO, logger="agent_control_spec_remote_policy.poller"
        ):
            async with CountingPoller(config, source, clock=clock) as poller:
                first = poller.get_policy("agent0")
                clock.advance(300)
                assert await poller.refresh("agent0") is first
                assert poller.decodes == 1
                assert (
                    poller.get_policy("agent0").monotonic_deadline
                    == first.monotonic_deadline
                )
                records = [
                    record
                    for record in caplog.records
                    if getattr(record, "event", None)
                    in ("policy_installed", "policy_not_modified")
                ]
                assert len(records) == 2
                assert all(
                    getattr(record, "etag", None) == first.etag for record in records
                )
                assert "agent=agent0" in caplog.text
                assert "policy=policy0" in caplog.text
                assert first.etag in caplog.text
                assert first.manifest_yaml not in caplog.text
                assert "package " not in caplog.text

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["expired", "fenced"])
def test_terminal_audit_preserves_last_verified_expiry(
    outcome: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock = FakeClock()
        source = MemorySource(config)
        with caplog.at_level(
            logging.INFO, logger="agent_control_spec_remote_policy.poller"
        ):
            async with PolicyPoller(config, source, clock=clock) as poller:
                expiry = poller.get_policy("agent0").expires_at.isoformat()
                if outcome == "expired":
                    clock.advance(901)
                    with pytest.raises(PolicyUnavailable):
                        poller.get_policy("agent0")
                else:
                    source.responses["agent0"] = PolicySourceError(
                        "authoritative", "forbidden"
                    )
                    with pytest.raises(PolicySourceError):
                        await poller.refresh("agent0")
                records = [
                    record
                    for record in caplog.records
                    if getattr(record, "event", None) == f"policy_{outcome}"
                ]
                assert len(records) == 1
                assert getattr(records[0], "expires_at", None) == expiry
                with pytest.raises(PolicyUnavailable):
                    poller.get_policy("agent0")
            closed = [
                record
                for record in caplog.records
                if getattr(record, "event", None) == "policy_closed"
            ]
            assert len(closed) == 1
            assert getattr(closed[0], "expires_at", None) == expiry

    asyncio.run(scenario())


def test_source_audit_context_is_isolated_reset_and_stable_when_busy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class TracedSource(MemorySource):
        def __init__(self, config: PollerConfig) -> None:
            super().__init__(config)
            self.trace_ids: dict[str, str] = {}

        async def fetch(
            self, selection: AgentPolicy, if_none_match: str | None
        ) -> Changed | NotModified:
            request_id = current_policy_request_id()
            assert request_id is not None and len(request_id) == 32
            self.trace_ids[selection.agent_id] = request_id
            return await super().fetch(selection, if_none_match)

    async def scenario() -> None:
        config = configuration()
        source = TracedSource(config)
        assert current_policy_request_id() is None
        with caplog.at_level(
            logging.INFO, logger="agent_control_spec_remote_policy.poller"
        ):
            async with PolicyPoller(config, source, clock=FakeClock()) as poller:
                assert current_policy_request_id() is None
                assert len(set(source.trace_ids.values())) == 2
                installed = [
                    record
                    for record in caplog.records
                    if getattr(record, "event", None) == "policy_installed"
                ]
                for agent in config.agents:
                    matching = [
                        record
                        for record in installed
                        if getattr(record, "agent_id", None) == agent.agent_id
                    ]
                    assert len(matching) == 1
                    assert (
                        getattr(matching[0], "request_id", None)
                        == source.trace_ids[agent.agent_id]
                    )
                source.entered.clear()
                source.gate = asyncio.Event()
                refresh = asyncio.create_task(poller.refresh("agent0"))
                await source.entered.wait()
                original_id = source.trace_ids["agent0"]
                try:
                    with pytest.raises(PolicySourceError, match="busy"):
                        await poller._refresh("agent0")
                finally:
                    source.gate.set()
                    await refresh
                unchanged = [
                    record
                    for record in caplog.records
                    if getattr(record, "event", None) == "policy_not_modified"
                ]
                assert getattr(unchanged[-1], "request_id", None) == original_id
                assert current_policy_request_id() is None
        assert source.active == 0 and source.closed
        assert current_policy_request_id() is None

    asyncio.run(scenario())


def test_same_etag_cannot_hide_changed_bytes() -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        source.conditional = False
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            original = source.responses["agent0"]
            assert isinstance(original, Changed)
            first = poller.get_policy("agent0")
            source.responses["agent0"] = Changed(original.body + b" ", original.etag)
            with pytest.raises(PolicyValidationError, match="etag"):
                await poller.refresh("agent0")
            assert poller.get_policy("agent0") is first

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "body",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"[" * 33 + b"0" + b"]" * 33,
        b'{"a":9223372036854775808}',
        b'{"a":"\\ud800"}',
        b"\xff",
        b"{}" * (512 * 1024 + 1),
    ],
    ids=[
        "duplicate-key",
        "nan",
        "infinity",
        "excessive-depth",
        "integer-overflow",
        "invalid-surrogate",
        "invalid-utf8",
        "oversized",
    ],
)
def test_strict_bounded_json(body: bytes) -> None:
    with pytest.raises(PolicyValidationError):
        decode_json(body)


@pytest.mark.parametrize("microseconds", [0, 1, 123456])
def test_utc_envelope_timestamps_preserve_timezone_and_precision(
    microseconds: int,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        clock = FakeClock()
        clock.wall = issued = NOW.replace(microsecond=microseconds)
        expires = issued + timedelta(seconds=900)
        source.responses["agent0"] = reply(
            document(config.agents[0], issued_at=issued, expires_at=expires)
        )
        async with PolicyPoller(config, source, clock=clock) as poller:
            snapshot = poller.get_policy("agent0")
            assert snapshot.issued_at == issued
            assert snapshot.expires_at == expires
            assert snapshot.issued_at.tzinfo is UTC
            assert snapshot.expires_at.tzinfo is UTC
        assert source.closed and source.active == 0
        assert not poller._flights and not poller._requests

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 1.0),
        ("tenant_id", "wrong"),
        ("policy_id", "wrong"),
        ("revision", True),
        ("revision", 0),
        ("issued_at", "2026-10-12 00:00:00+00:00"),
        ("issued_at", "2026-10-12T00:00:00+00:00"),
        ("issued_at", "2026-10-12T00:00:00.1234567Z"),
        ("expires_at", "2026-10-12T00:00:00z"),
        ("expires_at", "2026-02-30T00:00:00Z"),
        ("extra", "not-allowed"),
    ],
)
def test_invalid_envelope_fails_all_required_startup(
    field: str, value: JsonValue
) -> None:
    async def scenario() -> None:
        config = configuration()
        source = MemorySource(config)
        changed = document(config.agents[0])
        changed[field] = value
        source.responses["agent0"] = reply(changed)
        poller = PolicyPoller(config, source, clock=FakeClock())
        with pytest.raises(StartupError) as failure:
            await poller.start()
        assert "agent0" in failure.value.failures
        assert source.closed and not poller._requests and not poller._flights
        with pytest.raises(PolicyUnavailable):
            poller.get_policy("agent1")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "where,field",
    [
        ("definition", "bundle"),
        ("definition", "data"),
        ("definition", "data_paths"),
        ("definition", "bundle_url"),
        ("binding", "bundle"),
        ("binding", "data"),
        ("binding", "data_paths"),
        ("binding", "bundle_url"),
    ],
)
@pytest.mark.parametrize("path", ["/private/secret", "../private/secret"])
def test_files_and_network_adapter_fields_rejected(
    where: str, field: str, path: str
) -> None:
    raw = document(configuration(1).agents[0])
    manifest = raw["manifest"]
    assert isinstance(manifest, str)
    if where == "definition":
        manifest = manifest.replace(
            "    type: rego", f"    type: rego\n    {field}: {path}"
        )
    else:
        manifest = manifest.replace(
            "      id: gate", f"      id: gate\n      {field}: {path}"
        )
    with pytest.raises(PolicyValidationError):
        validate_acs_artifacts(manifest, raw["bundles"])


@pytest.mark.parametrize(
    "suffix",
    [
        "extends: [./local.yaml]\n",
        "approval: {}\n",
        "annotators:\n  secret:\n    type: custom\n    token_env: PRIVATE_TOKEN\n",
        "system_prompt_url: https://untrusted.example/prompt\n",
        "metadata: {a: 1, a: 2}\n",
        "metadata: &x {}\n",
        "metadata: {<<: {a: 1}}\n",
        "---\nmetadata: {}\n",
        "metadata: \0SENSITIVE_CONTROL_CHARACTER\n",
    ],
)
def test_remote_manifest_rejection_corpus(suffix: str) -> None:
    raw = document(configuration(1).agents[0])
    manifest = raw["manifest"]
    assert isinstance(manifest, str)
    with pytest.raises(PolicyValidationError):
        validate_acs_artifacts(manifest + suffix, raw["bundles"])


@pytest.mark.parametrize(
    "query",
    [
        "data.foo[0]",
        "http.send({})",
        "data.gate.verdict\n",
        "data.\u79d8\u5bc6.verdict",
        "data.gate.verdict; true",
    ],
)
def test_rule_queries_are_ascii_paths_only(query: str) -> None:
    raw = document(configuration(1).agents[0])
    manifest = raw["manifest"]
    assert isinstance(manifest, str)
    manifest = manifest.replace(
        "data.refund_limits.verdict", json.dumps(query, ensure_ascii=False)
    )
    with pytest.raises(PolicyValidationError):
        validate_acs_artifacts(manifest, raw["bundles"])


@pytest.mark.parametrize(
    "source",
    [
        "[" * 13 + "0" + "]" * 13,
        "x + " * 1025 + "1",
        "#" + "x" * 65536,
        "[" * 12 + "`" + "x" * 100 + "`" + "]" * 12,
    ],
    ids=["excessive-depth", "too-many-tokens", "oversized-token", "nested-raw-string"],
)
def test_rego_complexity_is_bounded_without_parsing(source: str) -> None:
    raw = document(configuration(1).agents[0])
    manifest = raw["manifest"]
    assert isinstance(manifest, str)
    with pytest.raises(PolicyValidationError):
        validate_acs_artifacts(manifest, {"gate": {"modules": {"limits.rego": source}}})


def test_updates_are_atomic_scoped_and_same_body_preserves_identity() -> None:
    async def scenario() -> None:
        config = configuration()
        source = MemorySource(config)
        source.conditional = False
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            original = poller.get_policy("agent0")
            independent = poller.get_policy("agent1")
            assert await poller.refresh("agent0") is original
            source.responses["agent0"] = reply(document(config.agents[0], revision=2))
            new = await poller.refresh("agent0")
            assert new.revision == 2
            assert poller.get_policy("agent1") is independent
            with pytest.raises(PolicyUnavailable):
                poller.assert_current("agent0", original)
            for bad in (
                document(config.agents[0], revision=1),
                document(
                    config.agents[0],
                    revision=2,
                    expires_at=NOW + timedelta(seconds=1000),
                ),
                document(AgentPolicy("agent0", "other-tenant", "policy0"), revision=3),
            ):
                source.responses["agent0"] = reply(bad)
                with pytest.raises(PolicyValidationError):
                    await poller.refresh("agent0")
                assert poller.get_policy("agent0") is new
            poller.assert_current("agent0", new)

    asyncio.run(scenario())


@pytest.mark.parametrize("code", ["unauthorized", "forbidden", "not_found", "gone"])
def test_authoritative_fence_recovers_via_unconditional_unchanged_200(
    code: str,
) -> None:
    async def scenario() -> None:
        config = configuration()
        source = MemorySource(config)
        original_reply = source.responses["agent0"]
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            original = poller.get_policy("agent0")
            other = poller.get_policy("agent1")
            source.responses["agent0"] = PolicySourceError("authoritative", code)
            with pytest.raises(PolicySourceError):
                await poller.refresh("agent0")
            with pytest.raises(PolicyUnavailable):
                poller.get_policy("agent0")
            assert poller.get_policy("agent1") is other
            source.responses["agent0"] = original_reply
            recovered = await poller.refresh("agent0")
            assert source.calls[-1] == ("agent0", None)
            assert recovered.revision == 1 and recovered is not original
            poller.assert_current("agent0", recovered)
            assert await poller.refresh("agent0") is recovered

    asyncio.run(scenario())


def test_transient_invalid_etag_and_304_do_not_renew_lease() -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock = FakeClock()
        source = MemorySource(config)
        async with PolicyPoller(config, source, clock=clock) as poller:
            original = poller.get_policy("agent0")
            source.responses["agent0"] = PolicySourceError("transient", "transport")
            with pytest.raises(PolicySourceError):
                await poller.refresh("agent0")
            assert poller.get_policy("agent0") is original
            source.conditional = False
            source.responses["agent0"] = Changed(b"{}", original.etag)
            with pytest.raises(PolicyValidationError):
                await poller.refresh("agent0")
            source.responses["agent0"] = NotModified(original.etag)
            clock.advance(500)
            assert await poller.refresh("agent0") is original
            clock.advance(401)
            with pytest.raises(PolicyUnavailable):
                poller.get_policy("agent0")
            with pytest.raises(PolicyValidationError):
                await poller.refresh("agent0")
            assert source.calls[-1] == ("agent0", None)

    asyncio.run(scenario())


def test_clock_rollback_does_not_reauthorize_identical_expired_content() -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock = FakeClock()
        source = MemorySource(config)
        async with PolicyPoller(config, source, clock=clock) as poller:
            original = poller.get_policy("agent0")
            clock.advance(901, wall_seconds=-50)
            with pytest.raises(PolicyUnavailable):
                poller.get_policy("agent0")
            with pytest.raises(PolicyValidationError) as failure:
                await poller.refresh("agent0")
            assert failure.value.code == "lease"
            with pytest.raises(PolicyUnavailable):
                poller.assert_current("agent0", original)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "issued,expires,code",
    [
        (NOW, NOW + timedelta(seconds=600), "lease"),
        (NOW, NOW + timedelta(days=2), "lease"),
        (NOW + timedelta(seconds=61), NOW + timedelta(seconds=961), "clock_skew"),
        (NOW - timedelta(seconds=1000), NOW - timedelta(seconds=1), "lease"),
    ],
)
def test_lease_budget_and_future_clock(
    issued: datetime, expires: datetime, code: str
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        source.responses["agent0"] = reply(
            document(config.agents[0], issued_at=issued, expires_at=expires)
        )
        with pytest.raises(StartupError) as failure:
            await PolicyPoller(config, source, clock=FakeClock()).start()
        detail = failure.value.failures["agent0"]
        assert isinstance(detail, PolicyValidationError) and detail.code == code

    asyncio.run(scenario())


def test_initial_wall_clock_is_trusted_even_for_aged_documents() -> None:
    async def scenario() -> None:
        config = configuration(1)
        clock = FakeClock()
        clock.wall -= timedelta(seconds=1800)
        source = MemorySource(config)
        source.responses["agent0"] = reply(
            document(config.agents[0], issued_at=NOW - timedelta(seconds=3600))
        )
        async with PolicyPoller(config, source, clock=clock) as poller:
            snapshot = poller.get_policy("agent0")
            assert snapshot.monotonic_deadline - clock.monotonic() == 2700
            clock.advance(2700, wall_seconds=-1800)
            with pytest.raises(PolicyUnavailable):
                poller.get_policy("agent0")

    asyncio.run(scenario())


def test_singleflight_caller_cancellation_and_request_admission() -> None:
    async def scenario() -> None:
        config = configuration(12)
        source = MemorySource(config)
        source.gate = asyncio.Event()
        poller = PolicyPoller(config, source, clock=FakeClock())
        startup = asyncio.create_task(poller.start())
        await asyncio.wait_for(source.at_capacity.wait(), 2)
        assert source.peak == 4 and len(poller._requests) <= 12
        source.gate.set()
        await startup
        source.gate = asyncio.Event()
        source.entered.clear()
        calls = len(source.calls)
        refreshes = [asyncio.create_task(poller.refresh("agent0")) for _ in range(20)]
        await asyncio.wait_for(source.entered.wait(), 2)
        for task in refreshes[:10]:
            task.cancel()
        cancelled = await asyncio.gather(*refreshes[:10], return_exceptions=True)
        assert all(isinstance(result, asyncio.CancelledError) for result in cancelled)
        assert len(poller._requests) == 1 and len(source.calls) == calls + 1
        source.gate.set()
        snapshots = await asyncio.gather(*refreshes[10:])
        assert all(snapshot is snapshots[0] for snapshot in snapshots)
        await poller.aclose()
        assert source.active == 0 and not poller._requests and not poller._flights

    asyncio.run(scenario())


def test_cancellation_resistant_source_is_retained_bounded_and_close_fails_explicitly() -> (
    None
):
    async def scenario() -> None:
        config = configuration(1, interval=0.05, timeout=0.02)
        source = MemorySource(config)
        poller = PolicyPoller(
            config, source, clock=FakeClock(), close_timeout_seconds=0.02
        )
        await poller.start()
        source.gate = asyncio.Event()
        source.ignore_cancellation = True
        calls = len(source.calls)
        with pytest.raises(PolicySourceError):
            await poller.refresh("agent0")
        for _ in range(3):
            with pytest.raises(PolicySourceError) as failure:
                await poller.refresh("agent0")
            assert failure.value.code == "busy"
        assert len(source.calls) == calls + 1 and len(poller._requests) == 1
        with pytest.raises(PolicyCloseError) as failure:
            await poller.aclose()
        assert failure.value.retained_tasks == 1
        with pytest.raises(PolicyUnavailable):
            poller.get_policy("agent0")
        pending = tuple(poller._requests.values())
        source.gate.set()
        await asyncio.gather(*pending)
        await poller.aclose()
        assert not poller._requests and not poller._flights and source.active == 0

    asyncio.run(scenario())


def test_real_scheduler_interval_and_close_cancellation() -> None:
    async def scenario() -> None:
        config = configuration(1, interval=0.1, timeout=0.05)
        source = MemorySource(config)
        poller = PolicyPoller(config, source, clock=FakeClock())
        loop = asyncio.get_running_loop()
        await poller.start()
        began = loop.time()
        await asyncio.wait_for(source.polled.wait(), 2)
        assert loop.time() - began >= 0.09
        await poller.aclose()
        assert poller._scheduler is not None and poller._scheduler.done()
        assert not poller._flights and not poller._requests
        await poller.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_unexpected_scheduler_failure_fences(
    monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    async def scenario() -> None:
        config = configuration(1, interval=0.05, timeout=0.02)
        source = MemorySource(config)
        poller = PolicyPoller(config, source, clock=FakeClock())
        await poller.start()
        scheduler = poller._scheduler
        assert scheduler is not None
        finished = asyncio.Event()
        scheduler.add_done_callback(lambda _: finished.set())
        if cancel:
            scheduler.cancel()
        else:

            async def fail() -> dict[str, PolicyError]:
                raise ValueError("untrusted detail is not logged")

            monkeypatch.setattr(poller, "_refresh_all", fail)
        await asyncio.wait_for(finished.wait(), 2)
        with pytest.raises(PolicyUnavailable):
            poller.get_policy("agent0")
        await poller.aclose()

    asyncio.run(scenario())


def test_error_content_never_enters_audit_or_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        config = configuration(1)
        source = MemorySource(config)
        secret = "SENSITIVE_RESPONSE_CONTENT"
        changed = document(config.agents[0])
        changed["manifest"] = f"not_a_manifest: {secret}"
        source.responses["agent0"] = reply(changed)
        with caplog.at_level(logging.INFO), pytest.raises(StartupError) as failure:
            await PolicyPoller(config, source, clock=FakeClock()).start()
        assert secret not in caplog.text
        assert secret not in str(failure.value.failures["agent0"])
        assert any(hasattr(record, "request_id") for record in caplog.records)

    asyncio.run(scenario())


def test_loop_affinity_and_no_restart() -> None:
    config = configuration(1)
    poller = PolicyPoller(config, MemorySource(config), clock=FakeClock())

    async def first() -> None:
        await poller.start()
        with pytest.raises(PolicyUsageError):
            await poller.start()
        with pytest.raises(PolicyUsageError):
            poller.get_policy("unknown")
        await poller.aclose()

    async def second() -> None:
        with pytest.raises(PolicyUsageError):
            poller.status("agent0")

    asyncio.run(first())
    asyncio.run(second())


def test_cancelling_close_waiter_does_not_orphan_owned_cleanup() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        config = configuration(1)

        class ClosingSource(MemorySource):
            async def aclose(self) -> None:
                entered.set()
                await release.wait()
                self.closed = True

        source = ClosingSource(config)
        poller = PolicyPoller(config, source, clock=FakeClock())
        await poller.start()
        closing = asyncio.create_task(poller.aclose())
        await entered.wait()
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        with pytest.raises(PolicyUnavailable):
            poller.get_policy("agent0")
        release.set()
        await poller.aclose()
        assert source.closed and poller.status("agent0").state == "closed"
        assert not poller._requests and not poller._flights

    asyncio.run(scenario())


def test_source_close_exception_is_observed_and_reported_without_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        config = configuration(1)

        class BrokenClose(MemorySource):
            async def aclose(self) -> None:
                raise ValueError("SENSITIVE_CLOSE_FAILURE")

        poller = PolicyPoller(config, BrokenClose(config), clock=FakeClock())
        await poller.start()
        with caplog.at_level(logging.ERROR), pytest.raises(PolicyCloseError):
            await poller.aclose()
        assert "SENSITIVE_CLOSE_FAILURE" not in caplog.text
        assert "policy_source_close_failed" in caplog.text
        assert poller.status("agent0").state == "failed"

    asyncio.run(scenario())
