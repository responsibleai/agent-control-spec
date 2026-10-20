# Copyright (c) Microsoft. All rights reserved.
"""Credential boundary, factory ownership and bounded lifecycle contracts."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import FrozenInstanceError, replace
from typing import cast

import httpx
import pytest
from agent_control_spec_remote_policy.auth import (
    AuthenticationRequest,
    Credential,
    CredentialCloseError,
    CredentialProviderFactory,
    CredentialProviderRegistry,
    RequestAuthentication,
)
from agent_control_spec_remote_policy.azure import azure_credential_factories
from agent_control_spec_remote_policy.poller import (
    CredentialConfig,
    CredentialOption,
    PolicyCloseError,
    PolicySourceError,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
    StartupError,
)

from .test_remote_policy import configuration


class Headers:
    """Return deliberately untyped test replies at the provider boundary."""

    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0
        self.requests: list[AuthenticationRequest] = []

    async def authenticate(self, request: AuthenticationRequest) -> Mapping[str, str]:
        self.calls += 1
        self.requests.append(request)
        return cast(Mapping[str, str], self.result)


class SingleHeader:
    """Deterministic single-header test double, not a real service credential."""

    def __init__(self, result: object = "Bearer unit-test") -> None:
        self.result = result

    async def authorization(self) -> str:
        return cast(str, self.result)


def configured(*, provider: str = "custom", timeout: float = 0.1) -> PollerConfig:
    return replace(
        configuration(1, timeout=timeout),
        credential_ref="reader",
        credentials={"reader": CredentialConfig(provider)},
    )


async def send(
    credential: Credential, *, headers: Mapping[str, str] | None = None
) -> int:
    """Exercise the real HTTPX auth flow, counting actual transport requests."""
    calls = 0

    def transport(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401)

    async with httpx.AsyncClient(
        auth=RequestAuthentication(credential), transport=httpx.MockTransport(transport)
    ) as client:
        try:
            result = await client.get(
                "https://policy.example.test/path",
                params={"api-version": "v1"},
                headers=headers,
            )
        except (PolicySourceError, asyncio.CancelledError):
            assert calls == 0
            raise
        assert result.status_code == 401
    return calls


def _audit_fields(record: logging.LogRecord) -> Mapping[str, object]:
    """Read structured logging extras at their dynamic record boundary."""
    return record.__dict__


def test_protocol_dispatch_rejects_both_and_neither_at_construction() -> None:
    class Both(SingleHeader):
        async def authenticate(
            self, request: AuthenticationRequest
        ) -> Mapping[str, str]:
            return {"Authorization": "Bearer unit-test"}

    for invalid in (Both(), object(), httpx.BasicAuth("test", "test")):
        with pytest.raises(PolicyValidationError, match="config"):
            RequestAuthentication(cast(Credential, invalid))


def test_request_is_final_read_only_and_sigv4_shaped_headers_are_add_only() -> None:
    async def scenario() -> None:
        credential = Headers(
            {
                "Authorization": "AWS4-HMAC-SHA256 Credential=test, SignedHeaders=host, Signature=test",
                "X-Amz-Date": "20261016T000000Z",
                "X-Amz-Security-Token": "unit-test-temporary-token",
            }
        )
        assert (
            await send(
                credential, headers={"If-None-Match": '"etag"', "X-Request-ID": "host"}
            )
            == 1
        )
        request = credential.requests[0]
        assert request.method == "GET" and request.body == b""
        assert request.url.endswith("?api-version=v1")
        assert request.headers["if-none-match"] == '"etag"'
        assert request.headers["x-request-id"] == "host"
        assert all(name == name.lower() for name in request.headers)
        assert "authorization" not in request.headers
        with pytest.raises(TypeError):
            cast(dict[str, str], request.headers)["host"] = "different"
        with pytest.raises(FrozenInstanceError):
            attribute = "url"
            setattr(request, attribute, "https://different.example.test")
        original = {"host": "original"}
        snapshot = AuthenticationRequest("GET", "https://example.test", original, b"")
        original["host"] = "changed"
        assert snapshot.headers["host"] == "original"
        assert "original" not in repr(snapshot)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "name",
    [
        "Host",
        "Connection",
        "Keep-Alive",
        "Content-Type",
        "Content-Length",
        "Transfer-Encoding",
        "TE",
        "Trailer",
        "Upgrade",
        "Expect",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "Forwarded",
        "X-Forwarded-Host",
        "Via",
        "Max-Forwards",
        "Range",
        "If-Match",
        "If-None-Match",
        "X-HTTP-Method-Override",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Accept",
        "Accept-Encoding",
        "User-Agent",
        "X-Request-ID",
    ],
)
def test_authentication_header_denylist_and_existing_collisions(name: str) -> None:
    async def scenario() -> None:
        with pytest.raises(PolicySourceError) as failure:
            await send(Headers({name: "test"}), headers={"X-Request-ID": "test"})
        assert (failure.value.kind, failure.value.code) == ("transient", "credential")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "result",
    [
        {},
        [],
        None,
        {"Authorization": ""},
        {"Authorization": " leading"},
        {"Authorization": "trailing "},
        {"Authorization": "a\tb"},
        {"Authorization": "a\r\nb"},
        {"Authorization": "non-ascii-\u00e9"},
        {"bad name": "value"},
        {"Bad:Name": "value"},
        {"": "value"},
        {1: "value"},
        {"Authorization": 1},
        {"Authorization": "one", "authorization": "two"},
    ],
)
def test_malformed_authentication_header_mappings_fail_before_transport(
    result: object,
) -> None:
    async def scenario() -> None:
        with pytest.raises(PolicySourceError, match="credential"):
            await send(Headers(result))

    asyncio.run(scenario())


@pytest.mark.parametrize("boundary", ["count", "name", "value", "aggregate"])
@pytest.mark.parametrize("over", [False, True])
def test_request_authentication_header_exact_bounds(boundary: str, over: bool) -> None:
    if boundary == "count":
        fields = {f"x-auth-{n}": "v" for n in range(32 + int(over))}
    elif boundary == "name":
        fields = {"x" * (128 + int(over)): "v"}
    elif boundary == "value":
        fields = {"x-auth": "v" * (16384 + int(over))}
    else:
        fields = {"x-a": "v" * 16384, "x-b": "v" * (16378 + int(over))}
        assert sum(len(k) + len(v) for k, v in fields.items()) == 32768 + int(over)

    async def scenario() -> None:
        if over:
            with pytest.raises(PolicySourceError, match="credential"):
                await send(Headers(fields))
        else:
            assert await send(Headers(fields)) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "value",
    [
        "x",
        "",
        None,
        "Bearer a b",
        "Bearer a\r\nb",
        "Bearer a\tb",
        "Bearer " + "x" * 16385,
    ],
)
def test_single_header_exact_malformed_header_contract(value: object) -> None:
    async def scenario() -> None:
        with pytest.raises(PolicySourceError, match="credential"):
            await send(SingleHeader(value))

    asyncio.run(scenario())


def test_single_header_maximum_is_not_narrowed_by_signing_header_bounds() -> None:
    assert asyncio.run(send(SingleHeader("Bearer " + "x" * 16384))) == 1


@pytest.mark.parametrize(
    "error",
    [
        PolicySourceError("authoritative", "forbidden"),
        TimeoutError("SENSITIVE_VENDOR_DATA"),
        httpx.ConnectError("SENSITIVE_VENDOR_DATA"),
        RuntimeError("SENSITIVE_VENDOR_DATA"),
    ],
)
def test_provider_errors_cannot_spoof_service_authority_or_leak(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    class Broken:
        async def authenticate(
            self, request: AuthenticationRequest
        ) -> Mapping[str, str]:
            raise error

    async def scenario() -> None:
        with pytest.raises(PolicySourceError) as failure:
            await send(Broken())
        assert (failure.value.kind, failure.value.code) == ("transient", "credential")
        assert failure.value.__suppress_context__
        assert "SENSITIVE" not in str(failure.value) + caplog.text
        assert all(record.exc_info is None for record in caplog.records)

    with caplog.at_level(logging.WARNING):
        asyncio.run(scenario())


def test_provider_cancellation_is_not_normalized() -> None:
    error = asyncio.CancelledError("caller cancellation")

    class Cancelled:
        async def authorization(self) -> str:
            raise error

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError) as failure:
            await send(Cancelled())
        assert failure.value is error

    asyncio.run(scenario())


def test_registry_selected_only_no_ambient_fallback_and_immutable_allowlist() -> None:
    async def scenario() -> None:
        opened: list[str] = []

        @asynccontextmanager
        async def selected(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            opened.append("selected")
            yield SingleHeader()

        @asynccontextmanager
        async def unused(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            opened.append("unused")
            yield SingleHeader()

        providers = {"custom": selected, "unused": unused}
        registry = CredentialProviderRegistry(providers)
        providers.clear()
        async with registry.open(configured()) as credentials:
            assert list(credentials) == ["reader"]
            with pytest.raises(TypeError):
                cast(dict[str, Credential], credentials)["overwrite"] = SingleHeader()
            with pytest.raises(PolicyUsageError):
                async with registry.open(configured()):
                    pytest.fail("concurrent admission")
        assert opened == ["selected"] and registry.pending_task_count == 0
        for config in (
            replace(configured(), credentials={}),
            configured(provider="unknown"),
            configured(provider="azure_cli"),
        ):
            with pytest.raises(PolicyValidationError):
                async with registry.open(config):
                    pytest.fail("unknown configuration opened")
        async with registry.open(
            replace(configured(), credential_ref=None)
        ) as anonymous:
            assert not anonymous
        assert opened == ["selected"]
        assert CredentialProviderRegistry({f"p{n}": selected for n in range(32)})

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "providers",
    [
        {str(n): object() for n in range(33)},
        {"bad/name": object()},
        {"custom": object()},
    ],
)
def test_registry_rejects_invalid_factory_registration(providers: object) -> None:
    with pytest.raises(PolicyValidationError):
        CredentialProviderRegistry(
            cast(Mapping[str, CredentialProviderFactory], providers)
        )


def test_factory_contextvars_and_entry_exit_task_identity() -> None:
    async def scenario() -> None:
        variable = ContextVar("credential-owner-scope", default="caller")
        tasks: list[asyncio.Task[object] | None] = []
        closed = asyncio.Event()

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            token = variable.set("factory")
            tasks.append(asyncio.current_task())
            try:
                yield SingleHeader()
            finally:
                tasks.append(asyncio.current_task())
                assert variable.get() == "factory"
                variable.reset(token)
                closed.set()

        registry = CredentialProviderRegistry({"custom": factory})
        async with registry.open(configured()) as credentials:
            assert variable.get() == "caller"
            assert await send(credentials["reader"]) == 1
        assert closed.is_set() and tasks[0] is tasks[1]
        assert tasks[0] is not asyncio.current_task()
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_factory_entry_timeout_and_cancellation_cancel_and_join(cancel: bool) -> None:
    async def scenario() -> None:
        entered, exited = asyncio.Event(), asyncio.Event()

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            entered.set()
            try:
                await asyncio.Event().wait()
                yield SingleHeader()
            finally:
                exited.set()

        registry = CredentialProviderRegistry({"custom": factory})

        async def use() -> None:
            async with registry.open(configured(timeout=0.02)):
                pytest.fail("entry should not complete")

        task = asyncio.create_task(use())
        await entered.wait()
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(PolicySourceError) as failure:
                await task
            assert (failure.value.kind, failure.value.code) == ("transient", "timeout")
        assert exited.is_set() and registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure_kind", ["startup", "poller_close", "cancellation", "none"]
)
def test_cleanup_error_is_safe_and_preserves_primary_identity(
    failure_kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                raise RuntimeError("SENSITIVE_VENDOR_DATA")

        registry = CredentialProviderRegistry({"custom": factory})
        primary = {
            "startup": StartupError({}),
            "poller_close": PolicyCloseError(0),
            "cancellation": asyncio.CancelledError(),
            "none": None,
        }[failure_kind]
        try:
            async with registry.open(configured()):
                if primary is not None:
                    raise primary
        except (
            StartupError,
            PolicyCloseError,
            asyncio.CancelledError,
            CredentialCloseError,
        ) as error:
            if primary is None:
                assert isinstance(error, CredentialCloseError)
                assert error.retained_tasks == 0
            else:
                assert error is primary
                assert "Credential cleanup also failed" in "\n".join(error.__notes__)
            assert "SENSITIVE" not in str(error) + caplog.text
        else:
            pytest.fail("cleanup failure was suppressed")
        assert registry.pending_task_count == 0
        with pytest.raises(PolicyUsageError):
            async with registry.open(configured()):
                pytest.fail("failed registry admitted work")

    asyncio.run(scenario())


def test_noncooperative_close_is_bounded_retained_observed_and_never_readmitted() -> (
    None
):
    async def scenario() -> None:
        release, closing, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                closing.set()
                while not release.is_set():
                    try:
                        await release.wait()
                    except asyncio.CancelledError:
                        cancelled.set()

        registry = CredentialProviderRegistry({"custom": factory})
        with pytest.raises(CredentialCloseError) as failure:
            async with registry.open(configured(timeout=0.02)):
                pass
        assert closing.is_set() and cancelled.is_set()
        assert failure.value.retained_tasks == registry.pending_task_count == 1
        for _ in range(3):
            with pytest.raises(PolicyUsageError):
                async with registry.open(configured()):
                    pytest.fail("retained owner admitted another")
        owner = registry._owner
        assert owner is not None
        release.set()
        await asyncio.wait_for(asyncio.shield(owner), 1)
        assert registry.pending_task_count == 0
        with pytest.raises(PolicyUsageError):
            async with registry.open(configured()):
                pytest.fail("failed registry recovered silently")

    asyncio.run(scenario())


def test_entry_timeout_preserves_primary_when_partial_cleanup_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                await asyncio.Event().wait()
                yield SingleHeader()
            finally:
                raise RuntimeError("SENSITIVE_PARTIAL_CLEANUP")

        registry = CredentialProviderRegistry({"custom": factory})
        with pytest.raises(PolicySourceError) as failure:
            async with registry.open(configured(timeout=0.02)):
                pytest.fail("entry unexpectedly completed")
        assert (failure.value.kind, failure.value.code) == ("transient", "timeout")
        assert "Credential cleanup also failed" in "\n".join(failure.value.__notes__)
        assert registry.pending_task_count == 0
        assert "SENSITIVE" not in caplog.text
        with pytest.raises(PolicyUsageError):
            async with registry.open(configured()):
                pytest.fail("cleanup-failed registry reused")

    asyncio.run(scenario())


def test_noncooperative_entry_is_retained_then_closed_without_late_publication() -> (
    None
):
    async def scenario() -> None:
        release, exited = asyncio.Event(), asyncio.Event()

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue
            try:
                yield SingleHeader()
            finally:
                exited.set()

        registry = CredentialProviderRegistry({"custom": factory})
        try:
            with pytest.raises(PolicySourceError) as failure:
                async with registry.open(configured(timeout=0.02)):
                    pytest.fail("entry unexpectedly completed")
            assert failure.value.code == "timeout"
            assert registry.pending_task_count == 1
            assert "Credential cleanup also failed" in "\n".join(
                failure.value.__notes__
            )
            with pytest.raises(PolicyUsageError):
                async with registry.open(configured()):
                    pytest.fail("retained entry admitted work")
        finally:
            release.set()
            owner = registry._owner
            assert owner is not None
            await asyncio.wait_for(asyncio.shield(owner), 1)
        assert exited.is_set() and registry.pending_task_count == 0

    asyncio.run(scenario())


def test_interrupted_cleanup_fails_closed_even_when_cancellation_drains_owner() -> None:
    async def scenario() -> None:
        exited = asyncio.Event()

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                try:
                    await asyncio.Event().wait()
                finally:
                    exited.set()

        registry = CredentialProviderRegistry({"custom": factory})
        with pytest.raises(CredentialCloseError) as failure:
            async with registry.open(configured(timeout=0.02)):
                pass
        assert failure.value.retained_tasks == registry.pending_task_count == 0
        assert exited.is_set()
        with pytest.raises(PolicyUsageError):
            async with registry.open(configured()):
                pytest.fail("interrupted cleanup registry reused")

    asyncio.run(scenario())


def test_repeated_caller_cancellation_does_not_extend_close_deadline() -> None:
    async def scenario() -> None:
        closing, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        body_error = asyncio.CancelledError("original cancellation")

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                closing.set()
                while not release.is_set():
                    try:
                        await release.wait()
                    except asyncio.CancelledError:
                        cancelled.set()

        registry = CredentialProviderRegistry({"custom": factory})

        async def use() -> None:
            async with registry.open(configured(timeout=0.04)):
                raise body_error

        task = asyncio.create_task(use())
        await closing.wait()
        task.cancel("repeated-one")
        await cancelled.wait()
        task.cancel("repeated-two")
        try:
            with pytest.raises(asyncio.CancelledError) as failure:
                async with asyncio.timeout(1):
                    await task
            assert failure.value is body_error
            assert registry.pending_task_count == 1
            assert "Credential cleanup also failed" in "\n".join(body_error.__notes__)
        finally:
            owner = registry._owner
            assert owner is not None
            release.set()
            await asyncio.wait_for(asyncio.shield(owner), 1)
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["validation", "vendor"])
def test_factory_entry_errors_are_sanitized(
    kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            if kind == "validation":
                raise PolicyValidationError("config")
            raise RuntimeError("SENSITIVE_VENDOR_DATA")
            yield SingleHeader()

        registry = CredentialProviderRegistry({"custom": factory})
        with pytest.raises((PolicyValidationError, PolicySourceError)) as failure:
            async with registry.open(configured()):
                pytest.fail("failed factory entered")
        assert failure.value.code == (
            "config" if kind == "validation" else "credential"
        )
        assert "SENSITIVE" not in str(failure.value) + caplog.text
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"scope": None},
        {"scope": ""},
        {"scope": "contains space"},
        {"scope": "x" * 2049},
        {"scope": "\u00e9"},
        {"scope": "valid", "process_timeout_seconds": True},
        {"scope": "valid", "process_timeout_seconds": 1.0},
        {"scope": "valid", "process_timeout_seconds": "5"},
        {"scope": "valid", "process_timeout_seconds": 0},
        {"scope": "valid", "process_timeout_seconds": 121},
        {"scope": "valid", "unknown": "SENSITIVE_OPTION"},
    ],
)
def test_azure_factory_options_fail_closed(
    options: Mapping[str, CredentialOption],
) -> None:
    async def scenario() -> None:
        with pytest.raises(PolicyValidationError, match="config"):
            async with azure_credential_factories()["azure_cli"](options):
                pytest.fail("invalid options entered Azure factory")

    asyncio.run(scenario())


@pytest.mark.parametrize("timeout", [None, 1, 120])
def test_azure_factory_owns_context_and_uses_bounded_process_timeout(
    timeout: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import azure.identity.aio

    from .test_remote_policy_http import AzureCredential

    credential = AzureCredential()
    observed: list[int] = []

    def construct(*, process_timeout: int) -> AzureCredential:
        observed.append(process_timeout)
        return credential

    monkeypatch.setattr(azure.identity.aio, "AzureCliCredential", construct)
    options: dict[str, CredentialOption] = {"scope": "api://policy/.default"}
    if timeout is not None:
        options["process_timeout_seconds"] = timeout

    async def scenario() -> None:
        async with azure_credential_factories()["azure_cli"](options) as provider:
            assert isinstance(provider, SingleHeader) is False
            assert not credential.closed
        assert credential.closed and observed == [5 if timeout is None else timeout]

    asyncio.run(scenario())


@pytest.mark.parametrize("registry_argument", ["omitted", "none", "empty"])
def test_default_registry_is_an_empty_allow_list(
    monkeypatch: pytest.MonkeyPatch, registry_argument: str
) -> None:
    """YAML alone never selects a factory, token scope or destination."""
    import agent_control_spec_remote_policy.azure as azure_module

    def forbidden() -> object:
        pytest.fail("the default registry loaded the Azure factory")

    monkeypatch.setattr(azure_module, "azure_credential_factories", forbidden)
    registry = {
        "omitted": CredentialProviderRegistry,
        "none": lambda: CredentialProviderRegistry(None),
        "empty": lambda: CredentialProviderRegistry({}),
    }[registry_argument]()
    assert not registry._providers
    config = configured(provider="azure_cli")
    config = replace(
        config,
        endpoint="https://attacker.example.test",
        credentials={
            "reader": CredentialConfig("azure_cli", {"scope": "api://victim/.default"})
        },
    )

    async def scenario() -> None:
        with pytest.raises(PolicyValidationError, match="config"):
            async with registry.open(config):
                pytest.fail("an unregistered provider was opened")
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


def test_explicit_registration_is_the_only_way_to_enable_azure() -> None:
    registry = CredentialProviderRegistry(azure_credential_factories())
    assert set(registry._providers) == {"azure_cli"}


def test_custom_source_fetch_with_real_azure_import_blocker_and_safe_missing_extra() -> (
    None
):
    script = r"""
import asyncio
import importlib.abc
import sys
from contextlib import asynccontextmanager
for name in list(sys.modules):
    if name == "azure" or name.startswith("azure.") or name == "agent_control_spec_remote_policy.azure":
        del sys.modules[name]
class BlockAzure(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "azure" or fullname.startswith("azure."):
            raise ModuleNotFoundError("SENSITIVE_IMPORT_DETAILS", name=fullname)
sys.meta_path.insert(0, BlockAzure())
import httpx
from agent_control_spec_remote_policy.poller import AgentPolicy, CredentialConfig, PollerConfig, PolicyValidationError
from agent_control_spec_remote_policy.auth import CredentialProviderRegistry
from agent_control_spec_remote_policy.azure import azure_credential_factories
from agent_control_spec_remote_policy.http import HttpPolicySource
class Credential:
    async def authorization(self):
        return "Bearer unit-test"
@asynccontextmanager
async def factory(options):
    yield Credential()
async def main():
    selection = AgentPolicy("a", "t", "p")
    config = PollerConfig((selection,), endpoint="https://example.test", credential_ref="reader",
                          credentials={"reader": CredentialConfig("custom")})
    async with CredentialProviderRegistry({"custom": factory}).open(config) as credentials:
        source = HttpPolicySource(config.endpoint, credentials["reader"],
            transport=httpx.MockTransport(lambda request: httpx.Response(
                304, headers={"ETag": '"' + "a" * 64 + '"'})))
        try:
            assert (await source.fetch(selection, '"' + "a" * 64 + '"')).etag
        finally:
            await source.aclose()
    explicit = CredentialProviderRegistry(azure_credential_factories())
    azure_config = PollerConfig((selection,), credential_ref="reader",
        credentials={"reader": CredentialConfig("azure_cli", {"scope": "valid"})})
    try:
        async with explicit.open(azure_config):
            raise AssertionError("Azure fallback")
    except PolicyValidationError as error:
        assert error.code == "config"
        assert "SENSITIVE" not in str(error)
    assert not any(name == "azure" or name.startswith("azure.") for name in sys.modules)
    print("custom-fetch-ok")
asyncio.run(main())
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "custom-fetch-ok"
    assert "agent-control-spec-remote-policy[azure]" in result.stderr
    assert "SENSITIVE" not in result.stderr


@pytest.mark.parametrize("single_header", [False, True])
def test_synchronous_httpx_client_fails_before_provider_and_transport(
    single_header: bool,
) -> None:
    signer = Headers({"X-Auth": "unit-test"})
    credential = SingleHeader() if single_header else signer

    def transport(request: httpx.Request) -> httpx.Response:
        pytest.fail("synchronous auth reached transport")

    with (
        httpx.Client(
            auth=RequestAuthentication(credential),
            transport=httpx.MockTransport(transport),
        ) as client,
        pytest.raises(TypeError, match="httpx.AsyncClient"),
    ):
        client.get("https://example.test")
    assert signer.calls == 0


@pytest.mark.parametrize("single_header", [False, True])
def test_unread_stream_is_sanitized_without_reading_provider_or_transport(
    single_header: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        reads = 0

        async def content() -> AsyncGenerator[bytes, None]:
            nonlocal reads
            reads += 1
            yield b"must-not-buffer"

        signer = Headers({"X-Auth": "unit-test"})
        credential = SingleHeader() if single_header else signer

        def transport(request: httpx.Request) -> httpx.Response:
            pytest.fail("unread stream reached transport")

        request = httpx.Request("POST", "https://example.test", content=content())
        async with httpx.AsyncClient(
            auth=RequestAuthentication(credential),
            transport=httpx.MockTransport(transport),
        ) as client:
            with pytest.raises(PolicySourceError) as failure:
                await client.send(request)
        assert (failure.value.kind, failure.value.code) == ("transient", "credential")
        assert reads == signer.calls == 0
        record = _audit_fields(caplog.records[-1])
        assert record["reason"] == "invalid_request"
        assert record["exception_class"] == "RequestNotRead"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "label", ["", "bad/name", "with space", "x" * 129, "\ud800", 1, True]
)
@pytest.mark.parametrize("field", ["credential_ref", "provider"])
def test_authentication_audit_labels_are_validated(field: str, label: object) -> None:
    labels = {field: cast(str | None, label)}
    with pytest.raises(PolicyValidationError, match="config"):
        RequestAuthentication(SingleHeader(), **labels)


@pytest.mark.parametrize(
    "kind,reason,exception_class",
    [
        ("provider", "provider_error", "RuntimeError"),
        ("timeout", "provider_timeout", "TimeoutError"),
        ("httpx_timeout", "provider_timeout", "ReadTimeout"),
        ("authoritative", "provider_error", "PolicySourceError"),
        ("single_header", "invalid_legacy_value", "ValueError"),
        ("headers", "invalid_headers", "ValueError"),
        ("request", "invalid_request", "PolicyValidationError"),
    ],
)
def test_authentication_failure_audit_has_safe_reason_class_and_both_correlations(
    kind: str,
    reason: str,
    exception_class: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Broken:
        async def authenticate(
            self, request: AuthenticationRequest
        ) -> Mapping[str, str]:
            errors = {
                "provider": RuntimeError("SENSITIVE_PROVIDER_DETAIL"),
                "timeout": TimeoutError("SENSITIVE_PROVIDER_DETAIL"),
                "httpx_timeout": httpx.ReadTimeout("SENSITIVE_PROVIDER_DETAIL"),
                "authoritative": PolicySourceError("authoritative", "forbidden"),
            }
            if kind in errors:
                raise errors[kind]
            return {}

    async def scenario() -> None:
        credential = SingleHeader("malformed") if kind == "single_header" else Broken()
        request = httpx.Request(
            "GET",
            "https://example.test",
            headers={"X-MS-Client-Request-ID": "child-id"},
            extensions={
                "acs_policy_request_id": object() if kind == "request" else "parent-id"
            },
        )

        def transport(request: httpx.Request) -> httpx.Response:
            pytest.fail("failed authentication reached transport")

        async with httpx.AsyncClient(
            auth=RequestAuthentication(
                credential, credential_ref="reader", provider="custom"
            ),
            transport=httpx.MockTransport(transport),
        ) as client:
            with pytest.raises(PolicySourceError) as failure:
                await client.send(request)
        assert (failure.value.kind, failure.value.code) == ("transient", "credential")
        record = _audit_fields(caplog.records[-1])
        assert (
            record["reason"] == reason and record["exception_class"] == exception_class
        )
        assert record["credential_ref"] == "reader" and record["provider"] == "custom"
        assert record["http_request_id"] == record["request_id"] == "child-id"
        assert record["policy_request_id"] == (
            None if kind == "request" else "parent-id"
        )
        assert record["exc_info"] is None and record["stack_info"] is None
        assert "SENSITIVE" not in repr(record)

    asyncio.run(scenario())


def test_exception_class_is_bounded_and_sanitized(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class UnusualError(Exception):
        pass

    UnusualError.__name__ = "SENSITIVE\ninjected-class"

    class Broken:
        async def authorization(self) -> str:
            raise UnusualError("SENSITIVE_DETAILS")

    with pytest.raises(PolicySourceError):
        asyncio.run(send(Broken()))
    record = _audit_fields(caplog.records[-1])
    assert record["exception_class"] == "Exception"
    assert "SENSITIVE" not in repr(record)


def test_audit_extension_is_not_in_signer_context_or_wire_headers() -> None:
    async def scenario() -> None:
        signer = Headers({"X-Auth": "unit-test"})

        def transport(request: httpx.Request) -> httpx.Response:
            assert request.extensions["acs_policy_request_id"] == "parent-only"
            assert "parent-only" not in repr(dict(request.headers))
            return httpx.Response(200)

        async with httpx.AsyncClient(
            auth=RequestAuthentication(
                signer, credential_ref="reader", provider="custom"
            ),
            transport=httpx.MockTransport(transport),
        ) as client:
            await client.get(
                "https://example.test",
                headers={"X-Request-ID": "child"},
                extensions={"acs_policy_request_id": "parent-only"},
            )
        assert not hasattr(signer.requests[0], "extensions")
        assert "parent-only" not in repr(signer.requests[0]) + repr(
            dict(signer.requests[0].headers)
        )

    asyncio.run(scenario())


def test_registry_lifecycle_audit_uses_configuration_labels_not_options(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            yield SingleHeader()

        registry = CredentialProviderRegistry({"custom": factory})
        config = replace(
            configured(),
            credentials={
                "reader": CredentialConfig("custom", {"option": "SENSITIVE_OPTION"})
            },
        )
        async with registry.open(config):
            pass
        records = [_audit_fields(r) for r in caplog.records]
        assert [r["event"] for r in records] == [
            "credential_opened",
            "credential_closed",
        ]
        assert [r["stage"] for r in records] == ["open", "close"]
        assert all(
            r["credential_ref"] == "reader" and r["provider"] == "custom"
            for r in records
        )
        assert all("SENSITIVE" not in repr(r) for r in records)

    with caplog.at_level(logging.INFO, logger="agent_control_spec_remote_policy.auth"):
        asyncio.run(scenario())


@pytest.mark.parametrize("primary_cancelled", [False, True])
def test_external_cancellation_during_failed_cleanup_preserves_primary(
    primary_cancelled: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        closing, release = asyncio.Event(), asyncio.Event()
        primary = (
            asyncio.CancelledError("original cancellation")
            if primary_cancelled
            else StartupError({})
        )

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                closing.set()
                await release.wait()
                raise RuntimeError("SENSITIVE_CLEANUP")

        registry = CredentialProviderRegistry({"custom": factory})

        async def use() -> None:
            async with registry.open(configured(timeout=2)):
                raise primary

        task = asyncio.create_task(use())
        await closing.wait()
        task.cancel("new external cancellation")
        release.set()
        with pytest.raises((StartupError, asyncio.CancelledError)) as failure:
            async with asyncio.timeout(3):
                await task
        assert failure.value is primary
        assert "Credential cleanup also failed" in "\n".join(primary.__notes__)
        assert registry.pending_task_count == 0
        record = _audit_fields(caplog.records[-1])
        assert record["event"] == "credential_cleanup_failed"
        assert record["credential_ref"] == "reader" and record["provider"] == "custom"
        assert record["reason"] == "cleanup_error"
        assert record["exception_class"] == "RuntimeError"
        assert "SENSITIVE" not in repr(record)

    asyncio.run(scenario())


@pytest.mark.parametrize("primary_cancelled", [False, True])
def test_external_cancellation_after_body_failure_and_successful_close(
    primary_cancelled: bool,
) -> None:
    async def scenario() -> None:
        closing, release = asyncio.Event(), asyncio.Event()
        primary = (
            asyncio.CancelledError("original cancellation")
            if primary_cancelled
            else StartupError({})
        )

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield SingleHeader()
            finally:
                closing.set()
                await release.wait()

        registry = CredentialProviderRegistry({"custom": factory})

        async def use() -> None:
            async with registry.open(configured(timeout=2)):
                raise primary

        task = asyncio.create_task(use())
        await closing.wait()
        task.cancel("new external cancellation")
        release.set()
        with pytest.raises(asyncio.CancelledError) as failure:
            async with asyncio.timeout(3):
                await task
        if primary_cancelled:
            assert failure.value is primary
        else:
            assert failure.value is not primary
            assert "prior body failure" in "\n".join(failure.value.__notes__)
        assert registry.pending_task_count == 0
        async with registry.open(configured()):
            pass

    asyncio.run(scenario())
