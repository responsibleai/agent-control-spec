# Copyright (c) Microsoft. All rights reserved.
"""Exact HTTP/auth contract; credentials and response content stay out of errors."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from collections.abc import AsyncGenerator, AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from types import TracebackType
from typing import Self

import httpx
import pytest
from agent_control_spec_remote_policy.auth import (
    AuthenticationRequest,
    AuthorizationProvider,
    Credential,
    CredentialProviderRegistry,
)
from agent_control_spec_remote_policy.azure import AzureAuthorizationProvider
from agent_control_spec_remote_policy.http import HttpPolicySource
from agent_control_spec_remote_policy.poller import (
    AgentPolicy,
    Changed,
    CredentialConfig,
    CredentialOption,
    NotModified,
    PolicyPoller,
    PolicySourceError,
    PolicyValidationError,
)
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import CredentialUnavailableError

from .test_remote_policy import (
    FakeClock,
    configuration,
    document,
    reply,
)


class Bearer:
    """Dummy authorization provider; this string is not an actual credential."""

    def __init__(self) -> None:
        self.calls = 0

    async def authorization(self) -> str:
        self.calls += 1
        return "Bearer unit-test-token"


def response(
    selection: AgentPolicy,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    envelope = reply(document(selection))
    return httpx.Response(
        status,
        content=envelope.body if content is None else content,
        headers=(
            {"Content-Type": "application/json", "ETag": envelope.etag}
            if headers is None
            else headers
        ),
    )


def test_authenticated_scope_conditional_headers_and_credential_ownership() -> None:
    async def scenario() -> None:
        selection = AgentPolicy("a", "tenant-a", "policy-a")
        expected = reply(document(selection))
        observed: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            if "If-None-Match" in request.headers:
                return response(selection, status=304, content=b"")
            return response(selection)

        credential = Bearer()
        source = HttpPolicySource(
            "https://policies.example.test/base",
            credential,
            transport=httpx.MockTransport(handler),
        )
        changed = await source.fetch(selection, None)
        assert isinstance(changed, Changed) and changed.body == expected.body
        unchanged = await source.fetch(selection, changed.etag)
        assert isinstance(unchanged, NotModified) and unchanged.etag == changed.etag
        assert str(observed[0].url) == (
            "https://policies.example.test/base/v1/tenants/tenant-a/policies/policy-a"
        )
        assert observed[0].headers["Authorization"] == "Bearer unit-test-token"
        assert observed[0].headers["Accept-Encoding"] == "identity"
        assert observed[1].headers["If-None-Match"] == changed.etag
        assert credential.calls == 2
        await source.aclose()
        with pytest.raises(PolicySourceError):
            await source.fetch(selection, None)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.test",
        "http://localhost:8000",
        "file:policy.yaml",
        "https://user:password@example.test",
        "https://example.test?token=secret",
        "https://example.test#fragment",
        "ftp://example.test",
        "not a URL",
    ],
)
def test_endpoint_restrictions_before_network(endpoint: str) -> None:
    with pytest.raises(PolicyValidationError):
        HttpPolicySource(endpoint, Bearer(), allow_insecure_localhost=True)


def test_no_credentials_over_loopback_and_unknown_credential_reference() -> None:
    with pytest.raises(PolicyValidationError):
        HttpPolicySource("http://127.0.0.1", Bearer(), allow_insecure_localhost=True)
    with pytest.raises(PolicyValidationError):
        HttpPolicySource("https://example.test")
    with pytest.raises(PolicyValidationError):
        HttpPolicySource.from_config(configuration(), {})


@pytest.mark.parametrize(
    "status,kind,code",
    [
        (401, "authoritative", "unauthorized"),
        (403, "authoritative", "forbidden"),
        (404, "authoritative", "not_found"),
        (410, "authoritative", "gone"),
        (429, "transient", "throttled"),
        (503, "transient", "service"),
        (302, "protocol", "redirect"),
        (201, "protocol", "unexpected_status"),
    ],
)
def test_status_matrix_and_no_401_retry(status: int, kind: str, code: str) -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return response(
                selection,
                status=status,
                headers={"Location": "https://different.example.test"},
                content=b"SENSITIVE_ERROR_BODY",
            )

        credential = Bearer()
        source = HttpPolicySource(
            "https://policies.example.test",
            credential,
            transport=httpx.MockTransport(handler),
        )
        try:
            with pytest.raises(PolicySourceError) as failure:
                await source.fetch(selection, None)
            assert failure.value.kind == kind and failure.value.code == code
            assert "SENSITIVE" not in str(failure.value)
            assert len(seen) == 1 and credential.calls == 1
        finally:
            await source.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/html", "ETag": '"' + "a" * 64 + '"'},
        {"Content-Type": "application/json"},
        {"Content-Type": "application/json", "ETag": 'W/"' + "a" * 64 + '"'},
        {"Content-Type": "application/json", "ETag": '"short"'},
        {
            "Content-Type": "application/json",
            "ETag": '"' + "a" * 64 + '"',
            "Content-Encoding": "gzip",
        },
        {
            "Content-Type": "application/json",
            "ETag": '"' + "a" * 64 + '"',
            "Content-Encoding": "identity",
        },
        {
            "Content-Type": "application/json",
            "ETag": '"' + "a" * 64 + '"',
            "Content-Length": "-1",
        },
        {
            "Content-Type": "application/json",
            "ETag": '"' + "a" * 64 + '"',
            "Content-Length": "1048577",
        },
    ],
)
def test_header_encoding_and_size_contract(headers: dict[str, str]) -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        source = HttpPolicySource(
            "https://policies.example.test",
            Bearer(),
            transport=httpx.MockTransport(
                lambda _: response(selection, headers=headers, content=b"{}")
            ),
        )
        try:
            with pytest.raises(PolicySourceError):
                await source.fetch(selection, None)
        finally:
            await source.aclose()

    asyncio.run(scenario())


class CountingStream(httpx.AsyncByteStream):
    """Offer chunks of the given sizes with no declared length; count the pulls."""

    def __init__(self, sizes: Sequence[int]) -> None:
        self.sizes = tuple(sizes)
        self.pulled = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for size in self.sizes:
            self.pulled += 1
            yield b"x" * size

    async def aclose(self) -> None:
        self.closed = True


def test_declared_length_bound_and_bad_304_body() -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        expected = reply(document(selection))

        def handler(request: httpx.Request) -> httpx.Response:
            if "If-None-Match" in request.headers:
                return response(selection, status=304, content=b"unexpected")
            # httpx derives Content-Length from bytes content, so this response
            # is rejected by the header check before any chunk is read.
            return response(
                selection,
                content=b"x" * (1024 * 1024 + 1),
                headers={"Content-Type": "application/json", "ETag": expected.etag},
            )

        source = HttpPolicySource(
            "https://policies.example.test",
            Bearer(),
            transport=httpx.MockTransport(handler),
        )
        try:
            with pytest.raises(PolicySourceError) as failure:
                await source.fetch(selection, None)
            assert failure.value.code == "body_too_large"
            with pytest.raises(PolicySourceError):
                await source.fetch(selection, expected.etag)
        finally:
            await source.aclose()

    asyncio.run(scenario())


MEBIBYTE = 1024 * 1024
CHUNK = 65536  # The source reads the response body in chunks of this size.


def streamed_source(
    stream: CountingStream, etag: str
) -> tuple[HttpPolicySource, list[httpx.Response]]:
    built: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        result = httpx.Response(
            200,
            headers={"Content-Type": "application/json", "ETag": etag},
            stream=stream,
        )
        built.append(result)
        return result

    source = HttpPolicySource(
        "https://policies.example.test",
        Bearer(),
        transport=httpx.MockTransport(handler),
    )
    return source, built


def test_stream_bound_without_content_length() -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        expected = reply(document(selection))
        stream = CountingStream([CHUNK] * 64)  # 4 MiB offered, 1 MiB allowed
        source, built = streamed_source(stream, expected.etag)
        try:
            with pytest.raises(PolicySourceError) as failure:
                await source.fetch(selection, None)
        finally:
            await source.aclose()
        assert failure.value.code == "body_too_large"
        # Only the per-chunk cap can have rejected it: no length was declared.
        # Sixteen chunks are exactly 1 MiB; the seventeenth crosses the limit and
        # nothing more is read.
        assert "Content-Length" not in built[0].headers
        assert stream.pulled == MEBIBYTE // CHUNK + 1
        assert stream.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "extra,accepted", [(0, True), (1, False)], ids=["one-mebibyte", "one-byte-over"]
)
def test_stream_bound_is_exactly_one_mebibyte(extra: int, accepted: bool) -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        expected = reply(document(selection))
        sizes = [CHUNK] * (MEBIBYTE // CHUNK) + ([extra] if extra else [])
        stream = CountingStream(sizes)
        source, _ = streamed_source(stream, expected.etag)
        try:
            if accepted:
                result = await source.fetch(selection, None)
                assert isinstance(result, Changed) and len(result.body) == MEBIBYTE
            else:
                with pytest.raises(PolicySourceError) as failure:
                    await source.fetch(selection, None)
                assert failure.value.code == "body_too_large"
        finally:
            await source.aclose()
        assert stream.pulled == len(sizes)

    asyncio.run(scenario())


def test_authentication_is_inside_total_request_deadline() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        exited = asyncio.Event()

        class SlowCredential:
            async def authorization(self) -> str:
                entered.set()
                try:
                    await release.wait()
                finally:
                    exited.set()
                return "Bearer unit-test-token"

        source = HttpPolicySource(
            "https://policies.example.test",
            SlowCredential(),
            request_timeout_seconds=0.03,
        )
        task = asyncio.create_task(source.fetch(configuration(1).agents[0], None))
        await entered.wait()
        with pytest.raises(PolicySourceError):
            await task
        assert exited.is_set()
        await source.aclose()

    asyncio.run(scenario())


def test_response_cookies_are_not_retained_or_forwarded_between_agents() -> None:
    async def scenario() -> None:
        observed: list[httpx.Request] = []
        first, second = configuration().agents

        def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            selected = first if request.url.path.endswith(first.policy_id) else second
            result = response(selected)
            result.headers["Set-Cookie"] = f"{selected.policy_id}=opaque; Path=/"
            return result

        source = HttpPolicySource(
            "https://policies.example.test",
            Bearer(),
            transport=httpx.MockTransport(handler),
        )
        try:
            for _ in range(3):
                await source.fetch(first, None)
                await source.fetch(second, None)
            assert all("Cookie" not in request.headers for request in observed)
        finally:
            await source.aclose()

    asyncio.run(scenario())


class AzureCredential:
    """Structurally compatible Azure credential without any real token acquisition."""

    def __init__(self, *, expired: bool = False, fail: bool = False) -> None:
        self.scopes: tuple[str, ...] = ()
        self.expired = expired
        self.fail = fail
        self.closed = False

    async def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
        self.scopes = scopes
        if self.fail:
            raise ClientAuthenticationError("SENSITIVE_AUTHENTICATION_DETAILS")
        return AccessToken(
            "unit-test-token", 0 if self.expired else int(time.time()) + 900
        )

    async def close(self) -> None:
        self.closed = True

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self.close()


def test_azure_scope_is_explicit_and_credential_is_caller_owned() -> None:
    async def scenario() -> None:
        credential = AzureCredential()
        provider = AzureAuthorizationProvider(credential, "api://policy-api/.default")
        assert await provider.authorization() == "Bearer unit-test-token"
        assert credential.scopes == ("api://policy-api/.default",)
        assert not credential.closed
        await credential.close()

    asyncio.run(scenario())


def test_azure_explicitly_implements_single_header_protocol() -> None:
    """Check nominal inheritance and a typed assignment to the shared interface."""
    credential = AzureCredential()
    provider: AuthorizationProvider = AzureAuthorizationProvider(
        credential, "api://policy-api/.default"
    )
    assert AuthorizationProvider in AzureAuthorizationProvider.__bases__
    assert isinstance(provider, AuthorizationProvider)
    assert not credential.closed


@pytest.mark.parametrize("expired,fail", [(True, False), (False, True)])
def test_azure_failure_is_typed_and_redacted(expired: bool, fail: bool) -> None:
    async def scenario() -> None:
        credential = AzureCredential(expired=expired, fail=fail)
        provider = AzureAuthorizationProvider(credential, "api://policy-api/.default")
        with pytest.raises(PolicySourceError) as failure:
            await provider.authorization()
        assert failure.value.code == "credential"
        assert "SENSITIVE" not in str(failure.value)
        assert "unit-test-token" not in str(failure.value)
        await credential.close()

    asyncio.run(scenario())


class HmacAuthenticator:
    """Test-only HMAC protocol exerciser; this is not an AWS implementation."""

    def __init__(self, expected_concurrency: int = 1) -> None:
        self.requests: list[AuthenticationRequest] = []
        self.ready = asyncio.Event()
        self.release = asyncio.Event()
        self.expected_concurrency = expected_concurrency
        self.fail = False
        if expected_concurrency == 1:
            self.release.set()

    async def authenticate(self, request: AuthenticationRequest) -> Mapping[str, str]:
        if self.fail:
            raise PolicySourceError("authoritative", "forbidden")
        self.requests.append(request)
        if len(self.requests) == self.expected_concurrency:
            self.ready.set()
        await self.release.wait()
        canonical = "\n".join(
            [
                request.method,
                request.url,
                request.headers["host"],
                request.headers.get("if-none-match", ""),
                request.headers["x-correlation-id"],
                request.body.hex(),
            ]
        ).encode("utf-8")
        signature = hmac.new(
            b"unit-test-hmac-key", canonical, hashlib.sha256
        ).hexdigest()
        return {
            "Authorization": f"HMAC Signature={signature}",
            "X-Signing-Date": "20261016",
        }


@pytest.mark.parametrize("conditional_status", [200, 304])
def test_generic_hmac_signed_is_sent_and_unchanged_requests_authenticate(
    conditional_status: int,
) -> None:
    async def scenario() -> None:
        selection = configuration(1).agents[0]
        observed: list[httpx.Request] = []

        def transport(request: httpx.Request) -> httpx.Response:
            # Independently recompute from the actual transport request, not the DTO.
            wire = (
                request.method
                + "\n"
                + str(request.url)
                + "\n"
                + request.headers["host"]
                + "\n"
                + request.headers.get("if-none-match", "")
                + "\n"
                + request.headers["x-correlation-id"]
                + "\n"
                + request.content.hex()
            ).encode()
            expected = hmac.digest(b"unit-test-hmac-key", wire, "sha256").hex()
            assert hmac.compare_digest(
                request.headers["Authorization"], "HMAC Signature=" + expected
            )
            assert request.headers["X-Signing-Date"] == "20261016"
            observed.append(request)
            if "if-none-match" in request.headers:
                return response(
                    selection,
                    status=conditional_status,
                    content=b"" if conditional_status == 304 else None,
                )
            return response(selection)

        signer = HmacAuthenticator()
        source = HttpPolicySource(
            "https://example.test/base",
            signer,
            transport=httpx.MockTransport(transport),
        )
        source._client.headers["X-Correlation-ID"] = "host-owned"
        try:
            first = await source.fetch(selection, None)
            assert isinstance(first, Changed)
            await source.fetch(selection, first.etag)
            assert len(observed) == len(signer.requests) == 2
            assert signer.requests[1].headers["if-none-match"] == first.etag
            assert all("authorization" not in item.headers for item in signer.requests)
        finally:
            await source.aclose()

    asyncio.run(scenario())


def test_invalid_etag_and_invalid_protocol_dispatch_never_call_provider_or_transport() -> (
    None
):
    async def scenario() -> None:
        credential = Bearer()

        def transport(request: httpx.Request) -> httpx.Response:
            pytest.fail("invalid ETag reached transport")

        source = HttpPolicySource(
            "https://example.test", credential, transport=httpx.MockTransport(transport)
        )
        try:
            with pytest.raises(PolicyValidationError, match="etag"):
                await source.fetch(configuration(1).agents[0], "invalid")
            assert credential.calls == 0
        finally:
            await source.aclose()

    asyncio.run(scenario())


def test_four_concurrent_signatures_are_reentrant_and_distinct() -> None:
    async def scenario() -> None:
        config = configuration(4)
        signer = HmacAuthenticator(4)
        signatures: set[str] = set()

        def transport(request: httpx.Request) -> httpx.Response:
            selection = next(
                item
                for item in config.agents
                if request.url.path.endswith(item.policy_id)
            )
            wire = "\n".join(
                (
                    request.method,
                    str(request.url),
                    request.headers["host"],
                    "",
                    request.headers["x-correlation-id"],
                    request.content.hex(),
                )
            ).encode()
            expected = hmac.digest(b"unit-test-hmac-key", wire, "sha256").hex()
            assert request.headers["authorization"] == "HMAC Signature=" + expected
            signatures.add(expected)
            return response(selection)

        source = HttpPolicySource(
            "https://example.test", signer, transport=httpx.MockTransport(transport)
        )
        source._client.headers["X-Correlation-ID"] = "host-owned"
        tasks = [
            asyncio.create_task(source.fetch(item, None)) for item in config.agents
        ]
        try:
            await asyncio.wait_for(signer.ready.wait(), 1)
            assert len(signer.requests) == 4
            assert not signatures
            signer.release.set()
            assert len(await asyncio.gather(*tasks)) == 4
            assert len(signatures) == 4
        finally:
            signer.release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await source.aclose()

    asyncio.run(scenario())


def test_provider_denial_is_transient_and_cannot_fence_existing_snapshot() -> None:
    async def scenario() -> None:
        config = configuration(1)
        signer = HmacAuthenticator()
        source = HttpPolicySource(
            "https://example.test",
            signer,
            transport=httpx.MockTransport(lambda _: response(config.agents[0])),
        )
        source._client.headers["X-Correlation-ID"] = "host-owned"
        async with PolicyPoller(config, source, clock=FakeClock()) as poller:
            snapshot = poller.get_policy("agent0")
            signer.fail = True
            with pytest.raises(PolicySourceError) as failure:
                await poller.refresh("agent0")
            assert (failure.value.kind, failure.value.code) == (
                "transient",
                "credential",
            )
            assert poller.get_policy("agent0") is snapshot

    asyncio.run(scenario())


@pytest.mark.parametrize("request_aware", [False, True])
def test_registry_outlives_source_and_source_close_does_not_close_credential(
    request_aware: bool,
) -> None:
    async def scenario() -> None:
        closed: list[str] = []
        config = replace(
            configuration(1),
            endpoint="https://example.test",
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom")},
        )

        @asynccontextmanager
        async def factory(
            options: Mapping[str, CredentialOption],
        ) -> AsyncGenerator[Credential, None]:
            try:
                yield HmacAuthenticator() if request_aware else Bearer()
            finally:
                closed.append("credential")

        registry = CredentialProviderRegistry({"custom": factory})
        async with registry.open(config) as credentials:
            # Existing synchronous construction accepts the selected union mapping.
            unused = HttpPolicySource.from_config(config, credentials)
            await unused.aclose()
            assert not closed

            class Source(HttpPolicySource):
                async def aclose(self) -> None:
                    await super().aclose()
                    closed.append("source")

            source = Source(
                config.endpoint or "",
                credentials["reader"],
                transport=httpx.MockTransport(lambda _: response(config.agents[0])),
            )
            source._client.headers["X-Correlation-ID"] = "host-owned"
            async with PolicyPoller(config, source, clock=FakeClock()) as poller:
                assert poller.get_policy("agent0")
            assert closed == ["source"]
        assert closed == ["source", "credential"]
        assert registry.pending_task_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "error,code",
    [
        (TimeoutError("SENSITIVE_TIMEOUT"), "timeout"),
        (httpx.ConnectTimeout("SENSITIVE_TIMEOUT"), "timeout"),
        (httpx.ReadTimeout("SENSITIVE_TIMEOUT"), "timeout"),
        (httpx.ConnectError("SENSITIVE_TRANSPORT"), "transport"),
        (httpx.RemoteProtocolError("SENSITIVE_TRANSPORT"), "transport"),
    ],
)
def test_generic_transport_timeout_classification(error: Exception, code: str) -> None:
    async def scenario() -> None:
        def transport(request: httpx.Request) -> httpx.Response:
            raise error

        source = HttpPolicySource(
            "https://example.test", Bearer(), transport=httpx.MockTransport(transport)
        )
        try:
            with pytest.raises(PolicySourceError) as failure:
                await source.fetch(configuration(1).agents[0], None)
            assert (failure.value.kind, failure.value.code) == ("transient", code)
            assert "SENSITIVE" not in str(failure.value)
        finally:
            await source.aclose()

    asyncio.run(scenario())


def test_total_fetch_deadline_is_timeout_and_joins_credential() -> None:
    async def scenario() -> None:
        entered, exited = asyncio.Event(), asyncio.Event()

        class Blocked:
            async def authorization(self) -> str:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    exited.set()
                return ""

        source = HttpPolicySource(
            "https://example.test",
            Blocked(),
            request_timeout_seconds=0.02,
        )
        try:
            task = asyncio.create_task(source.fetch(configuration(1).agents[0], None))
            await entered.wait()
            with pytest.raises(PolicySourceError) as failure:
                await task
            assert failure.value.code == "timeout" and exited.is_set()
        finally:
            await source.aclose()

    asyncio.run(scenario())


def test_generic_source_wires_config_labels_parent_extension_and_child_header(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        config = replace(
            configuration(1),
            endpoint="https://example.test",
            credential_ref="reader",
            credentials={"reader": CredentialConfig("custom")},
        )
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.http.current_policy_request_id",
            lambda: "parent-only",
        )

        class Broken:
            async def authorization(self) -> str:
                raise RuntimeError("SENSITIVE_PROVIDER_DETAIL")

        source = HttpPolicySource.from_config(config, {"reader": Broken()})
        try:
            with pytest.raises(PolicySourceError):
                await source.fetch(config.agents[0], None)
            record = caplog.records[-1].__dict__
            assert (
                record["credential_ref"] == "reader" and record["provider"] == "custom"
            )
            assert record["policy_request_id"] == "parent-only"
            assert isinstance(record["http_request_id"], str)
            assert len(record["http_request_id"]) == 32
            assert "SENSITIVE" not in repr(record)
        finally:
            await source.aclose()

        signer = HmacAuthenticator()

        def transport(request: httpx.Request) -> httpx.Response:
            assert request.extensions["acs_policy_request_id"] == "parent-only"
            assert "parent-only" not in repr(dict(request.headers))
            assert request.headers["x-request-id"]
            return response(config.agents[0])

        source = HttpPolicySource(
            "https://example.test", signer, transport=httpx.MockTransport(transport)
        )
        source._client.headers["X-Correlation-ID"] = "child-owned"
        try:
            await source.fetch(config.agents[0], None)
            assert not hasattr(signer.requests[0], "extensions")
            assert "parent-only" not in repr(signer.requests[0])
        finally:
            await source.aclose()

    asyncio.run(scenario())


class RotatingAzureCredential(AzureCredential):
    """Event-controlled tokens and failures; never contacts Azure or a subprocess."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0
        self.expires_on = 1120
        self.error: Exception | None = None
        self.token_override: str | None = None
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()

    async def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
        self.scopes = scopes
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        if self.error is not None:
            raise self.error
        return AccessToken(
            self.token_override
            if self.token_override is not None
            else f"unit-test-token-{self.calls}",
            self.expires_on,
        )


class SENSITIVEAuthenticationError(ClientAuthenticationError):
    """Test that untrusted vendor subclass names never enter audit records."""


@pytest.mark.parametrize(
    "error_type,expected_class",
    [
        (ClientAuthenticationError, "ClientAuthenticationError"),
        (CredentialUnavailableError, "CredentialUnavailableError"),
        (SENSITIVEAuthenticationError, "ClientAuthenticationError"),
    ],
)
def test_azure_acquisition_failure_logs_safe_vendor_class(
    error_type: type[ClientAuthenticationError],
    expected_class: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        error = error_type("SENSITIVE_AUTHENTICATION_DETAILS")
        credential = RotatingAzureCredential()
        credential.error = error
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        try:
            with (
                caplog.at_level(
                    "WARNING", logger="agent_control_spec_remote_policy.azure"
                ),
                pytest.raises(PolicySourceError) as failure,
            ):
                await provider.authorization()
            assert failure.value.code == "credential"
            records = [
                record
                for record in caplog.records
                if record.name == "agent_control_spec_remote_policy.azure"
            ]
            assert len(records) == 1
            record = records[0]
            assert record.getMessage() == "azure_token_acquisition_failed"
            assert record.__dict__.get("event") == "azure_token_acquisition_failed"
            assert record.__dict__.get("exception_class") == expected_class
            assert record.exc_info is None
            assert record.exc_text is None
            assert "SENSITIVE" not in (
                caplog.text + str(record.__dict__) + str(failure.value)
            )
            assert not credential.closed
        finally:
            await credential.close()

    asyncio.run(scenario())


def test_azure_single_token_cache_concurrent_refresh_and_exact_margin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        now = [1000.0]
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: now[0]
        )
        credential = RotatingAzureCredential()
        credential.release.clear()
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        tasks = [asyncio.create_task(provider.authorization()) for _ in range(4)]
        await credential.entered.wait()
        assert credential.calls == 1 and all(not task.done() for task in tasks)
        credential.release.set()
        first = await asyncio.gather(*tasks)
        assert len(set(first)) == 1 and credential.calls == 1
        now[0] = 1059
        assert await provider.authorization() == first[0]
        assert credential.calls == 1
        now[0] = 1060
        credential.expires_on = 1240
        credential.entered.clear()
        credential.release.clear()
        tasks = [asyncio.create_task(provider.authorization()) for _ in range(4)]
        await credential.entered.wait()
        assert credential.calls == 2
        credential.release.set()
        second = await asyncio.gather(*tasks)
        assert len(set(second)) == 1 and second[0] != first[0]
        assert credential.calls == 2 and not credential.closed

    asyncio.run(scenario())


@pytest.mark.parametrize("remaining", [0, 59, 60, 61])
def test_azure_fresh_token_minimum_remaining_validity(
    remaining: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: 1000.0
        )
        credential = RotatingAzureCredential()
        credential.expires_on = 1000 + remaining
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        if remaining <= 60:
            with pytest.raises(PolicySourceError) as failure:
                await provider.authorization()
            assert failure.value.code == "credential"
            assert provider._cached_authorization is None and provider._expires_on == 0
        else:
            assert await provider.authorization()
        assert credential.calls == 1 and not credential.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "value",
    ["", "contains space", "contains\r\nnewline", "\u00e9", "x" * 16384, "x" * 16385],
)
def test_azure_single_cached_token_is_bounded_by_single_header_value_grammar(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: 1000.0
        )
        credential = RotatingAzureCredential()
        credential.token_override = value
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        if len(value) == 16384:
            assert len(await provider.authorization()) == 16384 + 7
            assert credential.calls == 1
        else:
            with pytest.raises(PolicySourceError) as failure:
                await provider.authorization()
            assert failure.value.code == "credential"
            assert provider._cached_authorization is None

    asyncio.run(scenario())


@pytest.mark.parametrize("near_expiry", [False, True])
def test_azure_refresh_failure_discards_old_token_and_allows_retry(
    near_expiry: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        now = [1000.0]
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: now[0]
        )
        credential = RotatingAzureCredential()
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        first = await provider.authorization()
        now[0] = 1060
        if not near_expiry:
            credential.error = ClientAuthenticationError(
                "SENSITIVE_AUTHENTICATION_DETAILS"
            )
        with pytest.raises(PolicySourceError) as failure:
            await provider.authorization()
        assert failure.value.code == "credential"
        assert "SENSITIVE" not in str(failure.value)
        assert provider._cached_authorization is None and provider._expires_on == 0
        credential.error = None
        credential.expires_on = 2000
        assert await provider.authorization() != first
        assert credential.calls == 3 and not credential.closed

    asyncio.run(scenario())


def test_azure_cancelled_refresh_releases_lock_and_does_not_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: 1000.0
        )
        credential = RotatingAzureCredential()
        credential.release.clear()
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        task = asyncio.create_task(provider.authorization())
        await credential.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not provider._lock.locked() and provider._cached_authorization is None
        credential.release.set()
        assert await provider.authorization()
        assert credential.calls == 2 and not credential.closed

    asyncio.run(scenario())


def test_azure_cancelled_waiter_does_not_interrupt_shared_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(
            "agent_control_spec_remote_policy.azure.time.time", lambda: 1000.0
        )
        credential = RotatingAzureCredential()
        credential.release.clear()
        provider = AzureAuthorizationProvider(credential, "api://policy/.default")
        owner = asyncio.create_task(provider.authorization())
        await credential.entered.wait()
        waiting = asyncio.Event()

        async def wait_for_token() -> str:
            waiting.set()
            return await provider.authorization()

        waiter = asyncio.create_task(wait_for_token())
        await waiting.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert credential.calls == 1 and not owner.done()
        credential.release.set()
        token = await owner
        assert await provider.authorization() == token
        assert credential.calls == 1 and not provider._lock.locked()

    asyncio.run(scenario())


@pytest.mark.parametrize("character", [";", "&", "|", "$", "`", "<", ">"])
def test_pinned_azure_cli_rejects_shell_metacharacter_scope_before_command(
    character: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import azure.identity.aio._credentials.azure_cli as cli
    from azure.identity.aio import AzureCliCredential

    async def blocked_command(command_args: list[str], timeout: int) -> str:
        pytest.fail("invalid Azure CLI scope reached command execution")

    monkeypatch.setattr(cli, "_run_command", blocked_command)

    async def scenario() -> None:
        # SDK provider grammar remains unchanged; the pinned official CLI
        # credential performs its own stricter platform validation.
        async with AzureCliCredential(process_timeout=5) as credential:
            with pytest.raises(ValueError):
                await credential.get_token(f"api://policy{character}blocked/.default")

    asyncio.run(scenario())
