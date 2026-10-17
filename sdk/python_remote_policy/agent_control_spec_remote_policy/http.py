# Copyright (c) Microsoft. All rights reserved.
"""Configurable authenticated HTTP implementation of the v1 policy source."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from collections.abc import Mapping
from http.cookiejar import Cookie, DefaultCookiePolicy

import httpx

from .auth import (
    AuthorizationProvider,
    Credential,
    RequestAuthentication,
)
from .poller import (
    MAX_POLICY_BYTES,
    AgentPolicy,
    Changed,
    NotModified,
    PolicySourceError,
    PolicyValidationError,
    PollerConfig,
    current_policy_request_id,
)

__all__ = ["AuthorizationProvider", "HttpPolicySource"]


class _NoCookies(DefaultCookiePolicy):
    def set_ok(self, cookie: Cookie, request: object) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: object) -> bool:
        return False


class HttpPolicySource:
    """Own an async client; HTTPS/auth required except explicit anonymous loopback.

    Optional credential labels are host-supplied non-secret configuration
    metadata, never evidence of identity or authorization.
    """

    def __init__(
        self,
        endpoint: str,
        credential: Credential | None = None,
        *,
        allow_insecure_localhost: bool = False,
        request_timeout_seconds: float = 10,
        transport: httpx.AsyncBaseTransport | None = None,
        credential_ref: str | None = None,
        provider: str | None = None,
    ) -> None:
        try:
            url = httpx.URL(endpoint)
        except httpx.InvalidURL:
            raise PolicyValidationError("config") from None
        if (
            not url.host
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.scheme not in ("https", "http")
        ):
            raise PolicyValidationError("config")
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(url.host).is_loopback
            except ValueError:
                loopback = False
            if not allow_insecure_localhost or not loopback or credential is not None:
                raise PolicyValidationError("config")
        elif credential is None:
            raise PolicyValidationError("config")
        if (
            isinstance(request_timeout_seconds, bool)
            or not 0 < request_timeout_seconds <= 120
        ):
            raise PolicyValidationError("config")
        self._endpoint = str(url).rstrip("/")
        self._credential = credential
        self._timeout = request_timeout_seconds
        self._closed = False
        self._client = httpx.AsyncClient(
            auth=(
                RequestAuthentication(
                    credential, credential_ref=credential_ref, provider=provider
                )
                if credential is not None
                else None
            ),
            timeout=request_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
            transport=transport,
        )
        self._client.cookies.jar.set_policy(_NoCookies())

    @classmethod
    def from_config(
        cls,
        config: PollerConfig,
        credentials: Mapping[str, Credential],
    ) -> HttpPolicySource:
        """Resolve the non-secret YAML reference before acquiring any credential."""
        if config.endpoint is None:
            raise PolicyValidationError("config")
        credential: Credential | None = None
        provider: str | None = None
        if config.credential_ref is not None:
            if config.credential_ref not in credentials:
                raise PolicyValidationError("config")
            credential = credentials[config.credential_ref]
            definition = config.credentials.get(config.credential_ref)
            provider = definition.provider if definition is not None else None
        return cls(
            config.endpoint,
            credential,
            allow_insecure_localhost=config.allow_insecure_localhost,
            request_timeout_seconds=config.request_timeout_seconds,
            credential_ref=config.credential_ref,
            provider=provider,
        )

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        """GET a scoped complete envelope; never retry/redirect credentialed reads."""
        try:
            async with asyncio.timeout(self._timeout):
                return await self._fetch(selection, if_none_match)
        except (TimeoutError, httpx.TimeoutException):
            raise PolicySourceError("transient", "timeout") from None
        except httpx.HTTPError:
            raise PolicySourceError("transient", "transport") from None

    async def _fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        if self._closed:
            raise PolicySourceError("protocol", "closed")
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "X-Request-ID": uuid.uuid4().hex,
        }
        if if_none_match is not None:
            if re.fullmatch(r'"[0-9a-f]{64}"', if_none_match) is None:
                raise PolicyValidationError("etag")
            headers["If-None-Match"] = if_none_match
        url = (
            f"{self._endpoint}/v1/tenants/{selection.tenant_id}"
            f"/policies/{selection.policy_id}"
        )
        async with self._client.stream(
            "GET",
            url,
            headers=headers,
            extensions={"acs_policy_request_id": current_policy_request_id()},
        ) as response:
            status = response.status_code
            authoritative = {
                401: "unauthorized",
                403: "forbidden",
                404: "not_found",
                410: "gone",
            }
            if status in authoritative:
                raise PolicySourceError("authoritative", authoritative[status])
            if status == 429:
                raise PolicySourceError("transient", "throttled")
            if 500 <= status <= 599:
                raise PolicySourceError("transient", "service")
            if 300 <= status <= 399 and status != 304:
                raise PolicySourceError("protocol", "redirect")
            if status not in (200, 304):
                raise PolicySourceError("protocol", "unexpected_status")
            if "Content-Encoding" in response.headers:
                raise PolicySourceError("protocol", "headers")
            etag = response.headers.get("ETag", "")
            if re.fullmatch(r'"[0-9a-f]{64}"', etag) is None:
                raise PolicySourceError("protocol", "headers")
            if status == 200:
                content_type = response.headers.get("Content-Type", "").lower()
                parts = [part.strip() for part in content_type.split(";")]
                if parts not in (
                    ["application/json"],
                    ["application/json", "charset=utf-8"],
                ):
                    raise PolicySourceError("protocol", "headers")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                if re.fullmatch(r"[0-9]{1,10}", content_length) is None:
                    raise PolicySourceError("protocol", "headers")
                if int(content_length) > MAX_POLICY_BYTES:
                    raise PolicySourceError("protocol", "body_too_large")
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=65536):
                body.extend(chunk)
                if len(body) > MAX_POLICY_BYTES:
                    raise PolicySourceError("protocol", "body_too_large")
            if status == 304:
                if body:
                    raise PolicySourceError("protocol", "headers")
                return NotModified(etag)
            return Changed(bytes(body), etag)

    async def aclose(self) -> None:
        """Close the owned HTTP client; the injected credential remains host-owned."""
        self._closed = True
        await self._client.aclose()
