# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Chat-completion transport and the injectable model protocol."""

from __future__ import annotations

import http.client
import io
import json
import os
import time
from functools import partial
from typing import Protocol
from urllib import error, parse, request

DEFAULT_API_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
REQUEST_TIMEOUT_SECONDS = 60
REQUEST_DEADLINE_SECONDS = 120
MAX_RESPONSE_BYTES = 1_000_000


class LanguageModel(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class ProviderError(RuntimeError):
    """A provider/configuration failure, never retried as a bad policy plan."""


class _DeadlineExceeded(TimeoutError):
    pass


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _DeadlineExceeded
    return min(REQUEST_TIMEOUT_SECONDS, remaining)


class _DeadlineReader(io.RawIOBase):
    """Apply the remaining budget to every receive, including status/headers."""

    def __init__(self, sock, deadline: float):
        self._socket = sock
        self._raw = sock.makefile("rb", buffering=0)
        self._deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        timeout = _remaining(self._deadline)
        deadline_limited = timeout < REQUEST_TIMEOUT_SECONDS
        self._socket.settimeout(timeout)
        try:
            size = self._raw.readinto(buffer)
        except TimeoutError:
            # Socket timers and monotonic clocks can have different resolution
            # (notably on Windows). Classify by the budget that limited this read,
            # rather than requiring the clock to tick past the deadline first.
            if deadline_limited:
                raise _DeadlineExceeded from None
            _remaining(self._deadline)
            raise
        _remaining(self._deadline)
        return size

    def close(self):
        self._raw.close()
        super().close()


class _DeadlineResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, deadline: float, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp.close()
        self.fp = io.BufferedReader(_DeadlineReader(sock, deadline))


def _connection(kind, deadline, host, **kwargs):
    connection = kind(host, **kwargs)
    connection.response_class = partial(_DeadlineResponse, deadline=deadline)
    return connection


class _DeadlineHTTPHandler(request.HTTPHandler):
    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def http_open(self, req):
        return self.do_open(
            partial(_connection, http.client.HTTPConnection, self.deadline), req
        )


class _DeadlineHTTPSHandler(request.HTTPSHandler):
    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def https_open(self, req):
        return self.do_open(
            partial(_connection, http.client.HTTPSConnection, self.deadline),
            req,
            context=self._context,
        )


class _NoRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_azure_api_base(base: str) -> bool:
    hostname = (parse.urlsplit(base).hostname or "").lower().rstrip(".")
    return hostname == "azure.com" or hostname.endswith(".azure.com")


class OpenAICompatibleLanguageModel:
    """Use OpenAI-compatible v1 or Azure deployment chat completions.

    Credentials are read at construction; a request occurs only in complete().
    Redirects are errors. Provider bodies are not included in exception messages.
    """

    def __init__(
        self,
        *,
        api_base: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        api_version: str | None = None,
    ) -> None:
        # This is the only reader of ACS_GENERATOR_* environment variables.
        self.api_base = (
            api_base or os.getenv("ACS_GENERATOR_API_BASE") or DEFAULT_API_BASE
        ).rstrip("/")
        self.api_key = (
            api_key if api_key is not None else os.getenv("ACS_GENERATOR_API_KEY")
        )
        self.model = model or os.getenv("ACS_GENERATOR_MODEL") or DEFAULT_MODEL
        self.api_version = api_version or os.getenv("ACS_GENERATOR_API_VERSION") or None
        try:
            parsed = parse.urlsplit(self.api_base)
            valid = (
                parsed.hostname is not None
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and (
                    parsed.scheme == "https"
                    or parsed.scheme == "http"
                    and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
            port = parsed.port
            valid = valid and (port is None or 0 < port < 65536)
        except ValueError:
            valid = False
        if not valid:
            raise ProviderError(
                "API base must be HTTPS without credentials, query or fragment (HTTP is allowed only for loopback tests)"
            )
        self._scheme = parsed.scheme
        self.is_azure = self.api_version is not None or _is_azure_api_base(
            self.api_base
        )
        if self.api_version:
            # Accept either the Azure resource root or an explicit deployment
            # base. Do not guess a deployment when the caller supplied a path.
            if not parsed.path.strip("/"):
                self.api_base += "/openai/deployments/" + parse.quote(
                    self.model, safe=""
                )
            elif "/openai/deployments/" not in parsed.path:
                raise ProviderError(
                    "api-version requires an Azure resource root or /openai/deployments/NAME base"
                )
        elif self.is_azure and not parsed.path.strip("/"):
            self.api_base += "/openai/v1"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("ACS_GENERATOR_API_KEY is required")
        if not isinstance(self.api_key, str) or any(
            ord(char) < 33 or ord(char) > 126 for char in self.api_key
        ):
            raise ProviderError(
                "API key contains whitespace or a control character/non-ASCII character"
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_completion_tokens": 4096,
        }
        url = self.api_base + "/chat/completions"
        if self.api_version:
            url += "?" + parse.urlencode({"api-version": self.api_version})
        headers = {"Content-Type": "application/json"}
        if self.is_azure:
            headers["api-key"] = self.api_key
        else:
            headers["Authorization"] = "Bearer " + self.api_key
        req = request.Request(
            url, json.dumps(payload).encode("utf-8"), headers, method="POST"
        )
        deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
        handlers = [
            _NoRedirects(),
            _DeadlineHTTPHandler(deadline),
            _DeadlineHTTPSHandler(deadline),
        ]
        if self._scheme == "http":
            # HTTP is allowed only for loopback tests. Never send its bearer
            # token to a proxy selected by the host environment.
            handlers.append(request.ProxyHandler({}))
        try:
            with request.build_opener(*handlers).open(
                req, timeout=_remaining(deadline)
            ) as response:
                encoded = bytearray()
                while len(encoded) <= MAX_RESPONSE_BYTES:
                    _remaining(deadline)
                    chunk = response.read1(
                        min(65536, MAX_RESPONSE_BYTES + 1 - len(encoded))
                    )
                    _remaining(deadline)
                    if not chunk:
                        break
                    encoded.extend(chunk)
        except _DeadlineExceeded:
            raise ProviderError("LLM request exceeded the response deadline") from None
        except error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise ProviderError(
                f"LLM request failed with HTTP {status}; check endpoint, deployment, "
                "credentials and provider diagnostics (response body omitted)"
            ) from None
        except (OSError, ValueError, http.client.HTTPException):
            raise ProviderError(
                "LLM transport failed; check connectivity and endpoint configuration"
            ) from None
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ProviderError("provider response exceeds 1 MB")
        try:
            body = json.loads(encoded)
            choice = body["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise ProviderError(
                    "provider did not complete the response (truncation or filtering)"
                )
            message = choice["message"]
            if message.get("refusal"):
                raise ProviderError("provider refused the generation request")
            content = message["content"]
            if not isinstance(content, str) or not content.strip():
                raise ProviderError("provider returned no completion content")
            return content
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ProviderError(
                "provider returned an invalid chat-completion response"
            ) from None


class StubLanguageModel:
    """Recorded responses for offline examples and tests; never contacts a provider."""

    def __init__(self, responses: list[str | dict]) -> None:
        if not responses:
            raise ValueError("StubLanguageModel requires at least one response")
        self._responses = [
            json.dumps(item) if isinstance(item, dict) else item for item in responses
        ]
        self.prompts: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        return self._responses[min(len(self.prompts), len(self._responses)) - 1]
