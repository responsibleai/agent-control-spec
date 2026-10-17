# Copyright (c) Microsoft. All rights reserved.
"""Optional explicit Azure Entra authentication; no service audience assumption."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

from .auth import AuthorizationProvider, Credential, CredentialProviderFactory
from .poller import CredentialOption, PolicySourceError, PolicyValidationError

_LOG = logging.getLogger(__name__)


class AzureAuthorizationProvider(AuthorizationProvider):
    """Use one host-selected async credential and the policy API's approved scope."""

    def __init__(self, credential: AsyncTokenCredential, scope: str) -> None:
        scope_value: object = scope
        if (
            not isinstance(scope_value, str)
            or re.fullmatch(r"[\x21-\x7e]{1,2048}", scope_value) is None
        ):
            raise PolicyValidationError("config")
        self._credential = credential
        self._scope = scope
        self._cached_authorization: str | None = None
        self._expires_on = 0.0
        self._lock = asyncio.Lock()

    async def authorization(self) -> str:
        """Reuse one token until its 60-second refresh margin; serialize refresh.

        Failed or cancelled refresh never falls back to the stale token. The
        underlying credential's lifetime remains caller-owned.
        """
        async with self._lock:
            if (
                self._cached_authorization is not None
                and time.time() < self._expires_on - 60
            ):
                return self._cached_authorization
            self._cached_authorization = None
            self._expires_on = 0.0
            header = await self._acquire_authorization()
            self._cached_authorization = header
            return header

    async def _acquire_authorization(self) -> str:
        """Acquire a fresh token with more than 60 seconds of remaining validity."""
        from azure.core.exceptions import ClientAuthenticationError
        from azure.identity import CredentialUnavailableError

        try:
            token = await self._credential.get_token(self._scope)
        except (ClientAuthenticationError, CredentialUnavailableError) as error:
            _LOG.warning(
                "azure_token_acquisition_failed",
                extra={
                    "event": "azure_token_acquisition_failed",
                    "exception_class": (
                        "CredentialUnavailableError"
                        if isinstance(error, CredentialUnavailableError)
                        else "ClientAuthenticationError"
                    ),
                },
            )
            raise PolicySourceError("transient", "credential") from None
        token_value: object = token.token
        expires_on: object = token.expires_on
        if (
            not isinstance(token_value, str)
            or re.fullmatch(r"[\x21-\x7e]{1,16384}", token_value) is None
            or isinstance(expires_on, bool)
            or not isinstance(expires_on, int)
            or expires_on <= time.time() + 60
        ):
            raise PolicySourceError("transient", "credential")
        self._expires_on = expires_on
        return f"Bearer {token.token}"


@asynccontextmanager
async def _azure_cli(
    options: Mapping[str, CredentialOption],
) -> AsyncGenerator[Credential, None]:
    if options.keys() - {"scope", "process_timeout_seconds"}:
        raise PolicyValidationError("config")
    scope = options.get("scope")
    timeout = options.get("process_timeout_seconds", 5)
    if (
        not isinstance(scope, str)
        or re.fullmatch(r"[\x21-\x7e]{1,2048}", scope) is None
        or isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 120
    ):
        raise PolicyValidationError("config")
    try:
        from azure.identity.aio import AzureCliCredential
    except ModuleNotFoundError as error:
        if error.name is None or not (
            error.name == "azure" or error.name.startswith("azure.")
        ):
            raise
        _LOG.error(
            "Azure CLI credentials require agent-control-spec-remote-policy[azure]",
            extra={"event": "credential_dependency_missing", "stage": "entry"},
        )
        raise PolicyValidationError("config") from None
    async with AzureCliCredential(process_timeout=timeout) as credential:
        yield AzureAuthorizationProvider(credential, scope)


def azure_credential_factories() -> Mapping[str, CredentialProviderFactory]:
    """Return the static CLI allow-list without importing the optional Azure SDK."""
    return MappingProxyType({"azure_cli": _azure_cli})
