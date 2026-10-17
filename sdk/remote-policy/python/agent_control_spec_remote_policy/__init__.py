# Copyright (c) Microsoft. All rights reserved.
"""Optional remote policy polling with provider-neutral credential interfaces."""

from __future__ import annotations

from typing import TYPE_CHECKING

import agent_control_spec as _core

MANAGED_ACTIVATION_API_VERSION = 1

from .auth import (
    AuthenticationRequest,
    AuthorizationProvider,
    Credential,
    CredentialCloseError,
    CredentialProviderFactory,
    CredentialProviderRegistry,
    RequestAuthentication,
    RequestAuthenticator,
)
from .azure import AzureAuthorizationProvider, azure_credential_factories
from .client import RemotePolicyClient
from .evaluation import evaluate_policy_snapshot
from .http import HttpPolicySource
from .poller import (
    AgentPolicy,
    Changed,
    Clock,
    CredentialConfig,
    CredentialOption,
    NotModified,
    PolicyCloseError,
    PolicyError,
    PolicyPoller,
    PolicySnapshot,
    PolicySource,
    PolicySourceError,
    PolicyStatus,
    PolicyUnavailable,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
    StartupError,
)
from .ports import PolicyPollerFactory, PolicyPollerProtocol, PolicySourceFactory

if TYPE_CHECKING:
    from .integration import RemotePolicyFileLoader as RemotePolicyFileLoader


def __getattr__(name: str) -> object:
    """Lazy managed access; unsupported direct lookup/hasattr raises PolicyUsageError."""
    if name == "RemotePolicyFileLoader":
        from .integration import RemotePolicyFileLoader

        return RemotePolicyFileLoader
    raise AttributeError(name)


__all__ = [
    "MANAGED_ACTIVATION_API_VERSION",
    "AgentPolicy",
    "AuthenticationRequest",
    "AuthorizationProvider",
    "AzureAuthorizationProvider",
    "Changed",
    "Clock",
    "Credential",
    "CredentialCloseError",
    "CredentialConfig",
    "CredentialOption",
    "CredentialProviderFactory",
    "CredentialProviderRegistry",
    "HttpPolicySource",
    "NotModified",
    "PolicyCloseError",
    "PolicyError",
    "PolicyPoller",
    "PolicyPollerFactory",
    "PolicyPollerProtocol",
    "PolicySnapshot",
    "PolicySource",
    "PolicySourceError",
    "PolicySourceFactory",
    "PolicyStatus",
    "PolicyUnavailable",
    "PolicyUsageError",
    "PolicyValidationError",
    "PollerConfig",
    "RemotePolicyClient",
    "RequestAuthentication",
    "RequestAuthenticator",
    "StartupError",
    "azure_credential_factories",
    "evaluate_policy_snapshot",
]

if (
    getattr(_core, "MANAGED_ACTIVATION_API_VERSION", None)
    == MANAGED_ACTIVATION_API_VERSION
):
    __all__.append("RemotePolicyFileLoader")
