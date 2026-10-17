# Copyright (c) Microsoft. All rights reserved.
"""Lazy optional managed activation; host injection never executable YAML."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import TYPE_CHECKING

import agent_control_spec
from agent_hooks import Verdict

from .auth import Credential, CredentialProviderRegistry
from .client import RemotePolicyClient, SnapshotEvaluation
from .poller import (
    MAX_EVALUATION_BYTES,
    PolicyCapacityError,
    PolicyUnavailable,
    PolicyUsageError,
    PolicyValidationError,
    PollerConfig,
    decode_json,
)
from .ports import PolicyPollerFactory, PolicySourceFactory

if TYPE_CHECKING:
    from agent_control_spec.loading import AsyncPolicyEvaluator, PolicyEvaluation

if getattr(agent_control_spec, "MANAGED_ACTIVATION_API_VERSION", None) != 1:
    raise PolicyUsageError(
        "Managed activation requires agent-control-spec with managed activation API 1; "
        "install a compatible core release. Low-level polling remains available."
    )

_LOG = logging.getLogger(__name__)


def is_remote_configuration(source: str) -> bool:
    """Recognize a strict remote root without reinterpreting local manifests.

    Only a complete, strictly valid remote configuration selects this backend.
    Malformed/mixed roots retain the original native error without activation
    fallback or remote startup. The existing parser bounds YAML and rejects
    duplicates, aliases, tags, unknown fields, and mixed roots.
    """
    try:
        PollerConfig.from_yaml(source)
    except PolicyValidationError:
        return False
    return True


class _RemoteEvaluator:
    def __init__(self, client: RemotePolicyClient) -> None:
        self._client = client
        self._agents = frozenset(agent.agent_id for agent in client.config.agents)

    async def evaluate(
        self, point: str, context: Mapping[str, object]
    ) -> PolicyEvaluation:
        try:
            captured = decode_json(
                json.dumps(dict(context), allow_nan=False).encode("utf-8"),
                max_bytes=MAX_EVALUATION_BYTES,
            )
        except (ValueError, TypeError, UnicodeError):
            raise PolicyValidationError("json") from None
        if not isinstance(captured, dict):
            raise PolicyValidationError("json")
        agent = captured.get("agent")
        identity = agent.get("id") if isinstance(agent, dict) else None
        if not isinstance(identity, str) or identity not in self._agents:
            _LOG.warning("remote_policy_identity_rejected")
            raise PolicyValidationError("scope")
        # Identity and evaluation come from the same validated frozen envelope.
        # The client performs the final snapshot/lease/authorization gate.
        try:
            return await self._client.evaluate_completion(
                identity,
                point,
                captured,
            )
        except PolicyCapacityError:
            return SnapshotEvaluation(
                Verdict.deny(reason="runtime_error:acs_async_capacity_exceeded"),
                self._client,
                identity,
                self._client.get_policy(identity),
            )
        except (PolicyUnavailable, PolicyUsageError):
            _LOG.warning("remote_policy_interception_unavailable")
            # Preserve the typed fail-closed error. The real emitter converts
            # raised interceptor errors into host_error:interceptor_failed.
            raise


class RemotePolicyFileLoader:
    """Trusted registry/source/poller injection for ActivatedPolicy.activate.

    YAML selects only a provider already allowed by the registry. Injected
    credentials remain caller-owned; the existing client owns every other
    resource, including startup failure and repeated shutdown cancellation.
    """

    def __init__(
        self,
        *,
        registry: CredentialProviderRegistry | None = None,
        credentials: Mapping[str, Credential] | None = None,
        source_factory: PolicySourceFactory | None = None,
        poller_factory: PolicyPollerFactory | None = None,
    ) -> None:
        if registry is not None and credentials is not None:
            raise PolicyValidationError("config")
        self._registry = registry
        self._credentials = (
            MappingProxyType(dict(credentials)) if credentials is not None else None
        )
        self._source_factory = source_factory
        self._poller_factory = poller_factory

    def is_remote_configuration(self, configuration_yaml: str) -> bool:
        """Strictly classify configuration without opening any resources."""
        return is_remote_configuration(configuration_yaml)

    @asynccontextmanager
    async def open(
        self, configuration_yaml: str
    ) -> AsyncGenerator[AsyncPolicyEvaluator, None]:
        """Validate YAML and own the existing remote client for one context."""
        config = PollerConfig.from_yaml(configuration_yaml)
        async with RemotePolicyClient.open(
            config,
            registry=self._registry,
            credentials=self._credentials,
            source_factory=self._source_factory,
            poller_factory=self._poller_factory,
        ) as client:
            yield _RemoteEvaluator(client)
