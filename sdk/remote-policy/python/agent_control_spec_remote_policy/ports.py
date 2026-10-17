# Copyright (c) Microsoft. All rights reserved.
"""Trusted, typed poller/source construction independent of authentication."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol, TypeAlias

from .auth import Credential
from .poller import PolicySnapshot, PolicySource, PolicyStatus, PollerConfig


class PolicyPollerProtocol(Protocol):
    """Single-use owner of validated snapshots and its supplied source.

    Implementations must preserve bounded work, immutable atomic revisions,
    monotonic leases, authorization fences and synchronous identity gates.
    Constructors do no I/O; start/aclose own all asynchronous resources.
    """

    @property
    def config(self) -> PollerConfig: ...

    async def start(self) -> None: ...

    def get_policy(self, agent_id: str) -> PolicySnapshot: ...

    def assert_current(self, agent_id: str, snapshot: PolicySnapshot) -> None: ...

    def status(self, agent_id: str) -> PolicyStatus: ...

    async def refresh(self, agent_id: str) -> PolicySnapshot: ...

    async def aclose(self) -> None: ...


PolicySourceFactory: TypeAlias = Callable[
    [PollerConfig, Mapping[str, Credential]], PolicySource
]
PolicyPollerFactory: TypeAlias = Callable[
    [PollerConfig, PolicySource], PolicyPollerProtocol
]
