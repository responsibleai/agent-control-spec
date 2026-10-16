# Copyright (c) Microsoft. All rights reserved.
"""Loopback-only reference v1 contract server without production authentication."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Self

from agent_control_spec_remote_policy.poller import AgentPolicy, JsonValue, decode_json

_FIXTURE = (
    Path(__file__)
    .resolve()
    .parents[2]
    .joinpath(
        "sdk", "python_remote_policy", "tests", "fixtures", "remote_policy_v1.json"
    )
)
_LOG = logging.getLogger(__name__)


def policy_document(
    selection: AgentPolicy, *, revision: int, limit: int, lease_seconds: int = 900
) -> dict[str, JsonValue]:
    """Create real policy artifacts from the shared golden contract template."""
    template = decode_json(_FIXTURE.read_bytes())
    if not isinstance(template, dict):
        raise TypeError("Reference policy fixture must be an object")
    issued = datetime.now(UTC).replace(microsecond=0)
    template.update(
        {
            "tenant_id": selection.tenant_id,
            "policy_id": selection.policy_id,
            "revision": revision,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": (issued + timedelta(seconds=lease_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
            "bundles": {
                "gate": {
                    "modules": {
                        "limits.rego": (
                            "package refund_limits\n\n"
                            'default verdict := {"decision": "deny", "reason": "over_limit"}\n'
                            'verdict := {"decision": "allow", "reason": "within_limit"} if {\n'
                            "  is_number(input.policy_target.value.amount)\n"
                            "  input.policy_target.value.amount > 0\n"
                            f"  input.policy_target.value.amount <= {limit}\n"
                            "}\n"
                        )
                    }
                }
            },
        }
    )
    return template


@dataclass(frozen=True, slots=True)
class _Published:
    revision: int
    body: bytes
    etag: str


class _PolicyHTTPServer(HTTPServer):
    def __init__(self) -> None:
        self.policies: dict[tuple[str, str], _Published] = {}
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, format: str, *args: object) -> None:
        _LOG.debug("reference_policy_request")

    def do_GET(self) -> None:
        if not isinstance(self.server, _PolicyHTTPServer):
            raise TypeError("Reference handler has the wrong server")
        match = re.fullmatch(
            r"/v1/tenants/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})"
            r"/policies/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})",
            self.path,
        )
        published: _Published | None = None
        if match is not None:
            with self.server.lock:
                published = self.server.policies.get((match[1], match[2]))
        if published is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("If-None-Match") == published.etag:
            self.send_response(304)
            self.send_header("ETag", published.etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("ETag", published.etag)
        self.send_header("Content-Length", str(len(published.body)))
        self.end_headers()
        self.wfile.write(published.body)


class PolicyServer:
    """Own one bounded reference-service thread; only configured keys are served."""

    def __init__(
        self, agents: tuple[AgentPolicy, ...], *, lease_seconds: int = 900
    ) -> None:
        self._agents: Mapping[str, AgentPolicy] = {a.agent_id: a for a in agents}
        self._lease_seconds = lease_seconds
        self._server = _PolicyHTTPServer()
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="acs-reference-policy-api",
        )
        host, port = self._server.server_address[:2]
        self.endpoint = f"http://{host}:{port}"

    def publish(self, agent_id: str, *, limit: int) -> int:
        """Host-only example mutation, not an HTTP policy-write operation."""
        selection = self._agents[agent_id]
        key = (selection.tenant_id, selection.policy_id)
        with self._server.lock:
            previous = self._server.policies.get(key)
            revision = 1 if previous is None else previous.revision + 1
            body = json.dumps(
                policy_document(
                    selection,
                    revision=revision,
                    limit=limit,
                    lease_seconds=self._lease_seconds,
                ),
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self._server.policies[key] = _Published(
                revision, body, f'"{hashlib.sha256(body).hexdigest()}"'
            )
        return revision

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._thread.is_alive():
            self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("Reference policy service did not stop")
