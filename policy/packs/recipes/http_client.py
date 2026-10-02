"""An HTTP-tool example that checks the request it actually sends."""

import http.client
import uuid
from urllib.parse import urljoin, urlsplit

from agent_hooks import AgentContextBuilder


def destination(url):
    if (
        not isinstance(url, str)
        or any(ord(c) <= 32 or ord(c) == 127 for c in url)
        or "\\" in url
    ):
        raise ValueError("URL contains whitespace, controls or a backslash")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.fragment:
        raise ValueError("Expected an HTTP(S) URL without a fragment")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = (
        parsed.port
        if parsed.port is not None
        else (443 if parsed.scheme == "https" else 80)
    )
    if port == 0:
        raise ValueError("HTTP destination port must be positive")
    return parsed, {
        "origin": f"{parsed.scheme}://{hostname}:{port}",
        "has_credentials": parsed.username is not None or parsed.password is not None,
    }


async def get(
    url, *, emitter, builder: AgentContextBuilder, max_redirects=3, max_bytes=1048576
):
    """A bounded GET-only tool. Redirects get their own policy decision."""
    for hop in range(max_redirects + 1):
        parsed, metadata = destination(url)
        ctx = builder.pre_tool_call(
            call_id=f"http-{uuid.uuid4().hex}",
            name="http_get",
            args={"url": url, "method": "GET"},
        )
        ctx["extensions"] = {
            "policy_packs": {"destination": {**metadata, "method": "GET"}}
        }
        outcome = await emitter.emit(ctx)
        # This host does not support rewrites of request identity. Never send a stale URL.
        if outcome.target != {"url": url, "method": "GET"}:
            raise ValueError(
                "HTTP request transforms require a new destination evaluation"
            )
        connection_type = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(parsed.hostname, parsed.port, timeout=5)
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location:
                    raise RuntimeError("Redirect omitted Location")
                if hop == max_redirects:
                    raise RuntimeError("Redirect limit exceeded")
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise RuntimeError(f"HTTP tool returned {response.status}")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise RuntimeError("HTTP tool response exceeded the configured limit")
            return body
        finally:
            connection.close()
    raise RuntimeError("No HTTP result")
