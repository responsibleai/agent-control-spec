"""Run the adoption recipes with a temporary database and a loopback HTTP server."""

import asyncio
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent_hooks import AgentContextBuilder, InterceptionBlocked
from recipes.document_service import DocumentService
from recipes.http_client import get
from recipes.profiles import disclosure_emitter, document_emitters, http_emitter


async def main(directory, origin, requests):
    read, write = document_emitters(max_operations=2)
    service = DocumentService(
        directory / "documents.sqlite", read_emitter=read, write_emitter=write
    )
    service.seed("guide", "team-a", "Contact owner@example.com", ["alice"])
    alice = {"subject": "alice", "tenant": "team-a", "roles": ["reader", "editor"]}
    try:
        text = await service.execute(alice, "read_document", {"document_id": "guide"})
        builder = AgentContextBuilder(
            agent_id="demo", framework="example", session_id="demo"
        )
        delivered = await disclosure_emitter(redact=True).emit(
            builder.output(content=text)
        )
        assert delivered.target["content"] == "Contact [REDACTED]"
        print(f"Authorized database read: {delivered.target['content']}")

        try:
            await service.execute(
                {**alice, "subject": "bob"},
                "read_document",
                {"document_id": "guide", "subject": "alice"},
            )
        except InterceptionBlocked:
            print("Another user's document access: blocked")
        else:
            raise AssertionError("Unauthorized read executed")

        try:
            await service.execute(
                alice,
                "update_document",
                {"document_id": "guide", "body": "Unapproved edit"},
            )
        except InterceptionBlocked:
            assert (
                service.db.execute("SELECT body FROM documents").fetchone()[0] == text
            )
            print("Write without reviewer approval: blocked, database unchanged")
        else:
            raise AssertionError("Unapproved write executed")

        body = await get(
            origin + "/document", emitter=http_emitter([origin]), builder=builder
        )
        assert body == b"Public reference document"
        print("Allowed HTTP fetch: received a real loopback response")
        try:
            await get(
                origin + "/redirect", emitter=http_emitter([origin]), builder=builder
            )
        except InterceptionBlocked:
            assert "/private" not in requests
            print("Unapproved redirect: blocked before the destination was contacted")
        else:
            raise AssertionError("Disallowed redirect followed")

        await service.execute(alice, "read_document", {"document_id": "guide"})
        try:
            await service.execute(alice, "read_document", {"document_id": "guide"})
        except InterceptionBlocked:
            assert service.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == 2
            print("Persisted operation quota: third operation blocked")
        else:
            raise AssertionError("Quota exceeded")
    finally:
        service.close()
    print("policy workflows: PASS")


if __name__ == "__main__":
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://localhost:{self.server.server_port}/private"
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b"Public reference document"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="acs-workflows-") as temporary:
            asyncio.run(
                main(Path(temporary), f"http://127.0.0.1:{server.server_port}", seen)
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
