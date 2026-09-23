"""A local document service with database-derived authorization and real writes."""

import asyncio
import copy
import sqlite3
import uuid

from agent_hooks import AgentContextBuilder


class DocumentService:
    """Single-process example. principal is supplied by authentication, not tool args."""

    def __init__(self, database, *, read_emitter, write_emitter):
        self.db = sqlite3.connect(database)
        self.read_emitter = read_emitter
        self.write_emitter = write_emitter
        self.lock = asyncio.Lock()
        self.builder = AgentContextBuilder(
            agent_id="documents", framework="example", session_id="documents"
        )
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS grants (document TEXT, subject TEXT, PRIMARY KEY(document, subject));"
            "CREATE TABLE IF NOT EXISTS usage (singleton INTEGER PRIMARY KEY CHECK(singleton=1), tool_calls INTEGER NOT NULL);"
            "INSERT OR IGNORE INTO usage VALUES (1,0);"
        )

    def close(self):
        self.db.close()

    def seed(self, document, tenant, body, subjects):
        with self.db:
            self.db.execute(
                "INSERT INTO documents VALUES (?,?,?)", (document, tenant, body)
            )
            self.db.executemany(
                "INSERT INTO grants VALUES (?,?)", [(document, s) for s in subjects]
            )

    async def execute(self, principal, tool, args):
        # Private copies prevent caller mutation while approval awaits a decision.
        principal, args = copy.deepcopy(principal), copy.deepcopy(args)
        if tool not in {"read_document", "update_document"}:
            raise ValueError("Unknown document tool")
        if not isinstance(args, dict) or not isinstance(args.get("document_id"), str):
            raise TypeError("document_id must be a string")
        if tool == "update_document" and not isinstance(args.get("body"), str):
            raise ValueError("Updated document body must be a string")
        async with self.lock:
            # This example intentionally serializes writers, including other SQLite connections.
            # A production distributed service needs its own transaction/reservation design.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                document = self.db.execute(
                    "SELECT tenant,body FROM documents WHERE id=?",
                    (args["document_id"],),
                ).fetchone()
                if document is None:
                    raise LookupError("Document does not exist")
                subjects = [
                    r[0]
                    for r in self.db.execute(
                        "SELECT subject FROM grants WHERE document=?",
                        (args["document_id"],),
                    )
                ]
                used = self.db.execute(
                    "SELECT tool_calls FROM usage WHERE singleton=1"
                ).fetchone()[0]
                operation = "read" if tool == "read_document" else "write"
                ctx = self.builder.pre_tool_call(
                    call_id=f"operation-{uuid.uuid4().hex}", name=tool, args=args
                )
                ctx["extensions"] = {
                    "policy_packs": {
                        "subject": principal["subject"],
                        "tenant": principal["tenant"],
                        "roles": principal["roles"],
                        "resource": {
                            "id": args["document_id"],
                            "tenant": document[0],
                            "operation": operation,
                            "allowed_subjects": subjects,
                        },
                        "budget": {
                            "used": {"tool_calls": used},
                            "reserved": {"tool_calls": 1},
                        },
                    }
                }
                emitter = (
                    self.read_emitter if operation == "read" else self.write_emitter
                )
                outcome = await emitter.emit(ctx)
                if outcome.target != args:
                    raise ValueError(
                        "Document argument transforms require authorization to be repeated"
                    )
                if operation == "write":
                    self.db.execute(
                        "UPDATE documents SET body=? WHERE id=?",
                        (args["body"], args["document_id"]),
                    )
                self.db.execute(
                    "UPDATE usage SET tool_calls=tool_calls+1 WHERE singleton=1"
                )
                self.db.commit()
                return document[1] if operation == "read" else args["body"]
            except BaseException:
                # Cancellation and denied approval must roll back just like other failures.
                self.db.rollback()
                raise
