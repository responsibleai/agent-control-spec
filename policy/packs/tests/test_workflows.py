"""Exercise real SQLite and loopback HTTP boundaries through the shipped recipes."""

import asyncio
import importlib.util
import json
import threading
from functools import cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from agent_control_spec import AcsInterceptor
from agent_hooks import (
    AgentContextBuilder,
    ApprovalOutcome,
    ApprovalResolution,
    InterceptionBlocked,
    Verdict,
)

ROOT = Path(__file__).resolve().parents[1]


@cache
def recipe(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "recipes" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def builder():
    return AgentContextBuilder(
        agent_id="consumer", framework="test", session_id="consumer"
    )


class HumanDecision:
    """A scripted test reviewer, not a production auto-approver."""

    def __init__(self, approve):
        self.approve = approve
        self.requests = []

    def resolve(self, request):
        self.requests.append(request)
        return ApprovalResolution(
            ApprovalOutcome.APPROVE if self.approve else ApprovalOutcome.REJECT,
            request.context_identity,
            Verdict.allow() if self.approve else Verdict.deny("reviewer_rejected"),
        )


@pytest.fixture
def server():
    requests = []
    routes = {}

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.command, self.path, dict(self.headers), body))
            status, headers, response = routes.get(self.path, (404, {}, b"missing"))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        do_POST = handle_request
        do_GET = handle_request

        def log_message(self, *_args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}", requests, routes
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def service(tmp_path, *, reviewer=None, max_operations=50):
    profiles = recipe("profiles")
    read, write = profiles.document_emitters(
        resolver=reviewer, max_operations=max_operations
    )
    host = recipe("document_service").DocumentService(
        tmp_path / "documents.sqlite", read_emitter=read, write_emitter=write
    )
    host.seed("shared", "tenant-a", "Contact owner@example.com", ["alice", "carol"])
    host.seed("other", "tenant-b", "Other tenant's document", ["alice"])
    return host


ALICE = {"subject": "alice", "tenant": "tenant-a", "roles": ["reader", "editor"]}


def test_document_to_sanitized_response_is_a_real_workflow(tmp_path):
    host = service(tmp_path)

    async def run():
        result = await host.execute(ALICE, "read_document", {"document_id": "shared"})
        ctx = builder().output(content=result)
        delivered = await recipe("profiles").disclosure_emitter(redact=True).emit(ctx)
        assert delivered.target == {"content": "Contact [REDACTED]"}
        assert host.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == 1

    try:
        asyncio.run(run())
    finally:
        host.close()


@pytest.mark.parametrize(
    "principal,document,extra",
    [
        (
            {**ALICE, "subject": "bob"},
            "shared",
            {"subject": "alice", "roles": ["editor"]},
        ),
        (ALICE, "other", {"tenant": "tenant-b"}),
        ({**ALICE, "roles": []}, "shared", {"roles": ["reader"]}),
    ],
)
def test_database_derived_access_denial_does_not_charge_or_return_data(
    tmp_path, principal, document, extra
):
    host = service(tmp_path)
    try:
        with pytest.raises(InterceptionBlocked):
            asyncio.run(
                host.execute(
                    principal, "read_document", {"document_id": document, **extra}
                )
            )
        assert host.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == 0
    finally:
        host.close()


@pytest.mark.parametrize("approve", [False, True])
def test_approved_write_changes_the_database_and_rejection_does_not(tmp_path, approve):
    reviewer = HumanDecision(approve)
    host = service(tmp_path, reviewer=reviewer)
    try:
        call = host.execute(
            ALICE,
            "update_document",
            {"document_id": "shared", "body": "Reviewed revision"},
        )
        if approve:
            assert asyncio.run(call) == "Reviewed revision"
        else:
            with pytest.raises(InterceptionBlocked):
                asyncio.run(call)
        body = host.db.execute(
            "SELECT body FROM documents WHERE id='shared'"
        ).fetchone()[0]
        assert body == ("Reviewed revision" if approve else "Contact owner@example.com")
        assert len(reviewer.requests) == 1
        assert reviewer.requests[0].context["target"]["body"] == "Reviewed revision"
        assert host.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == int(
            approve
        )
    finally:
        host.close()


def test_concurrent_operations_cannot_spend_the_same_quota(tmp_path):
    host = service(tmp_path, max_operations=1)

    async def run():
        return await asyncio.gather(
            host.execute(ALICE, "read_document", {"document_id": "shared"}),
            host.execute(ALICE, "read_document", {"document_id": "shared"}),
            return_exceptions=True,
        )

    try:
        results = asyncio.run(run())
        assert sum(isinstance(result, InterceptionBlocked) for result in results) == 1
        assert results.count("Contact owner@example.com") == 1
        assert host.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == 1
    finally:
        host.close()
    read, write = recipe("profiles").document_emitters(max_operations=1)
    reopened = recipe("document_service").DocumentService(
        tmp_path / "documents.sqlite", read_emitter=read, write_emitter=write
    )
    try:
        with pytest.raises(InterceptionBlocked):
            asyncio.run(
                reopened.execute(ALICE, "read_document", {"document_id": "shared"})
            )
    finally:
        reopened.close()


def test_cancellation_rolls_back_a_pending_write_and_releases_the_lock(tmp_path):
    class WaitingReviewer:
        async def resolve(self, _request):
            await asyncio.Event().wait()

    host = service(tmp_path, reviewer=WaitingReviewer())

    async def run():
        task = asyncio.create_task(
            host.execute(
                ALICE,
                "update_document",
                {"document_id": "shared", "body": "Not approved"},
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (
            await host.execute(ALICE, "read_document", {"document_id": "shared"})
            == "Contact owner@example.com"
        )

    try:
        asyncio.run(run())
        assert host.db.execute("SELECT tool_calls FROM usage").fetchone()[0] == 1
    finally:
        host.close()


def test_acl_revocation_is_read_from_the_database(tmp_path):
    host = service(tmp_path)
    try:
        asyncio.run(host.execute(ALICE, "read_document", {"document_id": "shared"}))
        with host.db:
            host.db.execute("DELETE FROM grants WHERE subject='alice'")
        with pytest.raises(InterceptionBlocked):
            asyncio.run(host.execute(ALICE, "read_document", {"document_id": "shared"}))
    finally:
        host.close()


def test_actual_http_request_and_same_origin_redirect(server):
    origin, requests, routes = server
    routes["/start"] = (302, {"Location": "/document?version=1"}, b"")
    routes["/document?version=1"] = (200, {}, b"Retrieved document")
    result = asyncio.run(
        recipe("http_client").get(
            origin + "/start",
            emitter=recipe("profiles").http_emitter([origin]),
            builder=builder(),
        )
    )
    assert result == b"Retrieved document"
    assert [request[1] for request in requests] == ["/start", "/document?version=1"]


def test_disallowed_redirect_never_reaches_the_destination(server):
    origin, requests, routes = server
    # Same listener, different origin spelling: the transport would reach it if called.
    routes["/start"] = (
        302,
        {"Location": origin.replace("127.0.0.1", "localhost") + "/private"},
        b"",
    )
    routes["/private"] = (200, {}, b"Must not be fetched")
    with pytest.raises(InterceptionBlocked):
        asyncio.run(
            recipe("http_client").get(
                origin + "/start",
                emitter=recipe("profiles").http_emitter([origin]),
                builder=builder(),
            )
        )
    assert [request[1] for request in requests] == ["/start"]


@pytest.mark.parametrize("suffix", ["/?token=synthetic-value", "/#fragment"])
def test_disclosure_or_invalid_url_is_blocked_before_a_socket_request(server, suffix):
    origin, requests, _routes = server
    with pytest.raises((InterceptionBlocked, ValueError)):
        asyncio.run(
            recipe("http_client").get(
                origin + suffix,
                emitter=recipe("profiles").http_emitter([origin]),
                builder=builder(),
            )
        )
    assert requests == []


def azure(origin):
    return recipe("azure_safety").AzureSafety(
        origin, "synthetic-service-key", allow_loopback_for_tests=True
    )


ANALYZE = "/contentsafety/text:analyze?api-version=2024-09-01"
SHIELD = "/contentsafety/text:shieldPrompt?api-version=2024-09-01"


def response(value):
    return 200, {"Content-Type": "application/json"}, json.dumps(value).encode()


@pytest.mark.parametrize(
    "severity,proceeds", [(0, True), (3, True), (4, False), (7, False)]
)
def test_content_safety_real_wire_request_and_native_policy(server, severity, proceeds):
    origin, requests, routes = server
    routes[ANALYZE] = response(
        {
            "categoriesAnalysis": [
                {
                    "category": category,
                    "severity": severity if category == "Violence" else 0,
                }
                for category in azure(origin).categories
            ]
        }
    )
    control = AcsInterceptor(
        str(ROOT / "content-safety/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    emitter = recipe("profiles").emitter(control)
    record = asyncio.run(
        emitter.emit_unchecked(builder().input(content="A user message"))
    )
    assert record.proceeds == proceeds
    method, path, headers, body = requests[0]
    assert method == "POST" and path == ANALYZE
    assert headers["Ocp-Apim-Subscription-Key"] == "synthetic-service-key"
    assert json.loads(body) == {
        "text": '{"content": "A user message", "role": "user"}',
        "categories": ["Hate", "SelfHarm", "Sexual", "Violence"],
        "outputType": "EightSeverityLevels",
    }


@pytest.mark.parametrize("point", ["input", "post_tool_call"])
@pytest.mark.parametrize("detected", [False, True])
def test_prompt_shields_wire_contract_and_enforcement(server, point, detected):
    origin, requests, routes = server
    docs = [] if point == "input" else [{"attackDetected": detected}]
    routes[SHIELD] = response(
        {
            "userPromptAnalysis": {
                "attackDetected": detected if point == "input" else False
            },
            "documentsAnalysis": docs,
        }
    )
    b = builder()
    if point == "input":
        ctx = b.input(content="Summarize the document")
    else:
        ctx = b.post_tool_call(
            call_id="c", name="fetch", args={}, value="Retrieved document text"
        )
        ctx["extensions"] = {"policy_packs": {"user_prompt": "Summarize the document"}}
    control = AcsInterceptor(
        str(ROOT / "prompt-injection/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    result = asyncio.run(recipe("profiles").emitter(control).emit_unchecked(ctx))
    assert result.proceeds == (not detected)
    payload = json.loads(requests[0][3])
    assert payload["documents"] == (
        [] if point == "input" else ["Retrieved document text"]
    )
    assert payload["userPrompt"] == (
        '{"content": "Summarize the document", "role": "user"}'
        if point == "input"
        else "Summarize the document"
    )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"userPromptAnalysis": {"attackDetected": "false"}, "documentsAnalysis": []},
        {"userPromptAnalysis": {"attackDetected": False}, "documentsAnalysis": [{}]},
    ],
)
def test_partial_or_malformed_provider_results_fail_closed(server, body):
    origin, _requests, routes = server
    routes[SHIELD] = response(body)
    control = AcsInterceptor(
        str(ROOT / "prompt-injection/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    verdict = control.intercept(builder().input(content="hello"))
    assert verdict.decision.value == "deny"
    assert verdict.reason == "runtime_error:annotation_failed"


def test_prompt_only_response_need_not_have_unrequested_document_analysis(server):
    origin, _requests, routes = server
    routes[SHIELD] = response({"userPromptAnalysis": {"attackDetected": False}})
    control = AcsInterceptor(
        str(ROOT / "prompt-injection/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    assert control.intercept(builder().input(content="hello")).decision.value == "allow"


def test_a_submitted_document_cannot_be_missing_from_provider_analysis(server):
    origin, _requests, routes = server
    routes[SHIELD] = response({"userPromptAnalysis": {"attackDetected": False}})
    control = AcsInterceptor(
        str(ROOT / "prompt-injection/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    ctx = builder().post_tool_call(
        call_id="c", name="fetch", args={}, value="Retrieved text"
    )
    ctx["extensions"] = {"policy_packs": {"user_prompt": "Summarize it"}}
    verdict = control.intercept(ctx)
    assert (
        verdict.decision.value == "deny"
        and verdict.reason == "runtime_error:annotation_failed"
    )


@pytest.mark.parametrize("status", [302, 401, 429, 500])
def test_provider_errors_do_not_become_clean_annotations(server, status):
    origin, requests, routes = server
    routes[ANALYZE] = (status, {"Location": "/unexpected"}, b"Provider failed")
    control = AcsInterceptor(
        str(ROOT / "content-safety/manifest.yaml"), annotator_dispatcher=azure(origin)
    )
    verdict = control.intercept(builder().input(content="hello"))
    assert (
        verdict.decision.value == "deny"
        and verdict.reason == "runtime_error:annotation_failed"
    )
    assert len(requests) == 1


def test_provider_refuses_oversized_and_image_inputs_without_truncation(server):
    origin, requests, _routes = server
    adapter = recipe("azure_safety").AzureSafety(
        origin, "synthetic-service-key", max_chars=10, allow_loopback_for_tests=True
    )
    control = AcsInterceptor(
        str(ROOT / "content-safety/manifest.yaml"), annotator_dispatcher=adapter
    )
    for content in [
        "x" * 11,
        [{"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}],
    ]:
        assert (
            control.intercept(builder().input(content=content)).decision.value == "deny"
        )
    assert requests == []


@pytest.mark.parametrize("point", ["input", "post_tool_call"])
def test_content_profile_never_discloses_credentials_to_external_detectors(
    server, point
):
    origin, requests, _routes = server
    emitter = recipe("profiles").content_emitter(azure(origin), point=point)
    b = builder()
    ctx = (
        b.input(content="TOKEN=synthetic-value")
        if point == "input"
        else b.post_tool_call(
            call_id="c",
            name="fetch",
            args={},
            value={"client_secret": "synthetic-value"},
        )
    )
    with pytest.raises(InterceptionBlocked):
        asyncio.run(emitter.emit(ctx))
    assert requests == []
