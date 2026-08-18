# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Evaluation releases the GIL while an annotator waits on the network.

A manifest whose annotators are `llm`, `endpoint` or `classifier` performs a
blocking HTTP request inside `intercept`. Holding the GIL across it stops every
thread in the process, not only the one being governed.

The check is deterministic rather than timing based: the classifier is served
from a thread of this same interpreter. If `intercept` holds the GIL, that
thread cannot be scheduled to answer, the annotator times out, and the point
fails closed with `runtime_error:annotation_failed`. If the GIL is released,
the thread answers and the label reaches the policy. No ratio, no threshold, no
sensitivity to a loaded runner.
"""

import json
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_control_spec import AcsInterceptor

CONTEXT = {
    "spec": "AGENT-HOOKS-0.1",
    "interception_point": "input",
    "timestamp": "2026-01-01T00:00:00Z",
    "sequence": 0,
    "agent": {"id": "a", "framework": "test"},
    "session": {"id": "s"},
    "target": {"content": "hello", "role": "user"},
    "input": {"content": "hello", "role": "user"},
}


class _Classifier(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.dumps(
            {"choices": [{"message": {"content": json.dumps({"label": "flagged"})}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        return


@pytest.fixture
def classifier_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Classifier)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def manifest(tmp_path, classifier_url):
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "p.rego").write_text(
        textwrap.dedent("""
            package gil

            import rego.v1

            verdict := {"decision": "deny", "reason": "annotator_ran"} if {
            	input.annotations.scan.label == "flagged"
            }

            else := {"decision": "allow"}
            """),
        encoding="utf-8",
    )
    path = tmp_path / "manifest.yaml"
    path.write_text(
        textwrap.dedent(f"""
            agent_control_specification_version: "0.4.0-alpha.1"
            policies:
              p:
                type: rego
                bundle: ./policy
                query: data.gil.verdict
            annotators:
              scan:
                type: llm
                provider: openai_compatible
                endpoint: {classifier_url}
                model: test
                timeout_ms: 4000
                system_prompt: classify
            intervention_points:
              input:
                policy_target: $.input.content
                annotations:
                  scan: {{from: $snap.input.content}}
                policy: {{id: p}}
            """),
        encoding="utf-8",
    )
    return str(path)


def test_annotator_reaches_a_classifier_served_by_this_interpreter(manifest):
    verdict = AcsInterceptor(manifest).intercept(CONTEXT)

    # Holding the GIL starves the server thread, so the annotator times out and
    # the reason is runtime_error:annotation_failed instead.
    assert verdict.reason == "annotator_ran", (
        f"annotation did not complete: {verdict.decision} / {verdict.reason}. "
        "The GIL is most likely held across the annotator's HTTP call."
    )
