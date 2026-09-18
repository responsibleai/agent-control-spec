# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Runnable regressions for the PR review, using local data and loopback only."""

import builtins
import io
import json
import re
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import (
    GenerationEngine,
    GenerationError,
    StubLanguageModel,
    cli,
    llm,
)
from agent_control_spec_generator.output import output_lock
from agent_control_spec_generator.plan import (
    PlanError,
    condition_regex_patterns,
    parse_policy_plan,
)
from agent_control_spec_generator.text import code_block, inline_code
from agent_hooks import AgentContextBuilder
from conftest import minimal_plan


@pytest.mark.parametrize(
    "separator",
    [
        "\r",
        "\v",
        "\f",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
        "\x1b",
        "\x7f",
        "\t",
        "\u202e",
    ],
)
def test_hidden_code_after_non_lf_separator_is_rejected(separator):
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [
        'contains(input.policy_target.value.content, "password") # note'
        + separator
        + "time.now_ns() < 0"
    ]
    with pytest.raises(PlanError, match="forbidden character"):
        parse_policy_plan(json.dumps(plan))


def test_multiline_raw_pattern_is_rendered_and_evaluated_unchanged():
    pattern = "a\n    \n    b"
    condition = f"regex.match(`{pattern}`, input.policy_target.value.content)"
    plan = minimal_plan()
    plan["rules"][0]["conditions"] = [condition]
    parsed = parse_policy_plan(json.dumps(plan))
    assert condition_regex_patterns(parsed) == (pattern,)
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="synthetic", write=False
    )
    assert "\n" + condition + "\n" in result.rego
    policy = ActivatedPolicy.from_memory(
        result.manifest_yaml,
        {
            result.slug: {"modules": {"policy.rego": result.rego}},
        },
    )
    builder = AgentContextBuilder(agent_id="a", framework="test", session_id="s")
    assert (
        policy.evaluate("input", builder.input(content=pattern)).decision.value
        == "deny"
    )
    assert (
        policy.evaluate("input", builder.input(content="a\n    b")).decision.value
        == "allow"
    )


def test_markdown_fences_and_inline_values_cannot_add_structure():
    text = "x\n```\n## Spoof\n````\nend"
    rendered = code_block(text)
    fence = rendered.split("\n")[0].removesuffix("rego")
    assert len(fence) > max(len(match[0]) for match in re.finditer(r"`+", text))
    assert rendered == f"{fence}rego\n{text}\n{fence}"
    value = inline_code("`blocked`\n## Approved\x1b[2K")
    assert "\n" not in value
    assert "\x1b" not in value


def test_model_text_is_data_in_report_and_terminal(tmp_path, monkeypatch, capsys):
    plan = minimal_plan()
    plan["rules"][0]["reason"] = "blocked\n\n## Reviewer sign-off\nApproved."
    plan["warnings"] = ["\x1b[2K\x1b[32mAll checks passed\x1b[0m"]
    model = StubLanguageModel([plan])
    monkeypatch.setattr(cli, "OpenAICompatibleLanguageModel", lambda **kwargs: model)
    assert cli.main(["--prompt", "synthetic", "--out", str(tmp_path / "out")]) == 0
    report = (tmp_path / "out/report.md").read_text(encoding="utf-8")
    assert "\n## Reviewer sign-off" not in report
    assert report.count("\n## Checks performed") == 1
    assert "\x1b" not in report
    assert "\\u001b" in report
    captured = capsys.readouterr()
    assert "\x1b" not in captured.err + captured.out
    assert "\\u001b" in captured.err


@contextmanager
def server(respond):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.seen.append(dict(self.headers))
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                respond(self)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                # Deadline tests intentionally close while the fixture is writing.
                return

        def log_message(self, *args):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.seen = []
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.01}
    )
    thread.start()
    try:
        yield httpd, f"http://127.0.0.1:{httpd.server_port}/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def response_body(content="{}"):
    return json.dumps(
        {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
    ).encode()


def send_body(handler, body):
    handler.send_response(200)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def test_real_loopback_response_is_read_with_deadline_handler():
    with server(lambda handler: send_body(handler, response_body())) as (_, endpoint):
        assert (
            llm.OpenAICompatibleLanguageModel(
                api_base=endpoint, api_key="TEST"
            ).complete("s", "u")
            == "{}"
        )


def test_malformed_status_line_cannot_escape_as_provider_text():
    with (
        server(
            lambda handler: handler.connection.sendall(
                b"PRIVATE-SERVER-TEXT bad status\r\n\r\n"
            )
        ) as (_, endpoint),
        pytest.raises(llm.ProviderError) as exc,
    ):
        llm.OpenAICompatibleLanguageModel(api_base=endpoint, api_key="TEST").complete(
            "s", "u"
        )
    assert "PRIVATE-SERVER-TEXT" not in str(exc.value)
    assert "transport failed" in str(exc.value)


def test_loopback_http_does_not_use_environment_proxy(monkeypatch):
    with server(lambda handler: handler.send_error(502)) as (proxy, proxy_url):
        monkeypatch.setenv("http_proxy", proxy_url)
        monkeypatch.setenv("HTTP_PROXY", proxy_url)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.delenv("NO_PROXY", raising=False)
        with socket.socket() as unreachable:
            unreachable.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{unreachable.getsockname()[1]}/v1"
            with pytest.raises(llm.ProviderError):
                llm.OpenAICompatibleLanguageModel(
                    api_base=endpoint, api_key="TEST"
                ).complete("s", "u")
        assert not proxy.seen


@pytest.mark.parametrize("phase", ["body", "headers"])
def test_trickle_cannot_outlive_absolute_response_deadline(monkeypatch, phase):
    monkeypatch.setattr(llm, "REQUEST_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(llm, "REQUEST_DEADLINE_SECONDS", 0.15)

    def trickle(handler):
        if phase == "body":
            handler.send_response(200)
            handler.send_header("Content-Length", "1000")
            handler.end_headers()
        else:
            handler.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
        for _ in range(100):
            handler.connection.sendall(b"x")
            time.sleep(0.02)

    with server(trickle) as (_, endpoint):
        started = time.monotonic()
        with pytest.raises(llm.ProviderError) as error:
            llm.OpenAICompatibleLanguageModel(
                api_base=endpoint, api_key="TEST"
            ).complete("s", "u")
        assert "deadline" in str(error.value), type(error.value.__context__).__name__
        assert time.monotonic() - started < 1


def test_response_cap_is_checked_on_real_http_data():
    with (
        server(
            lambda handler: send_body(handler, b"x" * (llm.MAX_RESPONSE_BYTES + 1))
        ) as (_, endpoint),
        pytest.raises(llm.ProviderError, match="exceeds 1 MB"),
    ):
        llm.OpenAICompatibleLanguageModel(api_base=endpoint, api_key="TEST").complete(
            "s", "u"
        )


def test_transport_timeout_covers_a_stalled_response(monkeypatch):
    monkeypatch.setattr(llm, "REQUEST_TIMEOUT_SECONDS", 0.03)
    with (
        server(lambda handler: time.sleep(0.1)) as (_, endpoint),
        pytest.raises(llm.ProviderError, match="transport failed"),
    ):
        llm.OpenAICompatibleLanguageModel(api_base=endpoint, api_key="TEST").complete(
            "s", "u"
        )


def test_shortened_socket_timeout_is_a_deadline_even_before_next_clock_tick(
    monkeypatch,
):
    class TimedOut(io.BytesIO):
        def readinto(self, buffer):
            raise TimeoutError

    class Socket:
        def makefile(self, *args, **kwargs):
            return TimedOut()

        def settimeout(self, value):
            self.timeout = value

    monkeypatch.setattr(llm, "time", SimpleNamespace(monotonic=lambda: 0.999))
    sock = Socket()
    with (
        llm._DeadlineReader(sock, deadline=1.0) as reader,
        pytest.raises(llm._DeadlineExceeded),
    ):
        reader.readinto(bytearray(1))
    assert 0 < sock.timeout < llm.REQUEST_TIMEOUT_SECONDS


def test_provider_deadline_releases_the_output_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "REQUEST_DEADLINE_SECONDS", 0.05)
    output = tmp_path / "out"
    with server(lambda handler: time.sleep(0.15)) as (_, endpoint):
        model = llm.OpenAICompatibleLanguageModel(api_base=endpoint, api_key="TEST")
        with pytest.raises(llm.ProviderError, match="deadline"):
            GenerationEngine(model).generate(prompt="synthetic", out_dir=output)
    assert not output.exists()
    with output_lock(output, force=False):
        assert not output.exists()


@pytest.mark.parametrize("attempts", [0, 6, True, 2.0, "3"])
def test_attempt_budget_rejects_invalid_values(attempts):
    with pytest.raises(ValueError, match="max_attempts"):
        GenerationEngine(StubLanguageModel([minimal_plan()]), max_attempts=attempts)


def test_bad_cli_attempt_budget_makes_no_call_or_output(tmp_path, monkeypatch):
    model = StubLanguageModel([minimal_plan()])
    monkeypatch.setattr(cli, "OpenAICompatibleLanguageModel", lambda **kwargs: model)
    assert (
        cli.main(
            ["--prompt", "x", "--out", str(tmp_path / "out"), "--max-attempts", "0"]
        )
        == 1
    )
    assert not model.prompts
    assert not (tmp_path / "out").exists()


def test_key_file_replaces_raw_key_argv(tmp_path, monkeypatch, capsys):
    key_file = tmp_path / "key"
    key_file.write_text("SYNTHETIC-KEY\n", encoding="utf-8")
    seen = []
    monkeypatch.setattr(
        cli,
        "OpenAICompatibleLanguageModel",
        lambda **kwargs: seen.append(kwargs) or StubLanguageModel([minimal_plan()]),
    )
    assert (
        cli.main(
            [
                "--prompt",
                "x",
                "--out",
                str(tmp_path / "out"),
                "--api-key-file",
                str(key_file),
            ]
        )
        == 0
    )
    assert seen[0]["api_key"] == "SYNTHETIC-KEY"
    captured = capsys.readouterr()
    assert "SYNTHETIC-KEY" not in captured.out + captured.err
    with pytest.raises(SystemExit):
        cli.main(
            [
                "--prompt",
                "x",
                "--out",
                str(tmp_path / "other"),
                "--api-key",
                "SYNTHETIC-KEY",
            ]
        )
    assert "SYNTHETIC-KEY" not in capsys.readouterr().err


def test_key_and_prompt_cannot_both_read_stdin(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("SYNTHETIC-KEY"))
    assert (
        cli.main(
            [
                "--prompt-file",
                "-",
                "--api-key-file",
                "-",
                "--out",
                str(tmp_path / "out"),
            ]
        )
        == 1
    )
    assert "stdin cannot supply both" in capsys.readouterr().err


def test_empty_api_version_does_not_switch_openai_auth(monkeypatch):
    monkeypatch.setenv("ACS_GENERATOR_API_VERSION", "")
    model = llm.OpenAICompatibleLanguageModel(
        api_base="https://api.openai.com/v1", api_key="TEST"
    )
    assert model.api_version is None
    assert not model.is_azure


def test_llm_is_the_only_package_environment_reader():
    package = Path(llm.__file__).parent
    readers = {
        p.name
        for p in package.glob("*.py")
        if re.search(r"os\.(?:getenv|environ)", p.read_text(encoding="utf-8"))
    }
    assert readers == {"llm.py"}


def test_stale_public_authoring_import_is_reported_before_model_call(monkeypatch):
    original = builtins.__import__

    def stale(name, *args, **kwargs):
        if name == "agent_control_spec.authoring":
            raise AttributeError("old native build")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", stale)
    model = StubLanguageModel([minimal_plan()])
    with pytest.raises(RuntimeError, match="same checkout"):
        GenerationEngine(model).generate(prompt="synthetic", write=False)
    assert not model.prompts


def test_missing_annotation_declaration_and_empty_path_are_rejected():
    plan = minimal_plan(annotations=[{"point": "input", "annotator": "ghost"}])
    with pytest.raises(GenerationError, match="undeclared annotator"):
        GenerationEngine(StubLanguageModel([plan]), max_attempts=1).generate(
            prompt="x", write=False
        )
    plan["annotations"][0]["from"] = ""
    with pytest.raises(PlanError, match="annotation path"):
        parse_policy_plan(json.dumps(plan))


def test_repeated_iteration_warns_without_changing_the_policy():
    plan = minimal_plan(
        rules=[
            {
                "point": "pre_model_call",
                "decision": "deny",
                "reason": "blocked",
                "conditions": [
                    "some i, a in input.policy_target.value",
                    "some j, b in input.policy_target.value",
                    'a.content == "secret"',
                    'b.content == "secret"',
                ],
            }
        ]
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="x", write=False
    )
    assert any("Cartesian product" in warning for warning in result.warnings)
    assert "some j, b in input.policy_target.value" in result.rego


def test_binding_outside_target_is_preserved_and_reported():
    plan = minimal_plan(
        annotators=[{"name": "check", "type": "classifier"}],
        annotations=[
            {"point": "input", "annotator": "check", "from": "$snap.agent.id"}
        ],
    )
    result = GenerationEngine(StubLanguageModel([plan])).generate(
        prompt="x", write=False
    )
    assert (
        result.manifest["intervention_points"]["input"]["annotations"]["check"]["from"]
        == "$snap.agent.id"
    )
    assert any("reads outside $target" in warning for warning in result.warnings)
