# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The command surface a partner actually runs.

The model is replaced with a scripted one, so these exercise argument
handling, output layout, and failure reporting without a provider.
"""

from __future__ import annotations

import io
import json

import pytest
import yaml
from agent_control_spec import ActivatedPolicy
from agent_control_spec_generator import cli
from agent_control_spec_generator.llm import (
    OpenAICompatibleLanguageModel,
    StubLanguageModel,
)
from agent_hooks import AgentContextBuilder
from conftest import PAYMENTS_PLAN, minimal_plan


@pytest.fixture
def scripted(monkeypatch):
    """Replace the provider with a scripted model and record the plan used."""

    def install(plans: list[dict]) -> StubLanguageModel:
        model = StubLanguageModel(plans)
        monkeypatch.setattr(
            cli, "OpenAICompatibleLanguageModel", lambda **kwargs: model
        )
        return model

    return install


def test_it_writes_the_documented_output_layout(scripted, tmp_path, capsys):
    scripted([PAYMENTS_PLAN])
    out = tmp_path / "payments"

    code = cli.main(["--prompt", "payments agent guardrails", "--out", str(out)])

    assert code == 0
    assert sorted(p.name for p in out.iterdir()) == [
        "manifest.yaml",
        "policy",
        "report.md",
    ]
    assert (out / "policy" / "payments_agent.rego").is_file()
    captured = capsys.readouterr()
    assert "payments_agent" in captured.out
    assert "draft" in captured.out.lower(), "the caller must be told this needs review"


def test_dry_run_prints_the_artifacts_and_writes_nothing(scripted, tmp_path, capsys):
    scripted([PAYMENTS_PLAN])
    out = tmp_path / "payments"

    code = cli.main(
        ["--prompt", "payments agent guardrails", "--out", str(out), "--dry-run"]
    )

    assert code == 0
    assert not out.exists()
    printed = capsys.readouterr().out
    assert "--- manifest.yaml ---" in printed
    assert "agent_control_specification_version" in printed
    assert "package agent_control_specification.payments_agent" in printed


def test_a_non_empty_output_directory_is_refused_without_force(
    scripted, tmp_path, capsys
):
    scripted([minimal_plan()])
    out = tmp_path / "out"
    out.mkdir()
    (out / "notes.txt").write_text("work in progress", encoding="utf-8")

    code = cli.main(["--prompt", "guard the input", "--out", str(out)])

    assert code == 1
    assert (out / "notes.txt").read_text(encoding="utf-8") == "work in progress"
    assert "not empty" in capsys.readouterr().err


def test_force_regenerates_over_an_earlier_run(scripted, tmp_path):
    scripted([minimal_plan(), minimal_plan()])
    out = tmp_path / "out"

    assert cli.main(["--prompt", "guard the input", "--out", str(out)]) == 0
    assert cli.main(["--prompt", "guard the input", "--out", str(out), "--force"]) == 0
    assert (out / "manifest.yaml").is_file()


def test_repeated_generation_into_the_same_directory_needs_force(scripted, tmp_path):
    scripted([minimal_plan(), minimal_plan()])
    out = tmp_path / "out"

    assert cli.main(["--prompt", "guard the input", "--out", str(out)]) == 0
    assert cli.main(["--prompt", "guard the input", "--out", str(out)]) == 1


def test_tool_flags_become_catalog_entries(scripted, tmp_path):
    model = scripted(
        [
            minimal_plan(
                guarded_points=["pre_tool_call"],
                tools=["wire_transfer"],
                rules=[
                    {
                        "point": "pre_tool_call",
                        "decision": "deny",
                        "reason": "blocked",
                        "conditions": ['input.tool.id == "wire_transfer"'],
                    }
                ],
            )
        ]
    )
    out = tmp_path / "out"

    code = cli.main(
        [
            "--prompt",
            "guard transfers",
            "--tool",
            "wire_transfer:banking,payments",
            "--out",
            str(out),
        ]
    )

    assert code == 0
    document = yaml.safe_load((out / "manifest.yaml").read_text(encoding="utf-8"))
    assert document["tools"]["wire_transfer"]["security_labels"] == [
        "banking",
        "payments",
    ]
    assert "clearance" not in document["tools"]["wire_transfer"]
    assert "wire_transfer" in model.prompts[0][1]


def test_a_malformed_tool_flag_is_reported(scripted, tmp_path, capsys):
    scripted([minimal_plan()])

    code = cli.main(
        ["--prompt", "x", "--tool", "wire_transfer", "--out", str(tmp_path / "out")]
    )

    assert code == 1
    assert "name:clearance1,clearance2" in capsys.readouterr().err


@pytest.mark.parametrize(
    "suffix,dump", [(".json", json.dumps), (".yaml", yaml.safe_dump)]
)
def test_a_tools_file_is_read_in_either_format(scripted, tmp_path, suffix, dump):
    """Asserts the entry actually gates a decision, not merely that it was
    serialized into the manifest."""
    tools_file = tmp_path / f"tools{suffix}"
    tools_file.write_text(
        dump({"lookup": {"type": "Tool", "clearance": "internal"}}), encoding="utf-8"
    )
    scripted(
        [
            minimal_plan(
                guarded_points=["pre_tool_call"],
                tools=["lookup"],
                rules=[
                    {
                        "point": "pre_tool_call",
                        "decision": "deny",
                        "reason": "blocked",
                        "conditions": ['input.tool.id == "lookup"'],
                    }
                ],
            )
        ]
    )
    out = tmp_path / "out"

    code = cli.main(
        ["--prompt", "x", "--tools-file", str(tools_file), "--out", str(out)]
    )

    assert code == 0
    document = yaml.safe_load((out / "manifest.yaml").read_text(encoding="utf-8"))
    assert document["tools"]["lookup"]["clearance"] == "internal"

    policy = ActivatedPolicy.activate(str(out / "manifest.yaml"))
    verdict = policy.evaluate(
        "pre_tool_call",
        AgentContextBuilder(agent_id="a", framework="t", session_id="s").pre_tool_call(
            call_id="c", name="lookup", args={}
        ),
    )
    assert (verdict.decision.value, verdict.reason) == ("deny", "blocked")


def test_a_tools_file_that_is_not_a_mapping_is_reported(scripted, tmp_path, capsys):
    scripted([minimal_plan()])
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(json.dumps(["lookup"]), encoding="utf-8")

    code = cli.main(
        ["--prompt", "x", "--tools-file", str(tools_file), "--out", str(tmp_path / "o")]
    )

    assert code == 1
    assert "must contain a mapping" in capsys.readouterr().err


def test_the_prompt_can_come_from_a_file(scripted, tmp_path):
    model = scripted([minimal_plan()])
    prompt_file = tmp_path / "guardrails.md"
    prompt_file.write_text("Never disclose the internal ledger.", encoding="utf-8")

    code = cli.main(["--prompt-file", str(prompt_file), "--out", str(tmp_path / "out")])

    assert code == 0
    assert "internal ledger" in model.prompts[0][1]


def test_the_prompt_can_come_from_stdin(scripted, tmp_path, monkeypatch):
    model = scripted([minimal_plan()])
    monkeypatch.setattr("sys.stdin", io.StringIO("Guard the support agent."))

    code = cli.main(["--prompt-file", "-", "--out", str(tmp_path / "out")])

    assert code == 0
    assert "Guard the support agent." in model.prompts[0][1]


def test_prompt_and_prompt_file_are_mutually_exclusive(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["--prompt", "a", "--prompt-file", "b", "--out", str(tmp_path)])


def test_a_generation_that_cannot_be_repaired_exits_nonzero(scripted, tmp_path, capsys):
    broken = minimal_plan()
    broken["rules"][0]["decision"] = "block"
    scripted([broken])
    out = tmp_path / "out"

    code = cli.main(["--prompt", "x", "--out", str(out), "--max-attempts", "2"])

    assert code == 1
    assert not out.exists()
    error = capsys.readouterr().err
    assert "acs-policy-gen failed" in error
    assert "unsupported decision 'block'" in error


def test_warnings_go_to_stderr_so_stdout_stays_machine_readable(
    scripted, tmp_path, capsys
):
    scripted(
        [
            minimal_plan(
                guarded_points=["pre_tool_call"],
                rules=[
                    {
                        "point": "pre_tool_call",
                        "decision": "deny",
                        "reason": "blocked",
                        "conditions": ["input.policy_target.value.amount > 1"],
                    }
                ],
            )
        ]
    )

    code = cli.main(["--prompt", "x", "--out", str(tmp_path / "out")])

    assert code == 0
    captured = capsys.readouterr()
    assert "guarded without tool projection" in captured.err
    assert "guarded without tool projection" not in captured.out


def test_a_missing_credential_is_reported_without_a_traceback(tmp_path, monkeypatch):
    monkeypatch.delenv("ACS_GENERATOR_API_KEY", raising=False)
    model = OpenAICompatibleLanguageModel(api_key=None)

    with pytest.raises(RuntimeError, match="ACS_GENERATOR_API_KEY"):
        model.complete("system", "user")


@pytest.mark.parametrize(
    "api_base,api_version,expected",
    [
        ("https://api.openai.com/v1", None, False),
        ("https://example.openai.azure.com", None, True),
        ("https://example.azure.com", None, True),
        ("https://notazure.com", None, False),
        ("https://azure.com.evil.test", None, False),
        ("https://gateway.internal", "2024-10-21", True),
    ],
)
def test_azure_mode_is_selected_by_host_or_explicit_api_version(
    api_base, api_version, expected, monkeypatch
):
    """Azure mode changes both the auth header and the query string, so the
    detection must not be fooled by a hostname that merely contains the
    string `azure.com`."""
    for name in ("ACS_GENERATOR_API_BASE", "ACS_GENERATOR_API_VERSION"):
        monkeypatch.delenv(name, raising=False)

    model = OpenAICompatibleLanguageModel(api_base=api_base, api_version=api_version)

    assert model.is_azure is expected


def test_help_documents_the_output_layout_and_the_review_requirement(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    # argparse re-wraps its description, so compare against collapsed text.
    text = " ".join(capsys.readouterr().out.split())
    assert "manifest.yaml" in text
    assert "report.md" in text
    assert "draft for human review, never an approved control" in text
    assert "ACS_GENERATOR_API_KEY" in text


def test_a_credentialed_request_does_not_follow_a_redirect(monkeypatch):
    """The request carries the provider credential in a header. Following a
    redirect would re-issue it against whatever host the response named."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen: dict[str, str | None] = {}

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["first"] = self.headers.get("Authorization")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{second.server_port}/v1")
            self.end_headers()

        def log_message(self, *args):
            pass

    class Destination(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["second"] = self.headers.get("Authorization")
            body = _json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # urllib changes a redirected POST to GET for 302. Record that method
        # too, or this test would miss a followed redirect carrying credentials.
        do_GET = do_POST

        def log_message(self, *args):
            pass

    first = HTTPServer(("127.0.0.1", 0), Redirector)
    second = HTTPServer(("127.0.0.1", 0), Destination)
    for server in (first, second):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        model = OpenAICompatibleLanguageModel(
            api_base=f"http://127.0.0.1:{first.server_port}/v1",
            api_key="SECRET-KEY",
        )
        with pytest.raises(RuntimeError):
            model.complete("system", "user")
    finally:
        first.shutdown()
        second.shutdown()
        first.server_close()
        second.server_close()

    assert seen.get("first") == "Bearer SECRET-KEY"
    assert "second" not in seen, "the credential must not reach the redirect target"


def test_a_key_with_a_control_character_is_refused_before_the_request():
    """http.client would otherwise raise with the header value in the message,
    and the CLI prints the message."""
    model = OpenAICompatibleLanguageModel(api_key="sk-good\nInjected: header")

    with pytest.raises(RuntimeError, match="control character"):
        model.complete("system", "user")
