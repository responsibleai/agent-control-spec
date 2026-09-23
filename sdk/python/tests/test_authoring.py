# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The authoring parser uses Regorus without evaluating the supplied source."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import tomllib
from agent_control_spec import _native
from agent_control_spec.authoring import REGORUS_AST_VERSION, parse_rego_ast


def test_regorus_ast_version_and_source_are_explicit():
    source = 'package test\nimport rego.v1\nrule if { input["text"] == "café" }\n'
    policies = parse_rego_ast(source)
    assert REGORUS_AST_VERSION == resolved_regorus_version()
    assert policies[0]["version"] == 1
    assert policies[0]["source"]["contents"] == source
    assert policies[0]["ast"]["package"]["refr"]["Var"]["value"] == "test"
    assert policies[0]["ast"]["rego_v1"]


def resolved_regorus_version():
    sdk = Path(__file__).resolve().parents[1]
    lock = tomllib.loads((sdk / "Cargo.lock").read_text(encoding="utf-8"))
    versions = [
        package["version"]
        for package in lock["package"]
        if package["name"] == "regorus"
    ]
    assert len(versions) == 1, "authoring and runtime must resolve the same Regorus"
    cargo = tomllib.loads((sdk / "Cargo.toml").read_text(encoding="utf-8"))
    assert cargo["dependencies"]["regorus"]["version"] == "=" + versions[0]
    return versions[0]


def test_compiled_ast_version_matches_the_resolved_crate():
    assert _native.REGORUS_AST_VERSION == resolved_regorus_version()


def test_parsing_does_not_compile_or_evaluate_builtins():
    # An unknown function would fail compilation/evaluation. Parsing preserves
    # the call so the authoring consumer can reject it without executing it.
    source = "package test\nrule := not_a_real_builtin(input)\n"
    assert "not_a_real_builtin" in json.dumps(parse_rego_ast(source))


@pytest.mark.parametrize("source", ["", "package", "package test\nx := ["])
def test_invalid_source_raises_value_error(source):
    with pytest.raises(ValueError, match="invalid Rego"):
        parse_rego_ast(source)


def test_authoring_size_limit_is_enforced_by_native_boundary():
    with pytest.raises(ValueError, match="65536"):
        _native.parse_rego_ast(" " * 65_537)


def test_parallel_parses_do_not_share_module_state():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(parse_rego_ast, [f"package p{i}\nvalue := {i}" for i in range(8)])
        )
    assert [item[0]["ast"]["package"]["refr"]["Var"]["value"] for item in results] == [
        f"p{i}" for i in range(8)
    ]


def test_parsing_runs_with_an_empty_path():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from agent_control_spec.authoring import parse_rego_ast\n"
                "assert parse_rego_ast('package offline\\nvalue := 1')[0]['version'] == 1\n"
            ),
        ],
        env={**os.environ, "PATH": ""},
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_tiny_nested_array_is_rejected_before_regorus_backtracking():
    code = """
from agent_control_spec.authoring import parse_rego_ast
source = 'package p\\nx := ' + '[' * 24 + '1' + ']' * 24
try:
    parse_rego_ast(source)
except ValueError as exc:
    assert 'nesting exceeds' in str(exc), exc
else:
    raise AssertionError('nested arrays were not rejected')
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_work_budget_counts_literal_bytes_at_their_actual_nesting():
    source = "package p\nx := " + "[" * 10 + json.dumps("x" * 1000) + "]" * 10
    with pytest.raises(ValueError, match="complexity budget"):
        parse_rego_ast(source)


@pytest.mark.parametrize("tail", ['[\n"a"\n]' * 1100, " in\nx" * 1100])
def test_reference_and_keyword_chains_have_a_structural_budget(tail):
    with pytest.raises(ValueError, match="structural tokens"):
        parse_rego_ast("package p\nx := input" + tail)


@pytest.mark.parametrize(
    "source",
    [
        "package p\nvalue := " + json.dumps('"' + "[" * 50 + '#"'),
        "package p\nvalue := `" + "\\[" * 50 + "`",
        "# " + "[" * 50 + "\npackage p\nvalue := 1",
    ],
)
def test_delimiters_in_literals_and_comments_do_not_change_depth(source):
    assert parse_rego_ast(source)[0]["version"] == 1
