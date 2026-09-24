# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The `acs-policy-gen` command."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from .engine import GenerationEngine, GenerationError
from .llm import DEFAULT_API_BASE, DEFAULT_MODEL, OpenAICompatibleLanguageModel
from .manifest_builder import validate_inventory
from .output import check_output
from .text import terminal_text
from .vocabulary import MAX_REPAIR_ATTEMPTS


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if any(arg == "--api-key" or arg.startswith("--api-key=") for arg in arguments):
        parser.error(
            "--api-key was removed; use --api-key-file or ACS_GENERATOR_API_KEY"
        )
    args = parser.parse_args(arguments)
    try:
        out_dir = Path(args.out)
        if not args.dry_run:
            check_output(out_dir, force=args.force)
        model = OpenAICompatibleLanguageModel(
            api_base=args.api_base,
            api_key=_api_key(args),
            model=args.model,
            api_version=args.api_version,
        )
        result = GenerationEngine(model, max_attempts=args.max_attempts).generate(
            prompt=_prompt(args),
            out_dir=out_dir,
            tool_inventory=_tool_inventory(args),
            write=not args.dry_run,
            force=args.force,
        )
    except (OSError, ValueError, GenerationError, RuntimeError, yaml.YAMLError) as exc:
        print(terminal_text(f"acs-policy-gen failed: {exc}"), file=sys.stderr)
        return 1
    if args.dry_run:
        print(
            terminal_text(
                f"--- manifest.yaml ---\n{result.manifest_yaml}", multiline=True
            )
        )
        print(
            terminal_text(
                f"--- policy/{result.slug}.rego ---\n{result.rego}", multiline=True
            )
        )
        print(terminal_text(f"--- report.md ---\n{result.report}", multiline=True))
    else:
        print(
            f"Generated ACS artifacts for '{result.slug}' in {terminal_text(str(out_dir))} "
            f"after {result.attempts} model call(s)."
        )
        print(
            "The policy is a model-generated draft. Review report.md and every rule "
            "before binding it to an agent."
        )
    if result.warnings:
        print("Warnings:", file=sys.stderr)
        for warning in result.warnings:
            print(f"  - {terminal_text(warning)}", file=sys.stderr)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acs-policy-gen",
        allow_abbrev=False,
        description=(
            "Generate an ACS manifest and Rego policy from natural-language "
            "guardrails using a language model. Artifacts are validated by the "
            "engine that will run them and are written only after they pass. The "
            "result is a draft for human review, never an approved control."
        ),
        epilog=(
            "Output layout: manifest.yaml, policy/<slug>.rego, report.md. "
            "Credentials come from --api-key-file or ACS_GENERATOR_API_KEY and are "
            "never written to the output."
        ),
    )
    prompt = parser.add_mutually_exclusive_group(required=True)
    prompt.add_argument(
        "--prompt",
        help="Natural-language description of the agent, its policy, or both",
    )
    prompt.add_argument(
        "--prompt-file",
        help="File holding the description. Use - to read it from stdin",
    )
    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME:LABEL,LABEL",
        help="Tool name and security labels as name:label1,label2. Repeatable",
    )
    parser.add_argument(
        "--tools-file",
        help="JSON or YAML object mapping tool names to tool catalog entries",
    )
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an artifact-only directory, retaining the previous directory as a sibling backup",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the artifacts instead of writing them",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=MAX_REPAIR_ATTEMPTS,
        help=(
            "Maximum model calls per generation, one per repair round "
            f"(default {MAX_REPAIR_ATTEMPTS})"
        ),
    )
    parser.add_argument(
        "--api-base",
        help=f"OpenAI-compatible API base URL (default {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--api-key-file",
        help="Read a key from a UTF-8 file, or - for stdin. Alternatively set ACS_GENERATOR_API_KEY",
    )
    parser.add_argument(
        "--model",
        help=f"Provider model or deployment name (default {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--api-version",
        help="Azure OpenAI api-version. Setting it selects Azure api-key auth",
    )
    return parser


def _prompt(args: argparse.Namespace) -> str:
    if args.prompt_file == "-":
        return sys.stdin.read()
    if args.prompt_file:
        return Path(args.prompt_file).read_text(encoding="utf-8")
    return args.prompt


def _api_key(args: argparse.Namespace) -> str | None:
    if args.api_key_file is None:
        return None
    if args.api_key_file == "-":
        if args.prompt_file == "-":
            raise ValueError(
                "stdin cannot supply both --api-key-file and --prompt-file"
            )
        key = sys.stdin.read(65537)
    else:
        with Path(args.api_key_file).open(encoding="utf-8") as handle:
            key = handle.read(65537)
    if len(key) > 65536 or not key.strip():
        raise ValueError("API key file must be non-empty and at most 65536 characters")
    return key.strip()


def _tool_inventory(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    if args.tools_file:
        raw = Path(args.tools_file).read_text(encoding="utf-8")
        loaded = (
            json.loads(raw)
            if args.tools_file.endswith(".json")
            else yaml.safe_load(raw)
        )
        if not isinstance(loaded, dict):
            raise ValueError(
                "--tools-file must contain a mapping of tool name to entry"
            )
        inventory.update(validate_inventory(loaded))
    for entry in args.tool:
        name, separator, clearances = entry.partition(":")
        if not separator or not name:
            raise ValueError(
                f"--tool must use name:clearance1,clearance2, got '{entry}'"
            )
        labels = [part.strip() for part in clearances.split(",") if part.strip()]
        inventory[name] = {
            "type": "Tool",
            "id": name,
            "security_labels": labels,
        }
    return inventory


if __name__ == "__main__":
    raise SystemExit(main())
