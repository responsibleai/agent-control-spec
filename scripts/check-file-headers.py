#!/usr/bin/env python3
# Copyright (c) Microsoft. All rights reserved.

"""Fail when a tracked source file does not start with the copyright header.

Every source file in this repository opens with one line in the language's
comment style:

    Copyright (c) Microsoft. All rights reserved.

A shebang may come first; the header is then the second line. Ruff checks
the same line for Python under sdk/python, scripts and generator (CPY001)
and the .NET build checks it for C# under sdk/dotnet (IDE0073). Neither
reaches Rust, TypeScript, JavaScript, shell, Rego or Cedar, nor the Python
and C# outside those trees, so CI runs this script over every tracked file
of the types below.

Skipped: the napi-generated sdk/node/binding.js and binding.d.ts (the
release workflow re-stamps them), test fixtures (any `fixtures` directory)
and the conformance harness's policy bundle.

    python3 scripts/check-file-headers.py        # report misses, exit 1
    python3 scripts/check-file-headers.py --fix  # insert the missing headers
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NOTICE = "Copyright (c) Microsoft. All rights reserved."

COMMENT_PREFIX = {
    ".cedar": "//",
    ".cs": "//",
    ".js": "//",
    ".mjs": "//",
    ".py": "#",
    ".rego": "#",
    ".rs": "//",
    ".sh": "#",
    ".ts": "//",
}

SKIP_FILES = {
    "sdk/node/binding.d.ts",
    "sdk/node/binding.js",
}
SKIP_PREFIXES = ("tests/conformance/bindings/bundle/",)
SKIP_DIR_NAMES = {"fixtures"}

BOM = "﻿"


def tracked_sources() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    sources = []
    for rel in listing.split("\0"):
        if not rel:
            continue
        path = Path(rel)
        if path.suffix not in COMMENT_PREFIX:
            continue
        if rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES):
            continue
        if SKIP_DIR_NAMES.intersection(path.parts[:-1]):
            continue
        sources.append(path)
    return sources


def header_for(path: Path) -> str:
    return f"{COMMENT_PREFIX[path.suffix]} {NOTICE}"


def split_shebang(text: str) -> tuple[str, str]:
    """Return the shebang line (with its newline) and the rest of the text.

    A Rust inner attribute (`#![...]`) also opens with `#!` and is not one.
    """
    if not text.startswith("#!") or text.startswith("#!["):
        return "", text
    end = text.find("\n")
    if end == -1:
        return text + "\n", ""
    return text[: end + 1], text[end + 1 :]


def has_header(text: str, header: str) -> bool:
    _, body = split_shebang(text.removeprefix(BOM))
    return body.split("\n", 1)[0].rstrip("\r") == header


def with_header(text: str, header: str) -> str:
    bom = BOM if text.startswith(BOM) else ""
    shebang, body = split_shebang(text.removeprefix(BOM))
    if not body:
        return f"{bom}{shebang}{header}\n"
    separator = "\n" if body.startswith("\n") else "\n\n"
    return f"{bom}{shebang}{header}{separator}{body}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that every tracked source file starts with the copyright header."
    )
    parser.add_argument(
        "--fix", action="store_true", help="insert the header where it is missing"
    )
    args = parser.parse_args()

    sources = tracked_sources()
    missing = []
    for path in sources:
        text = (ROOT / path).read_bytes().decode("utf-8")
        header = header_for(path)
        if has_header(text, header):
            continue
        missing.append(path)
        if args.fix:
            (ROOT / path).write_bytes(with_header(text, header).encode("utf-8"))

    if not missing:
        print(f"all {len(sources)} source files carry the copyright header")
        return 0
    if args.fix:
        for path in missing:
            print(f"added header: {path}")
        print(f"added the copyright header to {len(missing)} of {len(sources)} files")
        return 0
    for path in missing:
        print(f"missing copyright header: {path}", file=sys.stderr)
    print(
        f"{len(missing)} of {len(sources)} source files lack the header"
        " `Copyright (c) Microsoft. All rights reserved.`;"
        " run `python3 scripts/check-file-headers.py --fix`",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
