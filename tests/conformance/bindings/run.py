#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Conformance for the language bindings.

The case corpus under `tests/conformance/cases` checks what the engine
decides. These checks cover the layer above it: whether a host can reach
that decision at all, from the language it actually writes in, through
the artifact it actually installs.

Three failure classes live here, each one having shipped at least once.

`language_coverage` catches a capability the engine offers and no
binding exposes. Cross-language comparison cannot: a surface absent from
every language is consistent across every language.

`cross_language_parity` catches two bindings that expose a capability
and disagree about it. Each reaches the engine through a different
mechanism and converts enums, offsets and absent values at its own
boundary, so agreement is not structural.

`published_artifacts` catches a package that ships less than the
repository holds. Nothing that imports from the checkout can, because
the checkout has the engine on its loader path and the package may not.

Run one:
    python tests/conformance/bindings/run.py language_coverage

Run all:
    python tests/conformance/bindings/run.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Ordered cheapest first, so a run fails on the fastest signal available.
CHECKS = {
    "language_coverage": (
        "every engine capability is reachable from every binding",
        HERE / "language_coverage.py",
    ),
    "cross_language_parity": (
        "every binding answers identically",
        HERE / "cross_language_parity.py",
    ),
    "published_artifacts": (
        "every built package carries the whole surface",
        HERE / "published_artifacts.py",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "checks",
        nargs="*",
        choices=sorted(CHECKS),
        help="checks to run, or none for all",
    )
    args = parser.parse_args()
    selected = args.checks or list(CHECKS)

    failed: list[str] = []
    for name in selected:
        description, path = CHECKS[name]
        print(f"\n=== {name}: {description} ===", flush=True)
        if subprocess.run([sys.executable, str(path)], check=False).returncode:
            failed.append(name)

    print()
    if failed:
        print(f"binding conformance FAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"binding conformance passed: {', '.join(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
