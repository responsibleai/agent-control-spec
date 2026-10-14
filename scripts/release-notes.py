#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one version.

The release workflow feeds the output to `gh release create --notes-file`.
Exit 1 when the section is missing so an untracked version cannot ship
with empty notes.

Usage: release-notes.py <version>        (for example 0.4.0-beta.1)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def section(changelog: str, version: str) -> str | None:
    """Return the body under `## <version>`, or None when absent."""
    heading = re.compile(r"^## (\S+)\s*$", re.MULTILINE)
    matches = list(heading.finditer(changelog))
    for i, m in enumerate(matches):
        if m.group(1) != version:
            continue
        end = matches[i + 1].start() if i + 1 < len(matches) else len(changelog)
        return changelog[m.end() : end].strip() + "\n"
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    version = argv[1]
    body = section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    if body is None:
        print(f"::error::CHANGELOG.md has no '## {version}' section", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
