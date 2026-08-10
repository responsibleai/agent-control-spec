#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail when the version surfaces disagree.

One tag releases every package together, so all version manifests MUST
carry the same version at all times:

  Cargo.toml                   [workspace.package] version   (SemVer)
  sdk/python/Cargo.toml        [package] version             (SemVer)
  sdk/python/pyproject.toml    [project] version             (PEP 440)
  sdk/node/package.json        version                       (SemVer)
  sdk/node/npm/*/package.json  version                       (SemVer)
  sdk/dotnet csproj            <Version>                     (SemVer)

PEP 440 spells SemVer pre-releases differently (0.4.0-alpha.1 ->
0.4.0a1), so versions are compared after normalizing both spellings.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def normalize(version: str) -> str:
    """Map a SemVer or PEP 440 pre-release to one canonical spelling."""
    v = version.strip().lower()
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(a|b|rc)(\d+)", v)
    if m:
        word = {"a": "alpha", "b": "beta", "rc": "rc"}[m.group(2)]
        return f"{m.group(1)}-{word}.{m.group(3)}"
    return v


def read_versions() -> dict[str, str]:
    versions: dict[str, str] = {}

    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    assert m, "no workspace version in Cargo.toml"
    versions["Cargo.toml"] = m.group(1)

    pycargo = (ROOT / "sdk/python/Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pycargo, re.MULTILINE)
    assert m, "no version in sdk/python/Cargo.toml"
    versions["sdk/python/Cargo.toml"] = m.group(1)

    py = (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', py, re.MULTILINE)
    assert m, "no version in sdk/python/pyproject.toml"
    versions["sdk/python/pyproject.toml"] = m.group(1)

    pkg = json.loads((ROOT / "sdk/node/package.json").read_text(encoding="utf-8"))
    versions["sdk/node/package.json"] = pkg["version"]

    for plat in sorted((ROOT / "sdk/node/npm").iterdir()):
        p = plat / "package.json"
        versions[str(p.relative_to(ROOT))] = json.loads(p.read_text(encoding="utf-8"))[
            "version"
        ]

    for name in ("AgentControlSpec", "AgentControlSpec.ContentSafety"):
        rel = f"sdk/dotnet/src/{name}/{name}.csproj"
        csproj = (ROOT / rel).read_text(encoding="utf-8")
        m = re.search(r"<Version>([^<]+)</Version>", csproj)
        assert m, f"no <Version> in {name}.csproj"
        versions[rel] = m.group(1)
    return versions


def main() -> int:
    versions = read_versions()
    normalized = {path: normalize(v) for path, v in versions.items()}
    if len(set(normalized.values())) == 1:
        print(f"version surfaces agree: {next(iter(normalized.values()))}")
        return 0
    print("::error::version surfaces disagree:")
    for path, raw in versions.items():
        print(f"  {path}: {raw} (normalized {normalized[path]})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
