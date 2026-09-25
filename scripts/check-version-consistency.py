#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail when SDK package version surfaces disagree.

Manifest contract versions are separate. The engine's artifact tests compare
every registered contract against the schema, specification, and changelog.

Runtime packages release together. The generator shares their version metadata
but is outside tag publication. All these manifests must agree:

  Cargo.toml                   [workspace.package] version   (SemVer)
  sdk/python/Cargo.toml        [package] version             (SemVer)
  sdk/python/Cargo.toml        agent-control-spec req         (SemVer)
  sdk/python/pyproject.toml    [project] version             (PEP 440)
  generator/pyproject.toml     [project] version             (PEP 440)
  sdk/node/package.json        version                       (SemVer)
  sdk/node/npm/*/package.json  version                       (SemVer)
  sdk/dotnet csproj            <Version>                     (SemVer)

The Python binding is the one crate that pins its engine dependency by
version as well as by path, so that requirement is a version surface too.
It resolves even when stale, because a caret requirement carrying a
pre-release admits later pre-releases of the same triple, which is exactly
why nothing noticed it drifting.

PEP 440 spells SemVer pre-releases differently (0.4.0-alpha.1 ->
0.4.0a1), so versions are compared after normalizing both spellings.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import tomllib

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

    m = re.search(
        r'^agent-control-spec\s*=\s*\{[^}]*?version\s*=\s*"([^"]+)"',
        pycargo,
        re.MULTILINE | re.DOTALL,
    )
    assert m, "no agent-control-spec version req in sdk/python/Cargo.toml"
    versions["sdk/python/Cargo.toml (agent-control-spec req)"] = m.group(1)

    py = (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', py, re.MULTILINE)
    assert m, "no version in sdk/python/pyproject.toml"
    versions["sdk/python/pyproject.toml"] = m.group(1)

    generator = tomllib.loads(
        (ROOT / "generator/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    versions["generator/pyproject.toml"] = generator["version"]
    # alpha.4 is the first SDK release containing the public authoring helper.
    assert "agent-control-spec>=0.4.0a4,<0.5" in generator["dependencies"], (
        "generator SDK floor must name the first authoring-enabled SDK (0.4.0a4)"
    )

    pkg = json.loads((ROOT / "sdk/node/package.json").read_text(encoding="utf-8"))
    versions["sdk/node/package.json"] = pkg["version"]

    for plat in sorted((ROOT / "sdk/node/npm").iterdir()):
        p = plat / "package.json"
        versions[str(p.relative_to(ROOT))] = json.loads(p.read_text(encoding="utf-8"))[
            "version"
        ]

    csproj = (
        ROOT / "sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj"
    ).read_text(encoding="utf-8")
    m = re.search(r"<Version>([^<]+)</Version>", csproj)
    assert m, "no <Version> in AgentControlSpec.csproj"
    versions["sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj"] = m.group(1)
    return versions


def main() -> int:
    versions = read_versions()
    regorus = {}
    for relative in ("Cargo.lock", "sdk/python/Cargo.lock"):
        lock = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
        resolved = [p["version"] for p in lock["package"] if p["name"] == "regorus"]
        assert len(resolved) == 1, (
            f"{relative} must resolve exactly one Regorus version"
        )
        regorus[relative] = resolved[0]
    if len(set(regorus.values())) != 1:
        print("::error::Regorus versions disagree across runtime and Python lockfiles:")
        for path, version in regorus.items():
            print(f"  {path}: {version}")
        return 1
    normalized = {path: normalize(v) for path, v in versions.items()}
    if len(set(normalized.values())) == 1:
        print(f"package version surfaces agree: {next(iter(normalized.values()))}")
        return 0
    print("::error::version surfaces disagree:")
    for path, raw in versions.items():
        print(f"  {path}: {raw} (normalized {normalized[path]})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
