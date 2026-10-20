#!/usr/bin/env python3
# Copyright (c) Microsoft. All rights reserved.

"""Fail when SDK package version surfaces disagree.

Manifest contract versions are separate. The engine's artifact tests compare
every registered contract against the schema, specification, and changelog.

Runtime packages release together. The generator shares their version metadata
but is outside tag publication. All these manifests must agree:

  Cargo.toml                   [workspace.package] version   (SemVer)
  sdk/python/Cargo.toml        [package] version             (SemVer)
  sdk/python/Cargo.toml        agent-control-spec req         (SemVer)
  sdk/python/pyproject.toml    [project] version             (PEP 440)
  sdk/remote-policy/python/pyproject.toml [project] version   (PEP 440)
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

The maturin build backend is pinned in four places that must agree:
sdk/python/pyproject.toml [build-system] requires (the sdist build),
sdk/remote-policy/python/requirements-dev.lock (the CI editable install and
the environment every CI Python test runs in),
sdk/python/requirements-dev.lock (the core-only lock) and
.github/requirements/maturin.txt (the hashed pin the release and CI wheel
builds install). A wheel built by one maturin and an sdist declaring
another once shipped in the same release.

Every pin in sdk/python/requirements-dev.in must appear in
sdk/python/requirements-dev.lock. CI installs from the lock, so a bump
to the .in that leaves the lock behind is never exercised until the lock
is regenerated (RELEASING.md).

The polling package's setuptools build backend is pinned in three places that
must agree: its pyproject.toml [build-system] requires, its
requirements-dev.lock and .github/requirements/setuptools.txt, the hashed pin
the release workflow installs before building without isolation.

The polling package requires the core release it is published with: its
``agent-control-spec`` requirement is derived from the core version, never
written down separately, so it cannot name a release without managed activation.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The files that pin the maturin build backend besides pyproject.toml.
MATURIN_PIN_FILES = (
    "sdk/python/requirements-dev.in",
    "sdk/python/requirements-dev.lock",
    "sdk/remote-policy/python/requirements-dev.lock",
    ".github/requirements/maturin.txt",
)
# The files that pin the polling package's setuptools besides its pyproject.toml.
SETUPTOOLS_PIN_FILES = (
    "sdk/remote-policy/python/requirements-dev.lock",
    ".github/requirements/setuptools.txt",
)


def normalize(version: str) -> str:
    """Map a SemVer or PEP 440 pre-release to one canonical spelling."""
    v = version.strip().lower()
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(a|b|rc)(\d+)", v)
    if m:
        word = {"a": "alpha", "b": "beta", "rc": "rc"}[m.group(2)]
        return f"{m.group(1)}-{word}.{m.group(3)}"
    return v


def sdk_requirement(core_version: str) -> str:
    """The polling package's core requirement, derived from the core's version."""
    m = re.match(r"(\d+)\.(\d+)\.\d+", core_version)
    assert m, f"unrecognized core version {core_version!r}"
    major, minor = int(m.group(1)), int(m.group(2))
    ceiling = f"0.{minor + 1}" if major == 0 else str(major + 1)
    return f"agent-control-spec>={core_version},<{ceiling}"


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

    remote = tomllib.loads(
        (ROOT / "sdk/remote-policy/python/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    versions["sdk/remote-policy/python/pyproject.toml"] = remote["version"]
    floor = sdk_requirement(versions["sdk/python/pyproject.toml"])
    assert floor in remote["dependencies"], (
        f"polling package must require {floor}: it ships with the core release "
        "that carries the managed activation API"
    )

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


def read_pins(name: str, pyproject: str, files: tuple[str, ...]) -> dict[str, str]:
    """Read one build backend's exact pin from its pyproject and every file."""
    pins: dict[str, str] = {}
    build = tomllib.loads((ROOT / pyproject).read_text(encoding="utf-8"))[
        "build-system"
    ]["requires"]
    pinned = [r for r in build if re.fullmatch(rf"{name}==[\w.]+", r)]
    assert len(pinned) == 1, f"{pyproject} [build-system] must pin {name} exactly"
    pins[pyproject] = pinned[0].split("==")[1]
    for relative in files:
        text = (ROOT / relative).read_text(encoding="utf-8")
        m = re.search(rf"^{name}==([\w.]+)", text, re.MULTILINE)
        assert m, f"no {name} pin in {relative}"
        pins[relative] = m.group(1)
    return pins


def stale_dev_lock_pins() -> list[str]:
    """Pins in requirements-dev.in that requirements-dev.lock does not carry."""
    lock = (ROOT / "sdk/python/requirements-dev.lock").read_text(encoding="utf-8")
    stale = []
    for line in (
        (ROOT / "sdk/python/requirements-dev.in")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        pin = line.split("#", 1)[0].strip()
        if not pin:
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==(\S+)", pin)
        assert m, f"requirements-dev.in must pin exactly: {pin}"
        name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
        if not re.search(
            rf"^{re.escape(name)}=={re.escape(m.group(2))}(\s|$)", lock, re.MULTILINE
        ):
            stale.append(pin)
    return stale


def main() -> int:
    try:
        versions = read_versions()
        backends = {
            "maturin": read_pins(
                "maturin", "sdk/python/pyproject.toml", MATURIN_PIN_FILES
            ),
            "setuptools": read_pins(
                "setuptools",
                "sdk/remote-policy/python/pyproject.toml",
                SETUPTOOLS_PIN_FILES,
            ),
        }
        stale = stale_dev_lock_pins()
    except FileNotFoundError as exc:
        print(
            f"::error::missing version surface: {Path(exc.filename).relative_to(ROOT).as_posix()}"
        )
        return 1
    if stale:
        print("::error::requirements-dev.in pins missing from requirements-dev.lock:")
        for pin in stale:
            print(f"  {pin}")
        return 1
    for name, pins in backends.items():
        if len(set(pins.values())) != 1:
            print(f"::error::{name} pins disagree:")
            for path, version in pins.items():
                print(f"  {path}: {version}")
            return 1
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
        for name, pins in backends.items():
            print(f"{name} pins agree: {next(iter(pins.values()))}")
        return 0
    print("::error::version surfaces disagree:")
    for path, raw in versions.items():
        print(f"  {path}: {raw} (normalized {normalized[path]})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
