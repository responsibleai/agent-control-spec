# Copyright (c) Microsoft. All rights reserved.
"""Metadata and archive boundaries for the native and optional distributions."""

from __future__ import annotations

import os
import re
import tarfile
import tomllib
from collections.abc import Iterable, Mapping
from email.parser import Parser
from importlib.metadata import distribution
from pathlib import Path, PurePosixPath
from typing import cast
from zipfile import ZipFile

import pytest
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = "agent_control_spec_remote_policy"
PUBLIC_FILES = frozenset(
    {"__init__.py", "auth.py", "azure.py", "http.py", "poller.py", "py.typed"}
)
REMOTE_DEPENDENCIES = frozenset(
    {"httpx", "pyyaml", "azure-identity", "azure-core", "aiohttp"}
)


def _dependency_names(requirements: Iterable[str]) -> set[str]:
    names: set[str] = set()
    for requirement in requirements:
        match = re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]*", requirement)
        assert match is not None, requirement
        names.add(re.sub(r"[-_.]+", "-", match[0]).lower())
    return names


def _table(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    return cast(Mapping[str, object], value)


def _remote_project_identity() -> tuple[str, str]:
    """Read the checkout's normalized distribution name and version."""
    config = _table(
        tomllib.loads(
            ROOT.joinpath("sdk/python_remote_policy/pyproject.toml").read_text("utf-8")
        )
    )
    project = _table(config["project"])
    name, version = project["name"], project["version"]
    assert isinstance(name, str) and isinstance(version, str)
    return re.sub(r"[-_.]+", "_", name).lower(), str(Version(version))


def _artifact(variable: str, suffix: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        if os.environ.get("ACS_REQUIRE_PACKAGE_ARTIFACTS") == "1":
            pytest.fail(
                f"{variable} must be set to a built archive path when "
                "ACS_REQUIRE_PACKAGE_ARTIFACTS=1",
                pytrace=False,
            )
        pytest.skip(f"Set {variable} to inspect the built archive")
    path = Path(value).resolve(strict=True)
    assert path.is_file() and path.name.endswith(suffix)
    return path


@pytest.mark.parametrize(
    ("variable", "suffix"),
    [
        ("ACS_CORE_WHEEL", ".whl"),
        ("ACS_REMOTE_POLICY_WHEEL", ".whl"),
        ("ACS_REMOTE_POLICY_SDIST", ".tar.gz"),
    ],
)
@pytest.mark.parametrize("value", [None, ""])
def test_missing_required_artifact_fails_clearly(
    monkeypatch: pytest.MonkeyPatch, variable: str, suffix: str, value: str | None
) -> None:
    monkeypatch.setenv("ACS_REQUIRE_PACKAGE_ARTIFACTS", "1")
    if value is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, value)
    with pytest.raises(
        pytest.fail.Exception,
        match=rf"{variable} must be set.*ACS_REQUIRE_PACKAGE_ARTIFACTS=1",
    ):
        _artifact(variable, suffix)


@pytest.mark.parametrize(
    ("variable", "suffix"),
    [
        ("ACS_CORE_WHEEL", ".whl"),
        ("ACS_REMOTE_POLICY_WHEEL", ".whl"),
        ("ACS_REMOTE_POLICY_SDIST", ".tar.gz"),
    ],
)
def test_missing_artifact_skips_when_not_required(
    monkeypatch: pytest.MonkeyPatch, variable: str, suffix: str
) -> None:
    monkeypatch.delenv("ACS_REQUIRE_PACKAGE_ARTIFACTS", raising=False)
    monkeypatch.delenv(variable, raising=False)
    with pytest.raises(pytest.skip.Exception, match=variable):
        _artifact(variable, suffix)


def _assert_core_payload(names: Iterable[str]) -> None:
    assert not any(
        PurePosixPath(name).parts[0] == PACKAGE
        or (
            PurePosixPath(name).parts[0] == "agent_control_spec"
            and any(
                part.startswith("remote_policy")
                for part in PurePosixPath(name).parts[1:]
            )
        )
        for name in names
    )


def _assert_remote_payload(names: Iterable[str]) -> None:
    payload = set(names)
    assert {f"{PACKAGE}/{name}" for name in PUBLIC_FILES} <= payload
    for name in payload:
        path = PurePosixPath(name)
        # Metadata (including the public MIT license) is owned by the backend.
        if path.parts[0].endswith(".dist-info"):
            continue
        assert len(path.parts) == 2 and path.parts[0] == PACKAGE, name
        assert path.name in PUBLIC_FILES, name


def test_native_checkout_has_no_optional_polling_feature() -> None:
    """Keep unrelated native build, dependency, and pytest metadata intact."""
    config = _table(
        tomllib.loads(ROOT.joinpath("sdk/python/pyproject.toml").read_text("utf-8"))
    )
    project = _table(config["project"])
    assert "optional-dependencies" not in project
    assert project["dependencies"] == ["agent-hooks-sdk==0.1.0b2"]
    assert not list(
        ROOT.joinpath("sdk/python/agent_control_spec").glob("remote_policy*.py")
    )


def test_installed_native_metadata_has_no_remote_or_cloud_dependency() -> None:
    core = distribution("agent-control-spec")
    assert _dependency_names(core.requires or ()) == {"agent-hooks-sdk"}
    assert not REMOTE_DEPENDENCIES & _dependency_names(core.requires or ())
    assert not core.metadata.get_all("Provides-Extra")
    assert core.files is not None
    _assert_core_payload(str(path) for path in core.files)


def test_installed_remote_metadata_is_a_separate_optional_distribution() -> None:
    remote = distribution("agent-control-spec-remote-policy")
    _, expected_version = _remote_project_identity()
    assert remote.version == expected_version
    requirements = remote.requires or []
    assert _dependency_names(
        requirement for requirement in requirements if ";" not in requirement
    ) == {"agent-control-spec", "httpx", "pyyaml"}
    optional = [
        requirement.partition(";") for requirement in requirements if ";" in requirement
    ]
    assert _dependency_names(parts[0] for parts in optional) == {
        "azure-identity",
        "aiohttp",
    }
    assert all(parts[2].replace(" ", "") == 'extra=="azure"' for parts in optional)
    assert remote.metadata.get_all("Provides-Extra") == ["azure"]
    assert remote.files is not None
    # Editable metadata does not describe wheel contents. The archive tests below
    # check actual built payloads, independently of the active import location.
    files = [str(path) for path in remote.files]
    if f"{PACKAGE}/__init__.py" in files:
        # RECORD also lists installer-generated cache files and install metadata;
        # only the wheel archive is authoritative for the exact payload.
        assert f"{PACKAGE}/py.typed" in files
        assert not any(
            PurePosixPath(path).parts[0] in {"tests", "examples", "sdk"}
            for path in files
        )


def test_native_wheel_has_no_polling_modules_or_dependencies() -> None:
    with ZipFile(_artifact("ACS_CORE_WHEEL", ".whl")) as wheel:
        names = wheel.namelist()
        _assert_core_payload(names)
        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        assert len(metadata_names) == 1
        metadata = Parser().parsestr(wheel.read(metadata_names[0]).decode("utf-8"))
        assert metadata["Name"] == "agent-control-spec"
        assert _dependency_names(metadata.get_all("Requires-Dist", [])) == {
            "agent-hooks-sdk"
        }
        assert not REMOTE_DEPENDENCIES & _dependency_names(
            metadata.get_all("Requires-Dist", [])
        )
        assert not metadata.get_all("Provides-Extra")


def test_remote_wheel_contains_only_public_typed_package_and_metadata() -> None:
    path = _artifact("ACS_REMOTE_POLICY_WHEEL", ".whl")
    assert path.name.endswith("-py3-none-any.whl")
    with ZipFile(path) as wheel:
        _assert_remote_payload(wheel.namelist())
        metadata_names = [
            name for name in wheel.namelist() if name.endswith(".dist-info/WHEEL")
        ]
        assert len(metadata_names) == 1
        metadata = Parser().parsestr(wheel.read(metadata_names[0]).decode("utf-8"))
        assert metadata["Root-Is-Purelib"] == "true"
        assert metadata.get_all("Tag") == ["py3-none-any"]
        licenses = [
            name
            for name in wheel.namelist()
            if name.endswith(".dist-info/licenses/LICENSE")
        ]
        assert len(licenses) == 1
        assert wheel.read(licenses[0]) == ROOT.joinpath("LICENSE").read_bytes()


def test_remote_sdist_contains_only_public_sources_and_build_metadata() -> None:
    """Read archive names without extracting any files or following links."""
    name, version = _remote_project_identity()
    expected_root = f"{name}-{version}"
    public = {
        "LICENSE",
        "MANIFEST.in",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "setup.cfg",
        *(f"{PACKAGE}/{name}" for name in PUBLIC_FILES),
        *(
            f"{PACKAGE}.egg-info/{name}"
            for name in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "requires.txt",
                "top_level.txt",
            )
        ),
    }
    seen: set[str] = set()
    with tarfile.open(
        _artifact("ACS_REMOTE_POLICY_SDIST", ".tar.gz"), "r:gz"
    ) as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            assert path.parts[0] == expected_root
            assert member.isfile() or member.isdir(), member.name
            if member.isfile():
                relative = str(PurePosixPath(*path.parts[1:]))
                assert relative in public, relative
                seen.add(relative)
    assert {f"{PACKAGE}/{name}" for name in PUBLIC_FILES} <= seen
    assert {"LICENSE", "README.md", "pyproject.toml"} <= seen
