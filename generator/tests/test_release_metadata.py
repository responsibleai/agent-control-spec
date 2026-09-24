# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Release metadata gates include the separate, unpublished generator."""

import importlib.util
import re
from pathlib import Path

import pytest


def checker():
    path = Path(__file__).resolve().parents[2] / "scripts/check-version-consistency.py"
    spec = importlib.util.spec_from_file_location("version_consistency", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copied_metadata(tmp_path):
    module = checker()
    for key in module.read_versions():
        relative = key.split(" (", 1)[0]
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((module.ROOT / relative).read_bytes())
    for relative in ("Cargo.lock", "sdk/python/Cargo.lock"):
        (tmp_path / relative).write_bytes((module.ROOT / relative).read_bytes())
    module.ROOT = tmp_path
    return module


def test_generator_is_part_of_version_consistency_check():
    module = checker()
    assert "generator/pyproject.toml" in module.read_versions()
    assert module.main() == 0


def test_generator_version_drift_is_rejected(tmp_path):
    module = copied_metadata(tmp_path)
    path = tmp_path / "generator/pyproject.toml"
    source = path.read_text(encoding="utf-8")
    version = module.read_versions()["generator/pyproject.toml"]
    path.write_text(
        source.replace(f'version = "{version}"', 'version = "9.9.9"'), encoding="utf-8"
    )
    assert module.main() == 1


def test_floor_cannot_admit_sdk_without_authoring(tmp_path):
    module = copied_metadata(tmp_path)
    path = tmp_path / "generator/pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "agent-control-spec>=0.4.0a4",
            "agent-control-spec>=0.4.0a3",
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="first authoring-enabled SDK"):
        module.read_versions()


@pytest.mark.parametrize("relative", ["Cargo.lock", "sdk/python/Cargo.lock"])
def test_regorus_cannot_drift_between_lockfiles(tmp_path, capsys, relative):
    module = copied_metadata(tmp_path)
    path = tmp_path / relative
    source, count = re.subn(
        r'(\[\[package\]\]\nname = "regorus"\nversion = ")[^"]+',
        r"\g<1>0.12.99",
        path.read_text(encoding="utf-8"),
    )
    assert count == 1
    path.write_text(source, encoding="utf-8")
    assert module.main() == 1
    diagnostic = capsys.readouterr().out
    assert "Regorus versions disagree" in diagnostic
    assert "Cargo.lock:" in diagnostic
    assert "sdk/python/Cargo.lock:" in diagnostic
