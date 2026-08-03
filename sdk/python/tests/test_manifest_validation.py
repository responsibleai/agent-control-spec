# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Grammar checks are reachable without building a runtime."""

import pathlib

import pytest
from agent_control_spec import (
    ManifestInvalidError,
    supported_manifest_versions,
    validate_manifest,
    validate_manifest_file,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
VALID = (FIXTURES / "manifest.yaml").read_text(encoding="utf-8")


def test_valid_manifest_is_accepted():
    assert validate_manifest(VALID) is None


def test_unsupported_version_is_rejected_with_the_engine_message():
    source = VALID.replace('"0.4.0-alpha.1"', '"0.3.1-beta"')
    with pytest.raises(ManifestInvalidError) as excinfo:
        validate_manifest(source)
    assert "0.3.1-beta" in str(excinfo.value)


def test_unknown_path_root_is_rejected():
    # `$policy_target` was the pre-0.4 root and the grammar no longer
    # accepts it, which is exactly the class of error a migration tool
    # needs reported.
    source = VALID.replace('"$.input"', '"$policy_target.input"')
    with pytest.raises(ManifestInvalidError):
        validate_manifest(source)


def test_malformed_yaml_is_rejected():
    with pytest.raises(ManifestInvalidError):
        validate_manifest("agent_control_specification_version: [")


def test_validation_needs_no_policy_engine_on_path(monkeypatch):
    # The point of the entry point: no dispatchers, no policy bundle.
    monkeypatch.setenv("PATH", "")
    assert validate_manifest(VALID) is None


def test_a_lone_surrogate_is_not_relabelled_as_a_bad_manifest():
    # pyo3 raises UnicodeEncodeError, a ValueError subclass, before the
    # manifest is ever parsed. Calling that a grammar failure would be
    # wrong, and lone surrogates arrive routinely from
    # surrogateescape-decoded reads.
    with pytest.raises(UnicodeEncodeError):
        validate_manifest("\ud800")


def test_a_non_string_argument_is_not_relabelled_as_a_bad_manifest():
    with pytest.raises(TypeError):
        validate_manifest(42)


def test_manifest_invalid_error_remains_a_value_error():
    # Callers written against the previous shape keep working.
    assert issubclass(ManifestInvalidError, ValueError)


def test_manifest_invalid_error_survives_pickling():
    # Authoring tools validate batches in a ProcessPoolExecutor, which
    # marshals the exception back to the parent. An unimportable
    # __module__ turns the engine's message into a PicklingError.
    import pickle

    try:
        validate_manifest("x: [")
    except ManifestInvalidError as exc:
        restored = pickle.loads(pickle.dumps(exc))
        assert isinstance(restored, ManifestInvalidError)
        assert str(restored) == str(exc)
    else:
        raise AssertionError("expected the manifest to be rejected")


def test_extends_is_not_reported_as_an_invalid_manifest():
    # validate() checks references across the merged document, so judging
    # a child alone would blame it for something its parent defines. The
    # runtime loads this file fine.
    child = REPO_ROOT / "examples" / "coding_agent" / "manifest.yaml"
    source = child.read_text(encoding="utf-8")
    with pytest.raises(ValueError) as excinfo:
        validate_manifest(source)
    assert not isinstance(excinfo.value, ManifestInvalidError)
    assert "extends" in str(excinfo.value)


def test_validate_manifest_file_resolves_extends():
    child = REPO_ROOT / "examples" / "coding_agent" / "manifest.yaml"
    assert validate_manifest_file(str(child)) is None


def test_an_unreadable_path_is_not_reported_as_an_invalid_manifest():
    # The document was never read, so its content was never judged.
    for path in ["/nonexistent/typo.yaml", str(FIXTURES)]:
        with pytest.raises(ValueError) as excinfo:
            validate_manifest_file(path)
        assert not isinstance(excinfo.value, ManifestInvalidError), path


def test_supported_versions_are_reported_not_hardcoded():
    versions = supported_manifest_versions()
    assert isinstance(versions, tuple)
    assert versions
    # The fixture is written against whatever the engine currently accepts.
    assert any(v in VALID for v in versions)
