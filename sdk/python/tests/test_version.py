# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``__version__`` reports what was installed.

It used to be a literal in ``__init__.py``. That made it a seventh version
surface, and the one surface covered by neither
``scripts/check-version-consistency.py`` nor RELEASING.md, so it held
``0.4.0a1`` through the 0.4.0-alpha.2 release with CI green. Worse for the
bump that follows: the literal did not contain the version being replaced,
so a search-and-replace release never touched it.

Reading the distribution removes the surface. This test fails if anyone
puts it back.
"""

import importlib.metadata
import pathlib
import re

import agent_control_spec

SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_version_matches_the_installed_distribution():
    assert agent_control_spec.__version__ == importlib.metadata.version(
        "agent-control-spec"
    )


def test_version_is_not_hardcoded_in_the_package():
    source = (SDK_ROOT / "agent_control_spec" / "__init__.py").read_text(
        encoding="utf-8"
    )
    literal = re.search(r'^__version__\s*=\s*["\']', source, re.MULTILINE)
    assert literal is None, (
        "__version__ is assigned a literal again. Derive it from the installed "
        "distribution instead: a literal here is a version surface that neither "
        "check-version-consistency.py nor RELEASING.md covers."
    )
