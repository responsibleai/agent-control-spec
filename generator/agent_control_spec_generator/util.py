# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Small shared helpers."""

from __future__ import annotations

import re

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    """A Rego-package-safe and filename-safe identifier.

    The result is used as a Rego package segment, a policy id, and a file
    stem, so it must be a bare identifier. An input that reduces to nothing
    yields `generated_policy` rather than an empty package name.
    """
    slug = _NON_SLUG.sub("_", value.strip().lower()).strip("_")
    if not slug or slug[0].isdigit():
        slug = f"policy_{slug}" if slug else "generated_policy"
    return slug
