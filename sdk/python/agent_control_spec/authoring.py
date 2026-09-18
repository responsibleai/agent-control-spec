# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Python authoring helpers, separate from the ACS runtime/wire contract.

The AST is Regorus-specific and versioned by the native binding. It is intended
for inspection, not persistence as an ACS artifact or interchange between SDKs.
"""

from __future__ import annotations

import json
from typing import Any

from . import _native

REGORUS_AST_VERSION: str = _native.REGORUS_AST_VERSION


def parse_rego_ast(source: str) -> list[dict[str, Any]]:
    """Return Regorus's AST for one in-memory policy source.

    Parsing does not evaluate code, load files or fetch imports. Invalid syntax
    and exceeded parser limits raise ValueError. Input is capped at 64 KiB and
    serialized output at 8 MiB. Preflight limits nesting to 12 levels, structural
    tokens to 1024, and depth-weighted byte work to 262144 units. Regorus's
    own parser limits also apply. Native parsing releases the GIL.
    This is not a policy validation verdict.
    """
    try:
        return json.loads(_native.parse_rego_ast(source))
    except RecursionError:
        raise ValueError("Rego authoring AST exceeds Python's nesting limit") from None
