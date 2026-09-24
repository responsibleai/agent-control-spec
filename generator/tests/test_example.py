# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""The example in `examples/` must keep working.

A documented example that has drifted is worse than none, because a reader
copies it. This runs it as a subprocess, the way a reader would.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "payments_agent.py"


def test_the_payments_example_runs_and_enforces():
    completed = subprocess.run(
        [sys.executable, str(EXAMPLE)],
        capture_output=True,
        text=True,
        check=False,
        cwd=EXAMPLE.parent.parent,
    )

    assert completed.returncode == 0, completed.stderr
    out = completed.stdout
    # The generated policy decides, rather than merely loading.
    assert "input with a password" in out
    assert "deny  reason=credential_in_prompt" in out
    assert "approval=required" in out
    assert "transform=$target.content='Sent from [REDACTED] as requested.'" in out
    # And the reader is told the output needs review.
    assert "draft for review" in out
