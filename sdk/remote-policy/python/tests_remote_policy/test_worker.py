# Copyright (c) Microsoft. All rights reserved.
"""Portable worker limits without changing the test runner's own resources."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from types import ModuleType

import pytest
from agent_control_spec_remote_policy import _worker


class ResourceStub(ModuleType):
    RLIMIT_AS = 0
    RLIMIT_CPU = 1
    RLIM_INFINITY = -1

    def __init__(self, inherited: bool = False) -> None:
        super().__init__("resource")
        self.calls: list[tuple[int, tuple[int, int]]] = []
        self.inherited = inherited

    def getrlimit(self, kind: int) -> tuple[int, int]:
        if self.inherited:
            return (512 * 1024**2, 768 * 1024**2) if kind == self.RLIMIT_AS else (2, 3)
        return self.RLIM_INFINITY, self.RLIM_INFINITY

    def setrlimit(self, kind: int, limits: tuple[int, int]) -> None:
        self.calls.append((kind, limits))


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_worker_limits_are_finite_and_platform_appropriate(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    resources = ResourceStub()
    probes: list[list[str]] = []

    def measure(
        arguments: list[str], **options: object
    ) -> subprocess.CompletedProcess[str]:
        assert arguments == ["/bin/ps", "-o", "vsz=", "-p", str(os.getpid())]
        assert options == {
            "check": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "encoding": "ascii",
            "env": {},
            "timeout": 1,
        }
        probes.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout=str(4 * 1024**2))

    with monkeypatch.context() as scoped:
        scoped.setattr(_worker.os, "name", "nt" if platform == "win32" else "posix")
        scoped.setattr(_worker.sys, "platform", platform)
        scoped.setitem(sys.modules, "resource", resources)
        scoped.setattr(_worker.subprocess, "run", measure)
        _worker._apply_resource_limits()

    if platform == "win32":
        assert resources.calls == []
    else:
        memory_bytes = (5 if platform == "darwin" else 1) * 1024**3
        assert resources.calls == [
            (resources.RLIMIT_AS, (memory_bytes, memory_bytes)),
            (resources.RLIMIT_CPU, (5, 6)),
        ]
    assert len(probes) == (1 if platform == "darwin" else 0)


def test_worker_never_raises_inherited_resource_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resources = ResourceStub(inherited=True)
    with monkeypatch.context() as scoped:
        scoped.setattr(_worker.os, "name", "posix")
        scoped.setattr(_worker.sys, "platform", "linux")
        scoped.setitem(sys.modules, "resource", resources)
        _worker._apply_resource_limits()
    assert resources.calls == [
        (resources.RLIMIT_AS, (512 * 1024**2, 768 * 1024**2)),
        (resources.RLIMIT_CPU, (2, 3)),
    ]


@pytest.mark.parametrize("failure", ["timeout", "missing", "invalid", "zero", "limit"])
def test_resource_setup_failure_never_evaluates_or_falls_back(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    resources = ResourceStub()

    def measure(
        arguments: list[str], **options: object
    ) -> subprocess.CompletedProcess[str]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, 1)
        if failure == "missing":
            raise FileNotFoundError("private host details")
        return subprocess.CompletedProcess(
            arguments, 0, stdout="invalid" if failure == "invalid" else "0"
        )

    def reject(kind: int, limits: tuple[int, int]) -> None:
        raise ValueError("private resource details")

    with monkeypatch.context() as scoped:
        scoped.setattr(_worker.os, "name", "posix")
        scoped.setattr(
            _worker.sys, "platform", "linux" if failure == "limit" else "darwin"
        )
        scoped.setitem(sys.modules, "resource", resources)
        scoped.setattr(_worker.subprocess, "run", measure)
        if failure == "limit":
            scoped.setattr(resources, "setrlimit", reject)
        assert _worker.main() == 2
    output = capsys.readouterr().out
    assert output.strip() == '{"error":"resource_limit_failed"}'
    assert json.loads(output) == {"error": "resource_limit_failed"}
    assert resources.calls == []


def test_evaluation_failure_wire_matches_parent_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        io.TextIOWrapper(io.BytesIO(b"{}")) as request,
        monkeypatch.context() as scoped,
    ):
        scoped.setattr(_worker, "_apply_resource_limits", lambda: None)
        scoped.setattr(_worker.sys, "stdin", request)
        assert _worker.main() == 2
    assert capsys.readouterr().out.strip() == '{"error":"evaluation_failed"}'


@pytest.mark.skipif(os.name != "posix", reason="POSIX address-space enforcement")
def test_mapped_runtime_still_has_a_kernel_enforced_growth_limit() -> None:
    script = """
import mmap
import resource
import sys
from agent_control_spec_remote_policy import _worker

reserved = mmap.mmap(-1, 2 * 1024**3)
sys.platform = "darwin"
_worker._apply_resource_limits()
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
assert 3 * 1024**3 <= soft == hard
assert hard != resource.RLIM_INFINITY
try:
    extra = mmap.mmap(-1, 2 * 1024**3)
except OSError:
    pass
else:
    extra.close()
    raise AssertionError("Worker memory growth was not bounded by the kernel")
reserved.close()
print("finite-growth-bound")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "finite-growth-bound"
