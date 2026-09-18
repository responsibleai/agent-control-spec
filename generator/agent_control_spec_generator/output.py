# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Publish complete artifact directories without deleting an earlier version."""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def check_output(path: Path, *, force: bool) -> None:
    if path.is_symlink():
        raise ValueError("output directory must not be a symlink")
    if not path.exists():
        return
    if not path.is_dir():
        raise ValueError("output path exists and is not a directory")
    entries = list(path.iterdir())
    if entries and not force:
        raise ValueError(f"output directory is not empty: {path}; use --force")
    if force and entries:
        unexpected = {entry.name for entry in entries} - {
            "manifest.yaml",
            "report.md",
            "policy",
        }
        if unexpected:
            raise ValueError(
                "refusing to replace a directory containing unrelated entries: "
                + ", ".join(sorted(unexpected))
            )
        for entry in path.rglob("*"):
            if entry.is_symlink():
                raise ValueError("output artifacts must not contain symlinks")


@contextmanager
def output_lock(path: Path, *, force: bool) -> Iterator[Path]:
    # All cooperating writers use the same sibling lock. Keep it through model
    # calls so another invocation cannot change the destination after preflight.
    path = path.absolute()
    check_output(path, force=force)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.parent / f".{path.name}.acs-generator.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError(
            f"another generation owns {lock}; do not run concurrently"
        ) from None
    try:
        os.close(fd)
        check_output(path, force=force)
        yield path
    finally:
        lock.unlink()


def write_artifacts(path: Path, files: dict[str, str]) -> Path | None:
    """Stage all files, publish by rename, and retain any replaced directory.

    Replacing an existing directory uses two renames, not an atomic exchange.
    Consumers should activate versioned directories rather than load during a
    replacement. A failed second rename restores the old directory.
    """
    stage = Path(tempfile.mkdtemp(prefix=f".{path.name}.stage-", dir=path.parent))
    backup: Path | None = None
    try:
        for name, content in files.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        if path.exists():
            backup = path.parent / f".{path.name}.backup-{uuid.uuid4().hex}"
            path.rename(backup)
        try:
            stage.rename(path)
        except OSError:
            if backup is not None:
                backup.rename(path)
            raise
        return backup
    finally:
        # Only our uniquely named staging directory is disposable. The previous
        # output is never recursively deleted, even after successful replacement.
        if stage.exists():
            shutil.rmtree(stage)
