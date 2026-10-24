"""Single-writer protection for a scan output directory."""

from __future__ import annotations

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO


class WorkspaceBusyError(RuntimeError):
    """Raised when another scan owns the output directory."""


@contextmanager
def scan_output_lock(output_dir: Path) -> Iterator[Path]:
    """Hold an advisory lock for one scan or resume invocation."""
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / ".nwrapper.lock"
    lock_file: TextIO
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise WorkspaceBusyError(
                f"another nwrapper scan is using output directory: {output_dir}"
            ) from exc
        try:
            yield lock_path
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
