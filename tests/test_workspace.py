from __future__ import annotations

from pathlib import Path

import pytest

from nwrapper.workspace import WorkspaceBusyError, scan_output_lock


def test_scan_output_lock_rejects_a_second_writer(tmp_path: Path) -> None:
    output_dir = tmp_path / "results"

    with scan_output_lock(output_dir) as lock_path:
        assert lock_path == output_dir / ".nwrapper.lock"
        with pytest.raises(WorkspaceBusyError, match="another nwrapper scan"):
            with scan_output_lock(output_dir):
                pytest.fail("a second writer acquired the same workspace")
