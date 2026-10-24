from __future__ import annotations

import logging
from pathlib import Path

from nwrapper.runlog import configure_debug_log


def test_debug_log_appends_across_configured_runs(tmp_path: Path) -> None:
    log_path = configure_debug_log(tmp_path)
    logging.getLogger("nwrapper.test").debug("first run marker")

    assert configure_debug_log(tmp_path) == log_path
    logging.getLogger("nwrapper.test").debug("second run marker")

    contents = log_path.read_text(encoding="utf-8")
    assert "DEBUG nwrapper.test" in contents
    assert "first run marker" in contents
    assert "second run marker" in contents
