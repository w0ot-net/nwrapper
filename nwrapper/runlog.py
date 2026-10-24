"""Default append-only diagnostic logging for scan runs."""

from __future__ import annotations

import logging
import time
from pathlib import Path


def configure_debug_log(output_dir: Path) -> Path:
    """Write DEBUG-and-higher nwrapper events to the scan output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "nwrapper.log"

    logger = logging.getLogger("nwrapper")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()

    handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s pid=%(process)d %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)

    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.debug("debug logging initialized path=%s", log_path)
    return log_path
