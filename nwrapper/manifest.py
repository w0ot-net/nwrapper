"""Atomic plan manifest serialization."""

from __future__ import annotations

import json
import os
from pathlib import Path

from nwrapper.models import ScanPlan


def write_plan(plan: ScanPlan, destination: Path) -> None:
    """Atomically write a scan plan as formatted JSON."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(plan.to_dict(), output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
