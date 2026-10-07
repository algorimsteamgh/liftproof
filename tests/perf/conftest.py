"""The performance suite (PRD N8, N9; Technical Spec 17, 19): one named test per KPI.

Run with `pytest -m perf`. Every measurement, with the variables it depends on, is
written to perf-results.json (or LIFTPROOF_PERF_OUT) so each release keeps its numbers.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path

import pytest

from liftproof import __version__

RESULTS: dict[str, dict] = {}


@pytest.fixture
def kpi():
    """Record a KPI measurement: kpi(name, value=..., threshold=..., unit=..., **variables)."""

    def record(name: str, **fields) -> None:
        RESULTS[name] = fields

    return record


def pytest_sessionfinish(session, exitstatus):
    if not RESULTS:
        return
    out = Path(os.environ.get("LIFTPROOF_PERF_OUT", "perf-results.json"))
    out.write_text(
        json.dumps(
            {
                "product_version": __version__,
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "cpus": os.cpu_count(),
                "kpis": RESULTS,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
