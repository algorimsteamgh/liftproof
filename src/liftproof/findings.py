"""The common finding shape (Technical Spec 4) and crash safe finding storage.

Every comparator emits Finding objects and the report builder understands nothing else.
Findings are spooled to numbered JSONL segments (findings-00001.jsonl, ...) because
Amazon S3 objects cannot be appended to: a run that dies halfway still leaves every
completed segment behind as evidence.
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Comparator(StrEnum):
    UI = "ui"
    API = "api"
    DATABASE = "database"
    FILE = "file"
    RUN = "run"  # about the run itself: a scheduled run skipped, for example


class Kind(StrEnum):
    DIFFERENCE = "difference"
    NOT_CHECKED = "not_checked"
    PARTIAL = "partial"  # compared, but on a named subset of columns (spec 9.13)
    FLAKE = "flake"
    ERROR = "error"
    NOTICE = "notice"  # disclosed but not a difference: ignore rules, approximate columns


class Severity:
    """Ordered, 1 lowest. The report sorts most severe first."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


def utcnow() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Finding:
    comparator: Comparator
    kind: Kind
    severity: int
    object: str
    summary: str
    column: str | None = None
    locator: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    expected: str | None = None
    actual: str | None = None
    journey: str | None = None
    story: str | None = None
    run_id: str | None = None
    finding_id: str | None = None
    observed_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["comparator"] = str(self.comparator)
        d["kind"] = str(self.kind)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        d["comparator"] = Comparator(d["comparator"])
        d["kind"] = Kind(d["kind"])
        return cls(**d)


class FindingWriter:
    """Writes findings as numbered, completed JSONL segments.

    A segment is written to a temporary name and renamed when it is closed, so a reader
    never sees a half written segment. The store uploads closed segments.
    """

    def __init__(self, directory: Path, run_id: str, segment_size: int = 1000) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.segment_size = segment_size
        self._ids = itertools.count(1)
        self._segment_no = 0
        self._buffer: list[str] = []
        self.closed_segments: list[Path] = []
        self.count = 0

    def write(self, finding: Finding) -> Finding:
        finding.run_id = self.run_id
        finding.finding_id = f"f-{next(self._ids):06d}"
        self._buffer.append(json.dumps(finding.to_dict(), sort_keys=True))
        self.count += 1
        if len(self._buffer) >= self.segment_size:
            self.flush()
        return finding

    def flush(self) -> Path | None:
        if not self._buffer:
            return None
        self._segment_no += 1
        final = self.directory / f"findings-{self._segment_no:05d}.jsonl"
        tmp = final.with_suffix(".jsonl.partial")
        tmp.write_text("\n".join(self._buffer) + "\n", encoding="utf-8")
        tmp.replace(final)
        self._buffer.clear()
        self.closed_segments.append(final)
        return final

    def close(self) -> list[Path]:
        self.flush()
        return self.closed_segments


def read_findings(directory: Path) -> Iterator[Finding]:
    for segment in sorted(directory.glob("findings-*.jsonl")):
        with segment.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield Finding.from_dict(json.loads(line))
