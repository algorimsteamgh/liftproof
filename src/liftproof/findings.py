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
import time
from collections.abc import Callable, Iterator
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
    never sees a half written segment. `on_segment` receives each closed segment (the
    run uploads it at once); a segment also closes once `flush_seconds` have passed
    since the last, so a long run's evidence reaches the store as it goes.

    `keep` resumes an interrupted run: those segments stay, any later ones are removed,
    and numbering carries on after them.
    """

    def __init__(
        self,
        directory: Path,
        run_id: str,
        segment_size: int = 1000,
        *,
        on_segment: Callable[[Path], None] | None = None,
        flush_seconds: float | None = None,
        keep: list[str] | None = None,
    ) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.segment_size = segment_size
        self.on_segment = on_segment
        self.flush_seconds = flush_seconds
        self._last_flush = time.monotonic()
        self._buffer: list[str] = []
        self.closed_segments: list[Path] = []
        self.count = 0
        if keep is not None:
            for segment in self.directory.glob("findings-*.jsonl"):
                if segment.name not in keep:
                    segment.unlink()
            self.closed_segments = [self.directory / name for name in sorted(keep)]
            self.count = sum(
                1
                for seg in self.closed_segments
                for line in seg.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        self._segment_no = len(self.closed_segments)
        self._ids = itertools.count(self.count + 1)

    def write(self, finding: Finding) -> Finding:
        finding.run_id = self.run_id
        finding.finding_id = f"f-{next(self._ids):06d}"
        self._buffer.append(json.dumps(finding.to_dict(), sort_keys=True))
        self.count += 1
        if len(self._buffer) >= self.segment_size or (
            self.flush_seconds is not None
            and time.monotonic() - self._last_flush >= self.flush_seconds
        ):
            self.flush()
        return finding

    def flush(self) -> Path | None:
        self._last_flush = time.monotonic()
        if not self._buffer:
            return None
        self._segment_no += 1
        final = self.directory / f"findings-{self._segment_no:05d}.jsonl"
        tmp = final.with_suffix(".jsonl.partial")
        tmp.write_text("\n".join(self._buffer) + "\n", encoding="utf-8")
        tmp.replace(final)
        self._buffer.clear()
        self.closed_segments.append(final)
        if self.on_segment is not None:
            self.on_segment(final)
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
