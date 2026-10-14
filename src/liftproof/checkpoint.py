"""Progress kept in the store while long work runs (spec 3, 9.16 and 18).

Nothing irreplaceable stays on the instance. A reconciliation or a baseline that loses
its instance halfway leaves what it finished in the bucket, and a replacement instance
pointed at the same bucket resumes from there. Checkpoints are spaced out (at most one
every CHECKPOINT_SECONDS, plus a last one), so a schema of thousands of small tables
is not thousands of uploads; a loss repeats at most that much work.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from liftproof.canonical import CANONICAL_REVISION
from liftproof.errors import LiftproofError
from liftproof.findings import FindingWriter
from liftproof.reconcile.engine import ReconcileResult, TableResult
from liftproof.store import Store

log = logging.getLogger(__name__)

CHECKPOINT_SECONDS = 15.0
PROGRESS = "progress.json"
RUN_MARKER = "in-progress-run"  # the newest reconciliation that has not finished


def baseline_marker(side: str) -> str:
    """The baseline of this side that has not finished, if any."""
    return f"baselines/in-progress-{side}"


class Throttle:
    def __init__(
        self, every: float = CHECKPOINT_SECONDS, clock: Callable[[], float] = time.monotonic
    ):
        self.every = every
        self.clock = clock
        self._last: float | None = None

    def due(self) -> bool:
        now = self.clock()
        if self._last is None or now - self._last >= self.every:
            self._last = now
            return True
        return False


def keep(store: Store, key: str, path: Path) -> bool:
    """A copy kept for a replacement instance. Failing costs resumability, not the work:
    it is logged, and the next checkpoint or run copies it again."""
    try:
        store.put_file(key, path)
        return True
    except LiftproofError as exc:
        log.warning("%s not copied to the store, tried again later: %s", key, exc)
        return False


def set_marker(store: Store, local: Path, key: str, value: str) -> None:
    """Markers are small files in the store; an empty one means nothing in progress."""
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(value, encoding="utf-8")
    store.put_file(key, local)


def read_marker(store: Store, local: Path, key: str) -> str | None:
    store.get_file(key, local)
    value = local.read_text(encoding="utf-8").strip() if local.exists() else ""
    return value or None


class SegmentUploads:
    """Copies findings segments to the store as they close. A failed copy is retried at
    the next checkpoint and at the end of the run; it never stops the run."""

    def __init__(self, store: Store, run_id: str, already: Iterable[str] = ()) -> None:
        self.store = store
        self.run_id = run_id
        self.done: set[str] = set(already)

    def __call__(self, segment: Path) -> None:
        try:
            self.store.put_file(f"runs/{self.run_id}/{segment.name}", segment)
            self.done.add(segment.name)
        except LiftproofError as exc:
            log.warning("findings %s not in the store yet, retried later: %s", segment.name, exc)

    def catch_up(self, segments: Iterable[Path]) -> bool:
        """Copy what is missing; True when every segment is in the store."""
        segments = list(segments)
        for segment in segments:
            if segment.name not in self.done:
                self(segment)
        return all(s.name in self.done for s in segments)


@dataclass
class RunProgress:
    """What a reconciliation has finished, enough to carry on from there."""

    run_id: str
    started_at: str
    options: dict[str, Any]  # what the run was asked to do, applied again on resume
    baseline: str | None = None
    segments: list[str] = field(default_factory=list)  # findings of the finished tables
    tables: list[dict[str, Any]] = field(default_factory=list)
    systemic: bool = False
    sample_seed: int | None = None  # the run's sampling seed, so a resume samples alike
    prelude_done: bool = False  # the table list and table level findings are written
    complete: bool = False
    resumed_at: list[str] = field(default_factory=list)
    canonical_revision: int = CANONICAL_REVISION  # a resume must hash under the same rules

    def done(self) -> list[TableResult]:
        return [TableResult(**t) for t in self.tables]

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> RunProgress:
        d = json.loads(path.read_text(encoding="utf-8"))
        d.setdefault("canonical_revision", 0)  # saved before canonical revisions
        return cls(**d)


class RunCheckpoint:
    """Keeps a reconciliation's finished tables, and their findings, in the store."""

    def __init__(
        self,
        store: Store,
        run_dir: Path,
        progress: RunProgress,
        writer: FindingWriter,
        uploads: SegmentUploads,
    ) -> None:
        self.store = store
        self.run_dir = run_dir
        self.progress = progress
        self.writer = writer
        self.uploads = uploads
        self.throttle = Throttle()

    def table_done(self, result: ReconcileResult) -> None:
        if self.throttle.due():
            self.save(result)

    def save(self, result: ReconcileResult, *, complete: bool = False) -> None:
        # The writer only holds findings of finished tables, so the closed segments and
        # the table list agree. The progress file goes last, and only once every segment
        # it names is in the store. A checkpoint that cannot be written costs resumability,
        # not the run: the run carries on and the next checkpoint tries again.
        self.writer.flush()
        if not self.uploads.catch_up(self.writer.closed_segments):
            return
        p = self.progress
        p.segments = [s.name for s in self.writer.closed_segments]
        p.tables = [asdict(t) for t in result.tables]
        p.systemic = result.systemic
        p.prelude_done = True
        p.complete = complete
        local = self.run_dir / PROGRESS
        p.save(local)
        keep(self.store, f"runs/{p.run_id}/{PROGRESS}", local)
