"""Scheduled runs (PRD F12, Technical Spec 14).

A small scheduler service (mvt-scheduler.service) reads the schedules in every project
file and starts each run as its own `liftproof` process when it falls due. It is
deliberately simple: customers who want richer scheduling already have a pipeline, and
F11 lets them drive Liftproof from it through SSM Run Command.

Overlap is enforced by the run lock, not by the scheduler: a scheduled run that finds
the project's previous run still going is skipped, and the skip is recorded as a run
with a finding and a CloudWatch metric, never just a log line.

The scheduler watches the clock only. It calls no AWS API on a timer.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from liftproof.errors import ConfigError

log = logging.getLogger("liftproof.scheduler")

COMMANDS = ("validate", "reconcile", "files", "replay", "smoke", "baseline")
FIELDS = (("minute", 0, 59), ("hour", 0, 23), ("day of month", 1, 31), ("month", 1, 12),
          ("day of week", 0, 7))  # fmt: skip
NAMES = {
    "month": {m: i for i, m in enumerate(
        "jan feb mar apr may jun jul aug sep oct nov dec".split(), start=1)},
    "day of week": {d: i for i, d in enumerate("sun mon tue wed thu fri sat".split())},
}  # fmt: skip
HORIZON_DAYS = 4 * 366  # every valid expression fires within four years (29 February)


class Cron:
    """A standard five field cron expression: minute hour day-of-month month day-of-week,
    with lists, ranges, steps and names. When both day fields are restricted, a day
    matches either, as in cron."""

    def __init__(self, expr: str) -> None:
        self.expr = expr
        parts = expr.split()
        if len(parts) != 5:
            raise ConfigError(f"cron {expr!r}: expected five fields (minute hour day month "
                              "weekday)")  # fmt: skip
        sets = [self._field(p, *f) for p, f in zip(parts, FIELDS, strict=True)]
        self.minutes, self.hours, self.days, self.months, dow = sets
        self.weekdays = {d % 7 for d in dow}  # 7 is Sunday too
        self.day_any = parts[2] == "*"
        self.weekday_any = parts[4] == "*"
        if self.next_after(dt.datetime(2000, 1, 1)) is None:
            raise ConfigError(f"cron {expr!r} never fires")

    @staticmethod
    def _field(text: str, name: str, lo: int, hi: int) -> set[int]:
        names = NAMES.get(name, {})

        def number(v: str) -> int:
            n = names.get(v.lower()) if not v.isdigit() else int(v)
            if n is None or not lo <= n <= hi:
                raise ConfigError(f"cron {name} {v!r} is not between {lo} and {hi}")
            return n

        out: set[int] = set()
        for item in text.split(","):
            rng, _, step = item.partition("/")
            if step and (not step.isdigit() or int(step) == 0):
                raise ConfigError(f"cron {name} step {step!r} must be a positive number")
            if rng == "*":
                a, b = lo, hi
            elif "-" in rng:
                x, _, y = rng.partition("-")
                a, b = number(x), number(y)
                if a > b:
                    raise ConfigError(f"cron {name} range {rng!r} runs backwards")
            else:
                a = number(rng)
                b = hi if step else a
            out.update(range(a, b + 1, int(step) if step else 1))
        return out

    def _day_matches(self, d: dt.date) -> bool:
        dom = d.day in self.days
        dow = (d.isoweekday() % 7) in self.weekdays
        if self.day_any or self.weekday_any:
            return dom and dow
        return dom or dow

    def next_after(self, t: dt.datetime) -> dt.datetime | None:
        """The first matching minute strictly after t, in t's own (wall clock) time."""
        start = t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
        day = start.date()
        for _ in range(HORIZON_DAYS):
            if day.month in self.months and self._day_matches(day):
                for h in sorted(self.hours):
                    for m in sorted(self.minutes):
                        candidate = dt.datetime(day.year, day.month, day.day, h, m,
                                                tzinfo=t.tzinfo)  # fmt: skip
                        if candidate >= start:
                            return candidate
            day += dt.timedelta(days=1)
            start = dt.datetime(day.year, day.month, day.day, tzinfo=t.tzinfo)
        return None


@dataclass
class Schedule:
    name: str
    cron: Cron
    command: str = "validate"
    timezone: str = "UTC"
    args: list[str] = field(default_factory=list)

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def next_after(self, t: dt.datetime) -> dt.datetime | None:
        """Matching is on wall clock time in the schedule's zone. A wall time repeated when
        the clocks go back fires once, at its first occurrence; one skipped when they go
        forward fires at the moment it would have been."""
        wall = t.astimezone(self.zone).replace(tzinfo=None)
        while (nxt := self.cron.next_after(wall)) is not None:
            utc = nxt.replace(tzinfo=self.zone).astimezone(dt.UTC)
            if utc > t:
                return utc
            wall = nxt  # the repeated hour: its first occurrence has already passed
        return None


def parse_schedules(d: object) -> list[Schedule]:
    if not d:
        return []
    if not isinstance(d, list):
        raise ConfigError("schedules must be a list of {name, cron, command}")
    out, names = [], set()
    for i, s in enumerate(d):
        where = f"schedules.{i}"
        if not isinstance(s, dict) or not s.get("name") or not s.get("cron"):
            raise ConfigError(f"{where}: every schedule needs a name and a cron expression")
        name = str(s["name"])
        if name in names:
            raise ConfigError(f"{where}: schedule name {name!r} is used twice")
        names.add(name)
        command = str(s.get("command", "validate"))
        if command not in COMMANDS:
            raise ConfigError(f"{where}.command must be one of {', '.join(COMMANDS)}")
        args = [str(a) for a in s.get("args") or []]
        if any(a in ("--project", "--workdir", "--scheduled", "--run-id") for a in args):
            raise ConfigError(f"{where}.args: the scheduler sets --project, --workdir, "
                              "--scheduled and --run-id itself")  # fmt: skip
        tz = str(s.get("timezone", "UTC"))
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigError(f"{where}.timezone {tz!r} is not a time zone name") from None
        out.append(Schedule(name, Cron(str(s["cron"])), command, tz, args))
    return out


# ------------------------------------------------------------------------- service
@dataclass
class Due:
    project: str
    path: Path
    schedule: Schedule
    at: dt.datetime  # the scheduled time, UTC


class Scheduler:
    """Fires due schedules. State (the last time each schedule fired) is kept on disk so a
    restart neither repeats a run nor fires one immediately. Runs missed while the
    service was down are not caught up one by one: the latest missed one fires once."""

    def __init__(
        self,
        projects_dir: Path,
        workdir: Path,
        *,
        launch: Callable[[Due, Path], int] | None = None,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ) -> None:
        self.projects_dir = projects_dir
        self.workdir = workdir
        self.state_file = workdir / "scheduler-state.json"
        self.now = now
        self.launch = launch or launch_run

    def _state(self) -> dict[str, str]:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def _save(self, state: dict[str, str]) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.state_file)

    def projects(self) -> list[tuple[str, Path, list[Schedule]]]:
        from liftproof.config import load_project

        out = []
        for path in sorted(self.projects_dir.glob("*.yaml")):
            try:
                p = load_project(path)
            except ConfigError as exc:
                log.error("project %s skipped: %s", path, exc)
                continue
            if p.schedules:
                out.append((p.name, path, p.schedules))
        return out

    def due(self) -> list[Due]:
        now = self.now()
        state = self._state()
        found = []
        for name, path, schedules in self.projects():
            for s in schedules:
                key = f"{name}/{s.name}"
                last = state.get(key)
                if last is None:
                    state[key] = now.isoformat()  # first sight: start counting from now
                    continue
                last_at = dt.datetime.fromisoformat(last)
                at, nxt = None, s.next_after(last_at)
                while nxt is not None and nxt <= now:
                    at, nxt = nxt, s.next_after(nxt)  # several missed: fire the latest once
                if at is not None:
                    state[key] = at.isoformat()
                    found.append(Due(name, path, s, at))
        self._save(state)
        return found

    def tick(self, wait: bool = False) -> list[Due]:
        fired = self.due()
        threads = []
        for d in fired:
            t = threading.Thread(target=self._run, args=(d,), daemon=True)
            t.start()
            threads.append(t)
        if wait:
            for t in threads:
                t.join()
        return fired

    def _run(self, d: Due) -> None:
        log.info("starting scheduled run %s/%s (%s)", d.project, d.schedule.name,
                 d.schedule.command)  # fmt: skip
        code = self.launch(d, self.workdir)
        log.info("scheduled run %s/%s finished with exit code %s", d.project,
                 d.schedule.name, code)  # fmt: skip

    def serve(self, interval: float = 30.0) -> None:
        log.info("scheduler watching %s", self.projects_dir)
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("scheduler tick failed")
            time.sleep(interval)


def run_id_for(d: Due) -> str:
    return f"s-{d.at.strftime('%Y%m%d-%H%M')}-{d.schedule.name}"


def command_line(d: Due, workdir: Path) -> list[str]:
    return [
        sys.executable, "-m", "liftproof.cli", d.schedule.command,
        "--project", str(d.path), "--workdir", str(workdir),
        "--scheduled", d.schedule.name, "--format", "json",
        *([] if d.schedule.command == "baseline" else ["--run-id", run_id_for(d)]),
        *d.schedule.args,
    ]  # fmt: skip


def launch_run(d: Due, workdir: Path) -> int:
    """Each run is its own process: a crash in one run cannot take the scheduler down."""
    return subprocess.run(command_line(d, workdir), check=False).returncode  # noqa: S603


def next_runs(schedules: Sequence[Schedule], now: dt.datetime) -> list[dict[str, str]]:
    return [
        {
            "name": s.name,
            "cron": s.cron.expr,
            "timezone": s.timezone,
            "command": " ".join([s.command, *s.args]),
            "next_run_utc": (n.strftime("%Y-%m-%dT%H:%MZ") if (n := s.next_after(now)) else ""),
        }
        for s in schedules
    ]
