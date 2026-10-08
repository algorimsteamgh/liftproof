"""File comparison (PRD F7, Technical Spec 10).

Files are paired by relative path, then compared by size and SHA-256 content hash. Where
the bytes differ and the type is one the comparator understands (see text.py), the text
is compared as well: identical text is a low severity difference that names why the
bytes changed, different text is a real difference located to the page, line, row or
column. Both hashes are always reported.

File content is an egress path just like row values, so the report shows where a text
difference is but not what the text says unless the file set opts in (show_content).
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any

from liftproof.files import text as textmod
from liftproof.files.sources import Entry, FileSource
from liftproof.findings import Comparator, Finding, Kind, Severity

CHUNK = 1 << 20


@dataclass
class IgnoreFile:
    path: str  # pattern, as for include
    reason: str


@dataclass
class FileSetConfig:
    name: str
    source: str
    target: str
    include: list[str] = field(default_factory=list)  # default: every file
    ignore: list[IgnoreFile] = field(default_factory=list)
    ignore_text: list[str] = field(default_factory=list)  # regular expressions
    path_map: list[tuple[str, str]] = field(default_factory=list)  # source regex -> target
    case_insensitive: bool = False
    show_content: bool = False
    max_text_mb: int = 64
    workers: int = 8
    source_endpoint_url: str | None = None
    target_endpoint_url: str | None = None
    source_secret_arn: str | None = None
    target_secret_arn: str | None = None


@dataclass
class FileSetResult:
    name: str
    source: str
    target: str
    files: int = 0  # in scope on the source
    matched: int = 0
    different: int = 0  # content or size differs
    text_equal: int = 0  # bytes differ, text identical (counted in different)
    missing: int = 0  # on the source only
    extra: int = 0  # on the target only
    not_checked: int = 0
    excluded: int = 0
    source_bytes: int = 0


@dataclass
class FileResult:
    sets: list[FileSetResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FileResult:
        return cls(sets=[FileSetResult(**s) for s in d.get("sets", [])])


def _matches(path: str, patterns: list[str]) -> bool:
    """fnmatch patterns; '*' crosses folders, so '*.pdf' is every PDF at any depth."""
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


@dataclass
class _Side:
    sha256: str | None = None
    data: bytes | None = None  # kept only when the text may need comparing
    error: str | None = None


def _read(source: FileSource, path: str, keep: bool, limit: int) -> _Side:
    h = hashlib.sha256()
    kept = bytearray() if keep else None
    try:
        with source.open(path) as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
                if kept is not None:
                    kept += chunk
                    if len(kept) > limit:
                        kept = None  # too large to extract: hash only
    except Exception as exc:  # noqa: BLE001 - one unreadable file is a finding, not a crash
        return _Side(error=f"{type(exc).__name__}: {exc}")
    return _Side(h.hexdigest(), bytes(kept) if kept is not None else None)


class FileComparator:
    def __init__(
        self,
        config: FileSetConfig,
        source: FileSource,
        target: FileSource,
        emit: Callable[[Finding], None],
    ) -> None:
        self.c = config
        self.source = source
        self.target = target
        self.emit = emit
        self.masks = [re.compile(p) for p in config.ignore_text]
        self.result = FileSetResult(config.name, source.describe(), target.describe())

    def _f(self, kind: Kind, severity: int, path: str, summary: str, **kw: Any) -> None:
        self.emit(Finding(Comparator.FILE, kind, severity, f"{self.c.name}:{path}", summary, **kw))

    def _target_path(self, path: str) -> str:
        for pattern, replacement in self.c.path_map:
            path = re.sub(pattern, replacement, path)
        return path

    def _key(self, path: str) -> str:
        return path.casefold() if self.c.case_insensitive else path

    def _in_scope(self, path: str) -> bool:
        return not self.c.include or _matches(path, self.c.include)

    def _ignored(self, path: str) -> IgnoreFile | None:
        return next((r for r in self.c.ignore if _matches(path, [r.path])), None)

    def run(self) -> FileSetResult:
        res = self.result
        src: dict[str, tuple[Entry, str]] = {}  # target key -> (source entry, target path)
        for e in self.source.entries():
            if not self._in_scope(e.path):
                continue
            rule = self._ignored(e.path)
            if rule:
                res.excluded += 1
                self._f(Kind.NOTICE, Severity.INFO, e.path,
                        f"file excluded by ignore rule: {rule.reason}",
                        detail={"reason": rule.reason})  # fmt: skip
                continue
            tpath = self._target_path(e.path)
            src[self._key(tpath)] = (e, tpath)
        tgt = {
            self._key(e.path): e
            for e in self.target.entries()
            if self._in_scope(e.path) and not self._ignored(e.path)
        }
        for side, skipped in (("source", self.source), ("target", self.target)):
            for path, reason in getattr(skipped, "skipped", []):
                res.not_checked += 1
                self._f(Kind.NOT_CHECKED, Severity.MEDIUM, path, f"{side} file {reason}")
        res.files = len(src)
        res.source_bytes = sum(e.size for e, _ in src.values())

        pairs = []
        for key, (e, _tpath) in sorted(src.items(), key=lambda kv: kv[1][0].path):
            t = tgt.get(key)
            if t is None:
                res.missing += 1
                self._f(Kind.DIFFERENCE, Severity.HIGH, e.path, "file missing in target",
                        detail={"size": e.size})  # fmt: skip
            else:
                pairs.append((e, t))
        for key in sorted(set(tgt) - set(src)):
            res.extra += 1
            t = tgt[key]
            self._f(Kind.DIFFERENCE, Severity.MEDIUM, t.path, "file only in target",
                    detail={"size": t.size})  # fmt: skip

        limit = self.c.max_text_mb * (1 << 20)
        with ThreadPoolExecutor(max_workers=max(1, self.c.workers)) as pool:
            outcomes = pool.map(lambda p: self._read_pair(*p, limit), pairs)
            for (e, t), (a, b) in zip(pairs, outcomes, strict=True):
                self._compare(e, t, a, b)
        return res

    def _read_pair(self, e: Entry, t: Entry, limit: int) -> tuple[_Side, _Side]:
        keep = textmod.kind_of(e.path) is not None
        return _read(self.source, e.path, keep, limit), _read(self.target, t.path, keep, limit)

    def _compare(self, e: Entry, t: Entry, a: _Side, b: _Side) -> None:
        res = self.result
        if a.error or b.error:
            res.not_checked += 1
            which = "source" if a.error else "target"
            self._f(Kind.NOT_CHECKED, Severity.MEDIUM, e.path,
                    f"cannot read the {which} file: {a.error or b.error}")  # fmt: skip
            return
        if a.sha256 == b.sha256 and e.size == t.size:
            res.matched += 1
            return
        res.different += 1
        hashes = {
            "source_sha256": a.sha256,
            "target_sha256": b.sha256,
            "source_size": e.size,
            "target_size": t.size,
        }
        expected, actual = f"sha256:{a.sha256[:12]}", f"sha256:{b.sha256[:12]}"
        kind = textmod.kind_of(e.path)
        if kind is None:
            self._f(Kind.DIFFERENCE, Severity.HIGH, e.path, "file content differs",
                    expected=expected, actual=actual, detail=hashes)  # fmt: skip
            return
        if a.data is None or b.data is None:
            self._f(Kind.DIFFERENCE, Severity.HIGH, e.path,
                    f"file content differs (text not compared: over {self.c.max_text_mb} MB)",
                    expected=expected, actual=actual, detail=hashes)  # fmt: skip
            return
        try:
            ta, tb = textmod.extract(e.path, a.data), textmod.extract(t.path, b.data)
        except textmod.TextError as exc:
            self._f(Kind.DIFFERENCE, Severity.HIGH, e.path,
                    f"file content differs (text not compared: {exc})",
                    expected=expected, actual=actual, detail=hashes)  # fmt: skip
            return
        diff = textmod.first_difference(ta, tb, self.masks)
        if diff is None:
            res.text_equal += 1
            reasons = textmod.why_bytes_differ(ta, tb, self.masks)
            self._f(Kind.DIFFERENCE, Severity.LOW, e.path,
                    "bytes differ but the text is identical: " + "; ".join(reasons),
                    expected=expected, actual=actual,
                    detail={**hashes, "text": "identical", "reasons": reasons})  # fmt: skip
            return
        detail = {**hashes, "text": "differs", "first_difference": diff.locator}
        if self.c.show_content:
            detail.update({"expected_text": diff.expected, "actual_text": diff.actual})
        self._f(
            Kind.DIFFERENCE,
            Severity.HIGH,
            e.path,
            f"file text differs from {diff.locator}",
            column=diff.column,
            locator=diff.locator,
            expected=diff.expected if self.c.show_content else expected,
            actual=diff.actual if self.c.show_content else actual,
            detail=detail,
        )


def compare_files(
    sets: list[FileSetConfig],
    emit: Callable[[Finding], None],
    open_source: Callable[[FileSetConfig, str], FileSource],
) -> FileResult:
    """Compare every file set. open_source(config, "source" | "target") builds a side."""
    result = FileResult()
    for c in sets:
        source, target = open_source(c, "source"), open_source(c, "target")
        result.sets.append(FileComparator(c, source, target, emit).run())
    return result
