"""Text content of the document types the file comparator understands (spec 10).

A file regenerated on the target can differ in bytes and still say the same thing: a
PDF's creation date and object ids, Windows line endings becoming Unix ones, a byte
order mark, a different character encoding, JSON with its keys in another order. For
these types the comparator extracts the text and compares that as well, so a raw hash
difference with identical text ranks below a real difference rather than failing.

Understood: PDF; JSON; CSV and other delimited files; plain text, XML, HTML, logs and
fixed width data files. Everything else is compared by hash only.
"""

from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

TEXT_SUFFIXES = {
    ".txt", ".log", ".xml", ".html", ".htm", ".dat", ".prn", ".fixed", ".fwf", ".edi",
    ".yaml", ".yml", ".md", ".ini", ".cfg", ".conf", ".sql", ".properties", ".eml",
}  # fmt: skip
DELIMITED = {".csv": ",", ".tsv": "\t", ".psv": "|", ".dsv": ","}
MASK = "<masked>"


class TextError(ValueError):
    """The file claims a type but its content cannot be read as that type."""


def kind_of(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".json":
        return "json"
    if suffix in DELIMITED:
        return "delimited"
    if suffix in TEXT_SUFFIXES:
        return "text"
    return None


@dataclass
class Text:
    kind: str
    lines: list[str]  # normalised content, one comparable unit per entry
    where: list[str]  # where each line came from, for the report ("line 12")
    encoding: str | None = None
    bom: bool = False
    newlines: str | None = None  # crlf | lf | cr | mixed
    header: list[str] = field(default_factory=list)  # delimited files only
    rows: list[list[str]] = field(default_factory=list)  # delimited files only


def _decode(data: bytes) -> tuple[str, str, bool]:
    bom = data.startswith(b"\xef\xbb\xbf")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding), "utf-8" if encoding == "utf-8-sig" else encoding, bom
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1"), "latin-1", bom


def _newlines(text: str) -> str | None:
    crlf = text.count("\r\n")
    cr = text.count("\r") - crlf
    lf = text.count("\n") - crlf
    used = [n for n, c in (("crlf", crlf), ("cr", cr), ("lf", lf)) if c]
    if not used:
        return None
    return used[0] if len(used) == 1 else "mixed"


def _lines(text: str) -> list[str]:
    lines = re.split(r"\r\n|\r|\n", unicodedata.normalize("NFC", text))
    while lines and lines[-1] == "":
        lines.pop()  # a final newline, or several, is not content
    return lines


def extract(path: str, data: bytes) -> Text | None:
    kind = kind_of(path)
    if kind is None:
        return None
    if kind == "pdf":
        return _pdf(data)
    text, encoding, bom = _decode(data)
    newlines = _newlines(text)
    if kind == "json":
        try:
            value = json.loads(text)
        except ValueError:
            kind = "text"  # not valid JSON: compared as plain text
        else:
            canonical = json.dumps(value, sort_keys=True, indent=1, ensure_ascii=False)
            lines = _lines(canonical)
            return Text("json", lines, [f"line {i + 1} (keys sorted)" for i in range(len(lines))],
                        encoding, bom, newlines)  # fmt: skip
    lines = _lines(text)
    if kind == "delimited":
        delimiter = DELIMITED[PurePosixPath(path).suffix.lower()]
        rows = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=delimiter))
        return Text(
            "delimited",
            [json.dumps(r, ensure_ascii=False) for r in rows],
            [f"row {i + 1}" for i in range(len(rows))],
            encoding,
            bom,
            newlines,
            header=rows[0] if rows else [],
            rows=rows,
        )
    return Text(
        "text", lines, [f"line {i + 1}" for i in range(len(lines))], encoding, bom, newlines
    )


def _pdf(data: bytes) -> Text:
    """Text of every page, whitespace collapsed: two renderings of the same document lay
    out spaces differently. Metadata (creation date, producer, document id) is not text."""
    import logging

    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    logging.getLogger("pypdf").setLevel(logging.ERROR)
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise TextError("the PDF is encrypted")
        lines, where = [], []
        for n, page in enumerate(reader.pages, start=1):
            k = 0
            for raw in (page.extract_text() or "").splitlines():
                line = " ".join(unicodedata.normalize("NFC", raw).split())
                if line:
                    k += 1
                    lines.append(line)
                    where.append(f"page {n}, line {k}")
    except PdfReadError as exc:
        raise TextError(f"not a readable PDF: {exc}") from None
    return Text("pdf", lines, where)


def _mask(value: str, masks: Sequence[re.Pattern[str]]) -> str:
    for m in masks:
        value = m.sub(MASK, value)
    return value


def masked_rows(text: Text, masks: Sequence[re.Pattern[str]]) -> list[list[str]]:
    return [[_mask(c, masks) for c in row] for row in text.rows]


def masked(text: Text, masks: Sequence[re.Pattern[str]]) -> list[str]:
    """Comparable lines with every mask applied (per cell for delimited files)."""
    if not masks:
        return text.lines
    if text.kind == "delimited":
        return [json.dumps(r, ensure_ascii=False) for r in masked_rows(text, masks)]
    return [_mask(line, masks) for line in text.lines]


@dataclass
class TextDiff:
    locator: str
    expected: str | None
    actual: str | None
    column: str | None = None


def first_difference(a: Text, b: Text, masks: Sequence[re.Pattern[str]] = ()) -> TextDiff | None:
    """Where the two texts first differ, after masking; None when they are the same."""
    la, lb = masked(a, masks), masked(b, masks)
    if la == lb:
        return None
    for i, (x, y) in enumerate(zip(la, lb, strict=False)):
        if x != y:
            if a.kind == "delimited" and b.kind == "delimited":
                return _cell(a, masked_rows(a, masks)[i], masked_rows(b, masks)[i], i)
            return TextDiff(a.where[i], x, y)
    i = min(len(la), len(lb))
    if len(la) > len(lb):
        return TextDiff(f"{a.where[i]} onwards: missing in target", la[i], None)
    return TextDiff(f"{b.where[i]} onwards: only in target", None, lb[i])


def _cell(a: Text, ra: list[str], rb: list[str], i: int) -> TextDiff:
    for c in range(max(len(ra), len(rb))):
        x = ra[c] if c < len(ra) else None
        y = rb[c] if c < len(rb) else None
        if x != y:
            name = a.header[c] if i > 0 and c < len(a.header) else f"column {c + 1}"
            return TextDiff(f"row {i + 1}, {name}", x, y, column=name)
    return TextDiff(f"row {i + 1}", json.dumps(ra), json.dumps(rb))


def why_bytes_differ(a: Text, b: Text, masks: Sequence[re.Pattern[str]]) -> list[str]:
    """Reasons two files with the same text have different bytes, for the report."""
    reasons = []
    if a.kind == "pdf":
        reasons.append("PDF internals (creation date, document id, object layout)")
    if a.encoding != b.encoding:
        reasons.append(f"character encoding {a.encoding} became {b.encoding}")
    if a.bom != b.bom:
        reasons.append("byte order mark added" if b.bom else "byte order mark removed")
    if a.newlines != b.newlines and a.newlines and b.newlines:
        reasons.append(f"line endings {a.newlines} became {b.newlines}")
    if a.kind == "json":
        reasons.append("JSON formatting or key order")
    if masks and a.lines != b.lines:
        reasons.append("masked text (files.ignore_text)")
    return reasons or ["whitespace at the end of the file"]
