"""Per type rendering rules (canonical 9.4), reference implementation.

render() turns a driver value into the canonical string for its canonical type. The
engine pushdown SQL in each adapter must produce exactly the same string.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import unicodedata
import uuid
import xml.etree.ElementTree as ET
from decimal import Decimal
from typing import Any

from liftproof.canonical.types import CanonicalType

XML_DECLARATION = re.compile(r"\A﻿?[ \t\r\n]*<\?xml[ \t\r\n][^?]*\?>")
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"
CONTENT = "liftproof-content"  # the element a value is parsed inside, then cut off
UNDECLARED = "XML namespaces cannot be resolved: an xsi:type value names an undeclared prefix"


class RenderError(ValueError):
    """A value cannot be rendered under its canonical type. The row hasher names the
    column; the message never holds the value."""

    def __init__(self, reason: str, column: str | None = None) -> None:
        super().__init__(f"column {column}: {reason}" if column else reason)
        self.reason = reason
        self.column = column


class Verbatim(str):
    """A value the adapter rendered itself, used as is.

    Only for engine values that have no canonical type value at all, such as MySQL zero
    dates, a MySQL TIME outside one day or a PostgreSQL infinity date. The adapter's
    pushdown must render the same text; see docs/canonical-v1.md.
    """


def _decimal(value: Any) -> str:
    d = value if isinstance(value, Decimal) else Decimal(str(value))
    if d.is_nan():
        return "NaN"
    if d.is_infinite():
        return "Infinity" if d > 0 else "-Infinity"
    if d.is_zero():
        return "0"  # no negative zero, no 0E-10
    text = format(d, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _fraction(microsecond: int, precision: int) -> str:
    if precision <= 0:
        return ""
    return "." + f"{microsecond:06d}"[: min(precision, 6)]


def _timestamp(value: dt.datetime, precision: int) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S") + _fraction(value.microsecond, precision)


def _json_canonical(value: Any) -> str:
    if isinstance(value, (str, bytes, bytearray)):
        value = json.loads(value)
    return unicodedata.normalize(
        "NFC", json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


class _C14NFilter:
    """Parser target in front of ElementTree's C14N 2.0 writer: drops comments and text
    that is only XML whitespace (outside xml:space="preserve"), and normalises each text
    run, attribute value and processing instruction to NFC on its own (NFC over written
    markup would fold a '>' and a following U+0338 into one character)."""

    def __init__(self, out: ET.C14NWriterTarget, document: bool) -> None:
        self._out = out
        self._text: list[str] = []
        self._preserve = [False]
        self._document = document
        if document:  # parsed as it is: open the element content is parsed inside
            out.start(CONTENT, {})

    def _flush(self) -> None:
        text = "".join(self._text)
        self._text.clear()
        if text and (self._preserve[-1] or text.strip(" \t\r\n")):
            self._out.data(_nfc(text))

    def start_ns(self, prefix: str, uri: str) -> None:
        self._flush()
        self._out.start_ns(prefix, uri)

    def start(self, tag: str, attrs: dict[str, str]) -> None:
        self._flush()
        space = attrs.get(XML_SPACE)
        self._preserve.append(self._preserve[-1] if space is None else space == "preserve")
        self._out.start(tag, {k: _nfc(v) for k, v in attrs.items()})

    def end(self, tag: str) -> None:
        self._flush()
        self._preserve.pop()
        self._out.end(tag)

    def data(self, text: str) -> None:
        self._text.append(text)

    def pi(self, target: str, data: str | None) -> None:
        self._flush()
        self._out.pi(target, _nfc(data or ""))

    def close(self) -> None:
        self._flush()
        if self._document:
            self._out.end(CONTENT)


def _c14n(text: str, document: bool) -> str:
    out: list[str] = []
    writer = ET.C14NWriterTarget(out.append, qname_aware_attrs={XSI_TYPE})
    # expat never fetches an external entity or DTD for ElementTree, and from 2.4.1 refuses
    # entity expansion out of proportion to its input (a test pins the version)
    parser = ET.XMLParser(target=_C14NFilter(writer, document))  # noqa: S314
    try:
        parser.feed(text if document else f"<{CONTENT}>{text}</{CONTENT}>")
        parser.close()
    except ValueError:  # the writer resolving an xsi:type value (not a ParseError)
        raise RenderError(UNDECLARED) from None
    return "".join(out)[len(CONTENT) + 2 : -(len(CONTENT) + 3)]


def _where(exc: ET.ParseError, document: bool) -> str:
    """expat's message, which names positions and entities but never the text, with the
    column on the first line counted from the start of the value."""
    line, column = exc.position
    if line == 1 and not document:
        column -= len(CONTENT) + 2
    return f"{str(exc).rsplit(': line ', 1)[0]}: line {line}, column {column}"


def _xml_canonical(value: Any) -> str:
    """Parsed as content (several elements, text at the top level), or failing that as a
    document (one with a DOCTYPE), and written as C14N 2.0 less comments and whitespace
    only text, in NFC. docs/canonical-v1.md states the rule."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RenderError(f"XML is not UTF-8 (byte {exc.start})") from None
    text = XML_DECLARATION.sub("", str(value), count=1)
    try:
        return _c14n(text, document=False)
    except ET.ParseError as content:
        try:
            return _c14n(text, document=True)
        except ET.ParseError as document:
            raise RenderError(
                f"not well-formed XML: as content, {_where(content, False)}; "
                f"as a document, {_where(document, True)}"
            ) from None


def render(value: Any, ctype: CanonicalType, *, precision: int = 6) -> str | None:
    """Render one value. Returns None for SQL NULL; framing handles NULL separately."""
    if value is None:
        return None
    if isinstance(value, Verbatim):
        return str(value)
    match ctype:
        case CanonicalType.INTEGER:
            if isinstance(value, bool):
                return "1" if value else "0"
            return str(int(value))
        case CanonicalType.DECIMAL:
            return _decimal(value)
        case CanonicalType.BOOLEAN:
            return "1" if bool(value) else "0"
        case CanonicalType.TEXT:
            return unicodedata.normalize("NFC", str(value))
        case CanonicalType.CHAR:
            return unicodedata.normalize("NFC", str(value).rstrip(" "))
        case CanonicalType.DATE:
            if isinstance(value, dt.datetime):
                value = value.date()
            return value.isoformat()
        case CanonicalType.TIME:
            return value.strftime("%H:%M:%S") + _fraction(value.microsecond, precision)
        case CanonicalType.TIMESTAMP:
            if value.tzinfo is not None:
                raise RenderError("naive timestamp column returned a zone aware value")
            return _timestamp(value, precision)
        case CanonicalType.TIMESTAMPTZ:
            if value.tzinfo is None:
                raise RenderError("zone aware timestamp column returned a naive value")
            return _timestamp(value.astimezone(dt.UTC), precision)
        case CanonicalType.BINARY:
            return bytes(value).hex()
        case CanonicalType.UUID:
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))
        case CanonicalType.JSON:
            return _json_canonical(value)
        case CanonicalType.XML:
            return _xml_canonical(value)
        case _:
            raise RenderError(f"canonical type {ctype} is not hashed")
