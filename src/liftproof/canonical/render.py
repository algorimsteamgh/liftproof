"""Per type rendering rules (canonical 9.4), reference implementation.

render() turns a driver value into the canonical string for its canonical type. The
engine pushdown SQL in each adapter must produce exactly the same string.
"""

from __future__ import annotations

import datetime as dt
import json
import unicodedata
import uuid
from decimal import Decimal
from typing import Any

from liftproof.canonical.types import CanonicalType


class RenderError(ValueError):
    """A value cannot be rendered under its canonical type."""


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
        case _:
            raise RenderError(f"canonical type {ctype} is not hashed")
