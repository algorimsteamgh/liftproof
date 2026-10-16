"""Framing, hashing, reduction and aggregation (canonical 9.3, 9.6, 9.7, 9.8).

The algorithm, stated once so no adapter has to choose:

1. Each hashed column, in canonical order, is framed and hashed on its own:
       frame(v)  = ascii(len(utf8(v))) 0x1F utf8(v)       for a value
       frame(v)  = "-1" 0x1F                               for NULL
       digest(c) = lower hex MD5(frame)                     32 characters
2. Column digests are taken in groups of GROUP_SIZE, in canonical order. Each group is
       group(g)  = lower hex MD5(concatenated column digests of the group)
3.     row_hash  = lower hex MD5(concatenated group digests)
4.     v         = unsigned 64 bit integer of the first 16 hex characters of row_hash
5. A table or bucket aggregate is SUM(v) as exact decimal, reduced with a mathematical
   modulo:  r = ((total % 2**64) + 2**64) % 2**64, emitted as 16 lower hex characters.
6. bucket = value64(key_hash) mod N, where key_hash is steps 1 to 3 over the key
   columns only, or over the whole row when a table has no usable key.

Grouping depends on the column count alone, never on the data, so every engine groups
identically and no single concatenation grows past a few kilobytes (Oracle 4000 byte
and SQL Server 8000 byte limits). See docs/canonical-v1.md for why this departs from
the byte-size grouping sketched in the Technical Specification.
"""

from __future__ import annotations

import hashlib
from collections.abc import Container, Iterable, Sequence
from typing import Any

from liftproof.canonical.render import RenderError, render
from liftproof.canonical.types import CanonicalType

CANONICAL_VERSION = "1.0"
# Rules added within a version that give a rendering to values that had none (they failed
# to load, hashed as NULL, or their columns were not compared); a baseline records the
# revision of each table it holds.
#   1: PostgreSQL infinity and -infinity dates and timestamps
#   2: XML columns (PostgreSQL xml, Oracle XMLTYPE, SQL Server xml)
CANONICAL_REVISION = 2
HASH_ALGORITHM = "md5"
GROUP_SIZE = 32
MOD64 = 1 << 64
UNIT_SEPARATOR = b"\x1f"
NULL_FRAME = b"-1" + UNIT_SEPARATOR


def _md5_hex(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def frame(rendered: str | None) -> bytes:
    """Length prefixed frame. NULL has its own frame, so it can never equal any string."""
    if rendered is None:
        return NULL_FRAME
    raw = rendered.encode("utf-8")
    return str(len(raw)).encode("ascii") + UNIT_SEPARATOR + raw


def column_digest(rendered: str | None) -> str:
    return _md5_hex(frame(rendered))


def combine(digests: Sequence[str]) -> str:
    """Two stage combination of column digests into a row hash."""
    groups = [
        _md5_hex("".join(digests[i : i + GROUP_SIZE]).encode("ascii"))
        for i in range(0, len(digests), GROUP_SIZE)
    ]
    return _md5_hex("".join(groups).encode("ascii"))


def row_hash(rendered_values: Sequence[str | None]) -> str:
    """Row hash over already rendered values, in canonical column order."""
    return combine([column_digest(v) for v in rendered_values])


def value64(hex_hash: str) -> int:
    return int(hex_hash[:16], 16)


def reduce_total(total: int) -> str:
    return format(((total % MOD64) + MOD64) % MOD64, "016x")


def aggregate(hashes: Iterable[str]) -> str:
    return reduce_total(sum(value64(h) for h in hashes))


def bucket_of(key_hash: str, buckets: int) -> int:
    return value64(key_hash) % buckets


class RowHasher:
    """Hashes driver rows for one table, application side.

    columns: (name, canonical type) pairs already in canonical order, hashed columns only.
    key_positions: indexes into columns that form the bucketing key; empty means bucket
    on the whole row.
    """

    def __init__(
        self,
        columns: Sequence[tuple[str, CanonicalType]],
        key_positions: Sequence[int] = (),
        precision: int = 6,
    ) -> None:
        self.columns = list(columns)
        self.key_positions = list(key_positions)
        self.precision = precision

    def rendered(
        self, row: Sequence[Any], positions: Sequence[int] | None = None
    ) -> list[str | None]:
        """The row's values rendered, or only those at positions. A value that cannot be
        rendered raises RenderError naming its column."""
        columns = self.columns if positions is None else [self.columns[i] for i in positions]
        values = row if positions is None else [row[i] for i in positions]
        try:
            return [
                render(value, ctype, precision=self.precision)
                for value, (_, ctype) in zip(values, columns, strict=True)
            ]
        except RenderError as exc:
            for value, (name, ctype) in zip(values, columns, strict=True):  # which column
                try:
                    render(value, ctype, precision=self.precision)
                except RenderError:
                    raise RenderError(exc.reason, name) from None
            raise

    def digests(self, row: Sequence[Any]) -> list[str]:
        return [column_digest(v) for v in self.rendered(row)]

    def hash_row(self, row: Sequence[Any]) -> tuple[str, str]:
        """Returns (row_hash, key_hash)."""
        digests = self.digests(row)
        rh = combine(digests)
        if not self.key_positions:
            return rh, rh
        return rh, combine([digests[i] for i in self.key_positions])

    def key_values(self, row: Sequence[Any]) -> tuple[str | None, ...]:
        return tuple(self.rendered(row, self.key_positions))

    def placed(
        self, row: Sequence[Any], buckets: int, wanted: Container[int] | None = None
    ) -> tuple[int, str] | None:
        """(bucket, row hash), or None when the row's bucket is not among those wanted.
        The key is hashed first, so a row outside them costs only its key columns'
        rendering, never its documents' (an XML column is never a key)."""
        if wanted is None or not self.key_positions:
            rh, kh = self.hash_row(row)
            b = value64(kh) % buckets
            return (b, rh) if wanted is None or b in wanted else None
        kh = combine([column_digest(v) for v in self.rendered(row, self.key_positions)])
        b = value64(kh) % buckets
        return (b, combine(self.digests(row))) if b in wanted else None
