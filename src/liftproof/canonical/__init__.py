"""Canonical encoding and hashing, version 1.0.

This package is the wire format that lets two different database engines produce
byte identical hashes for the same data. Every rule here is normative and is written
out in docs/canonical-v1.md. The pure Python implementation in this package is the
reference: every engine pushdown must match it byte for byte, and the parity tests
prove that they do.
"""

from liftproof.canonical.encoding import (
    CANONICAL_VERSION,
    GROUP_SIZE,
    HASH_ALGORITHM,
    MOD64,
    NULL_FRAME,
    RowHasher,
    aggregate,
    bucket_of,
    column_digest,
    frame,
    reduce_total,
    row_hash,
    value64,
)
from liftproof.canonical.render import Verbatim, render
from liftproof.canonical.types import CanonicalType

__all__ = [
    "CANONICAL_VERSION",
    "GROUP_SIZE",
    "HASH_ALGORITHM",
    "MOD64",
    "NULL_FRAME",
    "CanonicalType",
    "RowHasher",
    "Verbatim",
    "aggregate",
    "bucket_of",
    "column_digest",
    "frame",
    "reduce_total",
    "render",
    "row_hash",
    "value64",
]
