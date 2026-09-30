"""The database adapter interface (Technical Spec 20).

A new engine means one adapter implementing this interface, plus a full set of cross
engine fixtures. Nothing outside the adapter changes.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from certus.canonical import CanonicalType


@dataclass(frozen=True)
class TableRef:
    schema: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    def __str__(self) -> str:
        return self.qualified


@dataclass
class Column:
    name: str
    native_type: str
    canonical: CanonicalType
    fixed_width: bool = False


@dataclass
class TableSchema:
    table: TableRef
    columns: list[Column]
    primary_key: list[str] = field(default_factory=list)

    def column(self, name: str) -> Column | None:
        for c in self.columns:
            if c.name.lower() == name.lower():
                return c
        return None


@dataclass
class HashPlan:
    """How one table is hashed. Identical on both sides, and recorded in the manifest.

    columns are the hashed columns, in canonical order (lower cased name, byte order).
    key_columns are the bucketing and row matching key, in canonical order; empty means
    the table is bucketed on the whole row and matched as a multiset of row hashes.
    """

    table: TableRef
    columns: list[tuple[str, CanonicalType]]
    key_columns: list[str]
    buckets: int
    precision: int = 6
    strategy: str = "hash"

    @property
    def key_positions(self) -> list[int]:
        names = [c for c, _ in self.columns]
        return [names.index(k) for k in self.key_columns]


@dataclass
class BucketAggregate:
    count: int
    total: int  # exact SUM of value64 over the bucket, before reduction


@dataclass
class FloatStats:
    count: int
    non_null: int
    minimum: float | None
    maximum: float | None
    total: float | None
    nan_count: int
    inf_count: int


class Adapter(abc.ABC):
    engine: str = "abstract"

    @abc.abstractmethod
    def close(self) -> None: ...

    @abc.abstractmethod
    def begin_snapshot(self) -> dict[str, Any]:
        """Start one consistent read only snapshot and return its consistency position."""

    @abc.abstractmethod
    def end_snapshot(self) -> None: ...

    @abc.abstractmethod
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]: ...

    @abc.abstractmethod
    def describe(self, table: TableRef) -> TableSchema: ...

    @abc.abstractmethod
    def row_count(self, table: TableRef) -> int: ...

    @abc.abstractmethod
    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]: ...

    @abc.abstractmethod
    def row_hashes(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[tuple[Any, ...], str]]:
        """Yield (key values, row hash) for every row in the given buckets.

        For a keyless plan the key values are the empty tuple.
        """

    @abc.abstractmethod
    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        """Fetch raw values for the hashed columns of the given keys. Bounded by the caller."""

    @abc.abstractmethod
    def float_stats(self, table: TableRef, column: str) -> FloatStats: ...

    def session_settings(self) -> dict[str, str]:
        """Pinned session parameters, recorded in the manifest."""
        return {}

    def __enter__(self) -> Adapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
