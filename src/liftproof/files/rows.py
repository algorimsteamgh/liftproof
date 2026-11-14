"""Files a database table holds, as one side of a file set (Technical Spec 10).

An application that stored uploads inside its database (a BLOB column, or base64 text)
and moves them to object storage changes where each file lives, not what it is. Each row
of the table is one file: its content is one column, its name the row's values put into a
path template, the key the migration wrote it under ("{id}/{file_name}"). Paired with the
objects under the target prefix by that path, the files are compared as any others are:
size, SHA-256 and, for text formats, the text.

The rows are read once, through the project's own (read only) database connection, and
each file is spooled to a private temporary directory on this instance while the set is
compared; nothing is written anywhere else, and the directory goes with the comparison.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import string
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from liftproof.adapters.base import Adapter, TableRef
from liftproof.errors import ConfigError
from liftproof.files.sources import Entry, FileSource

ENCODINGS = ("binary", "base64", "text")
BATCH = 16  # rows fetched at once: each can hold a file of megabytes


@dataclass(frozen=True)
class RowFiles:
    database: str  # source | target: the project's connection to read
    table: str  # schema.table, or a table in the home schema
    content: str  # the column holding the file
    path: str  # template of the file's path, from the row's columns: "{id}/{file_name}"
    where: str | None = None  # rows to read, one SQL condition in that database's dialect
    encoding: str = "binary"  # binary (BLOB, bytea), base64 or text (UTF-8)

    @property
    def path_columns(self) -> list[str]:
        return [f for _, f, _, _ in string.Formatter().parse(self.path) if f]

    def describe(self) -> str:
        return f"{self.database} database {self.table}.{self.content}"


def _bytes(value: Any, encoding: str) -> bytes:
    if hasattr(value, "read"):  # an Oracle LOB
        value = value.read()
    if isinstance(value, memoryview):
        value = value.tobytes()
    if encoding == "base64":
        text = value.decode("ascii") if isinstance(value, (bytes, bytearray)) else str(value)
        if "," in text[:100] and text.startswith("data:"):  # a data: URL
            text = text.split(",", 1)[1]
        return base64.b64decode("".join(text.split()), validate=True)
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


class RowFileSource(FileSource):
    def __init__(self, config: RowFiles, adapter: Adapter, table: TableRef) -> None:
        self.c = config
        self.adapter = adapter
        self.table = table
        self.skipped: list[tuple[str, str]] = []  # (path, reason): reported not checked
        self.notes: list[str] = []  # reported as notices
        self._spool = tempfile.TemporaryDirectory(prefix="liftproof-rows-")
        self._files: dict[str, Path] = {}

    def describe(self) -> str:
        return self.c.describe()

    def _check_columns(self) -> None:
        schema = self.adapter.describe(self.table)
        names = {c.name.lower() for c in schema.columns}
        missing = [c for c in [self.c.content, *self.c.path_columns] if c.lower() not in names]
        if missing:
            raise ConfigError(
                f"{self.describe()}: {', '.join(missing)} not a column of {self.table}"
            )

    def entries(self) -> Iterator[Entry]:
        self._check_columns()
        self.skipped, self.notes, self._files = [], [], {}
        names = self.c.path_columns
        empty = 0
        rows = self.adapter.stream_columns(
            self.table, [self.c.content, *names], self.c.where, batch=BATCH
        )
        for content, *values in rows:
            named = {n: "" if v is None else v for n, v in zip(names, values, strict=True)}
            path = self.c.path.format(**named).lstrip("/")
            if content is None:
                empty += 1
                continue
            if path in self._files:
                self.skipped.append((path, "path given by more than one row of the table"))
                continue
            try:
                data = _bytes(content, self.c.encoding)
            except (binascii.Error, ValueError) as exc:
                self.skipped.append((path, f"content is not {self.c.encoding}: {exc}"))
                continue
            spooled = Path(self._spool.name) / hashlib.sha256(path.encode()).hexdigest()
            spooled.write_bytes(data)
            self._files[path] = spooled
            yield Entry(path, len(data))
        if empty:
            self.notes.append(f"{empty} row(s) of {self.table} hold no file ({self.c.content} "
                              "is NULL); not compared")  # fmt: skip

    def open(self, path: str) -> IO[bytes]:
        return self._files[path].open("rb")

    def close(self) -> None:
        self._files = {}
        self._spool.cleanup()
        self.adapter.close()


def row_table(config: RowFiles, adapter: Adapter, home_schema: str) -> TableRef:
    schema, _, name = config.table.rpartition(".")
    return TableRef(schema or home_schema, name)


def open_rows(config: RowFiles, connect: Callable[[str], tuple[Adapter, str]]) -> RowFileSource:
    """connect(database) opens the project's source or target connection, with the schema
    a bare table name is in there."""
    adapter, home = connect(config.database)
    return RowFileSource(config, adapter, row_table(config, adapter, home))
