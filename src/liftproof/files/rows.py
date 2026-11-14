"""Files a database table holds or names, as one side of a file set (Technical Spec 10).

An application that stored uploads inside its database (a BLOB column, or base64 text)
and moves them to object storage changes where each file lives, not what it is. Each row
of the table is one file: its content is one column, its name the row's values put into a
path template, the key the migration wrote it under ("{id}/{file_name}"). Paired with the
objects under the target prefix by that path, the files are compared as any others are:
size, SHA-256 and, for text formats, the text.

An application that keeps its uploads in an object store has rows that name them instead:
a key or a URL column. With `object` in place of `content`, each row's file is the object
its columns name ("s3://bucket/{cv_key}", or "{photo_url}" for a column holding the whole
URL), and its path the same path template. Pairing the source's rows with the target's by
that template compares each record's file across the move, whatever keys the migration
gave the objects, and a row naming an object that is not there is reported missing.

The rows are read once, through the project's own (read only) database connection. Files
a table holds are spooled to a private temporary directory on this instance while the set
is compared; nothing is written anywhere else, and the directory goes with the comparison.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import string
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from liftproof.adapters.base import Adapter, TableRef
from liftproof.errors import ConfigError
from liftproof.files.sources import Entry, FileSource, open_source, split_location

ENCODINGS = ("binary", "base64", "text")
BATCH = 16  # rows fetched at once: each can hold a file of megabytes


@dataclass(frozen=True)
class RowFiles:
    database: str  # source | target: the project's connection to read
    table: str  # schema.table, or a table in the home schema
    content: str | None  # the column holding the file; or None, and object names it
    path: str  # template of the file's path, from the row's columns: "{id}/{file_name}"
    where: str | None = None  # rows to read, one SQL condition in that database's dialect
    encoding: str = "binary"  # binary (BLOB, bytea), base64 or text (UTF-8)
    # the file a row names: template of its location, from the row's columns
    object: str | None = None
    object_map: tuple[str, str] | None = None  # [regex, replacement] on that location
    endpoint_url: str | None = None  # the store the objects are in, as a location side's
    secret_arn: str | None = None
    kind: str | None = None

    @property
    def path_columns(self) -> list[str]:
        return _fields(self.path)

    @property
    def object_columns(self) -> list[str]:
        return _fields(self.object or "")

    def describe(self) -> str:
        if self.object:
            return f"files named by {self.database} database {self.table} ({self.object})"
        return f"{self.database} database {self.table}.{self.content}"

    def location(self, named: dict[str, Any]) -> str:
        loc = (self.object or "").format(**named)
        if self.object_map:
            loc = re.sub(self.object_map[0], self.object_map[1], loc, count=1)
        return loc


def _fields(template: str) -> list[str]:
    return [f for _, f, _, _ in string.Formatter().parse(template) if f]


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
    def __init__(
        self,
        config: RowFiles,
        adapter: Adapter,
        table: TableRef,
        stores: Callable[[str], FileSource] | None = None,
    ) -> None:
        self.c = config
        self.adapter = adapter
        self.table = table
        self.skipped: list[tuple[str, str]] = []  # (path, reason): reported not checked
        self.notes: list[str] = []  # reported as notices
        self._spool = tempfile.TemporaryDirectory(prefix="liftproof-rows-")
        self._files: dict[str, Path] = {}
        # files a row names: the store each is in, opened once per store
        self._stores = stores or self._open_store
        self._opened: dict[str, FileSource] = {}
        self._objects: dict[str, tuple[FileSource, str]] = {}

    def describe(self) -> str:
        return self.c.describe()

    def _check_columns(self) -> None:
        schema = self.adapter.describe(self.table)
        names = {c.name.lower() for c in schema.columns}
        wanted = [self.c.content] if self.c.content else self.c.object_columns
        missing = [c for c in [*wanted, *self.c.path_columns] if c.lower() not in names]
        if missing:
            raise ConfigError(
                f"{self.describe()}: {', '.join(missing)} not a column of {self.table}"
            )

    def entries(self) -> Iterator[Entry]:
        self._check_columns()
        self.skipped, self.notes, self._files, self._objects = [], [], {}, {}
        if self.c.object:
            yield from self._named()
            return
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

    def _named(self) -> Iterator[Entry]:
        """The objects the rows name, each looked up on its own: a row naming one that is
        not there is left out, so the comparison reports its path missing on this side."""
        names = list(dict.fromkeys([*self.c.path_columns, *self.c.object_columns]))
        empty, absent = 0, []
        for values in self.adapter.stream_columns(self.table, names, self.c.where, batch=500):
            row = dict(zip(names, values, strict=True))
            path = self.c.path.format(**{n: "" if v is None else v for n, v in row.items()})
            path = path.lstrip("/")
            if any(row[n] is None or row[n] == "" for n in self.c.object_columns):
                empty += 1
                continue
            if path in self._objects:
                self.skipped.append((path, "path given by more than one row of the table"))
                continue
            try:
                root, key = split_location(self.c.location(row), self.c.kind)
            except ConfigError as exc:
                self.skipped.append((path, str(exc)))
                continue
            store = self._opened.get(root)
            if store is None:
                store = self._opened[root] = self._stores(root)
            size = store.stat(key)
            if size is None:
                absent.append(path)
                continue
            self._objects[path] = (store, key)
            yield Entry(path, size)
        if empty:
            cols = ", ".join(self.c.object_columns)
            self.notes.append(f"{empty} row(s) of {self.table} name no file ({cols} is NULL "
                              "or empty); not compared")  # fmt: skip
        if absent:
            shown = ", ".join(absent[:5]) + (" and more" if len(absent) > 5 else "")
            self.notes.append(f"{len(absent)} row(s) of {self.table} name an object that does "
                              f"not exist: {shown}")  # fmt: skip

    def _open_store(self, root: str) -> FileSource:
        return open_source(root + ("/" if root.startswith("s3://") else ""),
                           endpoint_url=self.c.endpoint_url, secret_arn=self.c.secret_arn,
                           kind=self.c.kind)  # fmt: skip

    def open(self, path: str) -> IO[bytes]:
        if path in self._objects:
            store, key = self._objects[path]
            return store.open(key)
        return self._files[path].open("rb")

    def close(self) -> None:
        self._files, self._objects, self._opened = {}, {}, {}
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
