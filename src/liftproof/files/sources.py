"""Where files are read from (Technical Spec 10): a path reachable from the instance (a
local disk, or an NFS or SMB share mounted on it) or an object store prefix (Amazon S3,
or an S3 compatible store through endpoint_url).

Sources are read only. Nothing here writes, moves or deletes a file.
"""

from __future__ import annotations

import abc
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from liftproof import aws
from liftproof.errors import ConfigError


@dataclass(frozen=True)
class Entry:
    path: str  # relative, "/" separated
    size: int


class FileSource(abc.ABC):
    @abc.abstractmethod
    def entries(self) -> Iterator[Entry]: ...

    @abc.abstractmethod
    def open(self, path: str) -> IO[bytes]: ...

    @abc.abstractmethod
    def describe(self) -> str: ...


class LocalSource(FileSource):
    """A directory tree. Symbolic links are not followed: a link can point outside the
    tree, and a link loop would never end. They are reported as not checked."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.skipped: list[tuple[str, str]] = []  # (path, reason)

    def describe(self) -> str:
        return str(self.root)

    def entries(self) -> Iterator[Entry]:
        if not self.root.is_dir():
            raise ConfigError(f"{self.root} is not a directory reachable from this instance")
        self.skipped = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            base = Path(dirpath)
            for d in list(dirnames):
                if (base / d).is_symlink():
                    self.skipped.append((self._rel(base / d), "symbolic link not followed"))
                    dirnames.remove(d)
            dirnames.sort()
            for name in sorted(filenames):
                p = base / name
                if p.is_symlink():
                    self.skipped.append((self._rel(p), "symbolic link not followed"))
                    continue
                try:
                    st = p.stat()
                except OSError as exc:
                    self.skipped.append((self._rel(p), f"cannot read: {exc.strerror}"))
                    continue
                yield Entry(self._rel(p), st.st_size)

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def open(self, path: str) -> IO[bytes]:
        return (self.root / path).open("rb")


class S3Source(FileSource):
    def __init__(
        self,
        bucket: str,
        prefix: str,
        *,
        endpoint_url: str | None = None,
        credentials: dict[str, str] | None = None,
        client: Any = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.lstrip("/")
        if self.prefix and not self.prefix.endswith("/"):
            self.prefix += "/"
        self.endpoint_url = endpoint_url
        self.skipped: list[tuple[str, str]] = []
        # an S3 compatible store outside AWS (endpoint_url, keys from a secret), or AWS S3
        # with the instance role; rate limited either way
        self.s3 = client or aws.client("s3", endpoint_url=endpoint_url, credentials=credentials)

    def describe(self) -> str:
        where = f"s3://{self.bucket}/{self.prefix}"
        return f"{where} at {self.endpoint_url}" if self.endpoint_url else where

    def entries(self) -> Iterator[Entry]:
        self.skipped = []
        pages = self.s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=self.prefix
        )
        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/"):
                    continue  # a folder placeholder, not a file
                yield Entry(key[len(self.prefix) :], int(obj["Size"]))

    def open(self, path: str) -> IO[bytes]:
        return self.s3.get_object(Bucket=self.bucket, Key=self.prefix + path)["Body"]


def open_source(
    location: str,
    *,
    endpoint_url: str | None = None,
    secret_arn: str | None = None,
    client: Any = None,
) -> FileSource:
    """A path on this instance, or s3://bucket/prefix. An S3 compatible store outside AWS
    takes its access key pair from a Secrets Manager secret with the keys
    access_key_id and secret_access_key, never from the project file."""
    if location.startswith("s3://"):
        bucket, _, prefix = location[len("s3://") :].partition("/")
        if not bucket:
            raise ConfigError(f"{location}: no bucket name")
        credentials = None
        if secret_arn:
            from liftproof.credentials import secret_value

            credentials = {
                "aws_access_key_id": secret_value(secret_arn, "access_key_id"),
                "aws_secret_access_key": secret_value(secret_arn, "secret_access_key"),
            }
        return S3Source(
            bucket, prefix, endpoint_url=endpoint_url, credentials=credentials, client=client
        )
    if "://" in location:
        raise ConfigError(f"{location}: only local paths and s3:// locations are supported")
    return LocalSource(location)
