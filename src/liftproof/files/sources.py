"""Where files are read from (Technical Spec 10): a path reachable from the instance (a
local disk, or an NFS or SMB share mounted on it), an object store prefix (Amazon S3, or
an S3 compatible store through endpoint_url), an Azure Blob Storage container prefix, or
the files a database table holds (files/rows.py).

Sources are read only. Nothing here writes, moves or deletes a file.
"""

from __future__ import annotations

import abc
import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
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


AZURE_HOST = ".blob.core.windows.net"
AZURE_VERSION = "2021-08-06"  # the Blob service REST API version every request names


def is_azure(location: str) -> bool:
    host = urllib.parse.urlsplit(location).hostname or ""
    return location.startswith("https://") and host.endswith(AZURE_HOST)


class AzureBlobSource(FileSource):
    """An Azure Blob Storage container, or a prefix in it, given as its URL
    (https://<account>.blob.core.windows.net/<container>/<prefix>), read with a shared
    access signature (SAS) that allows Read and List, from a Secrets Manager secret. The
    Blob service REST API directly: no Azure SDK on the image, and nothing but reads.
    Folder placeholders of a hierarchical namespace (Data Lake Storage) are not files."""

    def __init__(self, url: str, sas_token: str, *, timeout: float = 60.0) -> None:
        parts = urllib.parse.urlsplit(url)
        # https only; plain http for a local emulator (Azurite) on this instance alone
        local = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")
        if parts.scheme != "https" and not local:
            raise ConfigError(f"{url}: an Azure Blob Storage container URL starts with https://")
        container, _, prefix = parts.path.lstrip("/").partition("/")
        if not container:
            raise ConfigError(f"{url}: give the container URL, with the container's name")
        self.base = f"{parts.scheme}://{parts.netloc}/{container}"
        self.prefix = prefix
        if self.prefix and not self.prefix.endswith("/"):
            self.prefix += "/"
        self.sas = sas_token.lstrip("?")
        self.timeout = timeout
        self.skipped: list[tuple[str, str]] = []

    def describe(self) -> str:
        return f"{self.base}/{self.prefix}"

    def _get(self, url: str) -> Any:
        # the scheme is https (or a local emulator's http), checked when the source was made
        req = urllib.request.Request(url, headers={"x-ms-version": AZURE_VERSION})  # noqa: S310
        try:
            return urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310 - https URL
        except urllib.error.HTTPError as exc:
            code = ""
            try:
                code = ET.fromstring(exc.read()).findtext("Code") or ""  # noqa: S314
            except ET.ParseError:
                pass
            hint = {
                403: "the SAS token is wrong, expired, or lacks Read and List",
                404: "no such container",
            }.get(exc.code, "")
            raise ConfigError(
                f"Azure Blob Storage {self.describe()}: HTTP {exc.code} {code}"
                + (f" ({hint})" if hint else "")
            ) from None
        except urllib.error.URLError as exc:
            raise ConfigError(
                f"Azure Blob Storage {self.describe()} not reachable: {exc.reason}; the "
                "instance needs outbound HTTPS to the storage account, and the account must "
                "allow its address"
            ) from None

    def entries(self) -> Iterator[Entry]:
        self.skipped = []
        marker = ""
        while True:
            query = {"restype": "container", "comp": "list", "include": "metadata",
                     "maxresults": "5000"}  # fmt: skip
            if self.prefix:
                query["prefix"] = self.prefix
            if marker:
                query["marker"] = marker
            url = f"{self.base}?{urllib.parse.urlencode(query)}&{self.sas}"
            with self._get(url) as resp:
                root = ET.fromstring(resp.read())  # noqa: S314 - the storage service's listing
            for blob in root.iter("Blob"):
                name = blob.findtext("Name") or ""
                found = blob.find("Metadata")
                meta = {m.tag.lower(): m.text or "" for m in found} if found is not None else {}
                if name.endswith("/") or meta.get("hdi_isfolder", "").lower() == "true":
                    continue  # a folder, not a file
                size = int(blob.findtext("Properties/Content-Length") or 0)
                yield Entry(name[len(self.prefix) :], size)
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return

    def open(self, path: str) -> IO[bytes]:
        name = urllib.parse.quote(self.prefix + path, safe="/")
        return self._get(f"{self.base}/{name}?{self.sas}")


def open_source(
    location: str,
    *,
    endpoint_url: str | None = None,
    secret_arn: str | None = None,
    client: Any = None,
    kind: str | None = None,
) -> FileSource:
    """A path on this instance, s3://bucket/prefix, or an Azure Blob Storage container URL.
    An S3 compatible store outside AWS takes its access key pair from a Secrets Manager
    secret with the keys access_key_id and secret_access_key, and Azure Blob Storage its
    SAS token from one with the key sas_token; never from the project file."""
    if kind == "azure_blob" or is_azure(location):
        if not secret_arn:
            raise ConfigError(
                f"{location}: Azure Blob Storage is read with a SAS token (Read and List) in a "
                "Secrets Manager secret, key sas_token: give its secret_arn"
            )
        from liftproof.credentials import secret_value

        return AzureBlobSource(location, secret_value(secret_arn, "sas_token"))
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
        raise ConfigError(
            f"{location}: only local paths, s3:// locations and Azure Blob Storage container "
            "URLs are supported"
        )
    return LocalSource(location)
