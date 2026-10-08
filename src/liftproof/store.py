"""Where recordings, baselines and reports are kept (PRD F15).

Everything durable lives in Amazon S3, encrypted with AWS KMS (a customer managed key
when one is configured). The instance keeps only working copies: a replacement instance
pointed at the same bucket carries on. LocalStore serves development and tests.
"""

from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from liftproof import aws
from liftproof.errors import ConfigError, RunFailed
from liftproof.runlock import LOCK_KEY, LocalRunLock, RunLock, S3RunLock


class Store:
    def put_file(self, key: str, path: Path) -> None: ...

    def run_lock(self, run_id: str, command: str) -> RunLock: ...

    def get_file(self, key: str, path: Path) -> bool: ...

    def location(self, key: str) -> str: ...


class LocalStore(Store):
    def __init__(self, root: Path) -> None:
        self.root = root

    def put_file(self, key: str, path: Path) -> None:
        dest = self.root / key
        if dest.resolve() == path.resolve():
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)

    def get_file(self, key: str, path: Path) -> bool:
        src = self.root / key
        if not src.exists():
            return False
        if src.resolve() != path.resolve():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, path)
        return True

    def location(self, key: str) -> str:
        return str(self.root / key)

    def run_lock(self, run_id: str, command: str) -> RunLock:
        return LocalRunLock(self.root / LOCK_KEY, run_id, command)


class S3Store(Store):
    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        kms_key_id: str | None = None,
        client=None,
        report_lock_days: int = 0,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.kms_key_id = kms_key_id
        self.report_lock_days = report_lock_days
        self.s3 = client or aws.client("s3")

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def _object_args(self, key: str) -> dict:
        """Encryption, plus retention and classification by what the object is.

        Reports under runs/ are go live sign off records: governance mode Object Lock.
        Recorded bodies and snapshots are tagged so the bucket lifecycle expires them.
        """
        args: dict = {"ServerSideEncryption": "aws:kms"}
        if self.kms_key_id:
            args["SSEKMSKeyId"] = self.kms_key_id
        if key.startswith("runs/") and self.report_lock_days > 0:
            args["ObjectLockMode"] = "GOVERNANCE"
            args["ObjectLockRetainUntilDate"] = dt.datetime.now(dt.UTC) + dt.timedelta(
                days=self.report_lock_days
            )
        if "/assets/" in key:
            args["Tagging"] = "liftproof:class=asset"
        return args

    def put_file(self, key: str, path: Path) -> None:
        try:
            with path.open("rb") as fh:
                self.s3.put_object(
                    Bucket=self.bucket, Key=self._key(key), Body=fh, **self._object_args(key)
                )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "error")
            if code in ("AccessDenied", "NoSuchBucket", "KMS.AccessDeniedException"):
                raise ConfigError(
                    f"cannot write s3://{self.bucket}/{self._key(key)}: {code}"
                ) from None
            raise RunFailed(f"S3 write failed for {self._key(key)}: {code}") from None
        except BotoCoreError as exc:
            raise RunFailed(f"S3 write failed for {self._key(key)}: {exc}") from None

    def get_file(self, key: str, path: Path) -> bool:
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=self._key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return False
            raise ConfigError(f"cannot read s3://{self.bucket}/{self._key(key)}") from None
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            for chunk in resp["Body"].iter_chunks():
                fh.write(chunk)
        return True

    def location(self, key: str) -> str:
        return f"s3://{self.bucket}/{self._key(key)}"

    def run_lock(self, run_id: str, command: str) -> RunLock:
        return S3RunLock(
            self.s3, self.bucket, self._key(LOCK_KEY), run_id, command,
            put_args=self._object_args(LOCK_KEY),
        )  # fmt: skip
