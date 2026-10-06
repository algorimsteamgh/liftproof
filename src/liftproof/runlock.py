"""One run of a project at a time (Technical Spec 14).

The scheduler and the CLI are separate processes writing to the same prefixes, so runs
of one project are excluded by a lock object, not by convention:

- S3 store: locks/run.lock, created with a conditional put (If-None-Match: *). The
  holder renews a lease while the run lasts. A lock whose lease has expired was left by
  a lost process or instance and is taken over with a conditional put on its ETag, so
  two contenders cannot both win it.
- Local store (development): an advisory file lock, released by the kernel when the
  process dies, so it never goes stale.

A run that finds the lock held fails with exit code 2 and names the run holding it.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import socket
import threading
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from liftproof.errors import RunFailed

LEASE_SECONDS = 900
LOCK_KEY = "locks/run.lock"


class RunInProgress(RunFailed):
    """Another run of this project holds the lock."""

    def __init__(self, holder: dict[str, Any]) -> None:
        self.holder = holder
        since = holder.get("acquired_at", "an unknown time")
        super().__init__(
            f"run {holder.get('run_id', '?')} ({holder.get('command', '?')}) of this project "
            f"is in progress since {since} on {holder.get('host', '?')}; runs of one project "
            "never overlap"
        )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class RunLock:
    def __init__(self, run_id: str, command: str, lease_seconds: int = LEASE_SECONDS) -> None:
        self.lease = lease_seconds
        self.body = {
            "run_id": run_id,
            "command": command,
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "acquired_at": _iso(_now()),
        }
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _payload(self) -> bytes:
        expires = _now() + dt.timedelta(seconds=self.lease)
        return json.dumps(dict(self.body, expires_at=_iso(expires))).encode()

    def acquire(self) -> None: ...

    def renew(self) -> None: ...

    def release(self) -> None: ...

    def _heartbeat(self) -> None:
        while not self._stop.wait(self.lease / 3):
            try:
                self.renew()
            except Exception:  # noqa: BLE001, S110 - the next beat retries; the lease is long
                pass

    def __enter__(self) -> RunLock:
        self.acquire()
        self._thread = threading.Thread(target=self._heartbeat, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.release()


class LocalRunLock(RunLock):
    def __init__(self, path: Path, run_id: str, command: str) -> None:
        super().__init__(run_id, command)
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                holder = json.loads(os.read(fd, 4096) or b"{}")
            except ValueError:
                holder = {}
            os.close(fd)
            raise RunInProgress(holder) from None
        os.ftruncate(fd, 0)
        os.write(fd, self._payload())
        self._fd = fd

    def renew(self) -> None:
        pass  # the kernel holds a file lock for as long as the process lives

    def release(self) -> None:
        if self._fd is not None:
            os.ftruncate(self._fd, 0)
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


class S3RunLock(RunLock):
    def __init__(
        self, s3: Any, bucket: str, key: str, run_id: str, command: str,
        lease_seconds: int = LEASE_SECONDS, put_args: dict[str, Any] | None = None,
    ) -> None:  # fmt: skip
        super().__init__(run_id, command, lease_seconds)
        self.s3, self.bucket, self.key = s3, bucket, key
        self.put_args = put_args or {"ServerSideEncryption": "aws:kms"}
        self.etag: str | None = None

    def _put(self, **condition: str) -> str:
        resp = self.s3.put_object(
            Bucket=self.bucket,
            Key=self.key,
            Body=self._payload(),
            ContentType="application/json",
            **self.put_args,
            **condition,
        )
        return resp["ETag"]

    def acquire(self) -> None:
        try:
            self.etag = self._put(IfNoneMatch="*")
            return
        except ClientError as exc:
            if _code(exc) not in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise RunFailed(f"cannot take the run lock s3://{self.bucket}/{self.key}: "
                                f"{_code(exc)}") from None  # fmt: skip
        except BotoCoreError as exc:
            raise RunFailed(f"cannot take the run lock: {exc}") from None
        # held: by a live run, or left behind by a lost one
        try:
            resp = self.s3.get_object(Bucket=self.bucket, Key=self.key)
            holder = json.loads(resp["Body"].read() or b"{}")
            etag = resp["ETag"]
        except ClientError as exc:
            if _code(exc) in ("NoSuchKey", "404"):
                return self.acquire()  # released between our two calls
            raise RunFailed(f"cannot read the run lock: {_code(exc)}") from None
        expires = holder.get("expires_at")
        if expires and dt.datetime.fromisoformat(expires.replace("Z", "+00:00")) > _now():
            raise RunInProgress(holder)
        try:
            self.etag = self._put(IfMatch=etag)  # take over a stale lock, once
        except ClientError as exc:
            if _code(exc) in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise RunInProgress(holder) from None
            raise RunFailed(f"cannot take over the stale run lock: {_code(exc)}") from None
        self.body["took_over"] = holder.get("run_id")

    def renew(self) -> None:
        if self.etag:
            self.etag = self._put(IfMatch=self.etag)

    def release(self) -> None:
        if not self.etag:
            return
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=self.key, IfMatch=self.etag)
        except (ClientError, BotoCoreError):
            pass  # not ours any more, or conditional delete unsupported: the lease expires
        self.etag = None
