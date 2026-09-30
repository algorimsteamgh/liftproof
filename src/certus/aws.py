"""All AWS access goes through here (PRD N1 to N6, AWSAPI-001 to 005).

Credentials come only from the AWS SDK default credential provider chain: the instance
role through IMDSv2 on the product AMI, or IAM Identity Center or IAM Roles Anywhere
profiles where a customer configures them. There is deliberately no setting anywhere in
the product that accepts an access key.

Every client shares one token bucket so the product cannot throttle the customer
account, and uses the SDK's adaptive retry mode (exponential backoff with jitter). The
product never polls a control plane API.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import boto3
import botocore
from botocore.config import Config

from certus import __version__


class TokenBucket:
    def __init__(self, rate_per_second: float, burst: int) -> None:
        self.rate = rate_per_second
        self.capacity = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> None:
        if self.rate <= 0:
            return
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(wait)


_bucket = TokenBucket(rate_per_second=20, burst=40)


def configure_rate_limit(rate_per_second: float, burst: int | None = None) -> None:
    global _bucket
    _bucket = TokenBucket(rate_per_second, burst or max(1, int(rate_per_second * 2)))


def sdk_versions() -> dict[str, str]:
    """Recorded in every report and in `certus version` (AWSAPI-004)."""
    return {"boto3": boto3.__version__, "botocore": botocore.__version__}


def client(service: str, region: str | None = None) -> Any:
    cfg = Config(
        retries={"mode": "adaptive", "max_attempts": 10},
        user_agent_extra=f"certus/{__version__}",
        region_name=region,
    )
    c = boto3.session.Session().client(service, config=cfg)

    def _limit(**_kwargs: Any) -> None:
        _bucket.take()

    c.meta.events.register("before-call.*.*", _limit)
    return c
