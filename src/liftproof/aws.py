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

import ipaddress
import socket
import threading
import time
from typing import Any

import boto3
import botocore
from botocore.config import Config

from liftproof import __version__


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


_bucket = TokenBucket(rate_per_second=20, burst=40)  # until configure_rate_limit


def configure_rate_limit(rate_per_second: float, burst: int | None = None) -> None:
    global _bucket
    _bucket = TokenBucket(rate_per_second, burst or max(1, int(rate_per_second * 2)))


def sdk_versions() -> dict[str, str]:
    """Recorded in every report and in `liftproof version` (AWSAPI-004)."""
    return {"boto3": boto3.__version__, "botocore": botocore.__version__}


DEFAULT_RATE = 20.0  # requests per second, all clients together


def client(
    service: str,
    region: str | None = None,
    *,
    endpoint_url: str | None = None,
    credentials: dict[str, str] | None = None,
) -> Any:
    """Every client the product makes, rate limited and retried alike. `endpoint_url` and
    `credentials` serve an S3 compatible store outside AWS only, whose access key pair
    comes from a Secrets Manager secret; AWS itself is reached with the default chain."""
    cfg = Config(
        retries={"mode": "adaptive", "max_attempts": 10},
        user_agent_extra=f"liftproof/{__version__}",
        region_name=region,
    )
    c = boto3.session.Session().client(
        service, config=cfg, endpoint_url=endpoint_url, **(credentials or {})
    )

    def _limit(**_kwargs: Any) -> None:
        _bucket.take()

    c.meta.events.register("before-call.*.*", _limit)
    return c


METRIC_NAMESPACE = "Liftproof"  # the instance role may publish to this namespace only


def put_metric(name: str, value: float, dimensions: dict[str, str], unit: str = "Count") -> None:
    """One CloudWatch metric data point. Alarms on these are the customer's to set."""
    client("cloudwatch").put_metric_data(
        Namespace=METRIC_NAMESPACE,
        MetricData=[
            {
                "MetricName": name,
                "Dimensions": [{"Name": k, "Value": v} for k, v in dimensions.items()],
                "Value": value,
                "Unit": unit,
            }
        ],
    )


# The services the instance calls (and the SSM agent beside it), each through a VPC
# endpoint in a private subnet: infra/modules/liftproof/network.tf. S3 goes through a
# gateway endpoint, which routes rather than resolves, so its addresses stay public ones.
ENDPOINT_SERVICES = (
    "ssm", "ssmmessages", "ec2messages", "secretsmanager", "kms", "logs", "monitoring", "s3",
)  # fmt: skip
GATEWAY_SERVICES = ("s3",)


def reach(service: str, region: str, timeout: float = 5.0) -> str:
    """Opens a TCP connection to the service's regional endpoint on 443 and closes it.
    Returns "vpc endpoint" when the name resolves to a private address (an interface
    endpoint with private DNS), "gateway" for S3, and "public address" otherwise. Raises
    OSError when the name does not resolve or nothing answers."""
    host = f"{service}.{region}.amazonaws.com"
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    family, kind, proto, _name, addr = infos[0]
    with socket.socket(family, kind, proto) as sock:
        sock.settimeout(timeout)
        sock.connect(addr)
    if service in GATEWAY_SERVICES:
        return "gateway"
    return "vpc endpoint" if ipaddress.ip_address(addr[0]).is_private else "public address"
