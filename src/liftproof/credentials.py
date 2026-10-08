"""Database credentials (PRD F14, SECOPS-004).

Credentials are read from AWS Secrets Manager at the moment they are needed. They are
never written to disk, never placed in an environment variable and never logged; the
project file holds the secret ARN only. A missing secret is a configuration error with
no fallback of any kind.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from botocore.exceptions import BotoCoreError, ClientError

from liftproof import aws
from liftproof.errors import ConfigError
from liftproof.logs import register_secret


@dataclass(frozen=True)
class DbCredentials:
    username: str | None
    password: str | None

    def __repr__(self) -> str:  # never let a password reach a traceback or log
        return f"DbCredentials(username={self.username!r}, password=***)"


def _region_of(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 and parts[3] else None


def _secret_json(arn: str) -> dict:
    try:
        resp = aws.client("secretsmanager", _region_of(arn)).get_secret_value(SecretId=arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "error")
        raise ConfigError(f"cannot read secret {arn}: {code}") from None
    except BotoCoreError as exc:
        raise ConfigError(f"cannot reach AWS Secrets Manager for {arn}: {exc}") from None
    try:
        data = json.loads(resp["SecretString"])
    except (KeyError, ValueError):
        raise ConfigError(f"secret {arn} is not a JSON key/value secret") from None
    if not isinstance(data, dict):
        raise ConfigError(f"secret {arn} is not a JSON key/value secret")
    return data


def from_secrets_manager(
    arn: str,
    *,
    username_key: str = "username",
    password_key: str = "password",  # noqa: S107
) -> DbCredentials:
    data = _secret_json(arn)
    if password_key not in data:
        raise ConfigError(f"secret {arn} has no key {password_key!r}")
    register_secret(data[password_key])
    return DbCredentials(data.get(username_key), data[password_key])


def secret_value(arn: str, key: str) -> str:
    """One value from a key/value secret: the real value behind a journey's redaction
    token (spec 5). Registered with the log scrubber before it is returned."""
    data = _secret_json(arn)
    if key not in data:
        raise ConfigError(f"secret {arn} has no key {key!r}")
    value = str(data[key])
    register_secret(value)
    return value
