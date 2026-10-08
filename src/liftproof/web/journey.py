"""The journey file (Technical Spec 5): what a recording is, on disk and in S3.

A journey is data, never a script. It holds the steps the engineer took, the network
exchanges behind each step, what the touched page region looked like, timings, the
correlation rules, and the binding of each redaction token to a secret. Bodies are kept
out of the journey file: an opted in body is an asset referenced by hash, and everything
else is reduced to a hash and a shape (default deny, spec 5).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from liftproof.errors import ConfigError

JOURNEY_FORMAT = "1.0"
TOKEN_PREFIX = "@@REDACTED_"  # noqa: S105 - the marker, not a secret


@dataclass
class Locator:
    """Candidates in priority order: test id, role and name, label, text, css."""

    candidates: list[dict[str, str]]
    description: str = ""


@dataclass
class Exchange:
    method: str
    url: str  # path and query only; the base URL is the environment's
    status: int
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None  # form or JSON text after redaction; None if absent
    content_type: str = ""
    body_sha256: str | None = None
    body_shape: Any = None  # JSON structure with values replaced by type names
    body_asset: str | None = None  # assets/<sha256>, present only when the body was opted in
    duration_ms: float | None = None
    resource_type: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.method} {self.url.split('?', 1)[0]}"


@dataclass
class Step:
    n: int
    action: str  # goto | click | fill | select | check | uncheck | press
    url: str | None = None
    locator: Locator | None = None
    value: str | None = None
    non_idempotent: bool = False  # the step's requests changed state (POST, PUT, PATCH, DELETE)
    exchanges: list[Exchange] = field(default_factory=list)
    region: str | None = None  # accessible tree of the region the step touched, after it ran
    page_url: str | None = None  # where the browser was after the step
    duration_ms: float | None = None


@dataclass
class Correlation:
    """A value the server generates and a later step reuses (spec 6).

    extractor is one of json_path, form_field, header, header_segment, regex; source is the endpoint
    whose response carries it. used_in lists where the recorded value reappeared.
    """

    name: str
    extractor: str
    source: str
    expression: str
    recorded_value: str
    used_in: list[str] = field(default_factory=list)
    confirmed: bool = True  # False: below the length or entropy threshold, needs a human


@dataclass
class SecretBinding:
    arn: str | None = None
    key: str = "password"
    field: str = ""  # what was redacted, for the engineer binding it


@dataclass
class Journey:
    journey_id: str
    base_url: str
    story: str | None = None
    steps: list[Step] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    secrets: dict[str, SecretBinding] = field(default_factory=dict)
    writes_tables: list[str] = field(default_factory=list)
    recorded_at: str | None = None
    browser: str | None = None
    # wall clock of the whole recording, first navigation to last settled step; for a
    # journey an engineer drove it includes their pauses
    wall_ms: float | None = None
    format: str = JOURNEY_FORMAT

    @property
    def non_idempotent(self) -> bool:
        return any(s.non_idempotent for s in self.steps)

    @property
    def total_ms(self) -> float:
        return sum(s.duration_ms or 0.0 for s in self.steps)

    def unbound_tokens(self) -> list[str]:
        return sorted(t for t, b in self.secrets.items() if not b.arn)

    # serialisation ------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timings"] = {
            "total_ms": round(self.total_ms, 1),
            "per_step_ms": [round(s.duration_ms or 0.0, 1) for s in self.steps],
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Journey:
        if d.get("format", JOURNEY_FORMAT).split(".")[0] != JOURNEY_FORMAT.split(".")[0]:
            raise ConfigError(
                f"journey {d.get('journey_id')} has format {d.get('format')}; "
                f"this build reads {JOURNEY_FORMAT}"
            )
        steps = []
        for s in d.get("steps", []):
            s = dict(s)
            loc = s.pop("locator", None)
            exchanges = [Exchange(**e) for e in s.pop("exchanges", [])]
            steps.append(Step(**s, locator=Locator(**loc) if loc else None, exchanges=exchanges))
        return cls(
            journey_id=d["journey_id"],
            base_url=d["base_url"],
            story=d.get("story"),
            steps=steps,
            correlations=[Correlation(**c) for c in d.get("correlations", [])],
            secrets={k: SecretBinding(**v) for k, v in (d.get("secrets") or {}).items()},
            writes_tables=list(d.get("writes_tables", [])),
            recorded_at=d.get("recorded_at"),
            browser=d.get("browser"),
            wall_ms=d.get("wall_ms"),
            format=d.get("format", JOURNEY_FORMAT),
        )

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> Journey:
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            raise ConfigError(f"journey file not found: {path}") from None
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ConfigError(f"journey file {path} is not valid: {exc}") from None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shape(value: Any) -> Any:
    """The structure of a JSON value with every leaf replaced by its type name."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        # the union of element shapes, so a list of ten orders is one shape, not ten
        shapes: list[Any] = []
        for v in value:
            s = shape(v)
            if s not in shapes:
                shapes.append(s)
        return shapes
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "string"
