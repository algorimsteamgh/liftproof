"""Structured JSON logging (Technical Spec 16).

No customer data goes into logs. The redaction filter is defence in depth only: the
primary controls are structural (credentials are passed as separate connection
parameters, never interpolated into a string, and driver debug logging is off).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any

_secrets: set[str] = set()
_lock = threading.Lock()
_context: dict[str, Any] = {}


def register_secret(value: str | None) -> None:
    if value and len(value) >= 4:
        with _lock:
            _secrets.add(value)


def set_context(**kw: Any) -> None:
    _context.update({k: v for k, v in kw.items() if v is not None})


def scrub(text: str) -> str:
    with _lock:
        for s in _secrets:
            text = text.replace(s, "***")
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname.lower(),
            "component": record.name.removeprefix("liftproof."),
            "msg": record.getMessage(),
            **_context,
        }
        for key in ("finding_id", "table", "journey"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return scrub(json.dumps(entry, default=str))


def setup(level: str = "info", file: str | None = None) -> None:
    """Never fails: an unknown level falls back to info and a log file that cannot be
    opened to stderr alone, each with a warning, so a logging problem cannot stop a run
    or end it with a traceback."""
    root = logging.getLogger("liftproof")
    root.handlers.clear()
    problems = []
    try:
        root.setLevel(level.upper())
    except (ValueError, TypeError):
        root.setLevel(logging.INFO)
        problems.append(f"unknown log level {level!r}; logging at info")
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if file:
        try:
            handlers.append(logging.FileHandler(file, encoding="utf-8"))
        except OSError as exc:
            problems.append(f"cannot write the log file {file} ({exc.strerror}); stderr only")
    for h in handlers:
        h.setFormatter(JsonFormatter())
        root.addHandler(h)
    root.propagate = False
    # driver logging stays off at every level: it can carry statement parameters
    for noisy in ("psycopg", "pymysql", "oracledb", "pytds", "botocore", "boto3", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    for problem in problems:
        root.getChild("logs").warning(problem)
