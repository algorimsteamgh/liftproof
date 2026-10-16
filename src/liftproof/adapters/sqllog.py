"""Each statement an adapter sends, logged at debug level (spec 16): the SQL text only,
never its parameters, which can carry row keys and watermark values. It is installed only
when debug logging is on, so a normal run talks to the driver directly.
"""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger("liftproof.sql")
LIMIT = 4000  # a long generated statement (hundreds of columns) is cut, not dropped


def wrap(conn: Any, engine: str) -> Any:
    return LoggedConnection(conn, engine) if log.isEnabledFor(logging.DEBUG) else conn


def _text(query: Any, cursor: Any) -> str:
    as_string = getattr(query, "as_string", None)  # psycopg's composed SQL
    text = as_string(cursor) if as_string is not None else str(query)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= LIMIT else text[:LIMIT] + " ..."


class _Proxy:
    __slots__ = ("_inner", "_engine")

    def __init__(self, inner: Any, engine: str) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_engine", engine)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._inner, name, value)

    def __exit__(self, *exc: object) -> Any:
        return self._inner.__exit__(*exc)


class LoggedCursor(_Proxy):
    __slots__ = ()

    def __enter__(self) -> LoggedCursor:
        self._inner.__enter__()
        return self

    def __iter__(self) -> Any:
        return iter(self._inner)

    def execute(self, query: Any, *args: Any, **kw: Any) -> Any:
        log.debug("%s: %s", self._engine, _text(query, self._inner))
        return self._inner.execute(query, *args, **kw)

    def executemany(self, query: Any, *args: Any, **kw: Any) -> Any:
        log.debug("%s (many): %s", self._engine, _text(query, self._inner))
        return self._inner.executemany(query, *args, **kw)


class LoggedConnection(_Proxy):
    __slots__ = ()

    def __enter__(self) -> LoggedConnection:
        self._inner.__enter__()
        return self

    def cursor(self, *args: Any, **kw: Any) -> LoggedCursor:
        return LoggedCursor(self._inner.cursor(*args, **kw), self._engine)
