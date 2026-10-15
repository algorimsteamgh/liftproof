"""Canonical column types.

Each engine's native types map onto one of these. The mapping is a policy decision
(NUMBER(10,0) to integer, tinyint(1) to boolean) and lives in the versioned type map,
typemap.yaml, which a project can override within the alternatives it lists. The
canonical type decides how a value is rendered, never the native type.
"""

from enum import StrEnum


class CanonicalType(StrEnum):
    INTEGER = "integer"
    DECIMAL = "decimal"  # exact numerics
    FLOAT = "float"  # approximate numerics: excluded from the row hash (canonical 9.5)
    BOOLEAN = "boolean"
    TEXT = "text"
    CHAR = "char"  # fixed width; trailing spaces stripped
    DATE = "date"
    TIME = "time"
    TIMESTAMP = "timestamp"  # naive: rendered as stored, never converted
    TIMESTAMPTZ = "timestamptz"  # zone aware: converted to UTC
    BINARY = "binary"
    UUID = "uuid"
    JSON = "json"  # semantically canonicalised
    XML = "xml"  # semantically canonicalised; C14N 2.0 less comments and whitespace
    UNSUPPORTED = "unsupported"  # compared by nothing; reported not_checked

    @property
    def hashed(self) -> bool:
        """Whether the column takes part in the row hash."""
        return self not in (CanonicalType.FLOAT, CanonicalType.UNSUPPORTED)
