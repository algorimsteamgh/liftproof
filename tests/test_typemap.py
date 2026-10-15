"""The type map (Technical Spec 9.13): a versioned file, overridable per project within
the alternatives it lists, recorded wherever results are. No database needed."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import replace

import pytest
import yaml

from liftproof.adapters import oracle, sqlserver
from liftproof.adapters.base import Column, TableRef, TableSchema
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import Verbatim, render
from liftproof.canonical.typemap import (
    DEFAULT_TYPE_MAP,
    V1_FINGERPRINTS,
    TypeMap,
    TypeRule,
    legacy_record,
    type_keys,
)
from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.reconcile.baseline import Baseline
from liftproof.reconcile.plan import TypeOverride, map_types, plan_table

M = DEFAULT_TYPE_MAP

# The adapters' maps before the type map was a file, and the rules they wrote in code.
ADAPTER_MAPS = {
    "postgresql": {
        "smallint": "integer", "integer": "integer", "bigint": "integer",
        "numeric": "decimal", "real": "float", "double precision": "float",
        "boolean": "boolean", "text": "text", "character varying": "text", "name": "text",
        "citext": "text", "character": "char", "date": "date",
        "time without time zone": "time", "timestamp without time zone": "timestamp",
        "timestamp with time zone": "timestamptz", "bytea": "binary", "uuid": "uuid",
        "json": "json", "jsonb": "json", "xml": "xml",
    },
    "mysql": {
        "tinyint": "integer", "smallint": "integer", "mediumint": "integer", "int": "integer",
        "bigint": "integer", "year": "integer", "decimal": "decimal", "float": "float",
        "double": "float", "varchar": "text", "tinytext": "text", "text": "text",
        "mediumtext": "text", "longtext": "text", "enum": "text", "set": "text",
        "char": "char", "date": "date", "time": "time", "datetime": "timestamp",
        "timestamp": "timestamptz", "binary": "binary", "varbinary": "binary",
        "tinyblob": "binary", "blob": "binary", "mediumblob": "binary", "longblob": "binary",
        "json": "json",
        "tinyint(1)": "boolean",  # was: COLUMN_TYPE starting with tinyint(1)
    },
    "oracle": {
        "float": "float", "binary_float": "float", "binary_double": "float",
        "varchar2": "text", "nvarchar2": "text", "varchar": "text", "clob": "text",
        "nclob": "text", "char": "char", "nchar": "char", "date": "timestamp",
        "raw": "binary", "blob": "binary", "json": "json", "xmltype": "xml",
        "boolean": "boolean",
        # was: NUMBER by its scale, TIMESTAMP by its zone
        "number(p)": "integer", "integer": "integer", "number(p,s)": "decimal",
        "number": "decimal", "timestamp": "timestamp",
        "timestamp with time zone": "timestamptz",
        "timestamp with local time zone": "timestamptz",
    },
    "sqlserver": {
        "tinyint": "integer", "smallint": "integer", "int": "integer", "bigint": "integer",
        "decimal": "decimal", "numeric": "decimal", "money": "decimal",
        "smallmoney": "decimal", "real": "float", "float": "float", "bit": "boolean",
        "varchar": "text", "nvarchar": "text", "text": "text", "ntext": "text",
        "sysname": "text", "char": "char", "nchar": "char", "date": "date", "time": "time",
        "datetime": "timestamp", "datetime2": "timestamp", "smalldatetime": "timestamp",
        "datetimeoffset": "timestamptz", "binary": "binary", "varbinary": "binary",
        "image": "binary", "timestamp": "binary", "uniqueidentifier": "uuid",
        "json": "json", "xml": "xml",
    },
}  # fmt: skip

# Native types as describe() shows them, and what the adapters compared them as.
NATIVES = [
    ("mysql", "tinyint(1) unsigned", T.BOOLEAN),
    ("mysql", "tinyint(4)", T.INTEGER),
    ("mysql", "int unsigned", T.INTEGER),
    ("mysql", "decimal(12,4)", T.DECIMAL),
    ("mysql", "enum('a','b')", T.TEXT),
    ("mysql", "datetime(6)", T.TIMESTAMP),
    ("mysql", "bit(1)", T.UNSUPPORTED),
    ("mysql", "geometry", T.UNSUPPORTED),
    ("oracle", "NUMBER(10)", T.INTEGER),
    ("oracle", "NUMBER(5,-2)", T.INTEGER),
    ("oracle", "NUMBER(*,-2)", T.INTEGER),
    ("oracle", "INTEGER", T.INTEGER),
    ("oracle", "NUMBER(12,4)", T.DECIMAL),
    ("oracle", "NUMBER(*,2)", T.DECIMAL),
    ("oracle", "NUMBER", T.DECIMAL),
    ("oracle", "TIMESTAMP(6)", T.TIMESTAMP),
    ("oracle", "TIMESTAMP(3) WITH LOCAL TIME ZONE", T.TIMESTAMPTZ),
    ("oracle", "TIMESTAMP(9) WITH TIME ZONE", T.TIMESTAMPTZ),
    ("oracle", "VARCHAR2(4000)", T.TEXT),
    ("oracle", "INTERVAL DAY(2) TO SECOND(6)", T.UNSUPPORTED),
    ("oracle", "LONG", T.UNSUPPORTED),
    ("oracle", "SDO_GEOMETRY", T.UNSUPPORTED),
    ("sqlserver", "timestamp", T.BINARY),
    ("sqlserver", "varchar(max)", T.TEXT),
    ("sqlserver", "datetime2(7)", T.TIMESTAMP),
    ("sqlserver", "datetimeoffset(3)", T.TIMESTAMPTZ),
    ("sqlserver", "geography", T.UNSUPPORTED),
    ("postgresql", "ARRAY", T.UNSUPPORTED),
    ("postgresql", "hstore", T.UNSUPPORTED),
    ("postgresql", "character varying", T.TEXT),
]

# Every version shipped, and a digest of all it holds: alternatives and pairs included.
SHIPPED = {"1.0": "46712c041b6b7042"}


def _digest(m: TypeMap) -> str:
    entries = {
        e: {k: [str(r.canonical), *map(str, r.also)] for k, r in rules.items()}
        for e, rules in m.engines.items()
    }
    pairs = sorted([*sorted(map(str, t)), str(c)] for t, c in m.compatible)
    text = json.dumps({"engines": entries, "compatible": pairs}, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def test_default_map_reproduces_the_adapters_maps():
    for engine, entries in ADAPTER_MAPS.items():
        assert {k: str(r.canonical) for k, r in M.engines[engine].items()} == entries, engine
    for engine, native, expected in NATIVES:
        assert M.canonical(engine, native) is expected, (engine, native)
    assert oracle.canonical_type("NUMBER", None, 0) is T.INTEGER
    assert sqlserver.canonical_type("NVARCHAR") is T.TEXT


def test_type_keys():
    assert type_keys("mysql", "TinyInt(1)  Unsigned") == (
        "tinyint(1) unsigned", "tinyint(1)", "tinyint",
    )  # fmt: skip
    assert type_keys("mysql", "int") == ("int",)
    assert type_keys("oracle", "NUMBER(10)") == ("number(10)", "number(p)", "number")
    assert type_keys("oracle", "NUMBER(10,0)") == ("number(10)", "number(p)", "number")
    assert type_keys("oracle", "NUMBER(*,0)") == ("integer", "number(p)", "number")
    assert type_keys("oracle", "NUMBER(12,4)") == ("number(12,4)", "number(p,s)", "number")
    assert type_keys("oracle", "TIMESTAMP(6) WITH TIME ZONE") == (
        "timestamp(6) with time zone", "timestamp with time zone",
    )  # fmt: skip
    assert type_keys("sqlserver", "datetime2(7)") == ("datetime2(7)", "datetime2")
    assert type_keys("postgresql", "timestamp with time zone") == ("timestamp with time zone",)


def test_the_shipped_map_is_versioned():
    assert _digest(M) == SHIPPED.get(M.version), (
        "typemap.yaml changed: raise its version and add the new digest to SHIPPED"
    )
    if M.version == "1.0":  # what manifests from before the map was recorded were under
        assert {e: M.fingerprint(e) for e in M.engines} == V1_FINGERPRINTS


def test_a_fingerprint_is_what_decides_one_engines_comparison():
    mysql = M.fingerprint("mysql")
    engines = dict(M.engines)
    engines["mysql"] = dict(engines["mysql"], json=TypeRule(T.JSON, (T.TEXT,)))
    engines["oracle"] = dict(engines["oracle"], long=TypeRule(T.TEXT))
    other = replace(M, version="1.1", engines=engines)
    # an alternative allowed, another engine's entry, a version: nothing for MySQL
    assert other.fingerprint("mysql") == mysql
    assert other.fingerprint("oracle") != M.fingerprint("oracle")
    overridden = M.with_overrides({"mysql": {"tinyint(1)": "integer"}}, {"mysql"})
    assert overridden.fingerprint("mysql") != mysql
    assert overridden.fingerprint("postgresql") == M.fingerprint("postgresql")
    assert replace(M, compatible=M.compatible[:1]).fingerprint("mysql") != mysql


def test_overrides():
    both = {"mysql", "postgresql"}
    m = M.with_overrides({"mysql": {"TINYINT(1)": "integer", "datetime": "timestamptz"}}, both)
    assert m.canonical("mysql", "tinyint(1) unsigned") is T.INTEGER
    assert m.canonical("mysql", "datetime(6)") is T.TIMESTAMPTZ
    assert m.canonical("mysql", "tinyint(4)") is T.INTEGER
    assert m.default("mysql", "tinyint(1)") is T.BOOLEAN
    assert M.canonical("mysql", "tinyint(1)") is T.BOOLEAN  # the shipped map is unchanged
    # a more specific key wins: NUMBER(1) as boolean, every other NUMBER(p) as integer
    o = M.with_overrides({"oracle": {"NUMBER(1,0)": "boolean"}}, {"oracle"})
    assert o.canonical("oracle", "NUMBER(1)") is T.BOOLEAN
    assert o.canonical("oracle", "NUMBER(10)") is T.INTEGER
    o = M.with_overrides({"oracle": {"number(p)": "boolean", "NUMBER(10)": "integer"}},
                         {"oracle"})  # fmt: skip
    assert o.canonical("oracle", "NUMBER(1)") is T.BOOLEAN
    assert o.canonical("oracle", "NUMBER(10)") is T.INTEGER
    # and a more specific default beats a less specific override
    rules = {"tinyint(1)": "boolean", "tinyint": {"canonical": "integer", "also": ["decimal"]}}
    m = TypeMap.parse({"version": "x", "engines": {"mysql": rules}})
    m = m.with_overrides({"mysql": {"tinyint": "decimal"}}, {"mysql"})
    assert m.canonical("mysql", "tinyint(4)") is T.DECIMAL
    assert m.canonical("mysql", "tinyint(1)") is T.BOOLEAN

    assert m.record("mysql")["overrides"] == {"mysql": {"tinyint": "decimal"}}
    assert M.record("postgresql", "mysql", "mysql") == {
        "version": "1.0",
        "overrides": {},
        "fingerprints": {"mysql": V1_FINGERPRINTS["mysql"],
                         "postgresql": V1_FINGERPRINTS["postgresql"]},
    }  # fmt: skip
    assert legacy_record("mysql", "postgresql") == M.record("mysql", "postgresql")


@pytest.mark.parametrize(
    ("given", "says"),
    [
        (["mysql"], "database.type_map maps an engine"),
        ({"mysql": ["tinyint(1)"]}, "database.type_map maps an engine"),
        ({"db2": {"x": "integer"}}, "database.type_map.db2: not an engine"),
        ({"oracle": {"DATE": "date"}}, "neither the source nor the target is oracle"),
        ({"mysql": {"bool": "integer"}}, "database.type_map.mysql.bool: not a mysql type"),
        ({"mysql": {"datetime": "date"}},
         "mysql.datetime: datetime is compared as timestamp or timestamptz in type map 1.0, "
         "not date"),
        ({"mysql": {"tinyint(1)": "bool"}}, "boolean or integer in type map 1.0, not bool"),
        # columns are left out by ignore rules, which carry a reason (spec 9.12)
        ({"mysql": {"json": "unsupported"}}, "json is compared as json in type map 1.0"),
        ({"postgresql": {"boolean": "integer"}}, "boolean is compared as boolean in type map"),
        ({"mysql": {"tinyint(1)": None}}, "not None"),
    ],
)  # fmt: skip
def test_overrides_are_refused_beyond_the_alternatives(given, says):
    with pytest.raises(ConfigError) as e:
        M.with_overrides(given, {"mysql", "postgresql"})
    assert says in str(e.value)


def test_a_malformed_map_file_is_refused():
    def parse(entry, compatible=()):
        return TypeMap.parse(
            {"version": "9", "engines": {"mysql": entry}, "compatible": list(compatible)}
        )

    parse({"tinyint(1)": {"canonical": "boolean", "also": ["integer"]}})
    for bad in (
        {"tinyint(1)": {"canonical": "boolean", "also": ["boolean"]}},
        {"tinyint(1)": {"canonical": "boolean", "also": ["unsupported"]}},
        {"tinyint(1)": "bool"},
        {"TINYINT": "integer"},  # keys are written as type_keys makes them
    ):
        with pytest.raises(ValueError):
            parse(bad)
    with pytest.raises(ValueError):
        parse({}, [{"types": ["integer", "decimal"], "as": "text"}])
    with pytest.raises(ValueError):
        TypeMap.parse({"engines": {}})


def _schema(*columns, name="t"):
    return TableSchema(TableRef("public", name), [Column(n, nt, t) for n, nt, t in columns],
                       ["id"])  # fmt: skip


def _plan(source, target, **kw):
    return plan_table(source, target, rows=10, rows_per_bucket=5, precision=6, ignore=[], **kw)


ID = ("id", "integer", T.INTEGER)
MY_ID = ("id", "int", T.INTEGER)


def test_compatible_pairs_come_from_the_map():
    s = _schema(ID, ("code", "char(4)", T.CHAR), ("n", "NUMBER", T.DECIMAL),
                ("b", "boolean", T.BOOLEAN))  # fmt: skip
    t = _schema(ID, ("code", "text", T.TEXT), ("n", "bigint", T.INTEGER),
                ("b", "smallint", T.INTEGER))  # fmt: skip
    tp = _plan(s, t)
    assert dict(tp.plan.columns) == {"code": T.TEXT, "id": T.INTEGER, "n": T.DECIMAL}
    assert [(i.column, i.issue) for i in tp.issues] == [("b", "type_changed")]
    alone = replace(M, compatible=M.compatible[:1])  # without integer and decimal
    tp = _plan(s, t, type_map=alone)
    assert [i.column for i in tp.issues if i.issue == "type_changed"] == ["n", "b"]


def test_map_types():
    s = _schema(MY_ID, ("flag", "tinyint(1)", T.BOOLEAN), ("at", "datetime(6)", T.TIMESTAMP))
    same, none = map_types(s, "mysql", M, "source")
    assert same == s and none == []
    m = M.with_overrides({"mysql": {"tinyint(1)": "integer"}}, {"mysql"})
    mapped, over = map_types(s, "mysql", m, "source")
    assert [c.canonical for c in mapped.columns] == [T.INTEGER, T.INTEGER, T.TIMESTAMP]
    assert over == [TypeOverride("flag", "source", "tinyint(1)", "integer", "boolean")]
    assert s.columns[1].canonical is T.BOOLEAN  # the schema given is not changed
    # a stored baseline schema typed under an override no longer in the project file
    stored = _schema(MY_ID, ("flag", "tinyint(1)", T.INTEGER))
    mapped, over = map_types(stored, "mysql", M, "source")
    assert mapped.columns[1].canonical is T.BOOLEAN and over == []


def test_the_project_file_overrides_the_map(tmp_path):
    doc = {
        "project": "shop",
        "source": {"engine": "mysql", "host": "old.example", "database": "shop"},
        "target": {"engine": "postgresql", "host": "new.example", "database": "shop"},
    }
    path = tmp_path / "shop.yaml"
    path.write_text(yaml.safe_dump(doc))
    assert load_project(path).database.type_map is M
    doc["database"] = {"type_map": {"mysql": {"tinyint(1)": "integer"}}}
    path.write_text(yaml.safe_dump(doc))
    m = load_project(path).database.type_map
    assert m.canonical("mysql", "tinyint(1)") is T.INTEGER and m.version == M.version
    doc["database"] = {"type_map": {"oracle": {"DATE": "date"}}}
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError, match="neither the source nor the target is oracle"):
        load_project(path)


def test_a_baseline_records_its_type_map(tmp_path):
    record = M.with_overrides({"mysql": {"datetime": "timestamptz"}}, {"mysql"}).record("mysql")
    b = Baseline("b1", "mysql", {"type": "none"}, {}, "2026-10-01T00:00:00+00:00",
                 type_map=record)  # fmt: skip
    path = tmp_path / "manifest.json"
    b.save(path)
    assert Baseline.load(path).type_map == record
    d = json.loads(path.read_text())
    del d["type_map"]  # a manifest from before the map was recorded
    path.write_text(json.dumps(d))
    assert Baseline.load(path).type_map == legacy_record("mysql") == M.record("mysql")


def test_alternatives_render_alike_on_the_application_path():
    """The pushdown side of each is held to these by the engines' parity tests."""
    at = dt.datetime(2026, 1, 31, 13, 14, 15)
    assert oracle.prepare(at, T.DATE) == Verbatim("2026-01-31T13:14:15")
    assert render(oracle.prepare(at, T.DATE), T.DATE) == "2026-01-31T13:14:15"
    assert render(oracle.prepare(dt.datetime(2026, 1, 31), T.DATE), T.DATE) == "2026-01-31"
    assert render(oracle.prepare(dt.datetime(999, 1, 2, 3), T.DATE), T.DATE) == (
        "0999-01-02T03:00:00"
    )
    assert render(sqlserver.prepare(True, T.DECIMAL), T.DECIMAL) == "1"
    assert render(sqlserver.prepare(False, T.INTEGER), T.INTEGER) == "0"
    assert sqlserver.prepare(True, T.BOOLEAN) is True
