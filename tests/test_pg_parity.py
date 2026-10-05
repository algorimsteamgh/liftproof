"""Pushdown against fallback parity (Technical Spec 19).

The application side hash must produce byte identical values to the PostgreSQL
pushdown, for every type rule.
"""

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.adapters.postgres import PostgresAdapter
from liftproof.canonical import CanonicalType as T

pytestmark = pytest.mark.postgres

DDL = """
CREATE TABLE everything (
  id        bigint PRIMARY KEY,
  i2        smallint,
  num       numeric(12,4),
  flag      boolean,
  label     text,
  code      char(6),
  day       date,
  at_time   time(3),
  naive     timestamp(6),
  aware     timestamptz,
  blob      bytea,
  ref       uuid
);
INSERT INTO everything VALUES
 (1, 7, 10.5000, true, 'caf' || 'é', 'AB', '2026-01-31', '13:14:15.123',
  '2026-09-25 11:02:41.123456', '2026-09-25 13:02:41.5+02', '\\x00ff10',
  'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11'),
 (2, -1, -0.0000, false, 'cafe' || U&'\\0301', 'X     ', '1999-12-31', '00:00:00',
  '2000-01-01 00:00:00', '2000-01-01 00:00:00+00', '', '00000000-0000-0000-0000-000000000000'),
 (3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
 (4, 0, 'NaN', true, E'tab\\there\\u001fsep', '', '2026-02-28', '23:59:59.999',
  '2026-02-28 23:59:59.999999', '2026-02-28 23:59:59.999999-05', '\\xdeadbeef', NULL),
 (5, 32767, 12345678.9, false, '\\N', 'Z', '0001-01-01', '12:00', '1970-01-01', '1970-01-01+00',
  '\\x5c4e', NULL);
"""

COLUMNS = [
    ("aware", T.TIMESTAMPTZ), ("at_time", T.TIME), ("blob", T.BINARY), ("code", T.CHAR),
    ("day", T.DATE), ("flag", T.BOOLEAN), ("i2", T.INTEGER), ("id", T.INTEGER),
    ("label", T.TEXT), ("naive", T.TIMESTAMP), ("num", T.DECIMAL), ("ref", T.UUID),
]


@pytest.mark.parametrize("precision", [0, 3, 6])
@pytest.mark.parametrize("keyed", [True, False])
def test_pushdown_matches_fallback(make_db, adapter_for, precision, keyed):
    db, conn = make_db()
    conn.execute(DDL)
    a: PostgresAdapter = adapter_for(db)
    plan = HashPlan(TableRef("public", "everything"), COLUMNS, ["id"] if keyed else [], 3,
                    precision)
    pushed = a.bucket_aggregates(plan)
    fallback = a._bucket_aggregates_fallback(plan)
    assert pushed == fallback
    assert sum(b.count for b in pushed.values()) == 5

    rows_push = sorted(a.row_hashes(plan, set(range(3))))
    plan_json = HashPlan(plan.table, plan.columns, plan.key_columns, 3, precision)
    a._pushdown = lambda p: False  # force the fallback path
    rows_fb = sorted(a.row_hashes(plan_json, set(range(3))))
    assert rows_push == rows_fb


def test_describe_maps_types(make_db, adapter_for):
    db, conn = make_db()
    conn.execute(DDL)
    schema = adapter_for(db).describe(TableRef("public", "everything"))
    assert schema.primary_key == ["id"]
    got = {c.name: c.canonical for c in schema.columns}
    assert got == dict(COLUMNS)
