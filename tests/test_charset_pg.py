"""Single-byte PostgreSQL databases (Technical Spec 9.3, 19).

A database whose server encoding is LATIN1 or WIN1252 stores every character in one byte
and has no normalize(). The same data there and in a UTF8 database must give identical
hashes, and a reconcile between them must report exactly the injected differences.
"""

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import column_digest, render
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler

pytestmark = pytest.mark.postgres

N = 300

# every character the encoding has beyond ASCII (WIN1252 leaves five bytes undefined), and
# the canonical digest of all of them as one value: the same in every encoding
CHARACTERS = {
    "LATIN1": (bytes(range(0xA0, 0x100)).decode("latin-1"), "1c2615f7d720f2641fea65c569902115"),
    "WIN1252": (
        bytes(b for b in range(0x80, 0x100) if b not in {0x81, 0x8D, 0x8F, 0x90, 0x9D}).decode(
            "cp1252"
        ),
        "01453c2597defb988d9ac5722020ed2c",
    ),
}

DDL = """
CREATE TABLE items (
  code text PRIMARY KEY, name varchar(4000), fixed char(8), body text, n integer, at date
)"""

COLUMNS = [("code", T.TEXT), ("name", T.TEXT), ("fixed", T.CHAR), ("body", T.TEXT),
           ("n", T.INTEGER), ("at", T.DATE)]  # fmt: skip


def _rows(encoding: str):
    chars, _ = CHARACTERS[encoding]
    for i in range(1, N + 1):
        ch = chars[i % len(chars)]
        name = [f"plain {i}", f"Café crème {i} {ch}", f"back\\slash {i}", chars][i % 4]
        yield (
            f"K{i}" if i % 3 == 0 else f"{ch}-{i}",  # most keys are not ASCII
            name,
            None if i % 7 == 0 else ("Été" if i % 2 else "ab"),
            None if i % 5 == 0 else name[::-1],
            i,
            f"2026-01-{i % 28 + 1:02d}",
        )


@pytest.fixture(params=["LATIN1", "WIN1252"])
def single_byte(request, make_db, adapter_for):
    """(encoding, single-byte adapter, its connection, UTF8 adapter, its connection)"""
    encoding = request.param
    out = []
    for enc in (encoding, "UTF8"):
        db, conn = make_db("cs", enc)
        conn.execute(DDL)
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO items VALUES (%s, %s, %s, %s, %s, %s)", _rows(encoding))
        out += [adapter_for(db), conn]
    return (encoding, *out)


def test_the_database_stores_one_byte_per_character(single_byte):
    encoding, _, conn, _, utf8 = single_byte
    q = "SELECT max(octet_length(name) - length(name)) FROM items"
    assert conn.execute(q).fetchone() == (0,)
    assert utf8.execute(q).fetchone()[0] > 0
    assert conn.execute("SHOW server_encoding").fetchone() == (encoding,)


@pytest.mark.parametrize("keyed", [True, False])
def test_same_hashes_as_utf8(single_byte, keyed):
    _, a, _, b, _ = single_byte
    plan = HashPlan(TableRef("public", "items"), COLUMNS, ["code"] if keyed else [], 7)
    assert b._pushdown(plan)
    aggregates = a.bucket_aggregates(plan)
    assert aggregates == b.bucket_aggregates(plan)
    assert sum(x.count for x in aggregates.values()) == N
    assert sorted(a.row_hashes(plan, set(range(7)))) == sorted(b.row_hashes(plan, set(range(7))))
    assert a.drill_passes(plan, 7) == 7 and b.drill_passes(plan, 7) == 1


def test_a_value_of_every_character_has_the_golden_digest(single_byte):
    encoding, a, _, b, _ = single_byte
    chars, golden = CHARACTERS[encoding]
    key = f"{chars[7 % len(chars)]}-7"  # row 7's name is every character
    plan = HashPlan(TableRef("public", "items"), COLUMNS, ["code"], 1)
    for adapter in (a, b):
        [row] = adapter.fetch_rows(plan, [(key,)]).values()
        assert column_digest(render(row[1], T.TEXT)) == golden


def test_tables_without_text_are_still_hashed_in_the_database(single_byte):
    _, a, _, b, _ = single_byte
    plan = HashPlan(TableRef("public", "items"), [("n", T.INTEGER), ("at", T.DATE)], ["n"], 7)
    assert a._pushdown(plan)
    assert a.bucket_aggregates(plan) == b.bucket_aggregates(plan)


def _run(tmp_path, source, target):
    writer = FindingWriter(tmp_path / "findings", "r-x")
    options = ReconcileOptions(schemas=["public"], rows_per_bucket=50)
    result = Reconciler(target, writer, options, source=source).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


@pytest.mark.parametrize("direction", ["to_utf8", "from_utf8"])
def test_reconcile_reports_exactly_the_injected_differences(tmp_path, single_byte, direction):
    encoding, a, ac, b, bc = single_byte
    source, target, changed = (a, b, bc) if direction == "to_utf8" else (b, a, ac)
    result, findings = _run(tmp_path / "same", source, target)
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]

    chars, _ = CHARACTERS[encoding]
    changed.execute("DELETE FROM items WHERE n = 17")
    changed.execute("UPDATE items SET name = replace(name, 'é', 'e') WHERE n = 25")
    changed.execute("UPDATE items SET fixed = 'Ete' WHERE n = 31")
    result, findings = _run(tmp_path / "changed", source, target)
    [items] = result.tables
    assert (items.missing_rows, items.changed_rows, items.extra_rows) == (1, 2, 0)
    columns = {(f.column, f.locator) for f in findings if f.kind == Kind.DIFFERENCE and f.column}
    assert columns == {
        ("name", f"code = {chars[25 % len(chars)]}-25"),
        ("fixed", f"code = {chars[31 % len(chars)]}-31"),
    }
