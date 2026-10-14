"""Canonical v1.0 rules, one test per rule (Technical Spec 19).

The golden vectors pin the wire format: if any of them changes, baselines taken by an
earlier build can no longer be compared, and CANONICAL_VERSION must be bumped. A rule that
only gives a rendering to values that had none adds vectors and raises CANONICAL_REVISION.
"""

import datetime as dt
import itertools
import json
import uuid
from decimal import Decimal

import pytest

from liftproof.canonical import (
    CANONICAL_REVISION,
    GROUP_SIZE,
    MOD64,
    Verbatim,
    aggregate,
    bucket_of,
    column_digest,
    frame,
    reduce_total,
    render,
    row_hash,
    value64,
)
from liftproof.canonical import (
    CanonicalType as T,
)
from liftproof.canonical.render import RenderError
from liftproof.errors import ConfigError
from liftproof.reconcile.baseline import Baseline, BaselineTable, hashed_infinity_as_null


# -- rendering (9.4) ---------------------------------------------------------------
@pytest.mark.parametrize(
    "value, expected",
    [
        (Decimal("10.50"), "10.5"),
        (Decimal("10.00"), "10"),
        (Decimal("-0.000"), "0"),
        (Decimal("0E-10"), "0"),
        (Decimal("-12.340"), "-12.34"),
        (Decimal("1E+3"), "1000"),
        (Decimal("12345678901234567890.123"), "12345678901234567890.123"),
        (Decimal("NaN"), "NaN"),
        (Decimal("Infinity"), "Infinity"),
        (Decimal("-Infinity"), "-Infinity"),
        (7, "7"),
    ],
)
def test_exact_numerics(value, expected):
    assert render(value, T.DECIMAL) == expected


def test_integers_and_booleans_agree_across_engines():
    assert render(True, T.BOOLEAN) == render(1, T.BOOLEAN) == "1"  # pg boolean, mysql tinyint
    assert render(False, T.BOOLEAN) == "0"
    assert render(-42, T.INTEGER) == "-42"


def test_strings_are_nfc_and_never_trimmed_or_folded():
    decomposed = "café"
    assert render(decomposed, T.TEXT) == "café"
    assert render("  Mixed Case  ", T.TEXT) == "  Mixed Case  "


def test_fixed_width_char_strips_trailing_spaces_only():
    assert render("  AB    ", T.CHAR) == "  AB"


def test_empty_string_is_not_null():
    # Oracle treats '' as NULL; the canonical form must not.
    assert column_digest(render("", T.TEXT)) != column_digest(None)


def test_timestamps():
    naive = dt.datetime(2026, 9, 25, 11, 2, 41, 123456)
    assert render(naive, T.TIMESTAMP) == "2026-09-25T11:02:41.123456"
    assert render(naive, T.TIMESTAMP, precision=3) == "2026-09-25T11:02:41.123"  # truncated
    assert render(naive, T.TIMESTAMP, precision=0) == "2026-09-25T11:02:41"
    aware = dt.datetime(2026, 9, 25, 13, 2, 41, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    assert render(aware, T.TIMESTAMPTZ, precision=0) == "2026-09-25T11:02:41"
    with pytest.raises(RenderError):
        render(naive, T.TIMESTAMPTZ)
    with pytest.raises(RenderError):
        render(aware, T.TIMESTAMP)


@pytest.mark.parametrize("ctype", [T.DATE, T.TIMESTAMP, T.TIMESTAMPTZ])
@pytest.mark.parametrize("precision", [0, 3, 6])
def test_postgres_infinity_dates(ctype, precision):
    # as PostgreSQL prints them, with no fraction: never NULL, never each other, never a
    # finite date (which starts with a digit)
    for word in ("infinity", "-infinity"):
        assert render(Verbatim(word), ctype, precision=precision) == word
    digests = {column_digest(v) for v in ("infinity", "-infinity", None, "9999-12-31")}
    assert len(digests) == 4


def test_binary_uuid_json():
    assert render(b"\x00\xff", T.BINARY) == "00ff"
    u = "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11"
    assert render(u, T.UUID) == render(uuid.UUID(u), T.UUID) == u.lower()
    # jsonb reorders keys and strips whitespace, json does not: canonical form agrees
    assert render('{"b": 1, "a": [1, 2]}', T.JSON) == render({"a": [1, 2], "b": 1}, T.JSON)
    assert render({"a": 1}, T.JSON) == '{"a":1}'


def test_floats_are_not_hashed():
    with pytest.raises(RenderError):
        render(1.5, T.FLOAT)
    assert not T.FLOAT.hashed


# -- framing (9.3) -----------------------------------------------------------------
def test_frame_layout():
    assert frame("ab") == b"2\x1fab"
    assert frame("é") == b"2\x1f\xc3\xa9"  # length in bytes, not characters
    assert frame(None) == b"-1\x1f"


def test_null_never_equals_any_string():
    # The spec's draft rendered NULL as backslash N, which collides with that string.
    for s in ["\\N", "-1", "", "-1\x1f", "NULL"]:
        assert column_digest(s) != column_digest(None)


def test_encoding_is_injective_on_adversarial_rows():
    alphabet = ["", "a", "b", "ab", "\x1f", "1\x1fa", "\\N", None, "2", "a\x1f"]
    seen = {}
    for row in itertools.product(alphabet, repeat=3):
        h = row_hash(row)
        assert seen.setdefault(h, row) == row, f"collision: {row} vs {seen[h]}"


def test_grouping_depends_on_column_count_only():
    wide = [str(i) for i in range(GROUP_SIZE * 3 + 5)]
    long_values = [v * 5000 for v in wide]
    assert row_hash(wide) != row_hash(long_values)
    assert len(row_hash(long_values)) == 32


# -- reduction and aggregation (9.7) -----------------------------------------------
def test_value64_is_unsigned_big_endian_prefix():
    assert value64("ffffffffffffffff" + "0" * 16) == MOD64 - 1
    assert value64("0000000000000001" + "f" * 16) == 1


def test_mathematical_modulo_handles_negative_totals():
    assert reduce_total(-1) == "ffffffffffffffff"
    assert reduce_total(MOD64 + 5) == "0000000000000005"


def test_sum_not_xor_duplicates_do_not_cancel():
    h = row_hash(["x"])
    assert aggregate([h, h]) != aggregate([])


def test_aggregate_is_order_independent():
    hashes = [row_hash([str(i)]) for i in range(100)]
    assert aggregate(hashes) == aggregate(reversed(hashes))


def test_bucket_assignment_is_stable():
    h = row_hash(["42"])
    assert bucket_of(h, 25) == value64(h) % 25


# -- golden vectors ----------------------------------------------------------------
def test_golden_vectors():
    assert column_digest(None) == "17cfae03daf830ae90681326cbbc5a3d"
    assert column_digest("1") == "709a682b7c78647bae9a429ad449965a"
    a = row_hash(["1", "DISPATCHED", None])
    b = row_hash(["2", "OPEN", None])
    assert a == "76fc102734908db654e63701c08f3b38"
    assert aggregate([a, b]) == "5ef4b266564d16d3"


def test_golden_vectors_of_revision_1():
    assert CANONICAL_REVISION >= 1
    assert column_digest("infinity") == "4090a77607bb447150404f8a998bba1a"
    assert column_digest("-infinity") == "418090c1b3d71ee0febfff882916eac7"


# -- revisions in baselines ----------------------------------------------------------
def _entry(columns, revision=None, entry_ranges=None):
    d = {
        "columns": [[n, t, t, False] for n, t in columns],
        "primary_key": ["id"],
        "plan": {"columns": columns, "key_columns": ["id"], "buckets": 1, "precision": 6},
        "row_count": 1,
        "bucket_aggregates": {"0": [1, "5"]},
        "completed_at": "2026-10-01T00:00:00+00:00",
    }
    if revision is not None:
        d["canonical_revision"] = revision
    if entry_ranges is not None:
        d["ranges"] = entry_ranges
    return d


def test_entries_that_may_hold_infinity_hashed_as_null():
    dated = [["id", "integer"], ["valid_from", "date"], ["valid_to", "timestamptz"]]
    both = {"id": [1, 9], "valid_from": ["2026-01-01", "2026-02-01"], "valid_to": [None, None]}

    def stale(engine, d):
        return hashed_infinity_as_null(engine, BaselineTable.from_dict("public.t", d))

    assert stale("postgresql", _entry(dated))  # before ranges: nothing shows it held none
    assert stale("postgresql", _entry(dated, 0, {"valid_from": both["valid_from"]}))
    assert not stale("postgresql", _entry(dated, 0, both))  # reading the ranges would fail
    assert not stale("postgresql", _entry(dated, 1))
    assert not stale("mysql", _entry(dated))
    assert not stale("postgresql", _entry([["id", "integer"], ["name", "text"]]))
    # hashed here: loading infinity failed
    assert not stale("postgresql", _entry([*dated, ["doc", "json"]]))

    entry = BaselineTable.from_dict("public.t", _entry(dated))
    assert entry.canonical_revision == 0
    entry.canonical_revision = CANONICAL_REVISION
    assert entry.to_dict()["canonical_revision"] == CANONICAL_REVISION


def test_a_baseline_from_a_newer_revision_is_refused(tmp_path):
    # refused before its tables are read: a later revision may hash types this build lacks
    path = tmp_path / "manifest.json"
    later = _entry([["id", "integer"], ["doc", "a type from later"]], CANONICAL_REVISION + 1)
    doc = {
        "baseline_id": "b9", "canonical_version": "1.0", "hash_algorithm": "md5",
        "product_version": "9", "engine": "postgresql", "consistency": {}, "session": {},
        "taken_at": "2026-10-01T00:00:00+00:00", "selection": ["public.t"],
        "tables": {"public.t": later},
    }  # fmt: skip
    path.write_text(json.dumps(doc))
    newer = f"canonical revision {CANONICAL_REVISION + 1}; this build knows revision"
    with pytest.raises(ConfigError, match=newer):
        Baseline.load(path)
    doc["tables"]["public.t"] = _entry([["id", "integer"]], CANONICAL_REVISION)
    path.write_text(json.dumps(doc))
    assert Baseline.load(path).tables["public.t"].canonical_revision == CANONICAL_REVISION
