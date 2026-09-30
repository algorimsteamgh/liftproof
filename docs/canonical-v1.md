# Canonical encoding, version 1.0

This is the wire format that lets two database engines produce byte identical hashes
for the same data (Technical Spec section 9). It is normative. The Python reference
implementation is `src/certus/canonical/`; every engine pushdown must match it byte for
byte, and `tests/test_pg_parity.py` proves that for PostgreSQL. Every baseline records
`canonical_version` and `hash_algorithm`, and Certus refuses to compare baselines taken
under a different version.

Changing anything below changes the golden vectors in `tests/test_canonical.py` and
requires a new `CANONICAL_VERSION`.

## 1. Columns

- Columns are ordered by name, lower cased, compared as UTF-8 bytes. Physical order is
  ignored.
- Only the intersection of mapped columns is hashed. Ignored, missing, retyped and
  unsupported columns are excluded and named in the report (the table is then *partial*).
- Approximate numerics (float, double, real) are never hashed. They are compared per
  column by count, non-null count, min, max, sum and NaN/infinity counts under a relative
  tolerance.

## 2. Rendering (per canonical type)

| Type | Rule |
|---|---|
| integer | decimal digits, minus sign for negatives |
| decimal | fixed point, trailing zeros and a bare point stripped, no negative zero (`10.50` → `10.5`, `-0.00` → `0`), `NaN` |
| boolean | `1` / `0` (so PostgreSQL boolean and MySQL tinyint(1) agree) |
| text | UTF-8, Unicode NFC. No trimming, no case folding |
| char | as text, trailing spaces stripped; only when both sides are fixed width |
| date | `YYYY-MM-DD` |
| time | `HH:MM:SS[.f]` at the manifest precision |
| timestamp (naive) | `YYYY-MM-DDTHH:MM:SS[.f]` as stored, never converted; fraction truncated to the manifest precision |
| timestamptz | converted to UTC, then as naive |
| binary | lower case hex |
| uuid | lower case, hyphenated |
| json | keys sorted, no insignificant whitespace, NFC |

Every connection pins its session settings (PostgreSQL: `TimeZone=UTC`,
`DateStyle=ISO, YMD`, `extra_float_digits=3`, UTF-8 client encoding) and the manifest
records them.

## 3. Framing and hashing

```
frame(value) = ascii(byte_length(utf8(value))) 0x1F utf8(value)
frame(NULL)  = "-1" 0x1F
digest(col)  = lower_hex(MD5(frame))                        32 characters
group(g)     = lower_hex(MD5(concat of up to 32 column digests, in canonical order))
row_hash     = lower_hex(MD5(concat of group hashes))
v            = unsigned 64 bit integer of the first 16 hex characters of row_hash
aggregate    = ((SUM(v) as exact decimal) mod 2^64 + 2^64) mod 2^64, as 16 lower hex
bucket       = v(key_hash) mod N;  key_hash = the same pipeline over the key columns,
               or over the whole row when a table has no usable key
```

### Two deliberate departures from the Technical Specification draft

1. **NULL has its own frame.** The draft rendered NULL as the two characters `\N` with
   length 2. That collides with a text value that is literally `\N`: both frame to
   `2 0x1F \N`, so a NULL on one side and the string on the other would hash equal. A
   NULL frame of `-1 0x1F` can never equal any value's frame. There is a test for it.
2. **Each column is hashed on its own, and grouping is by column count (32), not by
   rendered bytes.** The draft grouped columns into chunks of at most 1000 rendered bytes
   but did not say whether that meant declared or actual width. Declared width breaks
   for a single wide column; actual width makes grouping depend on the data, which every
   engine would have to reproduce exactly. Hashing each column first makes every
   concatenation a fixed width string of hex digests (at most 32 × 32 = 1024 characters
   per group), which stays well inside Oracle's 4000 byte and SQL Server's 8000 byte
   limits whatever the data. It also yields per column digests for the drill-down at no
   extra cost, and LOBs need no special case in the encoding (an adapter still needs a
   way to MD5 a LOB, such as DBMS_CRYPTO on Oracle). The cost is more MD5 calls per row
   on the source; measure it against the throughput KPI.

## 4. Why each reduction step is written down

- MD5 is 128 bits; the first 8 bytes, big endian, unsigned, are the value. Stated so no
  adapter chooses differently.
- `SUM` of 64 bit integers overflows (SQL Server has no unsigned bigint); exact decimal
  does not.
- SQL and Python disagree on the sign of a modulo; the double modulo form gives the
  mathematical result in both.
- Sum, not XOR, so a lost pair of duplicate rows is still noticed.

## 5. Open for version 1.1

- SHA-256 as an alternative for FIPS hosts (MD5 is a hard error there). The pipeline is
  unchanged except the digest function; `v` still takes the first 8 bytes.
- Engine specific rules still to be written with their adapters: MySQL zero date,
  SQL Server `datetime` rounding, Oracle empty string, negative zero in floats.
