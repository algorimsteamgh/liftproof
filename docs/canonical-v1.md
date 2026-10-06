# Canonical encoding, version 1.0

This is the wire format that lets two database engines produce byte identical hashes
for the same data (Technical Spec section 9). It is normative. The Python reference
implementation is `src/liftproof/canonical/`; every engine pushdown must match it byte for
byte, and `tests/test_pg_parity.py` proves that for PostgreSQL. Every baseline records
`canonical_version` and `hash_algorithm`, and Liftproof refuses to compare baselines taken
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
MySQL sessions pin `time_zone='+00:00'`, `sql_mode='NO_ENGINE_SUBSTITUTION'` (so no
`ANSI_QUOTES`, `PIPES_AS_CONCAT` or `PAD_CHAR_TO_FULL_LENGTH`) and `utf8mb4`.

### MySQL type mapping and engine specific rules

| MySQL | Canonical | Note |
|---|---|---|
| tinyint(1) | boolean | MySQL's `BOOLEAN`; any non zero value is `1` |
| tinyint, smallint, mediumint, int, bigint (signed or unsigned), year | integer | |
| decimal | decimal | |
| float, double | float | statistical comparison only |
| varchar, text types, enum, set | text | enum and set as their label text |
| char | char | |
| date | date | |
| time | time | |
| datetime | timestamp (naive) | |
| timestamp | timestamptz | stored as UTC and read in a UTC session |
| binary, varbinary, blob types | binary | `binary(n)` keeps its zero padding, which is the stored value |
| json | json | always hashed application side |
| bit, geometry and the rest | unsupported | reported as not checked |

Values MySQL can store that no other engine can, rendered as MySQL prints them so that
they always show up as a difference against another engine rather than matching by
accident:

- zero and partial dates: `0000-00-00`, `2026-00-15`, and as timestamps
  `0000-00-00T00:00:00[.f]`;
- a `TIME` outside one day: `-01:02:03.5` renders `-01:02:03.500000` at precision 6,
  `125:00:00` renders `125:00:00`.

MySQL has no Unicode normalisation function, so a row whose text and char values are all
ASCII is hashed in the database and every other row is hashed application side; the two
are summed. The cost is proportional to the non-ASCII rows only.

Oracle sessions pin `TIME_ZONE='+00:00'` and `NLS_NUMERIC_CHARACTERS='.,'`; every
rendering uses an explicit format, so no other NLS setting matters.

### Oracle type mapping and engine specific rules

| Oracle | Canonical | Note |
|---|---|---|
| NUMBER(p), NUMBER(p,0), INTEGER, NUMBER(p,-s) | integer | |
| NUMBER(p,s), NUMBER | decimal | unconstrained NUMBER compares with an integer column (below) |
| FLOAT, BINARY_FLOAT, BINARY_DOUBLE | float | statistical comparison only; NaN and infinity counted for the binary types |
| VARCHAR2, NVARCHAR2, CLOB, NCLOB | text | LOB tables are hashed application side |
| CHAR, NCHAR | char | |
| DATE | timestamp (naive) | an Oracle DATE has a time of day; a target `date` column is reported as a type change |
| TIMESTAMP(n) | timestamp (naive) | nanoseconds are truncated to the precision, as everywhere |
| TIMESTAMP WITH TIME ZONE, WITH LOCAL TIME ZONE | timestamptz | converted to UTC |
| RAW, BLOB | binary | |
| JSON (21c and later) | json | always hashed application side |
| BOOLEAN (23ai) | boolean | |
| LONG, LONG RAW, INTERVAL, ROWID, XMLTYPE, spatial and the rest | unsupported | reported as not checked |

An integer column on one side and a decimal column on the other (the common Oracle
`NUMBER` to PostgreSQL `bigint` move) are both rendered as decimal: a whole number renders
identically under either rule, and a fraction lost in the move is a changed value.

Oracle stores the empty string as NULL. Text that is empty on the other engine and NULL in
Oracle is reported as a difference: it is one, and an application that tests for `''` or
`IS NULL` behaves differently after the move.

Oracle has no exact NFC function (`COMPOSE` composes without decomposing first) and SQL
strings stop at 4000 bytes, so a row is hashed in the database only when its text values
are plain ASCII of at most 3990 characters, its RAW values are at most 1995 bytes, and its
decimals print without an exponent. Every other row is hashed application side; the two
are summed.

### SQL Server type mapping and engine specific rules

SQL Server sessions pin `LANGUAGE us_english`, `DATEFORMAT ymd` and the ANSI settings;
every rendering uses an explicit `CONVERT` style, so no other setting matters.

| SQL Server | Canonical | Note |
|---|---|---|
| tinyint, smallint, int, bigint | integer | |
| decimal, numeric, money, smallmoney | decimal | |
| real, float | float | statistical comparison only; SQL Server stores no NaN or infinity |
| bit | boolean | |
| varchar, nvarchar, text, ntext | text | |
| char, nchar | char | |
| date | date | |
| time(n) | time | 100 ns digits are truncated to the precision |
| datetime | timestamp (naive) | hashed as shown, rounded to the millisecond (.003, .007), not as the 1/300 second tick it stores |
| datetime2(n), smalldatetime | timestamp (naive) | |
| datetimeoffset(n) | timestamptz | converted to UTC |
| binary, varbinary, image, rowversion | binary | rowversion values are never preserved by a migration; ignore the column |
| uniqueidentifier | uuid | |
| json (SQL Server 2025, Azure SQL) | json | always hashed application side |
| xml, sql_variant, geography, geometry, hierarchyid | unsupported | reported as not checked |

SQL Server has no NFC function and hashes `nvarchar` as UTF-16, so a row is hashed in the
database only when its text values are all characters U+0001 to U+007F (tested with a
binary collation). There is no length limit: `HASHBYTES` takes `varchar(max)`. Every other
row is hashed application side; the two are summed.

The default schema is `dbo`; a SQL Server `dbo` maps onto PostgreSQL `public` (or the MySQL
database) unless `database.schema_map` says otherwise.

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
- Engine specific rules still to be written with their adapters: SQL Server `datetime`
  rounding, Oracle empty string, negative zero in floats.
