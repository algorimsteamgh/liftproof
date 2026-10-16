# Canonical encoding, version 1.0

This is the wire format that lets two database engines produce byte identical hashes
for the same data (Technical Spec section 9). It is normative. The Python reference
implementation is `src/liftproof/canonical/`; every engine pushdown must match it byte for
byte, and `tests/test_pg_parity.py` proves that for PostgreSQL. Every baseline records
`canonical_version` and `hash_algorithm`, and Liftproof refuses to compare baselines taken
under a different version.

Changing the rendering of a value that already had one changes the golden vectors in
`tests/test_canonical.py` and requires a new `CANONICAL_VERSION`. Which canonical type a
native type is compared as is not a rendering rule: the per engine type tables below are the
type map's (see Type map), versioned on its own, and changing them alone needs a new type map
version, not a new `CANONICAL_VERSION`. A rule that only gives a rendering to values that had
none (they failed to load, hashed as NULL, or their columns were not compared) keeps the
version, adds golden vectors, and raises `CANONICAL_REVISION`, a whole number. Each
baseline table records the revision it was hashed under (`canonical_revision`; absent
means 0), and so do the report's run block and a run's checkpoint. A build refuses a
baseline holding a table of a newer revision than its own, and refuses to resume a run
started under another revision. A baseline table of an older revision is compared only
when nothing in it can render differently under the newer rules; otherwise it is reported
not checked, naming the baseline to take again. A column the older revision did not compare
at all is reported not checked on its own (`not_in_baseline`), and the rest of the table is
compared. Builds from before revisions do not read the field.

| Revision | Rule | An older baseline table is still compared when |
|---|---|---|
| 1 | PostgreSQL `infinity` and `-infinity` dates and timestamps (below) | it is not PostgreSQL, it has no date or timestamp column, its data ranges cover every one (reading the range of a column holding infinity failed then), or it has a JSON column (it was hashed application side, and loading infinity failed then) |
| 2 | XML columns: PostgreSQL `xml`, Oracle `XMLTYPE`, SQL Server `xml` (below) | always; its XML columns, which it recorded as unsupported, are reported not checked (`not_in_baseline`) until the baseline is taken again |

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
| decimal | fixed point, trailing zeros and a bare point stripped, no negative zero (`10.50` → `10.5`, `-0.00` → `0`), `NaN`, `Infinity`, `-Infinity` |
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
| xml | C14N 2.0 of the parsed value, less comments and whitespace only text, NFC (below) |

Every connection pins its session settings (PostgreSQL: `TimeZone=UTC`,
`DateStyle=ISO, YMD`, `extra_float_digits=3`, UTF-8 client encoding) and the manifest
records them.
MySQL sessions pin `time_zone='+00:00'`, `sql_mode='NO_ENGINE_SUBSTITUTION'` (so no
`ANSI_QUOTES`, `PIPES_AS_CONCAT` or `PAD_CHAR_TO_FULL_LENGTH`) and `utf8mb4`.

### Type map

Mapping a native type to a canonical type is a policy, not a fact (spec 9.13: `NUMBER(10,0)`
to integer, `tinyint(1)` to boolean). The mapping lives in
`src/liftproof/canonical/typemap.yaml`, version 1.0, shipped with the package; the engine
tables below are its defaults, which reproduce the mapping of the builds before it.

- **Lookup.** A native type, as each adapter reads it and the report shows it, is looked up
  by its keys, most specific first, each lower case with single spaces and none between
  its arguments (`NUMBER(1, 0)` is `number(1)`): the whole type
  (`tinyint(1) unsigned`, `timestamp(6) with time zone`); on MySQL the type with its
  arguments but without modifiers (`tinyint(1)`); on Oracle the class of a NUMBER
  (`number(p)` for NUMBER(p), NUMBER(p,0) and NUMBER(p,-s), `number(p,s)` for a positive
  scale); then the type without arguments (`tinyint`, `timestamp with time zone`,
  `datetime2`). A type with no entry is unsupported.
- **Alternatives.** An entry may list other canonical types the type can be compared as.
  Each renders alike in the engine's pushdown and in the reference implementation, and the
  engine's parity test proves that for every alternative in the file. Version 1.0 has these:

  | Engine | Native type | Default | Alternative | Rendered as |
  |---|---|---|---|---|
  | MySQL | tinyint(1) | boolean | integer | the stored number, so `2` is not `1`; as decimal against an exact number |
  | MySQL | datetime | timestamp | timestamptz | the stored values taken as UTC |
  | MySQL | timestamp | timestamptz | timestamp | the UTC values the session reads |
  | Oracle | NUMBER(p) | integer | boolean | `1` for any value but 0, `0` for 0 |
  | Oracle | DATE | timestamp | date | its date at midnight; with a time of day, a naive timestamp at whole seconds (`2026-01-31T13:14:15`), which no date equals |
  | SQL Server | bit | boolean | integer | `1` or `0`; as decimal against an exact number |

  PostgreSQL has none: its boolean and timestamps render differently in the database and
  in the reference implementation once typed otherwise, so the other side is mapped.
- **Overrides.** A project chooses alternatives under `database.type_map`, per engine of
  its source or target, keyed by the native type as the report shows it or by one of the
  keys above: `mysql: {tinyint(1): integer}`, `oracle: {NUMBER(1): boolean}`. At each key
  the project's choice comes before the default, so a choice for `NUMBER(1)` leaves
  `NUMBER(10)` alone. Nothing else is accepted: no type the file does not list, and not
  `unsupported` (an ignore rule leaves a column out, with the reason the report prints).
  Each table with a column compared otherwise than by default gets a notice naming the
  column, its side, its native type, the type it is compared as and the default.
- **Compatible pairs.** char with text compares as text (the strip rule only applies when
  both sides are fixed width), and integer with decimal as decimal. They are in the file
  and a project cannot change them.
- **Records.** A baseline manifest, a run's checkpoint and a report's run block record
  `type_map`: the version, the overrides and, per engine, a fingerprint of the mapping that
  applied (its defaults, the overrides and the pairs; not the alternatives allowed, another
  engine's entries or the version). `liftproof version` and the support bundle state the
  version. A manifest or checkpoint from before the map was recorded was taken under 1.0
  without overrides.
- **Changes.** Changing an entry, an alternative or a pair raises the file's version. A
  baseline is never refused for its map: its stored columns are typed again under the
  project's map, and a table whose plan then differs is hashed again from the live source,
  or reported not checked naming the columns the map compares otherwise. A baseline or a
  reconciliation is resumed only under a map with the same fingerprints. The alternatives'
  renderings are reached through the map alone: a build from before them types every column
  it reads by its default, so it never hashes one under an alternative.

### XML

XML columns are compared from revision 2. A value is rendered by the reference
implementation (`render.py`, ElementTree's C14N 2.0 writer behind expat) so that the same
document written by two engines, or by a migration tool, hashes alike:

1. Bytes are read as UTF-8. One leading XML declaration (`<?xml ...?>`, after an optional
   byte order mark and whitespace) is removed.
2. The value is parsed as content: any mix of elements, text, CDATA sections, processing
   instructions and comments at the top level, as PostgreSQL and SQL Server hold it. Only
   if that fails is it parsed as a document, which allows a DOCTYPE: entities declared in
   its internal subset are expanded and the DOCTYPE itself is not written. An external
   entity or DTD is never fetched.
3. It is written as C14N 2.0: elements as start and end tag pairs; attributes double
   quoted and sorted by `{namespace URI}local name`, those in no namespace first;
   character and entity references expanded and CDATA written as escaped text; line ends
   as `\n`; each namespace declared on the first element whose name or attributes use it,
   with the prefix already written for that URI on it or an ancestor, or else the
   innermost prefix the value bound to it there (a declaration is in scope to the end of
   its element, never for a sibling). Unused declarations are dropped.
4. Comments are dropped. Text that is only XML whitespace (space, tab, CR, LF) is dropped,
   except inside `xml:space="preserve"` (until a descendant sets `default`); any other
   text is kept exactly, leading and trailing whitespace included.
5. Each text run, attribute value and processing instruction's data is normalised to NFC
   on its own.
6. An `xsi:type` value of the form `prefix:name` (word characters only) is a qualified
   name: its prefix is resolved and declared as in 3. A prefix not in scope there is
   resolved only when it is one of ElementTree's well known prefixes (`xs`, `xsi`, `xml`,
   `html`, `rdf`, `wsdl`, `dc`).

So attribute order, quote style, `<x/>` against `<x></x>`, CDATA, indentation, comments,
where a namespace is declared and decomposed characters make no difference. A different
prefix for the same namespace, a default namespace against a prefix, an `xsi:type` naming
a different type, and any change of text or attribute value are differences.

A value that cannot be rendered under these rules (not well formed either way, not UTF-8,
an entity declared only in an external DTD such as XHTML's `&nbsp;`, an undeclared
`xsi:type` prefix, or entity expansion out of proportion to its size, which expat 2.4.1
and later refuses) takes its column out of the comparison for that table: the column is
reported not checked (`not_canonicalisable`) with the parser's reason, which names a line
and column (and an undefined entity's name) but never the text, and the rest of the table
is compared. A baseline taken
over such a value records the column as not hashed, with the reason. PostgreSQL stores
the XHTML entity in an `xml` column, and all three engines store the undeclared prefix.

No engine has a C14N function, so every table with an XML column is hashed application
side, fetching 25 rows at a time to bound memory (docs/kpis.md). An `xml` column against a
text column is a type change, as for json; MySQL has no XML type.

### PostgreSQL engine specific rules

PostgreSQL `date`, `timestamp` and `timestamptz` can hold `infinity` and `-infinity`, which
no other supported engine can store. They render as exactly those words, the way
PostgreSQL prints them, with no fraction at any precision (revision 1). Against PostgreSQL
they equal only the same infinity: never NULL, never each other, never a finite date,
which starts with a digit. Against another engine they are always a difference, so a
migration that mapped an open ended date to NULL or to a sentinel such as `9999-12-31`
reports each such row as a changed value; ignore the column if that mapping is intended.
The pushdown is `coalesce(<finite rendering>, c::text)`: `to_char` gives NULL for both
words, and their text form does not depend on `DateStyle`.

A database whose server encoding is not UTF8 (LATIN1, WIN1252) has no `normalize()`, and
`md5` there would hash its own bytes. Its text and char columns are read through the UTF8
client encoding and hashed application side; a table without them is still hashed in the
database. `tests/test_charset_pg.py` holds LATIN1 and WIN1252 databases to the hashes of
UTF8 ones.

### MySQL type mapping and engine specific rules

| MySQL | Canonical | Note |
|---|---|---|
| tinyint(1) | boolean | MySQL's `BOOLEAN`; any non zero value is `1`. Alternative: integer |
| tinyint, smallint, mediumint, int, bigint (signed or unsigned), year | integer | |
| decimal | decimal | |
| float, double | float | statistical comparison only |
| varchar, text types, enum, set | text | enum and set as their label text |
| char | char | |
| date | date | |
| time | time | |
| datetime | timestamp (naive) | Alternative: timestamptz, for a column holding UTC times; one holding local times then differs on every row |
| timestamp | timestamptz | stored as UTC and read in a UTC session. Alternative: timestamp (naive), the UTC values |
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
are summed. The cost is proportional to the non-ASCII rows only. The test for ASCII and
the rendering both go through `CONVERT(c USING utf8mb4)`, so a `latin1` (Windows-1252)
column, one byte per character, is held to the same rule (`tests/test_mysql_parity.py`).

Oracle sessions pin `TIME_ZONE='+00:00'` and `NLS_NUMERIC_CHARACTERS='.,'`; every
rendering uses an explicit format, so no other NLS setting matters.

### Oracle type mapping and engine specific rules

| Oracle | Canonical | Note |
|---|---|---|
| NUMBER(p), NUMBER(p,0), INTEGER, NUMBER(p,-s) | integer | Alternative for NUMBER(p): boolean, any value but 0 is `1` |
| NUMBER(p,s), NUMBER | decimal | unconstrained NUMBER compares with an integer column (below) |
| FLOAT, BINARY_FLOAT, BINARY_DOUBLE | float | statistical comparison only; NaN and infinity counted for the binary types |
| VARCHAR2, NVARCHAR2, CLOB, NCLOB | text | LOB tables are hashed application side |
| CHAR, NCHAR | char | |
| DATE | timestamp (naive) | an Oracle DATE has a time of day; a target `date` column is reported as a type change. Alternative: date, where a value with a time of day renders as a timestamp and so differs from every date |
| TIMESTAMP(n) | timestamp (naive) | nanoseconds are truncated to the precision, as everywhere |
| TIMESTAMP WITH TIME ZONE, WITH LOCAL TIME ZONE | timestamptz | converted to UTC |
| RAW, BLOB | binary | |
| JSON (21c and later) | json | always hashed application side |
| BOOLEAN (23ai) | boolean | |
| XMLTYPE | xml | read as `XMLSERIALIZE(CONTENT c AS CLOB NO INDENT)`, always hashed application side |
| LONG, LONG RAW, INTERVAL, ROWID, spatial and the rest | unsupported | reported as not checked |

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

Single-byte sources (WE8MSWIN1252, WE8ISO8859P1) need nothing more, and this is how the
Technical Specification's `CONVERT(col, 'AL32UTF8')` is met. The test for ASCII is
`ASCIISTR(c) = c`, which escapes every other character in any character set, so the only
rows hashed in Oracle are those whose bytes are the same in UTF-8. python-oracledb always
asks for AL32UTF8, so Oracle transcodes every other row before the reference
implementation hashes it. A test counting bytes against characters (`LENGTHB(c) =
LENGTH(c)`) would pass on AL32UTF8 and hash the Windows-1252 bytes of `é`;
`tests/test_charset_oracle.py` runs against a WE8MSWIN1252 database to catch that. A key
in `NVARCHAR2` or `NCHAR` is fetched for drill-down as itself, bound as `NVARCHAR`, since
`TO_CHAR` would turn a character outside the database character set into `¿`.

### SQL Server type mapping and engine specific rules

SQL Server sessions pin `LANGUAGE us_english`, `DATEFORMAT ymd` and the ANSI settings;
every rendering uses an explicit `CONVERT` style, so no other setting matters.

| SQL Server | Canonical | Note |
|---|---|---|
| tinyint, smallint, int, bigint | integer | |
| decimal, numeric, money, smallmoney | decimal | |
| real, float | float | statistical comparison only; SQL Server stores no NaN or infinity |
| bit | boolean | Alternative: integer (`1`, `0`) |
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
| xml | xml | always hashed application side; SQL Server stores a parsed form, without the declaration or whitespace only text |
| sql_variant, geography, geometry, hierarchyid | unsupported | reported as not checked |

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
