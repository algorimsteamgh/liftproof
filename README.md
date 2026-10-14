# Liftproof

Migration validation for workloads moving to AWS. Liftproof records how an application and
its database behave before a migration, checks the same behaviour afterwards, and
produces the report a release manager signs at go live.

This repository is being built against the *Migration Validation Tool* PRD and Technical
Specification (Draft 1). Supported databases: PostgreSQL (13 and later, including RDS and Aurora), MySQL (8.0 and
later, including Aurora MySQL 3; not MariaDB), Oracle (19c and later, including RDS for
Oracle) and SQL Server (2016 and later, including RDS for SQL Server and Azure SQL), as
source or target, in any combination. An older server is refused when Liftproof connects. Built so far: the database core, PRD F2 (baseline), F6 (reconcile), F8/F9 (reports),
F11 (CLI and exit codes), F14 (credentials) and F15 (storage); and record and replay,
F1 (record), F3 (replay), F4 (user interface comparison), F5 (API comparison) and F16
(response times).

## Quick start (development)

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
liftproof init acme                   # writes acme.yaml; no credentials go in it
liftproof doctor --project acme.yaml  # connections, versions, read only source, TLS, S3, KMS, endpoints
liftproof baseline --project acme.yaml
liftproof reconcile --project acme.yaml --baseline latest
# after cutover: the target becomes the reference for scheduled regression
liftproof rebaseline --project acme.yaml
liftproof reconcile --project acme.yaml --baseline latest-target
# something wrong? one file for the support ticket, values redacted
liftproof support-bundle --project acme.yaml --doctor
```

## Performance

KPIs, thresholds and how each is measured are in `docs/kpis.md`; `pytest -m perf` runs
the suite that gates every release.

## Protecting the source

The source is usually production, and the one machine Liftproof must not saturate. Point
`source` at a read replica where there is one: an RDS or Aurora reader, a PostgreSQL hot
standby, a MySQL replica, an Oracle Active Data Guard standby or a readable availability
group secondary. On a PostgreSQL hot standby turn on `hot_standby_feedback`, or set
`max_standby_streaming_delay` above the longest statement; otherwise the standby cancels
the hash queries that conflict with replication.

Each connection has its own limits, whole numbers where 0 turns one off:

| Setting | Source default | Target default | What it limits |
|---|---|---|---|
| `rows_per_second` | 75000 | 0 | rows read a second by one connection, over its statements |
| `pause_ms` | 100 | 0 | the least time between two statements on a connection |
| `lock_timeout_ms` | 10000 | 10000 | how long a read waits for a lock before the run fails |
| `statement_timeout_ms` | 0 (`init` writes 600000) | 0 | how long one statement may run |

Every statement that reads a table is charged the table's rows: the row count, the bucket
aggregate (the whole table, whatever row rules or a sample keep), the data ranges, each
float column's statistics, each pass of a drill-down and the fetch of changed rows'
values. A connection pays before its next statement, so nothing waits after the last one,
and idle time earns no credit. The database runs each statement at its own speed, which
`statement_timeout_ms` bounds; rows Liftproof hashes itself (JSON columns, and rows with
non-ASCII text outside PostgreSQL) are charged as they stream, which slows the read
itself. On MySQL, SQL Server and Oracle a table with text (on Oracle also exact numbers or
binary) is hashed in two statements, each a read of the table: the rows the database
renders exactly, then the rest, streamed here. Its aggregate and each drill-down pass are
charged twice, with the pause between. A capped connection runs each statement on one core
(PostgreSQL `max_parallel_workers_per_gather = 0`, SQL Server `OPTION (MAXDOP 1)`, Oracle
`DISABLE PARALLEL QUERY`, MySQL `innodb_parallel_read_threads = 1`), so the load is the
cap times `database.workers`, each worker being another connection. With the defaults a
matched table costs three reads (count, aggregate, ranges; `database.ranges: false` saves
one), so a source connection gets through at most 1.5 million rows of table a minute
(PostgreSQL measured about 1.2 million, docs/kpis.md); one whose aggregate takes two costs
four. The pause falls between tables, and between the buckets a drill-down reads one pass
at a time: on MySQL, Oracle and SQL Server, and for tables without a key everywhere.
PostgreSQL drills into every differing bucket in one pass and is not paused inside it.

The lock timeout is PostgreSQL's `lock_timeout`, SQL Server's `SET LOCK_TIMEOUT` (0 in
the project file is SQL Server's -1, wait), and MySQL's `lock_wait_timeout` in whole
seconds rounded up, which covers metadata locks. Oracle queries take no locks, so there
is nothing to set. A read that times out fails the run with exit code 2 and `--resume`
carries on; raise the timeout, or set 0 to wait as long as it takes. A live comparison on
SQL Server reads under READ COMMITTED, taking shared locks that wait for writers, unless
READ_COMMITTED_SNAPSHOT is on.

Slowing the reads has costs of its own. Everything that holds a snapshot lasts longer: a
baseline (one snapshot over every table) and PostgreSQL's drill-down cursor. Meanwhile
PostgreSQL keeps dead rows (bloat), Oracle needs undo to cover it (ORA-01555 when
`undo_retention` is too short), SQL Server keeps row versions in tempdb, and MySQL's purge
falls behind. On PostgreSQL and MySQL an `ALTER TABLE` waits for the lock a read holds on
the table (a baseline holds them to its end), and every later query of that table queues
behind the `ALTER`: keep schema changes and baselines apart, or give the DDL session its
own lock timeout.

The databases' own governors: on SQL Server, `QUERY_GOVERNOR_COST_LIMIT` is not set,
because the hash queries' estimated cost grows with the table and the governor would
refuse them outright rather than slow them; a Resource Governor workload group, with a
classifier on `APP_NAME() = 'liftproof'` and a pool with `CAP_CPU_PERCENT`, limits them
instead. On Oracle, Resource Manager can map the sessions to a consumer group by
`CLIENT_PROGRAM` `liftproof` (`DBMS_RESOURCE_MANAGER.SET_CONSUMER_GROUP_MAPPING`).
PostgreSQL and MySQL have no governor; a replica is how the load stays off the primary.

After cutover the target is production: give `target` a cap and a pause too, before
`rebaseline` and scheduled regression runs. The report's run block records the limits of
each database the run read, as its connections apply them (`source_protection`: MySQL's
lock timeout rounded up to whole seconds, Oracle's not applicable; no `source` entry when
the source was not read).

## Record and replay

```bash
liftproof record   --project acme.yaml --journey checkout --start /login --story ORD-14
liftproof bind     --project acme.yaml --journey checkout --token @@REDACTED_1a2b3c4d \
                   --secret-arn arn:aws:secretsmanager:REGION:ACCOUNT:secret:app-login --key password
liftproof replay   --project acme.yaml                  # every journey, against web.target_url
liftproof smoke    --project acme.yaml --journeys checkout
liftproof validate --project acme.yaml                  # reconcile, then replay, one report
```

`record` opens a Chromium window on `web.source_url`; carry out the journey and close the
window. Passwords become random tokens before anything is written; `bind` points each
token at a Secrets Manager secret for replay. Values the server generates (order ids,
CSRF tokens, ASP.NET view state) are detected as correlations, substituted forward at
replay, and never reported as differences.

## Files

```bash
liftproof files    --project acme.yaml                  # every file set in the project
liftproof files    --project acme.yaml --sets invoices
```

Each file set pairs a source location with a target location: a path on the instance (a
local disk, or an NFS or SMB share mounted read only) or an `s3://bucket/prefix`. Files
are paired by relative path and compared by size and SHA-256; both hashes are reported.
When the bytes differ, PDF, JSON, CSV and plain text files are also compared as text: the
same text with different bytes (a regenerated PDF, Windows line endings, a new encoding)
is a low severity difference that says why, and different text is located to the page,
line, or row and column. What the text says stays out of the report unless the set sets
`show_content: true`. `validate` compares files after reconciling and before replaying.
A bucket in AWS is read with the instance role. An S3 compatible store outside AWS is
given as `{location: s3://..., endpoint_url: https://..., secret_arn: ...}`, with its
access key pair in that secret (keys `access_key_id` and `secret_access_key`).

## Scheduled and pipeline runs

```bash
liftproof schedule --project acme.yaml     # the project's schedules and their next run
liftproof runs     --project acme.yaml     # run history, newest first (from S3 too)
```

A project file can carry `schedules:` (a name, a five field cron expression, a time zone
and the command to run). The `mvt-scheduler.service` on the instance starts each run when
it falls due. Runs of one project never overlap: a second run is refused with exit code
2, and a scheduled run that finds the previous one still going is skipped and recorded as
a run with an error finding and a `ScheduledRunSkipped` CloudWatch metric. CI and CD
pipelines start runs through the SSM document; see [docs/pipelines.md](docs/pipelines.md).

## When the instance is lost

Nothing irreplaceable stays on the instance. Every run copies its project file to the
bucket; a reconciliation sends its findings there at least every minute and checkpoints
its finished tables, and a baseline checkpoints its manifest the same way. On a
replacement instance pointed at the same bucket, `mvt-restore.service` writes the
project files back at first boot, `liftproof runs` and the UI list every run and journey
in the bucket, and an interrupted run carries on from its last checkpoint:

```bash
liftproof reconcile  --project acme.yaml --resume   # the newest unfinished reconciliation
liftproof baseline   --project acme.yaml --resume   # the newest unfinished baseline
liftproof restore    --projects-dir /var/lib/mvt/projects   # what the service runs
```

A resumed run compares only the tables it had not finished and keeps the run id, the
reference baseline and the sampling of the first attempt; its report says when it
resumed. Against a live source, the tables compared after the resume are read as of the
resume. The lost instance's run lock expires 15 minutes after its last renewal; until
then a resume is refused with exit code 2. A resume on a build that hashes under another
canonical revision (docs/canonical-v1.md) is refused with exit code 3: start a new run. A
run that fails rather than stops names each table, file set and journey it never reached
as not checked.

## Exit codes

| Code | Meaning | Pipeline action |
|---|---|---|
| 0 | completed, no differences | continue the cutover |
| 10 | completed, differences found | stop; a human reads the report |
| 2 | run failed; not a verdict | stop |
| 3 | configuration or connection error; nothing validated | fix the setup |
| 1 | reserved; a crash is mapped to 2 | treat as 2 |

`--fail-on never` returns 0 even when differences exist.

## Flags, logs and the report

`--format`, `--log-level`, `--workdir` and `--fail-on` work before or after the command
name (`liftproof --format json reconcile ...`). Logs are JSON lines on stderr and in
`/var/log/mvt/liftproof.log`; a log file that cannot be opened only costs the file.
`--log-level debug` adds each SQL statement sent to either database (the text, never its
parameters) and the locator each replay step used.

The report's range block says what was compared: the journeys and API endpoints, the
schemas and tables, the run window and, per table and side, the lowest and highest key
and the earliest and latest value of each date and time column of the rows compared
(`data_ranges`). Those are aggregates of integer keys and dates only; a text key's ends
appear only with `show_values`. `database.ranges: false` turns them off, saving one
MIN/MAX statement per table and side. A PostgreSQL date or timestamp can be `infinity` or
`-infinity`, shown and compared as those words: never equal to NULL or to a sentinel date
on the other side. The run block records the canonical version and revision the run
hashed under. `liftproof report --run ID` rebuilds the HTML and JSON from the run's
findings and keeps what the run was (its reference, window, schedule and who ran it),
adding when it was regenerated.

## Tests

`pytest` runs everything. Record and replay tests need Chromium
(`python -m playwright install chromium`, or point `LIFTPROOF_CHROMIUM` at a binary) and run
against a small shop application in `tests/webapp.py` that is served twice, once changed.
Database tests need PostgreSQL, MySQL, Oracle and SQL Server: set
`LIFTPROOF_TEST_PG_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `LIFTPROOF_TEST_MYSQL_HOST`,
`_PORT`, `_USER`, `_PASSWORD` and `LIFTPROOF_TEST_ORACLE_HOST`, `_PORT`, `_SERVICE`,
`_USER`, `_PASSWORD`, and `LIFTPROOF_TEST_MSSQL_HOST`, `_PORT`, `_USER`, `_PASSWORD` (CI uses
service containers; for Oracle, `gvenzl/oracle-free:23-slim-faststart`, for SQL Server,
`mcr.microsoft.com/mssql/server:2022-latest`); they are skipped when no server is reachable.
Cross engine tests load the same data into each engine and require identical hashes. The suite includes the golden vectors that pin the
canonical wire format, pushdown against fallback parity for every type rule, and the
PRD F6 acceptance test (a ten row injected difference, reported exactly).

## Layout

```
src/liftproof/canonical   canonical v1.0 encoding and hashing (docs/canonical-v1.md)
src/liftproof/adapters    one adapter per database engine
src/liftproof/reconcile   planning, baselines, reconciliation
src/liftproof/web         recorder, replay engine, UI and API comparison
src/liftproof/files       file sources (paths, S3), text extraction, file comparison
src/liftproof/report      JSON and self contained HTML reports
src/liftproof/cli.py      the product's complete interface
docs/decisions.md      defaults chosen where the spec leaves a choice open
```
