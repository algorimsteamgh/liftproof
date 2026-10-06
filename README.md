# Liftproof

Migration validation for workloads moving to AWS. Liftproof records how an application and
its database behave before a migration, checks the same behaviour afterwards, and
produces the report a release manager signs at go live.

This repository is being built against the *Migration Validation Tool* PRD and Technical
Specification (Draft 1). Supported databases: PostgreSQL, MySQL (8.0 and later, including Aurora), Oracle (19c and later, including RDS for Oracle)
and SQL Server (2016 and later, including RDS for SQL Server and Azure SQL), as source
or target, in any combination. This first increment is the database core: PRD F2 (baseline),
F6 (reconcile), F8/F9 (reports), F11 (CLI and exit codes), F14 (credentials) and F15
(storage).

## Quick start (development)

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
liftproof init acme                   # writes acme.yaml; no credentials go in it
liftproof doctor --project acme.yaml  # connections, read only source, TLS, S3 and KMS
liftproof baseline --project acme.yaml
liftproof reconcile --project acme.yaml --baseline latest
```

## Exit codes

| Code | Meaning | Pipeline action |
|---|---|---|
| 0 | completed, no differences | continue the cutover |
| 10 | completed, differences found | stop; a human reads the report |
| 2 | run failed; not a verdict | stop |
| 3 | configuration or connection error; nothing validated | fix the setup |
| 1 | reserved; a crash is mapped to 2 | treat as 2 |

`--fail-on never` returns 0 even when differences exist.

## Tests

`pytest` runs everything. Database tests need PostgreSQL, MySQL, Oracle and SQL Server: set
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
src/liftproof/report      JSON and self contained HTML reports
src/liftproof/cli.py      the product's complete interface
docs/decisions.md      defaults chosen where the spec leaves a choice open
```
