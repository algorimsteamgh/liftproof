# Liftproof

Migration validation for workloads moving to AWS. Liftproof records how an application and
its database behave before a migration, checks the same behaviour afterwards, and
produces the report a release manager signs at go live.

This repository is being built against the *Migration Validation Tool* PRD and Technical
Specification (Draft 1). Supported databases: PostgreSQL, MySQL (8.0 and later, including Aurora) and Oracle (19c and later, including RDS for Oracle), as source
or target, in any combination. Built so far: the database core, PRD F2 (baseline), F6 (reconcile), F8/F9 (reports),
F11 (CLI and exit codes), F14 (credentials) and F15 (storage); and record and replay,
F1 (record), F3 (replay), F4 (user interface comparison), F5 (API comparison) and F16
(response times).

## Quick start (development)

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
liftproof init acme                   # writes acme.yaml; no credentials go in it
liftproof doctor --project acme.yaml  # connections, read only source, TLS, S3 and KMS
liftproof baseline --project acme.yaml
liftproof reconcile --project acme.yaml --baseline latest
```

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

## Scheduled and pipeline runs

```bash
liftproof schedule --project acme.yaml     # the project's schedules and their next run
liftproof runs     --project acme.yaml     # run history on this instance, newest first
```

A project file can carry `schedules:` (a name, a five field cron expression, a time zone
and the command to run). The `mvt-scheduler.service` on the instance starts each run when
it falls due. Runs of one project never overlap: a second run is refused with exit code
2, and a scheduled run that finds the previous one still going is skipped and recorded as
a run with an error finding and a `ScheduledRunSkipped` CloudWatch metric. CI and CD
pipelines start runs through the SSM document; see [docs/pipelines.md](docs/pipelines.md).

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

`pytest` runs everything. Record and replay tests need Chromium
(`python -m playwright install chromium`, or point `LIFTPROOF_CHROMIUM` at a binary) and run
against a small shop application in `tests/webapp.py` that is served twice, once changed.
Database tests need PostgreSQL, MySQL and Oracle: set
`LIFTPROOF_TEST_PG_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `LIFTPROOF_TEST_MYSQL_HOST`,
`_PORT`, `_USER`, `_PASSWORD` and `LIFTPROOF_TEST_ORACLE_HOST`, `_PORT`, `_SERVICE`,
`_USER`, `_PASSWORD` (CI uses service containers; for Oracle,
`gvenzl/oracle-free:23-slim-faststart`); they are skipped when no server is reachable.
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
