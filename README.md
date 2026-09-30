# Certus

Migration validation for workloads moving to AWS. Certus records how an application and
its database behave before a migration, checks the same behaviour afterwards, and
produces the report a release manager signs at go live.

This repository is being built against the *Migration Validation Tool* PRD and Technical
Specification (Draft 1). This first increment is the database core: PRD F2 (baseline),
F6 (reconcile), F8/F9 (reports), F11 (CLI and exit codes), F14 (credentials) and F15
(storage).

## Quick start (development)

```bash
uv venv -p 3.12 && uv pip install -e ".[dev]"
certus init acme                   # writes acme.yaml; no credentials go in it
certus doctor --project acme.yaml  # connections, read only source, TLS, S3 and KMS
certus baseline --project acme.yaml
certus reconcile --project acme.yaml --baseline latest
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

`pytest` runs everything. Database tests need PostgreSQL: set `CERTUS_TEST_PG_HOST`,
`CERTUS_TEST_PG_PORT` and `CERTUS_TEST_PG_USER` (CI uses a service container); they are
skipped when no server is reachable. The suite includes the golden vectors that pin the
canonical wire format, pushdown against fallback parity for every type rule, and the
PRD F6 acceptance test (a ten row injected difference, reported exactly).

## Layout

```
src/certus/canonical   canonical v1.0 encoding and hashing (docs/canonical-v1.md)
src/certus/adapters    one adapter per database engine
src/certus/reconcile   planning, baselines, reconciliation
src/certus/report      JSON and self contained HTML reports
src/certus/cli.py      the product's complete interface
docs/decisions.md      defaults chosen where the spec leaves a choice open
```
