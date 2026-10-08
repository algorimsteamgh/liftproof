# Liftproof

Migration validation for workloads moving to AWS. Liftproof records how an application and
its database behave before a migration, checks the same behaviour afterwards, and
produces the report a release manager signs at go live.

This repository is being built against the *Migration Validation Tool* PRD and Technical
Specification (Draft 1). Supported databases: PostgreSQL and MySQL (8.0 and later, including Aurora), as source
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
Database tests need PostgreSQL and MySQL: set
`LIFTPROOF_TEST_PG_HOST`, `_PORT`, `_USER`, `_PASSWORD` and `LIFTPROOF_TEST_MYSQL_HOST`,
`_PORT`, `_USER`, `_PASSWORD` (CI uses service containers); they are skipped when no
server is reachable. Cross engine tests load the same data into both and require identical
hashes. The suite includes the golden vectors that pin the
canonical wire format, pushdown against fallback parity for every type rule, and the
PRD F6 acceptance test (a ten row injected difference, reported exactly).

## Layout

```
src/liftproof/canonical   canonical v1.0 encoding and hashing (docs/canonical-v1.md)
src/liftproof/adapters    one adapter per database engine
src/liftproof/reconcile   planning, baselines, reconciliation
src/liftproof/web         recorder, replay engine, UI and API comparison
src/liftproof/report      JSON and self contained HTML reports
src/liftproof/cli.py      the product's complete interface
docs/decisions.md      defaults chosen where the spec leaves a choice open
```
