# Build decisions

Defaults picked to start building where the PRD and Technical Spec leave a choice open.
Each can be revisited; the ones marked *reversible* cost little to change.

| # | Decision | Default chosen | Why | Reversible |
|---|---|---|---|---|
| 1 | Language | Python 3.12 | The database reconciliation is where the product lives or dies; spec section 2 | Costly |
| 2 | First database engine | PostgreSQL (source and target) | Most common target, and a full test server is easy in CI. MySQL, SQL Server and Oracle follow as adapters | Yes |
| 3 | Package and CLI name | package `certus`, commands `certus` and `mvt` | Project is called Certus; spec uses `mvt`. Both entry points work | Yes |
| 4 | Row hash grouping | per column digest, groups of 32 columns | Resolves the ambiguous 1000 byte rule; see canonical-v1.md | Canonical version bump |
| 5 | NULL encoding | own frame `-1 0x1F` | The draft `\N` collides with the string `\N` | Canonical version bump |
| 6 | Baseline contents | per bucket aggregates only | Keeps baselines small; row level drill-down needs the source readable at validate time, and the report says so when it is not | Yes |
| 7 | Verdict | failed on any difference of severity 3 or more, or an error; passed with differences on low severity differences or anything not checked or partial; else passed | The spec defines the three verdicts but no rule | Yes |
| 8 | Read only check in doctor | inspect grants and superuser, never attempt a write | A write attempt against production takes locks and fires triggers; DDL auto commits on MySQL and Oracle | Yes |
| 9 | Values in reports | hidden by default; `--show-values` or `show_values: true` | The report is an egress path (spec 15) | Yes |
| 10 | AWS keys in the environment | warn, do not refuse | They are part of the default provider chain (AWSAPI-005); database passwords in the environment are refused | Yes |
| 11 | Credentials when no `secret_arn` is set | connect without a password (for local development and IAM auth later) | Never from a file or environment variable | Yes |

## Not built yet

Recorder, replay, UI/API/file comparators, scheduler, web UI, SSM document, AMI build,
CloudFormation/Terraform module, replication position assertion on the target,
row predicate ignore rules, sampled mode, multi worker snapshots
(`pg_export_snapshot` is captured but workers are not used yet).
