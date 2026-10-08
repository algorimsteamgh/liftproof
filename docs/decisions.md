# Build decisions

Defaults picked to start building where the PRD and Technical Spec leave a choice open.
Each can be revisited; the ones marked *reversible* cost little to change.

| # | Decision | Default chosen | Why | Reversible |
|---|---|---|---|---|
| 1 | Language | Python 3.12 | The database reconciliation is where the product lives or dies; spec section 2 | Costly |
| 2 | First database engine | PostgreSQL (source and target) | Most common target, and a full test server is easy in CI. MySQL, SQL Server and Oracle follow as adapters | Yes |
| 3 | Package and CLI name | package `liftproof`, commands `liftproof` and `mvt` | Project is called Liftproof; spec uses `mvt`. Both entry points work | Yes |
| 4 | Row hash grouping | per column digest, groups of 32 columns | Resolves the ambiguous 1000 byte rule; see canonical-v1.md | Canonical version bump |
| 5 | NULL encoding | own frame `-1 0x1F` | The draft `\N` collides with the string `\N` | Canonical version bump |
| 6 | Baseline contents | per bucket aggregates only | Keeps baselines small; row level drill-down needs the source readable at validate time, and the report says so when it is not | Yes |
| 7 | Verdict | failed on any difference of severity 3 or more, or an error; passed with differences on low severity differences or anything not checked or partial; else passed | The spec defines the three verdicts but no rule | Yes |
| 8 | Read only check in doctor | inspect grants and superuser, never attempt a write | A write attempt against production takes locks and fires triggers; DDL auto commits on MySQL and Oracle | Yes |
| 9 | Values in reports | hidden by default; `--show-values` or `show_values: true` | The report is an egress path (spec 15) | Yes |
| 10 | AWS keys in the environment | warn, do not refuse | They are part of the default provider chain (AWSAPI-005); database passwords in the environment are refused | Yes |
| 11 | Credentials when no `secret_arn` is set | connect without a password (for local development and IAM auth later) | Never from a file or environment variable | Yes |
| 12 | Infrastructure | Terraform modules for the customer deployment and the Algorims build account; Packer AMI on Amazon Linux 2023 | The spec names CloudFormation and Terraform; Terraform first, CloudFormation for the Marketplace listing next | Yes |
| 13 | Second database engine | MySQL 8.0 and later (Aurora MySQL 3), via PyMySQL | The most common lift and shift engine, a pure Python driver, and a real cross engine test against PostgreSQL. Oracle and SQL Server follow | Yes |
| 14 | MySQL driver version | PyMySQL below 1.2 | PyMySQL 1.2.3 fails the full `caching_sha2_password` login exchange; lift the cap once fixed upstream | Yes |
| 15 | Schema names across engines | `database.schema_map`, defaulting to the source home schema mapped onto the target's (MySQL `shop` to PostgreSQL `public`) | In MySQL a schema is the database; a migration usually renames it | Yes |
| 16 | MySQL replication position | GTID set (or binlog file and position) read immediately after the snapshot opens, recorded with `exact: false` | MySQL does not expose the position of a consistent snapshot atomically; the alternative, a global read lock, is not acceptable on a production source | Yes |

## Not built yet

Recorder, replay, UI/API/file comparators, scheduler, web UI,
CloudFormation version of the deployment module, replication position assertion on the target,
row predicate ignore rules, sampled mode, multi worker snapshots
(`pg_export_snapshot` is captured but workers are not used yet).
