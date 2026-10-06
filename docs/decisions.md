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

| 17 | Response bodies at record time | default deny: kept only for `web.capture_bodies` URL patterns; every other body is a SHA-256 and a JSON shape | Spec 5: production bodies in the bucket indefinitely is the sentence that loses the deal. Shape comparison still catches added and missing fields | Yes |
| 18 | Which fields are sensitive | password inputs, any element with `data-liftproof-sensitive`, and names matching pass, secret, token, otp or pin | Errs towards redacting; the value is swapped for a random token in the recorder process and scrubbed from URLs, request bodies and page snapshots | Yes |
| 19 | "The region the step touched" | the nearest form, dialog, table, section, article or main around the element, else the page; compared as accessible tree text | Spec 7 asks for the region but does not define it; these are the elements that bound what a step can change | Yes |
| 20 | Waiting at replay | the requests the step made when recorded, then the page load, then no DOM change for 150 ms; step timeout 15 s; 3 attempts per step, 2 per journey that changes state | Conditions, not sleeps (spec 6). The DOM quiet period stops a snapshot racing the page's own rendering script | Yes |
| 21 | Journey with an unbound redaction token | not replayed; reported as not run, so coverage drops; `doctor` lists it beforehand | Replaying without the real secret would fail at login and read as a migration defect | Yes |
| 22 | API calls during recording and replay | fetched through a Playwright route so the body is held before the page sees it | A page that navigates straight after an API call discards that body before it can be read | Yes |

## Not built yet

File comparator, scheduler, web UI, parallel journeys, the target watermark that
excludes rows a replay created when reconciliation must follow replay (validate already
reconciles first), extractor transform chains (base64, URL encoding) for correlations,
CloudFormation version of the deployment module, replication position assertion on the target,
row predicate ignore rules, sampled mode, multi worker snapshots
(`pg_export_snapshot` is captured but workers are not used yet).
