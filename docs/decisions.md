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
| 26 | File content hash | SHA-256, streamed; files paired by relative path, with an optional regex path map and case folding | Files never need the cross engine MD5 of canonical v1.0, and SHA-256 works on a FIPS host. Windows shares moving to S3 change case and folders | Yes |
| 27 | Document types compared as text | PDF (pypdf, no system libraries), JSON (keys sorted), CSV, TSV and pipe delimited (row and column), and plain text types; up to 64 MB per file | Spec 23 leaves the list open and names PDF first. A pure Python reader keeps the AMI free of extra packages | Yes |
| 28 | Severity of file findings | missing in target: high; different text or unreadable type: high; only in target: medium; same text, different bytes: low; unreadable or symbolic link: not checked | Spec 10: a byte difference with identical text ranks below a real difference. A symbolic link is never followed, because it can leave the tree | Yes |
| 29 | Order inside `validate` | reconcile, then files, then replay | Replay creates data and generated files on the target; comparing after it would report them | Yes |
| 30 | Overlapping runs of one project | refused by a run lock: in S3, a conditional put (If-None-Match) with a 15 minute lease renewed while the run lasts and taken over with a conditional put once expired; on a local store, a kernel file lock | Spec 14: runs of one project never overlap. The scheduler, the CLI and SSM Run Command are separate processes, so only the store can arbitrate; S3 conditional writes need no DynamoDB table | Yes |
| 31 | A scheduled run that would overlap | skipped, and the skip is a run: a report with a high severity error finding and a `ScheduledRunSkipped` CloudWatch metric (namespace Liftproof; dimensions Deployment, which the deployment's alarm watches, and Deployment plus Project); exit code 2 | A skip seen only in a log goes unnoticed for weeks. A run started by hand is refused with exit code 2 and writes nothing | Yes |
| 32 | Scheduler | `mvt-scheduler.service` reads `schedules:` from every project file; five field cron, wall clock in a named time zone; each run is its own process; runs missed while it was down are not caught up, the latest missed one fires once | Customers with richer needs drive runs from their own pipeline through SSM Run Command (F11). No new dependency for cron parsing | Yes |
| 33 | SSM document modes | validate, reconcile, files, replay, smoke, baseline and doctor, with `journeys` and `sets` parameters restricted by pattern | Every pipeline stage the CLI has can be called without a shell on the instance; the patterns keep parameters out of the shell | Yes |
| 37 | CloudFormation template for the Marketplace listing | One template, `infra/cloudformation/liftproof.yaml`, written by hand to mirror `modules/liftproof`; a test compares the inputs, Run Command document, IAM statements, endpoints and instance settings of the two | Spec 3 offers both. Generating one from the other (cdktf, former2) would add a toolchain to the release path; a parity test catches drift with none | Yes |
| 38 | Database egress in the template | Four fixed slots (CIDR and port), an empty CIDR skips the slot; one application port for a list of CIDRs | CloudFormation has no loop over a map, and a Marketplace form cannot take a list of objects. Four covers source, target and a replica each side | Yes |
| 39 | Lookups the template needs | A small Lambda custom resource returns the VPC CIDR (endpoint security group) and the Region's S3 prefix list ID (S3 egress rule); read only EC2 permissions, runs outside the VPC so it needs no extra endpoint, logs to its own log group | Terraform reads both with data sources; CloudFormation has no equivalent | Yes |
| 40 | AMI in the template | `ImageId` is an SSM parameter type defaulting to the Marketplace public parameter for the product, so each stack launches the latest listed version | The ID differs per Region and per version; a mapping would have to be edited on every release | Yes |

## Not built yet

Web UI, parallel journeys, the target watermark that
excludes rows a replay created when reconciliation must follow replay (validate already
reconciles first), extractor transform chains (base64, URL encoding) for correlations,
replication position assertion on the target,
row predicate ignore rules, sampled mode, multi worker snapshots
(`pg_export_snapshot` is captured but workers are not used yet).
