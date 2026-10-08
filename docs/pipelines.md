# Running Liftproof from a pipeline (PRD F11, F12)

Liftproof runs on its own instance in your account, with no inbound ports. A pipeline
starts a run through AWS Systems Manager Run Command, using the document the deployment
module creates (`run_document_name` output, `Algorims-MVT-Run-<name>`), and reads the
product's exit code back from the command result.

| Exit code | Meaning | Pipeline action |
|---|---|---|
| 0 | completed, no differences | continue |
| 10 | completed, differences found | stop; a human reads the report |
| 2 | run failed, or another run of this project is in progress | stop |
| 3 | configuration or connection error; nothing validated | fix the setup |

The caller needs the operator policy (`operator_policy_arn` output): `ssm:SendCommand` on
that document and the Liftproof instance only, and `ssm:GetCommandInvocation`. It does
not need S3 or Secrets Manager access; the instance role reads secrets and writes the
report.

## Document parameters

| Parameter | Default | Values |
|---|---|---|
| `project` | | the project file name under `/var/lib/mvt/projects`, without `.yaml` |
| `mode` | `reconcile` | `validate`, `reconcile`, `files`, `replay`, `smoke`, `baseline`, `rebaseline`, `doctor`, `support-bundle` |
| `baseline` | `latest` | baseline id, `latest` (newest source baseline) or `latest-target` (newest rebaseline); used by `reconcile` and `validate` |
| `journeys` | all | comma separated journey ids; `replay`, `smoke`, `validate` |
| `sets` | all | comma separated file set names; `files`, `validate` |
| `failOn` | `differences` | `differences`, `errors`, `never` |
| `executionTimeout` | `14400` | seconds |

Every parameter is restricted by a pattern, so nothing a pipeline passes reaches the
shell as code. The run executes in its own systemd unit as the `mvt` user and survives an
agent restart.

## The run script

Both examples below call this script. Keep it in your pipeline repository.

```bash
#!/usr/bin/env bash
# liftproof-run.sh MODE [extra SSM parameters as JSON, e.g. '"journeys":["login"]']
set -euo pipefail
: "${LIFTPROOF_INSTANCE:?}" "${LIFTPROOF_DOCUMENT:?}" "${LIFTPROOF_PROJECT:?}"
mode="$1"; extra="${2:-}"

params="{\"project\":[\"$LIFTPROOF_PROJECT\"],\"mode\":[\"$mode\"]${extra:+,$extra}}"
id=$(aws ssm send-command \
  --instance-ids "$LIFTPROOF_INSTANCE" \
  --document-name "$LIFTPROOF_DOCUMENT" \
  --parameters "$params" \
  --comment "pipeline ${CI_RUN:-manual} $mode" \
  --query Command.CommandId --output text)

while :; do
  status=$(aws ssm get-command-invocation --command-id "$id" \
    --instance-id "$LIFTPROOF_INSTANCE" --query Status --output text 2>/dev/null || echo Pending)
  case "$status" in Pending|InProgress|Delayed) sleep 20 ;; *) break ;; esac
done

aws ssm get-command-invocation --command-id "$id" --instance-id "$LIFTPROOF_INSTANCE" \
  --query StandardOutputContent --output text
code=$(aws ssm get-command-invocation --command-id "$id" \
  --instance-id "$LIFTPROOF_INSTANCE" --query ResponseCode --output text)
echo "liftproof $mode finished with exit code $code"
exit "$code"
```

The standard output is the run summary as JSON, including `report_html`, the S3 location
of the report. Run Command keeps only the first 24,000 characters of output; the report
itself is always complete in S3.

## GitHub Actions

The workflow assumes an IAM role through OpenID Connect; no long lived keys are stored
in GitHub. Attach the operator policy to that role.

```yaml
name: cutover-validation
on:
  workflow_dispatch:
permissions:
  id-token: write
  contents: read
jobs:
  validate:
    runs-on: ubuntu-latest
    env:
      LIFTPROOF_INSTANCE: i-0123456789abcdef0
      LIFTPROOF_DOCUMENT: Algorims-MVT-Run-acme
      LIFTPROOF_PROJECT: acme
      CI_RUN: ${{ github.run_id }}
    steps:
      - uses: actions/checkout@v5
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::111122223333:role/liftproof-pipeline
          aws-region: ap-south-1
      - name: Smoke test the target
        run: ./liftproof-run.sh smoke '"journeys":["login,checkout-flow"]'
      - name: Full validation
        run: ./liftproof-run.sh validate
```

A step fails on any exit code other than 0, so differences (10) stop the workflow.

## AWS CodePipeline

Add a CodeBuild action after the cutover stage. The CodeBuild service role carries the
operator policy.

```yaml
# buildspec.yml
version: 0.2
env:
  variables:
    LIFTPROOF_INSTANCE: i-0123456789abcdef0
    LIFTPROOF_DOCUMENT: Algorims-MVT-Run-acme
    LIFTPROOF_PROJECT: acme
phases:
  build:
    commands:
      - export CI_RUN="$CODEBUILD_BUILD_NUMBER"
      - ./liftproof-run.sh reconcile '"baseline":["latest"]'
      - ./liftproof-run.sh files
```

## Scheduled runs on the instance

For unattended runs that no pipeline starts (nightly validation during a parallel run,
for example), add schedules to the project file:

```yaml
schedules:
  - name: nightly
    cron: "0 2 * * *"           # minute hour day-of-month month day-of-week
    timezone: Asia/Kolkata      # default UTC
    command: validate           # validate, reconcile, files, replay, smoke, baseline or rebaseline
    args: [--baseline, latest]
```

`mvt-scheduler.service` reads every project file in `/var/lib/mvt/projects` and starts
each run as its own process. `liftproof schedule --project acme.yaml` shows the next run
time of each schedule, and `liftproof runs --project acme.yaml` the history, with the
schedule that started each run.

Runs of one project never overlap, whoever starts them. A scheduled run that finds the
previous one still going is skipped and recorded as a run whose report carries an error
finding, and the `ScheduledRunSkipped` metric (namespace `Liftproof`) is published
twice: with the `Deployment` dimension, which the deployment's
`liftproof-NAME-scheduled-run-skipped` alarm watches, and with `Deployment` and
`Project`, which names the project. Runs missed while the instance was
stopped are not caught up; the latest missed one fires once when the scheduler starts
again.

## After cutover: regression against the target itself

Before cutover, runs compare the target with the source (live, or a source baseline).
After cutover the target takes live traffic, so every night it drifts further from the
frozen source and the report fills with differences that are not differences. Once the
target has been signed off, snapshot it as the new reference:

```bash
liftproof rebaseline --project acme.yaml
```

and point the scheduled runs at it:

```yaml
schedules:
  - name: nightly
    cron: "0 2 * * *"
    timezone: Asia/Kolkata
    command: reconcile
    args: [--baseline, latest-target]
```

Nightly runs then report what changed in the target since it was accepted. Tables that
live traffic is meant to change (orders, sessions, audit) need table ignore rules with a
reason; the rest (reference data, configuration, closed periods) should not change at
all, and a difference there is worth a look.

Only the target is read: `rebaseline` and runs against `latest-target` never connect to
the source, which may already be decommissioned. A target baseline holds bucket
aggregates, not rows, and the target's earlier state cannot be re-read, so differences
are reported down to the bucket (a share of the table's rows) rather than the row. To
move the reference forward after accepting a set of changes, run `rebaseline` again,
from a pipeline (SSM document mode `rebaseline`) or on a schedule (`command: rebaseline`).
`latest` keeps meaning the newest source baseline.
