# AWS Marketplace listing

The listing offers two ways to launch: the CloudFormation template
`infra/cloudformation/liftproof.yaml` (the "launch with CloudFormation" delivery option)
and the Terraform module `infra/modules/liftproof`. Both deploy the same thing, and
`tests/test_cloudformation.py` fails when one changes without the other.

The listing draft is product `prod-lf77qe6dmorug` in AWS Partner Central, version
`0.1.2`. The text below is the copy used on the listing form.

## Listing text (draft)

**Title:** Liftproof migration validation

**Short description (under 200 characters):** Prove a database, file and application
migration is complete before cutover. Runs privately in your own AWS account; your data
never leaves it.

**Long description:**

Liftproof checks that a migration moved everything and changed nothing. It runs inside
your AWS account on one private EC2 instance with no inbound access, and compares source
and target on three fronts:

- **Databases:** every row of every table, by hashing inside each database and narrowing
  any difference down to the rows involved. PostgreSQL 13+, MySQL 8.0+, Oracle 19c+ and SQL
  Server 2016+, in any pairing, including the Amazon RDS and Aurora versions.
- **Files:** local folders, network shares or Amazon S3 on either side, matched by size
  and SHA-256, with text aware comparison of PDF, CSV and JSON so a regenerated document
  is not reported as a lost one.
- **Applications:** record a user journey in the browser once, replay it against the
  migrated system and compare both the pages and the API responses, ignoring order
  numbers, tokens and timestamps.

Each run writes a retention locked report to your own S3 bucket, ranked by
severity, with an exit code a pipeline can gate a cutover on. Runs can be scheduled, or
started from GitHub Actions, AWS CodePipeline or any tool that can call AWS Systems
Manager.

Credentials stay in AWS Secrets Manager. Reports hold the location of a difference, not
your data. Nothing is sent to Algorims.

**Highlights:**

1. Row level proof across PostgreSQL, MySQL, Oracle and SQL Server without copying data
   out of either database.
2. Deploys into a private subnet with no inbound rule, no key pair and no public address;
   operators connect through Session Manager.
3. Reports are KMS encrypted and kept under S3 Object Lock for the retention you choose.

**Category:** Migration; Security, Compliance and Governance.

**Fulfilment:** Amazon Machine Image with CloudFormation template.

## Usage instructions (draft, shown after subscribing)

1. Store each database's credentials as a secret in AWS Secrets Manager in the same
   Region, as a key/value secret with the keys `username` and `password`.
2. Choose **Launch CloudFormation**. Pick a private subnet that can reach your
   databases and applications, and give that subnet's route tables in
   **PrivateRouteTableIds**. Paste the secret ARNs into **Secrets the product may
   read** and fill a database slot (CIDR and port) for each database the instance
   must reach; both can be left empty for a first deployment.
3. Leave **Create VPC endpoints** on unless the VPC already has endpoints for SSM,
   Secrets Manager, KMS, CloudWatch Logs and CloudWatch, and an S3 gateway endpoint.
4. When the stack finishes, connect to the instance with Session Manager
   (`aws ssm start-session --target` and the **InstanceId** output), or call the
   **RunDocumentName** output with mode `doctor`, to check network paths, credentials and
   permissions before the first comparison. The **ConnectUi** output opens the web
   interface (see `docs/ui.md`).
5. For a first report before any of your own systems are set up, run the worked
   example: the **RunDocumentName** output with project `example` and mode `files`. It
   compares two folders shipped on the instance, finds one changed invoice amount, and
   writes the report to the deployment's bucket.
6. To start a run from a pipeline, give the pipeline's role the **OperatorPolicyArn**
   output and call the command in the **StartRun** output.

Deleting the stack keeps the S3 bucket and its locked reports (DeletionPolicy Retain).

## Image requirements

The source AMI is built in us-east-1, the only Region AWS Marketplace takes a new version
from, and keeps a key only SSH daemon for the Marketplace security scan (decisions 134
and 135).

## Still needed before submission

- The architecture diagram is `docs/architecture.png` (source `docs/architecture.svg`).
  Redraw it with the official AWS architecture icons if the listing review asks for them.
- The deployment guide is `docs/deployment-guide.md`. Instance replacement and launch
  times in section 9 were measured on 21 November 2026; the Availability Zone and Region
  rows are still design targets.
- Pricing and the EULA.
