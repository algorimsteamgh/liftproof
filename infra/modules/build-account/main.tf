# Algorims build and distribution account. CI reaches AWS only through GitHub OIDC
# federation into short lived roles: no stored access keys (the second half of IAM-002).
# Packer builds the AMI through Session Manager (no SSH, no inbound rule), Amazon
# Inspector scans it, and scan and build evidence is kept for the competency review.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

variable "github_repository" {
  description = "owner/repo, for example algorimsteamgh/liftproof"
  type        = string
}

variable "release_refs" {
  description = "Git refs allowed to build and publish AMIs."
  type        = list(string)
  default     = ["refs/heads/main", "refs/tags/v*"]
}

variable "create_oidc_provider" {
  description = "False when the account already has the GitHub OIDC provider."
  type        = bool
  default     = true
}

variable "build_vpc_id" {
  type = string
}

variable "build_subnet_id" {
  description = "Subnet for Packer build instances. Needs a path to package mirrors (NAT) and to SSM."
  type        = string
}

variable "access_log_bucket" {
  description = "Bucket receiving S3 server access logs (the account baseline creates one)."
  type        = string
}

variable "evidence_retention_days" {
  description = "Build, test and vulnerability scan evidence is kept (Object Lock, compliance mode) for this long."
  type        = number
  default     = 400
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  tags       = merge(var.tags, { "liftproof:managed-by" = "terraform", "liftproof:scope" = "build" })
  oidc_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : (
    "arn:${local.partition}:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
  )
}

# --- GitHub OIDC ---------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  tags           = local.tags
}

data "aws_iam_policy_document" "release_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for r in var.release_refs : "repo:${var.github_repository}:ref:${r}"]
    }
  }
}

resource "aws_iam_role" "release" {
  name                 = "liftproof-github-release"
  description          = "GitHub Actions: build, scan and publish the Liftproof AMI"
  assume_role_policy   = data.aws_iam_policy_document.release_trust.json
  max_session_duration = 7200
  tags                 = local.tags
}

# --- KMS and evidence bucket -----------------------------------------------------------

data "aws_iam_policy_document" "build_key" {
  #checkov:skip=CKV_AWS_109:Key policy root statement; access is delegated to IAM
  #checkov:skip=CKV_AWS_111:Key policy root statement; access is delegated to IAM
  #checkov:skip=CKV_AWS_356:In a key policy "*" means this key
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "build" {
  description             = "Liftproof build account: evidence and AMI snapshots"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.build_key.json
  tags                    = local.tags
}

resource "aws_kms_alias" "build" {
  name          = "alias/liftproof-build"
  target_key_id = aws_kms_key.build.key_id
}

resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_144:Evidence is held under Object Lock compliance mode; replication is not required
  #checkov:skip=CKV2_AWS_62:No consumer for event notifications
  bucket              = "liftproof-build-evidence-${local.account_id}-${local.region}"
  object_lock_enabled = true
  tags                = local.tags
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3/liftproof-build-evidence/"
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.build.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "archive"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = data.aws_iam_policy_document.evidence_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# --- Packer build instance -------------------------------------------------------------

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "builder" {
  name               = "liftproof-ami-builder"
  description        = "Temporary Packer build instances (Session Manager only)"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "builder_ssm" {
  role       = aws_iam_role.builder.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "builder" {
  name = "liftproof-ami-builder"
  role = aws_iam_role.builder.name
  tags = local.tags
}

resource "aws_security_group" "builder" {
  #checkov:skip=CKV2_AWS_5:Attached by Packer to temporary build instances
  name        = "liftproof-ami-builder"
  description = "Packer build instances: no inbound; HTTPS out for packages and SSM"
  vpc_id      = var.build_vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_egress_rule" "builder_https" {
  security_group_id = aws_security_group.builder.id
  description       = "Package mirrors, PyPI and AWS APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# --- what the release role may do ------------------------------------------------------

data "aws_iam_policy_document" "release" {
  #checkov:skip=CKV_AWS_356:Describe and list actions have no resource level permissions; launches are tag conditioned
  #checkov:skip=CKV_AWS_111:Write actions are constrained by the liftproof:build tag and the build subnet
  #checkov:skip=CKV_AWS_108:Evidence reads are limited to the evidence bucket
  statement {
    sid = "PackerDescribe"
    actions = [
      "ec2:DescribeImages", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus",
      "ec2:DescribeSnapshots", "ec2:DescribeVolumes", "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups", "ec2:DescribeRegions", "ec2:DescribeImageAttribute",
      "ec2:DescribeTags", "ssm:DescribeInstanceInformation", "ssm:GetParameter",
      "inspector2:ListFindings", "inspector2:ListCoverage", "inspector2:GetFindingsReportStatus",
    ]
    resources = ["*"] # describe calls do not support resource level permissions
  }

  statement {
    sid       = "LaunchTaggedBuilders"
    actions   = ["ec2:RunInstances", "ec2:CreateTags"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/liftproof:build"
      values   = ["true"]
    }
  }

  statement {
    sid     = "LaunchIntoBuildNetwork"
    actions = ["ec2:RunInstances"]
    resources = [
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:subnet/${var.build_subnet_id}",
      aws_security_group.builder.arn,
      "arn:${local.partition}:ec2:${local.region}::image/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:network-interface/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:key-pair/packer_*",
    ]
  }

  statement {
    sid = "PackerTemporaryKeyPair"
    # Packer's SSH session runs over Session Manager but still uses a key pair it
    # creates for the build and deletes afterwards (named packer_<uuid>).
    actions = ["ec2:CreateKeyPair", "ec2:DeleteKeyPair"]
    resources = [
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:key-pair/packer_*",
    ]
  }

  statement {
    sid = "PackerInstanceAttributes"
    # ena_support and sriov_support are set on the stopped build instance
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/liftproof:build"
      values   = ["true"]
    }
  }

  statement {
    sid = "ManageOwnBuilders"
    actions = [
      "ec2:TerminateInstances", "ec2:StopInstances", "ec2:CreateImage", "ec2:CreateSnapshot",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/liftproof:build"
      values   = ["true"]
    }
  }

  statement {
    sid = "PublishImages"
    actions = [
      "ec2:RegisterImage", "ec2:CopyImage", "ec2:ModifyImageAttribute", "ec2:DeregisterImage",
      "ec2:ModifySnapshotAttribute", "ec2:DeleteSnapshot", "ec2:CreateTags",
    ]
    resources = [
      "arn:${local.partition}:ec2:*::image/*",
      "arn:${local.partition}:ec2:*::snapshot/*",
    ]
  }

  statement {
    sid       = "PassBuilderRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.builder.arn]
  }

  statement {
    sid       = "CheckBuilderProfile"
    actions   = ["iam:GetInstanceProfile"] # Packer checks iam_instance_profile before launch
    resources = [aws_iam_instance_profile.builder.arn]
  }

  statement {
    sid     = "SessionManagerToBuilders"
    actions = ["ssm:StartSession", "ssm:TerminateSession"]
    resources = [
      "arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:${local.partition}:ssm:${local.region}::document/AWS-StartPortForwardingSession",
      "arn:${local.partition}:ssm:*:${local.account_id}:session/*",
    ]
  }

  statement {
    sid       = "UseBuildKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant", "kms:ReEncrypt*"]
    resources = [aws_kms_key.build.arn]
  }

  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }
}

resource "aws_iam_role_policy" "release" {
  name   = "liftproof-release"
  role   = aws_iam_role.release.id
  policy = data.aws_iam_policy_document.release.json
}

# --- AWS Marketplace AMI ingestion ------------------------------------------------------

data "aws_iam_policy_document" "marketplace_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["assets.marketplace.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "marketplace_ingestion" {
  name               = "liftproof-marketplace-ami-ingestion"
  description        = "Lets AWS Marketplace scan and copy Liftproof AMIs for listing versions"
  assume_role_policy = data.aws_iam_policy_document.marketplace_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "marketplace_ingestion" {
  role       = aws_iam_role.marketplace_ingestion.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSMarketplaceAmiIngestion"
}

output "release_role_arn" {
  description = "Set as the role-to-assume in the GitHub Actions release workflow."
  value       = aws_iam_role.release.arn
}

output "builder_instance_profile" {
  value = aws_iam_instance_profile.builder.name
}

output "builder_security_group_id" {
  value = aws_security_group.builder.id
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.bucket
}

output "build_kms_key_arn" {
  value = aws_kms_key.build.arn
}

output "marketplace_ingestion_role_arn" {
  value = aws_iam_role.marketplace_ingestion.arn
}
