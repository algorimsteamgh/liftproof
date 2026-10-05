# Security baseline for each Algorims AWS account that builds or distributes Liftproof.
# These are account level settings, applied once per account and region.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

variable "name" {
  description = "Account label, for example algorims-build."
  type        = string
}

variable "budget_limit_usd" {
  description = "Monthly cost budget; alerts at 80 and 100 percent."
  type        = number
  default     = 500
}

variable "budget_emails" {
  type = list(string)
}

variable "enable_security_hub" {
  description = "AWS Security Hub with the Foundational Security Best Practices standard."
  type        = bool
  default     = true
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
  tags       = merge(var.tags, { "liftproof:managed-by" = "terraform" })
}

# Account wide guard rails
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 2
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.name}-account"
  type          = "ACCOUNT"
  tags          = local.tags
}

resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single account; there is no AWS Organization to delegate to yet
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = local.tags
}

resource "aws_inspector2_enabler" "this" {
  account_ids    = [local.account_id]
  resource_types = ["EC2", "ECR"]
}

resource "aws_securityhub_account" "this" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# --- CloudTrail --------------------------------------------------------------------------

data "aws_iam_policy_document" "trail_key" {
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
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/cloudtrail/*"]
    }
  }
  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }
}

resource "aws_kms_key" "trail" {
  description         = "${var.name} CloudTrail"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.trail_key.json
  tags                = local.tags
}

# --- S3 server access logs for the account's buckets ----------------------------------

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access log destination; logging it to itself would loop
  #checkov:skip=CKV_AWS_144:Replication not required for access logs
  #checkov:skip=CKV2_AWS_62:No consumer for event notifications
  #checkov:skip=CKV_AWS_145:S3 server access logging only supports SSE-S3 on the destination bucket
  bucket = "${var.name}-s3-access-logs-${local.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "retain"
    status = "Enabled"
    filter {}
    expiration {
      days = 400
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
  depends_on = [aws_s3_bucket_versioning.access_logs]
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "S3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
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

resource "aws_s3_bucket_policy" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  policy     = data.aws_iam_policy_document.access_logs.json
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

# --- CloudTrail bucket -------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_144:Replication of the trail bucket is left to an organisation log archive account later
  #checkov:skip=CKV2_AWS_62:No consumer for event notifications
  bucket = "${var.name}-cloudtrail-${local.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/cloudtrail/"
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "retain"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    expiration {
      days = 2555
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
  depends_on = [aws_s3_bucket_versioning.trail]
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
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

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.trail.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "trail_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_logs" {
  name               = "${var.name}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_logs_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "trail_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "trail_logs" {
  role   = aws_iam_role.trail_logs.id
  policy = data.aws_iam_policy_document.trail_logs.json
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:Alerting runs from GuardDuty and Security Hub, not per log file SNS
  name                          = "${var.name}-trail"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_logs.arn
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.trail.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  tags                          = local.tags
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# --- cost guard rail ----------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.budget_emails
    }
  }
}

output "access_log_bucket" {
  value = aws_s3_bucket.access_logs.bucket
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.trail.bucket
}
