# Everything durable lives here (F15). Nothing irreplaceable lives on the instance.

locals {
  # lp-<name>-<account>-<region> stays within the 63 character bucket name limit
  bucket_name = coalesce(var.bucket_name, "lp-${var.name}-${local.account_id}-${local.region}")
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_18:Access logging is a customer choice via var.access_log_bucket
  #checkov:skip=CKV_AWS_144:Cross region replication is a customer choice; reports are also held under Object Lock
  #checkov:skip=CKV2_AWS_62:No consumer for event notifications
  bucket = local.bucket_name
  # Object Lock can only be switched on at creation. The product applies governance
  # mode retention to objects under runs/ as it writes them; other prefixes stay mutable
  # (checkpoints, locks, working state).
  object_lock_enabled = true
  tags                = local.tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "journey-assets-retention"
    status = "Enabled"
    # Request and response bodies and page snapshots may hold production data. The
    # product tags them liftproof:class=asset on upload and they expire (spec 5).
    filter {
      tag {
        key   = "liftproof:class"
        value = "asset"
      }
    }
    expiration {
      days = var.asset_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.asset_retention_days
    }
  }

  rule {
    id     = "housekeeping"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.access_log_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3/${local.bucket_name}/"
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
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

  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_key_arn]
    }
  }

  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket     = aws_s3_bucket.this.id
  policy     = data.aws_iam_policy_document.bucket.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
