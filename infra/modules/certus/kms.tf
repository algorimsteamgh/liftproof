# One customer managed key protects the bucket, the log group and the instance volume
# (N7 / SECOPS-004). Rotation is on. Use is granted through IAM (the key policy
# delegates to the account), except for CloudWatch Logs, which needs a key policy
# statement of its own.

data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:Key policy root statement; access is delegated to IAM, the documented KMS default
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
    sid = "CloudWatchLogs"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/certus/${var.name}*"]
    }
  }
}

resource "aws_kms_key" "this" {
  count                   = var.kms_key_arn == null ? 1 : 0
  description             = "Certus ${var.name}: recordings, baselines, reports, logs and volumes"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  count         = var.kms_key_arn == null ? 1 : 0
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.this[0].key_id
}

locals {
  kms_key_arn = coalesce(var.kms_key_arn, try(aws_kms_key.this[0].arn, null))
}
