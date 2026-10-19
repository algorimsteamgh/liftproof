# One customer managed key protects the bucket, the log group and the instance volume
# (N7 / SECOPS-004). Rotation is on. Use is granted through IAM (the key policy
# delegates to the account), except for CloudWatch Logs and the Auto Scaling
# service-linked role, which need key policy statements of their own.

data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:Key policy root statement; access is delegated to IAM, the documented KMS default
  #checkov:skip=CKV_AWS_111:Key policy root statement; access is delegated to IAM
  #checkov:skip=CKV_AWS_356:In a key policy "*" means this key
  #checkov:skip=CKV_AWS_283:Principal "*" is narrowed to this account's Auto Scaling service-linked role by aws:PrincipalArn
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
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/liftproof/${var.name}*"]
    }
  }

  # Auto Scaling launches the instance, so its service-linked role encrypts the root
  # volume. Named by condition: the role may not exist until the group does.
  statement {
    sid = "AutoScalingVolumes"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.autoscaling_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AutoScalingVolumeGrants"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.autoscaling_role_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

locals {
  autoscaling_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
}

resource "aws_kms_key" "this" {
  count                   = var.kms_key_arn == null ? 1 : 0
  description             = "Liftproof ${var.name}: recordings, baselines, reports, logs and volumes"
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

# With an existing key (kms_key_arn), its policy is the customer's. CloudWatch Logs
# cannot use the key without a statement of its own, so the log group fails to create
# until it is added, and Auto Scaling cannot launch the instance with an encrypted root
# volume without its two; the instance role needs one too when the policy does not
# delegate to IAM. All are published as an output to paste in before the first apply.
data "aws_iam_policy_document" "customer_key" {
  #checkov:skip=CKV_AWS_109:Statements for the customer's own key policy, where "*" means that key
  #checkov:skip=CKV_AWS_111:Statements for the customer's own key policy, where "*" means that key
  #checkov:skip=CKV_AWS_356:In a key policy "*" means this key
  #checkov:skip=CKV_AWS_283:Principal "*" is narrowed to this account's Auto Scaling service-linked role by aws:PrincipalArn
  source_policy_documents = [data.aws_iam_policy_document.key.json]

  statement {
    sid       = "LiftproofInstanceRole"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:role/${local.name}-instance"]
    }
  }
}

locals {
  customer_key_statements = [
    for s in jsondecode(data.aws_iam_policy_document.customer_key.json).Statement : s
    if s.Sid != "AccountAdministration"
  ]
}
