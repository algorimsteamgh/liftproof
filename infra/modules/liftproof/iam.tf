# Two policies, not one (spec 15). The instance role is what the software runs as; the
# operator policy is what a person or pipeline needs to reach and invoke it. No IAM
# users and no access keys anywhere (N1 / IAM-002).

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "instance" {
  name                 = "${local.name}-instance"
  description          = "Liftproof product instance role"
  assume_role_policy   = data.aws_iam_policy_document.assume_ec2.json
  max_session_duration = 3600
  tags                 = local.tags
}

locals {
  log_group_arn = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/liftproof/${var.name}"
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid = "ObjectsReadWrite"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectTagging",
      "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }

  statement {
    sid       = "LockReports"
    actions   = ["s3:PutObjectRetention", "s3:GetObjectRetention"]
    resources = ["${aws_s3_bucket.this.arn}/*/runs/*"]
  }

  statement {
    # Only the scheduler's lease objects may be deleted; reports and baselines never.
    sid       = "ReleaseRunLocks"
    actions   = ["s3:DeleteObject"]
    resources = ["${aws_s3_bucket.this.arn}/*/locks/*"]
  }

  statement {
    sid       = "BucketLevel"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.this.arn]
  }

  statement {
    sid       = "UseKeys"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = distinct(concat([local.kms_key_arn], var.secret_kms_key_arns))
  }

  statement {
    sid       = "ReadCredentials"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = var.secret_arns
  }

  statement {
    sid       = "ShipLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${local.log_group_arn}:*"]
  }

  statement {
    sid       = "PublishMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData has no resource type; scoped by namespace below
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["Liftproof"]
    }
  }
}

resource "aws_iam_role_policy" "instance" {
  name   = "liftproof-runtime"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

# Session Manager is the only way in, so this is not optional (spec 15).
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${local.name}-instance"
  role = aws_iam_role.instance.name
  tags = local.tags
}

# --- operator -----------------------------------------------------------------------

data "aws_iam_policy_document" "operator" {
  # The group replaces its instance, so instances are matched by the group's tag, which
  # only Auto Scaling can set (aws: prefix)
  statement {
    sid       = "PortForwardToUi"
    actions   = ["ssm:StartSession"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/aws:autoscaling:groupName"
      values   = [local.name]
    }
    condition {
      test     = "BoolIfExists"
      variable = "ssm:SessionDocumentAccessCheck"
      values   = ["true"]
    }
  }

  statement {
    sid       = "PortForwardDocument"
    actions   = ["ssm:StartSession"]
    resources = ["arn:${local.partition}:ssm:${local.region}::document/AWS-StartPortForwardingSession"]
    condition {
      test     = "BoolIfExists"
      variable = "ssm:SessionDocumentAccessCheck"
      values   = ["true"]
    }
  }

  statement {
    sid       = "FindInstance"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"] # does not support resource level permissions
  }

  statement {
    sid       = "ManageOwnSessions"
    actions   = ["ssm:TerminateSession", "ssm:ResumeSession"]
    resources = ["arn:${local.partition}:ssm:*:${local.account_id}:session/$${aws:userid}-*"]
  }

  statement {
    sid       = "RunValidation"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/aws:autoscaling:groupName"
      values   = [local.name]
    }
  }

  statement {
    sid       = "RunValidationDocument"
    actions   = ["ssm:SendCommand"]
    resources = [aws_ssm_document.run.arn]
  }

  statement {
    sid       = "ReadCommandResults"
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"]
    resources = ["*"] # these actions do not support resource level permissions
  }

  statement {
    sid       = "ReadReports"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.this.arn}/*/runs/*"]
  }

  statement {
    sid       = "DecryptReports"
    actions   = ["kms:Decrypt"]
    resources = [local.kms_key_arn]
  }
}

resource "aws_iam_policy" "operator" {
  name        = "${local.name}-operator"
  description = "Reach the Liftproof UI over Session Manager, start runs with Run Command, read reports"
  policy      = data.aws_iam_policy_document.operator.json
  tags        = local.tags
}

data "aws_iam_policy_document" "assume_operator" {
  count = length(var.operator_principal_arns) > 0 ? 1 : 0
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = var.operator_principal_arns
    }
  }
}

resource "aws_iam_role" "operator" {
  count                = length(var.operator_principal_arns) > 0 ? 1 : 0
  name                 = "${local.name}-operator"
  description          = "People and pipelines operating Liftproof"
  assume_role_policy   = data.aws_iam_policy_document.assume_operator[0].json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "operator" {
  count      = length(var.operator_principal_arns) > 0 ? 1 : 0
  role       = aws_iam_role.operator[0].name
  policy_arn = aws_iam_policy.operator.arn
}
