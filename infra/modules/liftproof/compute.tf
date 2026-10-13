# One instance, disposable by design: projects, baselines and reports are in S3, so a
# lost instance is replaced by launching another against the same bucket.

resource "aws_cloudwatch_log_group" "this" {
  name              = "/liftproof/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
  tags              = local.tags
}

locals {
  instance_config = yamlencode({
    deployment       = var.name # the dimension the skipped run alarm watches
    region           = local.region
    bucket           = aws_s3_bucket.this.bucket
    kms_key          = local.kms_key_arn
    log_group        = aws_cloudwatch_log_group.this.name
    report_lock_days = var.report_lock_days
    # every AWS client shares one token bucket of this rate (AWSAPI-002)
    aws_requests_per_second = var.aws_requests_per_second
  })
}

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = false
  ebs_optimized               = true
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only (AWSAPI-004)
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gib
    encrypted             = true
    kms_key_id            = local.kms_key_arn
    delete_on_termination = true
  }

  maintenance_options {
    auto_recovery = "default"
  }

  # Instance level settings only; no credentials. Nothing for the customer to run.
  user_data = <<-EOT
    #cloud-config
    write_files:
      - path: /etc/mvt/config.yaml
        permissions: "0640"
        owner: root:mvt
        content: |
          ${indent(6, local.instance_config)}
  EOT

  user_data_replace_on_change = true

  tags        = merge(local.tags, { Name = local.name })
  volume_tags = merge(local.tags, { Name = local.name })

  lifecycle {
    ignore_changes = [ami] # upgrade by launching the new Marketplace version deliberately
  }
}
