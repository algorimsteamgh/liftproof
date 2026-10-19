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
    vpc_cidr         = data.aws_vpc.this.cidr_block # doctor: endpoint addresses inside it
    bucket           = aws_s3_bucket.this.bucket
    kms_key          = local.kms_key_arn
    log_group        = aws_cloudwatch_log_group.this.name
    report_lock_days = var.report_lock_days
    # every AWS client in a Liftproof process shares one token bucket of this rate
    # (AWSAPI-002); a run, the UI and the scheduler each have their own
    aws_requests_per_second = var.aws_requests_per_second
  })
}

# A group of one: the group replaces a failed instance, which restores its projects from
# S3 at first boot. A new AMI makes a new launch template version, which reaches the
# running instance only when it is replaced, so upgrades stay deliberate.
resource "aws_launch_template" "this" {
  name                   = local.name
  image_id               = var.ami_id
  instance_type          = var.instance_type
  ebs_optimized          = true
  update_default_version = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.instance.arn
  }

  monitoring {
    enabled = true
  }

  network_interfaces {
    device_index                = 0
    security_groups             = [aws_security_group.instance.id]
    associate_public_ip_address = false
    delete_on_termination       = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only (AWSAPI-004)
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  block_device_mappings {
    device_name = "/dev/sda1" # Ubuntu root device
    ebs {
      volume_type           = "gp3"
      volume_size           = var.root_volume_gib
      encrypted             = true
      kms_key_id            = local.kms_key_arn
      delete_on_termination = true
    }
  }

  # Instance level settings only; no credentials. Nothing for the customer to run.
  user_data = base64encode(<<-EOT
    #cloud-config
    write_files:
      - path: /etc/mvt/config.yaml
        permissions: "0640"
        owner: root:mvt
        content: |
          ${indent(6, local.instance_config)}
  EOT
  )

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = local.name })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, { Name = local.name })
  }

  tags = local.tags
}

resource "aws_autoscaling_group" "this" {
  name                      = local.name
  min_size                  = 1
  max_size                  = 1
  desired_capacity          = 1
  vpc_zone_identifier       = [var.subnet_id]
  health_check_type         = "EC2"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }

  # the policy grants the group's service-linked role use of the key for the root volume
  depends_on = [aws_kms_key.this]

  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

resource "aws_autoscaling_notification" "this" {
  count       = var.alarm_topic_arn == null ? 0 : 1
  group_names = [aws_autoscaling_group.this.name]
  notifications = [
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
  ]
  topic_arn = var.alarm_topic_arn
}
