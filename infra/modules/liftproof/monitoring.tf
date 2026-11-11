locals {
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "system_status" {
  alarm_name          = "${local.name}-system-status"
  alarm_description   = "Underlying host failed; EC2 recovers the instance onto new hardware"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  dimensions          = { InstanceId = aws_instance.this.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = concat(["arn:${local.partition}:automate:${local.region}:ec2:recover"], local.alarm_actions)
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "skipped_runs" {
  alarm_name          = "${local.name}-scheduled-run-skipped"
  alarm_description   = "A scheduled validation was skipped because the previous one was still running (spec 14). Nightly validation may have silently stopped."
  namespace           = "Liftproof"
  metric_name         = "ScheduledRunSkipped"
  dimensions          = { Deployment = var.name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name          = "${local.name}-instance-status"
  alarm_description   = "The operating system stopped answering (instance status check); EC2 reboots it. A run under way stops and is resumed or rerun (liftproof reconcile --resume)."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_Instance"
  dimensions          = { InstanceId = aws_instance.this.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = concat(["arn:${local.partition}:automate:${local.region}:ec2:reboot"], local.alarm_actions)
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "run_failed" {
  alarm_name          = "${local.name}-run-failed"
  alarm_description   = "A Liftproof run ended without a verdict (exit code 2 or 3): read its report or log. Scheduled validation gave no answer."
  namespace           = "Liftproof"
  metric_name         = "RunFailed"
  dimensions          = { Deployment = var.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  tags                = local.tags
}

# Published by the CloudWatch agent (infra/packer/files/mvt-cwagent-config). Working
# copies, hashes and captured responses are on the root volume; a full one fails runs.
resource "aws_cloudwatch_metric_alarm" "root_volume" {
  alarm_name          = "${local.name}-root-volume"
  alarm_description   = "The instance's root volume is over 85% full; runs will start failing. Grow the volume or clear the working directory."
  namespace           = "Liftproof"
  metric_name         = "disk_used_percent"
  dimensions          = { Deployment = var.name, path = "/", fstype = "ext4" }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 85
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching" # a stopped instance publishes nothing
  alarm_actions       = local.alarm_actions
  tags                = local.tags
}
