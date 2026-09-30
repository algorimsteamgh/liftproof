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
  namespace           = "Certus"
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
