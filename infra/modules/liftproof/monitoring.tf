locals {
  alarm_actions = var.alarm_topic_arn == null ? [] : [var.alarm_topic_arn]
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
