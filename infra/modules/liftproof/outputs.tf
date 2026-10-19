output "autoscaling_group_name" {
  description = "The group of one that runs the instance; it replaces a failed instance."
  value       = aws_autoscaling_group.this.name
}

output "bucket_name" {
  value = aws_s3_bucket.this.bucket
}

output "kms_key_arn" {
  value = local.kms_key_arn
}

output "instance_role_arn" {
  value = aws_iam_role.instance.arn
}

output "operator_policy_arn" {
  description = "Attach to people's and pipelines' roles, or assume operator_role_arn."
  value       = aws_iam_policy.operator.arn
}

output "operator_role_arn" {
  value = try(aws_iam_role.operator[0].arn, null)
}

output "run_document_name" {
  value = aws_ssm_document.run.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}

output "connect_ui" {
  description = "Open the web UI on localhost:8080 over Session Manager."
  value       = "aws ssm start-session --target $(aws ec2 describe-instances --filters Name=tag:aws:autoscaling:groupName,Values=${aws_autoscaling_group.this.name} Name=instance-state-name,Values=running --query Reservations[0].Instances[0].InstanceId --output text) --document-name AWS-StartPortForwardingSession --parameters portNumber=8080,localPortNumber=8080"
}

output "start_run" {
  description = "What a pipeline calls at cutover."
  value       = "aws ssm send-command --targets Key=tag:aws:autoscaling:groupName,Values=${aws_autoscaling_group.this.name} --document-name ${aws_ssm_document.run.name} --parameters project=PROJECT,mode=reconcile"
}

output "customer_key_policy_statements" {
  description = "With your own kms_key_arn: add these statements to that key's policy before the first apply (CloudWatch Logs cannot use the key without one). Null when the module creates the key."
  value       = var.kms_key_arn == null ? null : jsonencode(local.customer_key_statements)
}
