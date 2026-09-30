output "instance_id" {
  value = aws_instance.this.id
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
  value       = "aws ssm start-session --target ${aws_instance.this.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=8080,localPortNumber=8080"
}

output "start_run" {
  description = "What a pipeline calls at cutover."
  value       = "aws ssm send-command --instance-ids ${aws_instance.this.id} --document-name ${aws_ssm_document.run.name} --parameters project=PROJECT,mode=reconcile"
}
