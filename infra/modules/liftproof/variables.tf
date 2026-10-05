variable "name" {
  description = "Deployment name, used in resource names (for example acme-prod)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.name))
    error_message = "Use 2 to 31 lower case letters, digits or hyphens."
  }
}

variable "ami_id" {
  description = "Liftproof AMI from AWS Marketplace."
  type        = string
}

variable "instance_type" {
  description = "Instance type. 4 vCPU / 16 GiB is the starting point until the throughput KPI is measured."
  type        = string
  default     = "m7i.xlarge"
}

variable "root_volume_gib" {
  description = "Root volume size. Holds working copies and transient chunk hashes only."
  type        = number
  default     = 100
}

variable "vpc_id" {
  description = "VPC to deploy into."
  type        = string
}

variable "subnet_id" {
  description = "Private subnet for the instance. It needs no internet gateway route."
  type        = string
}

variable "create_vpc_endpoints" {
  description = "Create the interface and gateway endpoints the product needs in a private subnet. Set false if the VPC already has them."
  type        = bool
  default     = true
}

variable "endpoint_subnet_ids" {
  description = "Subnets for the interface endpoints, ideally one per Availability Zone. Defaults to the instance subnet."
  type        = list(string)
  default     = []
}

variable "private_route_table_ids" {
  description = "Route tables that get the Amazon S3 gateway endpoint."
  type        = list(string)
  default     = []
}

variable "database_egress" {
  description = "Source and target databases the instance may reach: CIDR and port."
  type = list(object({
    description = string
    cidr        = string
    port        = number
  }))
  default = []
}

variable "application_egress_cidrs" {
  description = "Networks hosting the source and target applications, reached over HTTPS for record and replay."
  type        = list(string)
  default     = []
}

variable "application_egress_ports" {
  description = "Ports the recorded applications listen on."
  type        = list(number)
  default     = [443]
}

variable "kms_key_arn" {
  description = "Existing customer managed KMS key. Leave null to create a dedicated key with rotation."
  type        = string
  default     = null
}

variable "secret_arns" {
  description = "Secrets Manager secrets the product may read (database and replay credentials). Wildcards allowed, for example arn:...:secret:liftproof/*"
  type        = list(string)
}

variable "secret_kms_key_arns" {
  description = "KMS keys that encrypt those secrets, when they differ from the product key. This is the usual cause of access denied on first run."
  type        = list(string)
  default     = []
}

variable "bucket_name" {
  description = "Bucket name. Leave null to derive one from the account and region."
  type        = string
  default     = null
}

variable "report_lock_days" {
  description = "Object Lock retention (governance mode) applied by the product to reports under runs/. The report is a go live sign off record."
  type        = number
  default     = 365
}

variable "asset_retention_days" {
  description = "Recorded request/response bodies and page snapshots expire after this many days."
  type        = number
  default     = 90
}

variable "noncurrent_version_days" {
  description = "Old object versions expire after this many days."
  type        = number
  default     = 90
}

variable "access_log_bucket" {
  description = "Existing bucket for S3 server access logs. Null disables access logging."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the product log group."
  type        = number
  default     = 365
}

variable "operator_principal_arns" {
  description = "IAM principals (people's roles, pipeline roles) allowed to assume the operator role. Empty skips the role; the operator policy is still created."
  type        = list(string)
  default     = []
}

variable "alarm_topic_arn" {
  description = "SNS topic for alarms. Null creates alarms without actions."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
