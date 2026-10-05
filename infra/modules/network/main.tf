# Reference network for customers without a suitable VPC, and for our own test
# environment: private subnets across two Availability Zones, no internet gateway by
# default, VPC Flow Logs on, the default security group locked down, and a virtual
# private gateway ready for a Site-to-Site VPN to the source environment.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

variable "name" {
  type = string
}

variable "cidr" {
  type    = string
  default = "10.42.0.0/20"
}

variable "az_count" {
  type    = number
  default = 2
}

variable "enable_vpn_gateway" {
  description = "Attach a virtual private gateway for a Site-to-Site VPN or Direct Connect to the source."
  type        = bool
  default     = false
}

variable "enable_nat" {
  description = "Only when the source is reachable over the internet. Adds an internet gateway and a NAT gateway."
  type        = bool
  default     = false
}

variable "flow_log_retention_days" {
  type    = number
  default = 365
}

variable "kms_key_arn" {
  description = "Key for the flow log group. Null uses CloudWatch Logs' default encryption."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only the first az_count zones are used, so a new zone does not change the result
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  azs  = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  tags = merge(var.tags, { "liftproof:managed-by" = "terraform" })
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required for interface endpoint private DNS
  tags                 = merge(local.tags, { Name = var.name })
}

resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-default-locked" })
  # no ingress or egress rules: nothing may use the default group
}

resource "aws_subnet" "private" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.cidr, 4, count.index)
  tags              = merge(local.tags, { Name = "${var.name}-private-${local.azs[count.index]}", Tier = "private" })
}

resource "aws_route_table" "private" {
  count  = var.az_count
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-private-${local.azs[count.index]}" })
}

resource "aws_route_table_association" "private" {
  count          = var.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# --- optional paths to the source --------------------------------------------------

resource "aws_vpn_gateway" "this" {
  count  = var.enable_vpn_gateway ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = var.name })
}

resource "aws_vpn_gateway_route_propagation" "private" {
  count          = var.enable_vpn_gateway ? var.az_count : 0
  vpn_gateway_id = aws_vpn_gateway.this[0].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_subnet" "public" {
  count             = var.enable_nat ? 1 : 0
  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[0]
  cidr_block        = cidrsubnet(var.cidr, 4, 15)
  tags              = merge(local.tags, { Name = "${var.name}-public-nat", Tier = "public" })
}

resource "aws_internet_gateway" "this" {
  count  = var.enable_nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = var.name })
}

resource "aws_route_table" "public" {
  count  = var.enable_nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }
  tags = merge(local.tags, { Name = "${var.name}-public" })
}

resource "aws_route_table_association" "public" {
  count          = var.enable_nat ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  count  = var.enable_nat ? 1 : 0
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${var.name}-nat" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = merge(local.tags, { Name = var.name })
}

resource "aws_route" "nat" {
  count                  = var.enable_nat ? var.az_count : 0
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

# --- flow logs ---------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "flow" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow.json
}

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn
  tags            = local.tags
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "private_route_table_ids" {
  value = aws_route_table.private[*].id
}

output "vpn_gateway_id" {
  value = try(aws_vpn_gateway.this[0].id, null)
}
