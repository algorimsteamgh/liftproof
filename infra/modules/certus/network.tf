# No inbound rule exists anywhere: the UI is reached over Session Manager port
# forwarding and runs are started with Run Command. Egress is limited to the VPC
# endpoints, the S3 prefix list, and the declared databases and applications.

data "aws_vpc" "this" {
  id = var.vpc_id
}

data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${local.region}.s3"
}

resource "aws_security_group" "instance" {
  name        = "${local.name}-instance"
  description = "Certus instance: no inbound, scoped egress"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${local.name}-instance" })
}

resource "aws_vpc_security_group_egress_rule" "endpoints" {
  security_group_id = aws_security_group.instance.id
  description       = "AWS service endpoints inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = data.aws_vpc.this.cidr_block
}

resource "aws_vpc_security_group_egress_rule" "s3" {
  security_group_id = aws_security_group.instance.id
  description       = "Amazon S3 through the gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_ec2_managed_prefix_list.s3.id
}

resource "aws_vpc_security_group_egress_rule" "databases" {
  for_each          = { for d in var.database_egress : "${d.cidr}:${d.port}" => d }
  security_group_id = aws_security_group.instance.id
  description       = each.value.description
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr
}

resource "aws_vpc_security_group_egress_rule" "applications" {
  for_each = {
    for pair in setproduct(var.application_egress_cidrs, var.application_egress_ports) :
    "${pair[0]}:${pair[1]}" => { cidr = pair[0], port = pair[1] }
  }
  security_group_id = aws_security_group.instance.id
  description       = "Source and target applications (record and replay)"
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr
}

# --- VPC endpoints (a customer prerequisite in private subnets) ---------------------

locals {
  interface_endpoints = var.create_vpc_endpoints ? toset([
    "ssm", "ssmmessages", "ec2messages", "secretsmanager", "kms", "logs", "monitoring",
  ]) : toset([])
  endpoint_subnets = length(var.endpoint_subnet_ids) > 0 ? var.endpoint_subnet_ids : [var.subnet_id]
}

resource "aws_security_group" "endpoints" {
  #checkov:skip=CKV2_AWS_5:Attached to the interface endpoints created with for_each
  count       = var.create_vpc_endpoints ? 1 : 0
  name        = "${local.name}-endpoints"
  description = "Interface endpoints used by Certus"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${local.name}-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  description                  = "HTTPS from the Certus instance"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.instance.id
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.endpoint_subnets
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${local.name}-${each.key}" })
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_vpc_endpoints ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids
  tags              = merge(local.tags, { Name = "${local.name}-s3" })
}
