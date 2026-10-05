# Example customer deployment: a reference private network plus Liftproof.
# Customers with an existing VPC skip module.network and pass their own ids.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
  # Remote state with native S3 locking. Create the bucket once, then uncomment.
  # backend "s3" {
  #   bucket       = "REPLACE-terraform-state"
  #   key          = "liftproof/acme-prod.tfstate"
  #   region       = "ap-south-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Product = "Liftproof", Environment = var.environment }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "ami_id" {
  type = string
}

variable "source_database_cidr" {
  description = "Where the source database lives (on premises over VPN, for example)."
  type        = string
}

variable "target_database_cidr" {
  description = "Where the migrated database lives on AWS."
  type        = string
}

variable "application_cidrs" {
  type = list(string)
}

variable "operator_principal_arns" {
  type    = list(string)
  default = []
}

module "network" {
  source             = "../../modules/network"
  name               = "liftproof-acme"
  enable_vpn_gateway = true # the customer attaches its Site-to-Site VPN here
}

module "liftproof" {
  source                  = "../../modules/liftproof"
  name                    = "acme-prod"
  ami_id                  = var.ami_id
  vpc_id                  = module.network.vpc_id
  subnet_id               = module.network.private_subnet_ids[0]
  endpoint_subnet_ids     = module.network.private_subnet_ids
  private_route_table_ids = module.network.private_route_table_ids
  secret_arns = [
    "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:liftproof/acme-prod/*",
  ]
  database_egress = [
    { description = "Source PostgreSQL (on premises)", cidr = var.source_database_cidr, port = 5432 },
    { description = "Target Amazon Aurora PostgreSQL", cidr = var.target_database_cidr, port = 5432 },
  ]
  application_egress_cidrs = var.application_cidrs
  operator_principal_arns  = var.operator_principal_arns
}

data "aws_caller_identity" "current" {}

output "liftproof" {
  value = {
    instance_id   = module.liftproof.instance_id
    bucket        = module.liftproof.bucket_name
    run_document  = module.liftproof.run_document_name
    connect_ui    = module.liftproof.connect_ui
    start_run     = module.liftproof.start_run
    operator_role = module.liftproof.operator_role_arn
  }
}
