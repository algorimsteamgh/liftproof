# Algorims build and distribution account: security baseline, build network, and the
# OIDC roles and evidence store the release pipeline uses.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
  # backend "s3" {
  #   bucket       = "REPLACE-algorims-terraform-state"
  #   key          = "liftproof/build-account.tfstate"
  #   region       = "ap-south-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Product = "Liftproof", Environment = "build", Owner = "algorims" }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "github_repository" {
  type    = string
  default = "algorimsteamgh/liftproof"
}

variable "budget_emails" {
  type = list(string)
}

module "baseline" {
  source        = "../../modules/account-baseline"
  name          = "algorims-liftproof-build"
  budget_emails = var.budget_emails
}

module "network" {
  source     = "../../modules/network"
  name       = "liftproof-build"
  enable_nat = true # build instances fetch OS packages and Python wheels
  az_count   = 2
}

module "build" {
  source            = "../../modules/build-account"
  github_repository = var.github_repository
  build_vpc_id      = module.network.vpc_id
  build_subnet_id   = module.network.private_subnet_ids[0]
  access_log_bucket = module.baseline.access_log_bucket
}

output "release_role_arn" {
  value = module.build.release_role_arn
}

output "packer" {
  value = {
    subnet_id        = module.network.private_subnet_ids[0]
    security_group   = module.build.builder_security_group_id
    instance_profile = module.build.builder_instance_profile
    kms_key_arn      = module.build.build_kms_key_arn
  }
}
