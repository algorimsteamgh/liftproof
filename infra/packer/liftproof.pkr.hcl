# Liftproof product AMI. Built by the release workflow through the OIDC role in the
# Algorims build account, over Session Manager (no SSH port, no inbound rule).
#
# Marketplace AMIs cannot carry encrypted snapshots, so the image itself is
# unencrypted; customers' volumes are encrypted with their own KMS key at launch
# (see infra/modules/liftproof). The image holds no credentials and no customer data.

packer {
  required_version = ">= 1.11"
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.3.0"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "version" {
  description = "Liftproof version being released, for example 0.1.0"
  type        = string
}

variable "wheel" {
  description = "Path to the built liftproof wheel."
  type        = string
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "instance_profile" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "m7i.large"
}

locals {
  timestamp = formatdate("YYYYMMDDhhmm", timestamp())
}

source "amazon-ebs" "liftproof" {
  region          = var.region
  instance_type   = var.instance_type
  ami_name        = "liftproof-${var.version}-al2023-${local.timestamp}"
  ami_description = "Liftproof ${var.version}: migration validation for workloads moving to AWS"

  source_ami_filter {
    filters = {
      name                = "al2023-ami-2023.*-kernel-*-x86_64"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  iam_instance_profile        = var.instance_profile
  associate_public_ip_address = false

  communicator  = "ssh"
  ssh_username  = "ec2-user"
  ssh_interface = "session_manager"

  # IMDSv2 only, on the builder and baked into the image (AWSAPI-004)
  imds_support = "v2.0"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  ena_support   = true
  sriov_support = true
  encrypt_boot  = false

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  run_tags = {
    "liftproof:build" = "true"
    Name              = "liftproof-ami-build"
  }
  run_volume_tags = {
    "liftproof:build" = "true"
  }
  tags = {
    "liftproof:version" = var.version
    Product             = "Liftproof"
    BaseImage           = "{{ .SourceAMIName }}"
  }
}

build {
  sources = ["source.amazon-ebs.liftproof"]

  provisioner "file" {
    source      = var.wheel
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "/tmp/liftproof-files"
  }

  provisioner "shell" {
    execute_command  = "sudo -E bash -euo pipefail '{{ .Path }}'"
    environment_vars = ["LIFTPROOF_VERSION=${var.version}"]
    scripts          = ["${path.root}/files/provision.sh", "${path.root}/files/harden.sh", "${path.root}/files/cleanup.sh"]
  }

  post-processor "manifest" {
    output     = "packer-manifest.json"
    strip_path = true
  }
}
