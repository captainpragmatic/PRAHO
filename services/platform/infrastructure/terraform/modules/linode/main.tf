# Linode Provider Module for Node Deployment
# Provisions Linode instances with firewall and SSH key authentication

terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.12"
    }
  }
  required_version = ">= 1.5.0"
}

# Configure the Linode Provider
provider "linode" {
  token = var.linode_token
}

# Create SSH key resource from provided public key
resource "linode_sshkey" "node" {
  label   = "${var.hostname}-key"
  ssh_key = var.ssh_public_key
}

# Create the instance
resource "linode_instance" "node" {
  label           = var.hostname
  image           = var.server_image
  type            = var.type
  region          = var.region
  authorized_keys = [var.ssh_public_key]

  tags = ["praho", "deployment-${var.deployment_id}", "env-${var.environment}", "type-${var.node_type}"]

  lifecycle {
    prevent_destroy = false
  }
}
