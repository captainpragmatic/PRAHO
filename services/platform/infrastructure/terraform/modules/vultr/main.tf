# Vultr Provider Module for Node Deployment
# Provisions VPS instances with firewall and SSH key authentication

terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.19"
    }
  }
  required_version = ">= 1.5.0"
}

# Configure the Vultr Provider
provider "vultr" {
  api_key = var.vultr_api_key
}

# Create SSH key resource from provided public key
resource "vultr_ssh_key" "node" {
  name    = "${var.hostname}-key"
  ssh_key = var.ssh_public_key
}

# Create the instance
resource "vultr_instance" "node" {
  plan        = var.plan
  region      = var.region
  os_id       = var.os_id
  hostname    = var.hostname
  ssh_key_ids = [vultr_ssh_key.node.id]
  label       = "praho-${var.deployment_id}"

  enable_ipv6 = true

  tags = ["praho", "deployment-${var.deployment_id}", "env-${var.environment}", "type-${var.node_type}"]

  lifecycle {
    prevent_destroy = false
  }
}

# Create firewall group
resource "vultr_firewall_group" "node" {
  description = "${var.hostname}-fw"
}
