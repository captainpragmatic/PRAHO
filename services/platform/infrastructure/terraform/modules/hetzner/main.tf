# Hetzner Cloud Provider Module for Node Deployment
# Provisions VPS servers with cloud firewall and SSH key authentication

terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
  required_version = ">= 1.5.0"
}

# Configure the Hetzner Cloud Provider
provider "hcloud" {
  token = var.hcloud_token
}

# Create SSH key resource from provided public key
resource "hcloud_ssh_key" "node" {
  name       = "${var.hostname}-key"
  public_key = var.ssh_public_key

  labels = {
    managed_by   = "praho"
    deployment   = var.deployment_id
    environment  = var.environment
    node_type    = var.node_type
  }
}

# Create the server
resource "hcloud_server" "node" {
  name        = var.hostname
  image       = var.server_image
  server_type = var.server_type
  location    = var.location

  ssh_keys = [hcloud_ssh_key.node.id]

  # Also include master SSH key if provided
  # ssh_keys = var.master_ssh_key_id != "" ? [hcloud_ssh_key.node.id, var.master_ssh_key_id] : [hcloud_ssh_key.node.id]

  labels = {
    managed_by   = "praho"
    deployment   = var.deployment_id
    environment  = var.environment
    node_type    = var.node_type
    hostname     = var.hostname
    provider     = "hetzner"
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  # Attach firewall
  firewall_ids = [hcloud_firewall.node.id]

  lifecycle {
    # Prevent accidental destruction
    prevent_destroy = false
  }
}

# Associate firewall with server (explicit association)
resource "hcloud_firewall_attachment" "node" {
  firewall_id = hcloud_firewall.node.id
  server_ids  = [hcloud_server.node.id]
}

# Reverse DNS for IPv4
resource "hcloud_rdns" "node_ipv4" {
  server_id  = hcloud_server.node.id
  ip_address = hcloud_server.node.ipv4_address
  dns_ptr    = var.fqdn
}

# Reverse DNS for IPv6
resource "hcloud_rdns" "node_ipv6" {
  server_id  = hcloud_server.node.id
  ip_address = hcloud_server.node.ipv6_address
  dns_ptr    = var.fqdn
}
