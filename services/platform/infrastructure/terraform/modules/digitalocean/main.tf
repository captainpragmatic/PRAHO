# DigitalOcean Provider Module for Node Deployment
# Provisions Droplets with cloud firewall and SSH key authentication

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.34"
    }
  }
  required_version = ">= 1.5.0"
}

# Configure the DigitalOcean Provider
provider "digitalocean" {
  token = var.do_token
}

# Create SSH key resource from provided public key
resource "digitalocean_ssh_key" "node" {
  name       = "${var.hostname}-key"
  public_key = var.ssh_public_key
}

# Create the Droplet
resource "digitalocean_droplet" "node" {
  name     = var.hostname
  image    = var.server_image
  size     = var.size
  region   = var.region

  ssh_keys = [digitalocean_ssh_key.node.fingerprint]

  ipv6       = true
  monitoring = true
  backups    = var.enable_backups

  tags = [
    "praho",
    "deployment-${var.deployment_id}",
    "env-${var.environment}",
    "type-${var.node_type}",
    "managed-by-terraform"
  ]

  lifecycle {
    # Prevent accidental destruction
    prevent_destroy = false
  }
}

# Create firewall for the node
resource "digitalocean_firewall" "node" {
  name = "${var.hostname}-fw"

  droplet_ids = [digitalocean_droplet.node.id]

  # SSH Access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.firewall_ssh_sources
  }

  # HTTP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # HTTPS
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Webmin/Virtualmin
  inbound_rule {
    protocol         = "tcp"
    port_range       = "10000"
    source_addresses = var.firewall_webmin_sources
  }

  # Usermin
  inbound_rule {
    protocol         = "tcp"
    port_range       = "20000"
    source_addresses = var.firewall_webmin_sources
  }

  # SMTP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "25"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SMTP Submission
  inbound_rule {
    protocol         = "tcp"
    port_range       = "587"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SMTPS
  inbound_rule {
    protocol         = "tcp"
    port_range       = "465"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # IMAP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "143"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # IMAPS
  inbound_rule {
    protocol         = "tcp"
    port_range       = "993"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # POP3
  inbound_rule {
    protocol         = "tcp"
    port_range       = "110"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # POP3S
  inbound_rule {
    protocol         = "tcp"
    port_range       = "995"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # DNS
  inbound_rule {
    protocol         = "tcp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # FTP
  inbound_rule {
    protocol         = "tcp"
    port_range       = "21"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # ICMP (ping)
  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow all outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  tags = ["praho", "deployment-${var.deployment_id}"]
}
