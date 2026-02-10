# =============================================================================
# PRAHO Management Servers - Hetzner Cloud Provisioning
# =============================================================================
# Provisions the VPS where PRAHO itself runs (not customer hosting nodes).
#
# Topology:
#   dev     → 1 server  (all-in-one: Platform + Portal + DB + Caddy)
#   staging → 2 servers (platform + portal, mirrors prod)
#   prod    → 2 servers (platform + portal)
#
# Usage:
#   terraform workspace new dev && terraform apply -var="environment=dev"
#   terraform workspace new staging && terraform apply -var="environment=staging"
#   terraform workspace new prod && terraform apply -var="environment=prod"
# =============================================================================

provider "hcloud" {
  token = var.hcloud_token
}

# =============================================================================
# SSH Keys
# =============================================================================

resource "hcloud_ssh_key" "praho" {
  name       = "praho-${var.environment}-key"
  public_key = var.ssh_public_key

  labels = merge(local.common_labels, {
    role = "ssh"
  })
}

# =============================================================================
# Cloud Firewall
# =============================================================================

resource "hcloud_firewall" "praho" {
  name = "praho-${var.environment}-fw"

  labels = merge(local.common_labels, {
    role = "firewall"
  })

  # SSH
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.firewall_ssh_sources
    description = "SSH access"
  }

  # HTTP (Caddy / Let's Encrypt)
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "HTTP"
  }

  # HTTPS
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "HTTPS"
  }

  # Allow all outbound TCP
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "All outbound TCP"
  }

  # Allow all outbound UDP
  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "All outbound UDP"
  }

  # ICMP outbound
  rule {
    direction       = "out"
    protocol        = "icmp"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "ICMP outbound"
  }
}

# =============================================================================
# Platform Server (all environments)
# =============================================================================
# In dev: runs all-in-one (Platform + Portal + DB + Caddy)
# In staging/prod: runs Platform + DB + Caddy

resource "hcloud_server" "platform" {
  name        = var.environment == "dev" ? "praho-dev" : "praho-${var.environment}-platform"
  image       = var.server_image
  server_type = local.platform_type
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.praho.id]
  firewall_ids = [hcloud_firewall.praho.id]

  labels = merge(local.common_labels, {
    role = var.environment == "dev" ? "all-in-one" : "platform"
  })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  lifecycle {
    prevent_destroy = false
  }
}

# Reverse DNS for platform server
resource "hcloud_rdns" "platform_ipv4" {
  server_id  = hcloud_server.platform.id
  ip_address = hcloud_server.platform.ipv4_address
  dns_ptr    = var.environment == "dev" ? "dev.${var.domain}" : "${var.environment}.${var.domain}"
}

# =============================================================================
# Portal Server (staging + prod only)
# =============================================================================

resource "hcloud_server" "portal" {
  count = local.deploy_portal ? 1 : 0

  name        = "praho-${var.environment}-portal"
  image       = var.server_image
  server_type = local.portal_type
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.praho.id]
  firewall_ids = [hcloud_firewall.praho.id]

  labels = merge(local.common_labels, {
    role = "portal"
  })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  lifecycle {
    prevent_destroy = false
  }
}

# Reverse DNS for portal server
resource "hcloud_rdns" "portal_ipv4" {
  count = local.deploy_portal ? 1 : 0

  server_id  = hcloud_server.portal[0].id
  ip_address = hcloud_server.portal[0].ipv4_address
  dns_ptr    = "portal.${var.environment}.${var.domain}"
}
