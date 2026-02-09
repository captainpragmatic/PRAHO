# Cloudflare DNS Module for Node Deployment
# Creates A, AAAA, and MX records for deployed nodes

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5.0"
}

# Configure the Cloudflare Provider
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Create A record for IPv4
resource "cloudflare_record" "node_a" {
  zone_id = var.zone_id
  name    = var.hostname
  type    = "A"
  value   = var.ipv4_address
  ttl     = var.ttl
  proxied = false  # Don't proxy hosting server traffic

  comment = "PRAHO node deployment: ${var.deployment_id}"
}

# Create AAAA record for IPv6 (if provided)
resource "cloudflare_record" "node_aaaa" {
  count   = var.ipv6_address != "" ? 1 : 0
  zone_id = var.zone_id
  name    = var.hostname
  type    = "AAAA"
  value   = var.ipv6_address
  ttl     = var.ttl
  proxied = false

  comment = "PRAHO node deployment: ${var.deployment_id}"
}

# Create MX record for email routing (if enabled)
resource "cloudflare_record" "node_mx" {
  count    = var.create_mx_record ? 1 : 0
  zone_id  = var.zone_id
  name     = var.hostname
  type     = "MX"
  value    = "${var.hostname}.${var.zone_name}"
  priority = var.mx_priority
  ttl      = var.ttl
  proxied  = false

  comment = "PRAHO node deployment MX: ${var.deployment_id}"
}

# Create SPF record for email authentication (if enabled)
resource "cloudflare_record" "node_spf" {
  count   = var.create_mx_record ? 1 : 0
  zone_id = var.zone_id
  name    = var.hostname
  type    = "TXT"
  value   = "v=spf1 a mx ip4:${var.ipv4_address}${var.ipv6_address != "" ? " ip6:${var.ipv6_address}" : ""} ~all"
  ttl     = var.ttl
  proxied = false

  comment = "PRAHO node deployment SPF: ${var.deployment_id}"
}
