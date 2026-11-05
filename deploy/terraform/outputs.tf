# =============================================================================
# PRAHO Management Servers - Outputs
# =============================================================================

# Platform server (always present)
output "platform_server_id" {
  description = "Platform server Hetzner ID"
  value       = hcloud_server.platform.id
}

output "platform_server_name" {
  description = "Platform server name"
  value       = hcloud_server.platform.name
}

output "platform_ipv4" {
  description = "Platform server public IPv4 address"
  value       = hcloud_server.platform.ipv4_address
}

output "platform_server_type" {
  description = "Platform server type"
  value       = hcloud_server.platform.server_type
}

output "platform_status" {
  description = "Platform server status"
  value       = hcloud_server.platform.status
}

# Separate Portal server (split topology only)
output "portal_server_id" {
  description = "Separate Portal server Hetzner ID (null in combined topology)"
  value       = local.deploy_portal ? hcloud_server.portal[0].id : null
}

output "portal_server_name" {
  description = "Separate Portal server name (null in combined topology)"
  value       = local.deploy_portal ? hcloud_server.portal[0].name : null
}

output "portal_ipv4" {
  description = "Portal role public IPv4 address (shared with Platform in combined topology)"
  value       = local.deploy_portal ? hcloud_server.portal[0].ipv4_address : hcloud_server.platform.ipv4_address
}

# Summary
output "environment" {
  description = "Deployed environment"
  value       = var.environment
}

output "server_count" {
  description = "Number of servers provisioned"
  value       = local.deploy_portal ? 2 : 1
}

output "ssh_key_fingerprint" {
  description = "SSH key fingerprint"
  value       = hcloud_ssh_key.praho.fingerprint
}

output "firewall_id" {
  description = "Cloud firewall ID"
  value       = hcloud_firewall.praho.id
}

output "native_topology" {
  value = local.native_topology
}

output "platform_firewall_id" {
  value = hcloud_firewall.praho.id
}

output "portal_firewall_id" {
  value = local.deploy_portal ? hcloud_firewall.portal[0].id : hcloud_firewall.praho.id
}

output "platform_ipv6" {
  value = hcloud_server.platform.ipv6_address
}

output "portal_ipv6" {
  value = local.deploy_portal ? hcloud_server.portal[0].ipv6_address : hcloud_server.platform.ipv6_address
}
