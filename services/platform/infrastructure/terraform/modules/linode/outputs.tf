# Outputs from Linode Instance Deployment
# Note: Output names match the output_mappings in PROVIDER_CONFIG

output "id" {
  description = "Linode instance ID"
  value       = linode_instance.node.id
}

output "server_name" {
  description = "Instance label"
  value       = linode_instance.node.label
}

output "ip_address" {
  description = "Instance public IPv4 address"
  value       = linode_instance.node.ip_address
}

output "ipv6" {
  description = "Instance IPv6 address (SLAAC)"
  value       = linode_instance.node.ipv6
}

output "status" {
  description = "Instance status"
  value       = linode_instance.node.status
}

output "region" {
  description = "Instance region"
  value       = linode_instance.node.region
}

output "type" {
  description = "Instance type"
  value       = linode_instance.node.type
}

output "ssh_key_id" {
  description = "SSH key ID"
  value       = linode_sshkey.node.id
}

output "firewall_id" {
  description = "Firewall ID"
  value       = linode_firewall.node.id
}

output "tags" {
  description = "Instance tags"
  value       = linode_instance.node.tags
}
