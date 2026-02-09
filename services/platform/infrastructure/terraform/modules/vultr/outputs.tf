# Outputs from Vultr Instance Deployment
# Note: Output names match the output_mappings in PROVIDER_CONFIG

output "instance_id" {
  description = "Vultr instance ID"
  value       = vultr_instance.node.id
}

output "server_name" {
  description = "Instance hostname"
  value       = vultr_instance.node.hostname
}

output "main_ip" {
  description = "Instance public IPv4 address"
  value       = vultr_instance.node.main_ip
}

output "v6_main_ip" {
  description = "Instance public IPv6 address"
  value       = vultr_instance.node.v6_main_ip
}

output "status" {
  description = "Instance status"
  value       = vultr_instance.node.status
}

output "region" {
  description = "Instance region"
  value       = vultr_instance.node.region
}

output "plan" {
  description = "Instance plan"
  value       = vultr_instance.node.plan
}

output "ssh_key_id" {
  description = "SSH key ID"
  value       = vultr_ssh_key.node.id
}

output "firewall_group_id" {
  description = "Firewall group ID"
  value       = vultr_firewall_group.node.id
}

output "tags" {
  description = "Instance tags"
  value       = vultr_instance.node.tags
}
