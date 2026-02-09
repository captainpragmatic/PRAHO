# Outputs from Hetzner Cloud Node Deployment

output "server_id" {
  description = "Hetzner server ID"
  value       = hcloud_server.node.id
}

output "server_name" {
  description = "Server hostname"
  value       = hcloud_server.node.name
}

output "ipv4_address" {
  description = "Server public IPv4 address"
  value       = hcloud_server.node.ipv4_address
}

output "ipv6_address" {
  description = "Server public IPv6 address"
  value       = hcloud_server.node.ipv6_address
}

output "ipv6_network" {
  description = "Server IPv6 network"
  value       = hcloud_server.node.ipv6_network
}

output "status" {
  description = "Server status"
  value       = hcloud_server.node.status
}

output "datacenter" {
  description = "Server datacenter"
  value       = hcloud_server.node.datacenter
}

output "server_type" {
  description = "Server type"
  value       = hcloud_server.node.server_type
}

output "ssh_key_id" {
  description = "SSH key ID"
  value       = hcloud_ssh_key.node.id
}

output "ssh_key_fingerprint" {
  description = "SSH key fingerprint"
  value       = hcloud_ssh_key.node.fingerprint
}

output "firewall_id" {
  description = "Firewall ID"
  value       = hcloud_firewall.node.id
}

output "labels" {
  description = "Server labels"
  value       = hcloud_server.node.labels
}
