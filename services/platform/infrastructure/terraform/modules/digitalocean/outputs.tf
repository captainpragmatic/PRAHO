# Outputs from DigitalOcean Droplet Deployment
# Note: Output names match the standard interface expected by PRAHO

output "server_id" {
  description = "DigitalOcean Droplet ID"
  value       = digitalocean_droplet.node.id
}

output "server_name" {
  description = "Droplet hostname"
  value       = digitalocean_droplet.node.name
}

output "ipv4_address" {
  description = "Droplet public IPv4 address"
  value       = digitalocean_droplet.node.ipv4_address
}

output "ipv6_address" {
  description = "Droplet public IPv6 address"
  value       = digitalocean_droplet.node.ipv6_address
}

output "status" {
  description = "Droplet status"
  value       = digitalocean_droplet.node.status
}

output "region" {
  description = "Droplet region"
  value       = digitalocean_droplet.node.region
}

output "size" {
  description = "Droplet size"
  value       = digitalocean_droplet.node.size
}

output "ssh_key_id" {
  description = "SSH key ID"
  value       = digitalocean_ssh_key.node.id
}

output "ssh_key_fingerprint" {
  description = "SSH key fingerprint"
  value       = digitalocean_ssh_key.node.fingerprint
}

output "firewall_id" {
  description = "Firewall ID"
  value       = digitalocean_firewall.node.id
}

output "tags" {
  description = "Droplet tags"
  value       = digitalocean_droplet.node.tags
}

output "urn" {
  description = "Droplet URN for DigitalOcean API"
  value       = digitalocean_droplet.node.urn
}
