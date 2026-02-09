# Variables for Linode Instance Deployment

variable "linode_token" {
  description = "Linode API token"
  type        = string
  sensitive   = true
}

variable "deployment_id" {
  description = "PRAHO deployment ID for tracking"
  type        = string
}

variable "hostname" {
  description = "Server hostname (23-char format: prd-sha-lin-us-east-001)"
  type        = string
  validation {
    condition     = length(var.hostname) == 23
    error_message = "Hostname must be exactly 23 characters."
  }
}

variable "fqdn" {
  description = "Fully qualified domain name"
  type        = string
}

variable "environment" {
  description = "Deployment environment (prd/stg/dev)"
  type        = string
  default     = "prd"
  validation {
    condition     = contains(["prd", "stg", "dev"], var.environment)
    error_message = "Environment must be prd, stg, or dev."
  }
}

variable "node_type" {
  description = "Node type code (sha/vps/ctr/ded/app)"
  type        = string
  default     = "sha"
  validation {
    condition     = contains(["sha", "vps", "ctr", "ded", "app"], var.node_type)
    error_message = "Node type must be sha, vps, ctr, ded, or app."
  }
}

variable "type" {
  description = "Linode plan type (e.g., g6-standard-2, g6-standard-4)"
  type        = string
  default     = "g6-standard-2"
}

variable "server_image" {
  description = "Server OS image"
  type        = string
  default     = "linode/ubuntu22.04"
}

variable "region" {
  description = "Linode region (e.g., us-east, eu-west, ap-south)"
  type        = string
  default     = "us-east"
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
  sensitive   = true
}

# Firewall configuration
variable "firewall_ssh_sources" {
  description = "Source IPs/CIDRs for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "firewall_webmin_sources" {
  description = "Source IPs/CIDRs for Webmin/Virtualmin access"
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}
