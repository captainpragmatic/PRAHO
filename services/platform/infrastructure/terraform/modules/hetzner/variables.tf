# Variables for Hetzner Cloud Node Deployment

variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "deployment_id" {
  description = "PRAHO deployment ID for tracking"
  type        = string
}

variable "hostname" {
  description = "Server hostname (23-char format: prd-sha-het-de-fsn1-001)"
  type        = string
  validation {
    condition     = length(var.hostname) == 23
    error_message = "Hostname must be exactly 23 characters."
  }
}

variable "fqdn" {
  description = "Fully qualified domain name for reverse DNS"
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

variable "server_type" {
  description = "Hetzner server type (e.g., cpx21, cpx31, cpx41)"
  type        = string
  default     = "cpx21"
}

variable "server_image" {
  description = "Server OS image"
  type        = string
  default     = "ubuntu-22.04"
}

variable "location" {
  description = "Hetzner datacenter location (e.g., fsn1, nbg1, hel1)"
  type        = string
  default     = "fsn1"
  validation {
    condition     = contains(["fsn1", "nbg1", "hel1", "ash", "hil"], var.location)
    error_message = "Location must be a valid Hetzner datacenter code."
  }
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
  sensitive   = true
}

variable "master_ssh_key_id" {
  description = "Optional Hetzner SSH key ID for master key (fallback access)"
  type        = string
  default     = ""
}

# Firewall configuration - allow all by default (can be customized)
variable "firewall_ssh_sources" {
  description = "Source IPs for SSH access (empty = all)"
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "firewall_webmin_sources" {
  description = "Source IPs for Webmin/Virtualmin access"
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}
