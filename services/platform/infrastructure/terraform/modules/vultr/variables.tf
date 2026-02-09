# Variables for Vultr Instance Deployment

variable "vultr_api_key" {
  description = "Vultr API key"
  type        = string
  sensitive   = true
}

variable "deployment_id" {
  description = "PRAHO deployment ID for tracking"
  type        = string
}

variable "hostname" {
  description = "Server hostname (23-char format: prd-sha-vul-us-ewr1-001)"
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

variable "plan" {
  description = "Vultr plan ID (e.g., vc2-2c-4gb, vc2-4c-8gb)"
  type        = string
  default     = "vc2-2c-4gb"
}

variable "os_id" {
  description = "Vultr OS ID (e.g., 1743 for Ubuntu 22.04)"
  type        = number
  default     = 1743
}

variable "server_image" {
  description = "Server OS image identifier (unused, os_id takes precedence)"
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "region" {
  description = "Vultr region code (e.g., ewr, ord, lax, ams, fra)"
  type        = string
  default     = "ewr"
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
