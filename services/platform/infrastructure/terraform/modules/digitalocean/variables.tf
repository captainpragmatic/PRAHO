# Variables for DigitalOcean Droplet Deployment

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "deployment_id" {
  description = "PRAHO deployment ID for tracking"
  type        = string
}

variable "hostname" {
  description = "Server hostname (23-char format: prd-sha-dig-us-nyc1-001)"
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

variable "size" {
  description = "DigitalOcean Droplet size (e.g., s-2vcpu-4gb, s-4vcpu-8gb)"
  type        = string
  default     = "s-2vcpu-4gb"
}

variable "server_image" {
  description = "Server OS image"
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "region" {
  description = "DigitalOcean datacenter region (e.g., nyc1, sfo1, ams3)"
  type        = string
  default     = "nyc1"
  validation {
    condition = contains([
      "nyc1", "nyc2", "nyc3",
      "sfo1", "sfo2", "sfo3",
      "ams2", "ams3",
      "sgp1",
      "lon1",
      "fra1",
      "tor1",
      "blr1",
      "syd1"
    ], var.region)
    error_message = "Region must be a valid DigitalOcean datacenter code."
  }
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
  sensitive   = true
}

variable "enable_backups" {
  description = "Enable DigitalOcean automated backups"
  type        = bool
  default     = true
}

# Firewall configuration
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
