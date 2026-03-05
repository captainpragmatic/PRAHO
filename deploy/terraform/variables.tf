# =============================================================================
# PRAHO Management Servers - Input Variables
# =============================================================================

variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Base domain for reverse DNS (e.g., pragmatichost.com)"
  type        = string
  default     = "pragmatichost.com"
}

variable "location" {
  description = "Hetzner datacenter location"
  type        = string
  default     = "fsn1"
  validation {
    condition     = contains(["fsn1", "nbg1", "hel1", "ash", "hil"], var.location)
    error_message = "Location must be a valid Hetzner datacenter code."
  }
}

variable "server_image" {
  description = "Server OS image"
  type        = string
  default     = "ubuntu-22.04"
}

# Server type overrides per role (defaults sized per plan)
variable "platform_server_type" {
  description = "Server type for platform server"
  type        = string
  default     = ""
}

variable "portal_server_type" {
  description = "Server type for portal server"
  type        = string
  default     = ""
}

# Firewall source restrictions
variable "firewall_ssh_sources" {
  description = <<-EOT
    Source IP CIDRs allowed for SSH access.
    WARNING: No permissive default — must be set explicitly in staging/prod tfvars.
    Example: ["203.0.113.0/24"]  # office/VPN CIDR
    Never use ["0.0.0.0/0", "::/0"] in production.
  EOT
  type    = list(string)
  default = []

  validation {
    condition     = length(var.firewall_ssh_sources) > 0
    error_message = "firewall_ssh_sources must contain at least one CIDR. Set your office/VPN IP range."
  }
}

# =============================================================================
# Computed locals
# =============================================================================

locals {
  # Server type defaults per environment
  default_server_type = {
    dev     = "cx23"  # 2 vCPU, 4GB, €2.99/mo
    staging = "cx23"  # 2 vCPU, 4GB, €2.99/mo
    prod    = "cx33"  # 4 vCPU, 8GB, €4.99/mo
  }

  platform_type = var.platform_server_type != "" ? var.platform_server_type : local.default_server_type[var.environment]
  portal_type   = var.portal_server_type != "" ? var.portal_server_type : local.default_server_type[var.environment]

  # Dev = single all-in-one server; staging/prod = separate platform + portal
  deploy_portal = var.environment != "dev"

  # Common labels applied to all resources
  common_labels = {
    project     = "praho"
    environment = var.environment
    managed_by  = "terraform"
    team        = "pragmatichost"
  }
}
