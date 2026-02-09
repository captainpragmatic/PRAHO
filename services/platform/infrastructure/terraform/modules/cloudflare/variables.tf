# Variables for Cloudflare DNS Module

variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone:DNS:Edit permissions"
  type        = string
  sensitive   = true
}

variable "zone_id" {
  description = "Cloudflare zone ID"
  type        = string
}

variable "zone_name" {
  description = "Cloudflare zone name (e.g., infra.example.com)"
  type        = string
}

variable "deployment_id" {
  description = "PRAHO deployment ID for tracking"
  type        = string
}

variable "hostname" {
  description = "Hostname for DNS record (without zone)"
  type        = string
}

variable "ipv4_address" {
  description = "IPv4 address for A record"
  type        = string
}

variable "ipv6_address" {
  description = "IPv6 address for AAAA record (optional)"
  type        = string
  default     = ""
}

variable "ttl" {
  description = "DNS record TTL in seconds (1 = automatic)"
  type        = number
  default     = 300  # 5 minutes
}

# Email/MX record configuration
variable "create_mx_record" {
  description = "Create MX and SPF records for email routing"
  type        = bool
  default     = true  # Virtualmin servers typically handle email
}

variable "mx_priority" {
  description = "MX record priority (lower = higher priority)"
  type        = number
  default     = 10
}
