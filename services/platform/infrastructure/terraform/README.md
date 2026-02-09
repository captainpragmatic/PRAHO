# PRAHO Terraform Infrastructure

Terraform modules for automated node deployment.

## Structure

```
terraform/
├── modules/
│   ├── hetzner/          # Hetzner Cloud VPS provisioning
│   │   ├── main.tf       # Server, SSH key, reverse DNS
│   │   ├── variables.tf  # Input variables
│   │   ├── outputs.tf    # Outputs (IPs, IDs)
│   │   └── firewall.tf   # Cloud firewall configuration
│   └── cloudflare/       # Cloudflare DNS management
│       ├── main.tf       # A/AAAA records
│       ├── variables.tf  # Input variables
│       └── outputs.tf    # Record IDs, FQDN
├── backends/
│   ├── local.tf.tpl      # Local state backend template
│   └── s3.tf.tpl         # S3 state backend template (TODO)
├── deployments/          # Per-deployment state (gitignored)
│   └── {deployment_id}/
│       ├── main.tf       # Generated deployment config
│       ├── backend.tf    # Generated from template
│       ├── terraform.tfvars
│       └── terraform.tfstate (local backend only)
└── README.md
```

## Hetzner Module

Provisions a Hetzner Cloud VPS with:
- Ubuntu 22.04 image (default)
- Cloud firewall with hosting ports
- SSH key authentication
- IPv4 and IPv6 addresses
- Reverse DNS configuration
- PRAHO labels for tracking

### Server Types

| Type   | vCPU | RAM   | Disk   | Price/mo |
|--------|------|-------|--------|----------|
| cpx11  | 2    | 2 GB  | 40 GB  | ~€4.15   |
| cpx21  | 3    | 4 GB  | 80 GB  | ~€8.30   |
| cpx31  | 4    | 8 GB  | 160 GB | ~€15.50  |
| cpx41  | 8    | 16 GB | 240 GB | ~€29.00  |
| cpx51  | 16   | 32 GB | 360 GB | ~€59.00  |

### Locations

| Code | City        | Country |
|------|-------------|---------|
| fsn1 | Falkenstein | Germany |
| nbg1 | Nuremberg   | Germany |
| hel1 | Helsinki    | Finland |
| ash  | Ashburn     | USA     |
| hil  | Hillsboro   | USA     |

## Cloudflare Module

Creates DNS records for deployed nodes:
- A record for IPv4
- AAAA record for IPv6 (optional)
- 5-minute TTL (configurable)

## Usage

This module is not used directly. The PRAHO NodeDeploymentService:

1. Generates `main.tf` with module calls
2. Generates `backend.tf` from template
3. Creates `terraform.tfvars` with credentials
4. Runs `terraform init/plan/apply`
5. Captures outputs for database storage

## Environment Variables

Required:
- `HCLOUD_TOKEN` - Hetzner Cloud API token
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token

For S3 backend (TODO):
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

## Manual Testing

```bash
cd deployments/test-deployment

# Initialize
terraform init

# Plan
terraform plan -var-file=terraform.tfvars

# Apply
terraform apply -var-file=terraform.tfvars

# Destroy
terraform destroy -var-file=terraform.tfvars
```

## Firewall Ports

| Port        | Protocol | Purpose          |
|-------------|----------|------------------|
| 22          | TCP      | SSH              |
| 80          | TCP      | HTTP             |
| 443         | TCP      | HTTPS            |
| 10000       | TCP      | Webmin/Virtualmin|
| 25          | TCP      | SMTP             |
| 465         | TCP      | SMTPS            |
| 587         | TCP      | Submission       |
| 993         | TCP      | IMAPS            |
| 995         | TCP      | POP3S            |
| 21          | TCP      | FTP control      |
| 40000-40100 | TCP      | FTP passive      |
| 53          | TCP/UDP  | DNS              |
