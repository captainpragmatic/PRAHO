# Node Deployment System - Implementation Plan

## Overview

This document outlines the plan for implementing an automated **Node Deployment** system in PRAHO that provisions Hetzner cloud servers (VPS), installs Virtualmin/Webmin via Ansible, and registers them as operational hosting nodes in the platform.

**Key Goals:**
- Deploy production-ready hosting nodes on Hetzner via Terraform
- Secure configuration with SSH keys and cloud firewalls
- Automated Virtualmin GPL installation with Ansible (pinned versions)
- Local backups enabled by default (TODO: S3 storage later)
- Auto-registration as `VirtualminServer` after validation
- Full lifecycle management (create, upgrade, destroy)
- Futureproof architecture for multiple providers (DigitalOcean, etc.) and panels (Blesta, etc.)
- Role-based access control for staff operations
- Complete audit trail integration
- Cost tracking per deployment
- Configurable via System Settings (Terraform state backend, DNS zone, etc.)
- Standardized node naming convention for consistency and clarity

---

## Node Naming Convention

### Format

```
{env}-{type}-{provider}-{country}-{region}-{number}
 3ch   3ch     3ch        2ch       4ch      3ch

Example: prd-sha-het-de-fsn1-001
```

**Total length: 23 characters (fixed)**

### Field Definitions

| Field | Length | Description | Examples |
|-------|--------|-------------|----------|
| **Environment** | 3 | Deployment environment | `prd`, `stg`, `dev` |
| **Type** | 3 | Node type/purpose | `sha`, `vps`, `ctr`, `ded`, `app` |
| **Provider** | 3 | Cloud provider code | `het`, `dig`, `vul`, `lin`, `aws` |
| **Country** | 2 | ISO 3166-1 alpha-2 country code | `de`, `fi`, `us`, `nl`, `sg` |
| **Region** | 4 | Normalized datacenter code | `fsn1`, `nyc1`, `ewr1`, `use1` |
| **Number** | 3 | Sequential node number (zero-padded) | `001`-`999` |

### Environment Codes

| Environment | Code |
|-------------|------|
| Production | `prd` |
| Staging | `stg` |
| Development | `dev` |

### Node Type Codes

| Type | Code | Description |
|------|------|-------------|
| Shared Hosting | `sha` | Traditional shared hosting (Virtualmin) |
| VPS Hosting | `vps` | Virtual private server nodes (TODO: future) |
| Container | `ctr` | Docker/container orchestration nodes (TODO: future) |
| Dedicated | `ded` | Dedicated server nodes (TODO: future) |
| Application | `app` | Application platform nodes (TODO: future) |

**Note:** Initial implementation supports `sha` (shared hosting with Virtualmin). Other types are placeholders for future expansion.

### Provider Codes

| Provider | Code |
|----------|------|
| Hetzner | `het` |
| DigitalOcean | `dig` |
| Vultr | `vul` |
| Linode | `lin` |
| AWS | `aws` |
| Google Cloud | `gcp` |

### Region Code Normalization

All regions are normalized to **exactly 4 characters** (3-letter code + 1-digit number).

#### Hetzner
| Native | Normalized | Country | Location |
|--------|------------|---------|----------|
| `fsn1` | `fsn1` | `de` | Falkenstein, Germany |
| `nbg1` | `nbg1` | `de` | Nuremberg, Germany |
| `hel1` | `hel1` | `fi` | Helsinki, Finland |
| `ash` | `ash1` | `us` | Ashburn, USA |
| `hil` | `hil1` | `us` | Hillsboro, USA |

#### DigitalOcean
| Native | Normalized | Country | Location |
|--------|------------|---------|----------|
| `nyc1` | `nyc1` | `us` | New York DC1 |
| `nyc2` | `nyc2` | `us` | New York DC2 |
| `nyc3` | `nyc3` | `us` | New York DC3 |
| `sfo1` | `sfo1` | `us` | San Francisco DC1 |
| `sfo2` | `sfo2` | `us` | San Francisco DC2 |
| `tor1` | `tor1` | `ca` | Toronto |
| `lon1` | `lon1` | `gb` | London |
| `ams2` | `ams2` | `nl` | Amsterdam DC2 |
| `ams3` | `ams3` | `nl` | Amsterdam DC3 |
| `fra1` | `fra1` | `de` | Frankfurt |
| `sgp1` | `sgp1` | `sg` | Singapore |
| `blr1` | `blr1` | `in` | Bangalore |
| `syd1` | `syd1` | `au` | Sydney |

#### Vultr (IATA Airport Codes + "1")
| Native | Normalized | Country | Location |
|--------|------------|---------|----------|
| `ewr` | `ewr1` | `us` | Newark |
| `ord` | `ord1` | `us` | Chicago |
| `dfw` | `dfw1` | `us` | Dallas |
| `sea` | `sea1` | `us` | Seattle |
| `lax` | `lax1` | `us` | Los Angeles |
| `atl` | `atl1` | `us` | Atlanta |
| `mia` | `mia1` | `us` | Miami |
| `ams` | `ams1` | `nl` | Amsterdam |
| `lhr` | `lhr1` | `gb` | London |
| `fra` | `fra1` | `de` | Frankfurt |
| `cdg` | `cdg1` | `fr` | Paris |
| `nrt` | `nrt1` | `jp` | Tokyo |
| `sgp` | `sgp1` | `sg` | Singapore |
| `syd` | `syd1` | `au` | Sydney |

#### Linode (City-based + "1")
| Native | Normalized | Country | Location |
|--------|------------|---------|----------|
| `us-east` | `nwk1` | `us` | Newark |
| `us-central` | `dal1` | `us` | Dallas |
| `us-west` | `fre1` | `us` | Fremont |
| `us-southeast` | `atl1` | `us` | Atlanta |
| `ca-central` | `tor1` | `ca` | Toronto |
| `eu-west` | `lon1` | `gb` | London |
| `eu-central` | `fra1` | `de` | Frankfurt |
| `ap-south` | `sgp1` | `sg` | Singapore |
| `ap-northeast` | `tyo1` | `jp` | Tokyo |
| `ap-west` | `mum1` | `in` | Mumbai |
| `ap-southeast` | `syd1` | `au` | Sydney |

#### AWS (Abbreviated)
| Native | Normalized | Country | Location |
|--------|------------|---------|----------|
| `us-east-1` | `use1` | `us` | N. Virginia |
| `us-east-2` | `use2` | `us` | Ohio |
| `us-west-1` | `usw1` | `us` | N. California |
| `us-west-2` | `usw2` | `us` | Oregon |
| `eu-west-1` | `euw1` | `ie` | Ireland |
| `eu-west-2` | `euw2` | `gb` | London |
| `eu-west-3` | `euw3` | `fr` | Paris |
| `eu-central-1` | `euc1` | `de` | Frankfurt |
| `eu-north-1` | `eun1` | `se` | Stockholm |
| `ap-northeast-1` | `ane1` | `jp` | Tokyo |
| `ap-northeast-2` | `ane2` | `kr` | Seoul |
| `ap-southeast-1` | `ase1` | `sg` | Singapore |
| `ap-southeast-2` | `ase2` | `au` | Sydney |
| `ap-south-1` | `aso1` | `in` | Mumbai |
| `sa-east-1` | `sae1` | `br` | São Paulo |

### Example Hostnames

```
prd-sha-het-de-fsn1-001   Production, Shared, Hetzner, Germany, Falkenstein
prd-sha-het-de-fsn1-002   Production, Shared, Hetzner, Germany, Falkenstein (2nd node)
prd-sha-het-fi-hel1-001   Production, Shared, Hetzner, Finland, Helsinki
prd-sha-het-us-ash1-001   Production, Shared, Hetzner, USA, Ashburn
prd-sha-dig-us-nyc1-001   Production, Shared, DigitalOcean, USA, New York DC1
prd-sha-dig-nl-ams3-001   Production, Shared, DigitalOcean, Netherlands, Amsterdam DC3
prd-sha-vul-us-ewr1-001   Production, Shared, Vultr, USA, Newark
prd-sha-vul-gb-lhr1-001   Production, Shared, Vultr, UK, London
prd-sha-aws-us-use1-001   Production, Shared, AWS, USA, us-east-1
prd-sha-aws-ie-euw1-001   Production, Shared, AWS, Ireland, eu-west-1
prd-sha-lin-us-nwk1-001   Production, Shared, Linode, USA, Newark
stg-sha-het-de-fsn1-001   Staging, Shared, Hetzner, Germany, Falkenstein
dev-sha-het-de-fsn1-001   Development, Shared, Hetzner, Germany, Falkenstein

# Future node types (not yet implemented):
prd-vps-het-de-fsn1-001   Production, VPS, Hetzner, Germany, Falkenstein
prd-ctr-het-de-fsn1-001   Production, Container, Hetzner, Germany, Falkenstein
```

### Sorting Behavior

When sorted alphabetically, nodes group by:
1. Environment (dev → prd → stg)
2. Type (app → ctr → ded → sha → vps)
3. Provider (aws → dig → het → lin → vul)
4. Country (au → de → fi → gb → us)
5. Region (alphabetically)
6. Number (001 → 002 → 003)

### Auto-Generation

The deployment form will:
1. User selects environment, node type, provider, and region
2. System looks up country code from region
3. System finds next available number for that env/type/provider/country/region combination
4. Hostname is auto-generated and shown as preview
5. User can override the display name (but hostname follows convention)

### Full DNS Hostname

Combined with the default DNS zone from settings:

```
prd-sha-het-de-fsn1-001.infra.example.com
```

**Note:** Using `infra.example.com` as the zone name provides flexibility for all infrastructure node types (shared hosting, VPS, containers, etc.).

---

## Architecture Design

### Provider Abstraction Layer

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PRAHO Platform                                │
├─────────────────────────────────────────────────────────────────────┤
│  UI Layer (Views/Templates)                                          │
│  ├── Node Deployment Dashboard                                       │
│  ├── Server Size Configuration                                       │
│  ├── Region Selection                                                │
│  └── Deployment History & Logs                                       │
├─────────────────────────────────────────────────────────────────────┤
│  Service Layer                                                       │
│  ├── NodeDeploymentService (orchestrates deployments)               │
│  ├── TerraformService (executes Terraform commands)                 │
│  ├── AnsibleService (executes playbooks)                            │
│  ├── DNSProvisioningService (Cloudflare integration)                │
│  └── NodeValidationService (health checks)                          │
├─────────────────────────────────────────────────────────────────────┤
│  Provider Abstraction                                                │
│  ├── BaseCloudProvider (abstract interface)                         │
│  ├── HetznerProvider                                                │
│  ├── DigitalOceanProvider (TODO: future)                            │
│  └── AWSProvider (TODO: future)                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Panel Abstraction                                                   │
│  ├── BasePanelInstaller (abstract interface)                        │
│  ├── VirtualminInstaller                                            │
│  └── BlestaInstaller (TODO: future)                                 │
├─────────────────────────────────────────────────────────────────────┤
│  Infrastructure (Terraform + Ansible)                                │
│  ├── terraform/                                                      │
│  │   ├── modules/hetzner/                                           │
│  │   ├── modules/cloudflare/                                        │
│  │   └── modules/digitalocean/ (TODO)                               │
│  └── ansible/                                                        │
│      ├── playbooks/virtualmin.yml                                   │
│      ├── playbooks/blesta.yml (TODO)                                │
│      └── roles/                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Location

New dedicated `apps/infrastructure/` app for all infrastructure management:

```
apps/infrastructure/
├── __init__.py
├── apps.py                    # InfrastructureConfig
├── models.py                  # CloudProvider, NodeSize, NodeDeployment, etc.
├── services.py                # Re-exports
├── deployment_service.py      # Main orchestration service
├── terraform_service.py       # Terraform wrapper
├── ansible_service.py         # Ansible wrapper
├── dns_service.py             # Cloudflare DNS integration
├── validation_service.py      # Node health validation
├── ssh_key_manager.py         # SSH key generation/storage
├── providers/
│   ├── __init__.py
│   ├── base.py                # BaseCloudProvider ABC
│   ├── hetzner.py             # HetznerProvider
│   └── digitalocean.py        # TODO: DigitalOceanProvider
├── panels/
│   ├── __init__.py
│   ├── base.py                # BasePanelInstaller ABC
│   ├── virtualmin.py          # VirtualminInstaller
│   └── blesta.py              # TODO: BlestaInstaller
├── views.py                   # Staff UI views
├── urls.py                    # URL routing
├── forms.py                   # Django forms
├── tasks.py                   # Async deployment tasks (Django-Q2)
├── signals.py                 # Audit integration signals
└── migrations/
    ├── __init__.py
    └── 0001_initial.py        # Node deployment models

# Note: This separation from provisioning provides:
# - Clean domain separation (infrastructure vs services)
# - Aligns with infra.example.com DNS zone naming
# - Room to grow for networking, monitoring, cloud provider management
```

### Terraform Structure

```
infrastructure/
├── terraform/
│   ├── modules/
│   │   ├── hetzner/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   ├── outputs.tf
│   │   │   ├── firewall.tf     # Hetzner cloud firewall
│   │   │   └── ssh_key.tf
│   │   └── cloudflare/
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   ├── backends/
│   │   ├── local.tf.tpl        # Local state backend template
│   │   └── s3.tf.tpl           # S3 state backend template (TODO: future)
│   └── deployments/            # Per-deployment state (gitignored)
│       └── {deployment_id}/
│           ├── main.tf
│           ├── backend.tf      # Generated from template based on settings
│           ├── terraform.tfvars
│           └── terraform.tfstate  # (local backend only)
```

### Ansible Structure

```
infrastructure/
└── ansible/
    ├── ansible.cfg
    ├── requirements.yml        # Ansible Galaxy requirements
    ├── inventory/
    │   └── dynamic.py          # Dynamic inventory from PRAHO DB
    ├── playbooks/
    │   ├── virtualmin.yml      # Main Virtualmin GPL installation
    │   ├── virtualmin_harden.yml # Security hardening
    │   ├── virtualmin_backup.yml # Configure local backups
    │   └── common_base.yml     # Base server setup
    ├── roles/
    │   ├── common/
    │   │   └── tasks/main.yml  # Base packages, users, SSH
    │   ├── virtualmin/
    │   │   ├── tasks/main.yml
    │   │   ├── vars/main.yml   # PINNED VERSIONS HERE
    │   │   ├── handlers/main.yml
    │   │   └── templates/
    │   ├── virtualmin_backup/
    │   │   ├── tasks/main.yml  # Configure local backups
    │   │   ├── vars/main.yml
    │   │   └── templates/
    │   │       └── backup_schedule.j2
    │   └── security/
    │       └── tasks/main.yml  # Fail2ban, etc.
    └── group_vars/
        └── all.yml             # Common variables
```

---

## System Settings Integration

### Node Deployment Settings Section

Add a dedicated section in System Settings (`apps/settings/`) for Node Deployment configuration:

```python
# Settings keys for Node Deployment
NODE_DEPLOYMENT_SETTINGS = {
    # Terraform Configuration
    'node_deployment.terraform.state_backend': 'local',  # 'local' or 's3'
    'node_deployment.terraform.s3_bucket': '',           # S3 bucket name (when backend=s3)
    'node_deployment.terraform.s3_region': '',           # S3 region (when backend=s3)
    'node_deployment.terraform.s3_key_prefix': 'praho/nodes/',  # S3 key prefix

    # DNS Configuration
    'node_deployment.dns.default_zone': '',              # Default Cloudflare zone for node hostnames
    'node_deployment.dns.cloudflare_zone_id': '',        # Cloudflare zone ID

    # Default Deployment Options
    'node_deployment.defaults.provider': 'hetzner',      # Default provider
    'node_deployment.defaults.region': 'fsn1',           # Default region
    'node_deployment.defaults.size': '',                 # Default size (if any)

    # Backup Configuration
    'node_deployment.backup.enabled': True,              # Enable backups on new nodes
    'node_deployment.backup.storage': 'local',           # 'local' or 's3' (TODO: s3)
    'node_deployment.backup.s3_bucket': '',              # S3 bucket for backups (TODO)
    'node_deployment.backup.retention_days': 7,          # Local backup retention
    'node_deployment.backup.schedule': '0 2 * * *',      # Cron schedule (2 AM daily)

    # Timeouts
    'node_deployment.timeouts.terraform_apply': 600,     # 10 minutes
    'node_deployment.timeouts.ansible_playbook': 1800,   # 30 minutes
    'node_deployment.timeouts.validation': 300,          # 5 minutes
}
```

### Settings UI Page

Add a settings page at `/settings/node-deployment/` with sections:

1. **Terraform State Backend**
   - Radio: Local / S3 (S3 shows additional fields when selected)
   - S3 Bucket, Region, Key Prefix (when S3 selected)

2. **DNS Configuration**
   - Default DNS Zone (e.g., `infra.example.com`)
   - Cloudflare Zone ID

3. **Default Deployment Options**
   - Default Provider dropdown
   - Default Region dropdown
   - Default Size dropdown (optional)

4. **Backup Configuration**
   - Enable backups checkbox
   - Storage type: Local / S3 (TODO badge on S3)
   - Retention days
   - Backup schedule (cron expression)

5. **Timeouts**
   - Terraform apply timeout
   - Ansible playbook timeout
   - Validation timeout

---

## Data Models

### New Models (nodes/models.py)

```python
class CloudProvider(models.Model):
    """Supported cloud providers (Hetzner, DigitalOcean, etc.)"""
    PROVIDER_CHOICES = [
        ('hetzner', 'Hetzner Cloud'),
        ('digitalocean', 'DigitalOcean'),  # TODO: future
        ('vultr', 'Vultr'),                 # TODO: future
        ('linode', 'Linode'),               # TODO: future
        ('aws', 'Amazon Web Services'),     # TODO: future
        ('gcp', 'Google Cloud Platform'),   # TODO: future
    ]

    name = models.CharField(max_length=50, unique=True)
    provider_type = models.CharField(max_length=20, choices=PROVIDER_CHOICES)

    # 3-letter code for hostname generation (het, dig, vul, lin, aws, gcp)
    code = models.CharField(max_length=3, unique=True)

    is_active = models.BooleanField(default=True)

    # API credentials stored in CredentialVault
    credential_identifier = models.CharField(max_length=100)

    # Provider-specific config (JSON)
    config = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class NodeSize(models.Model):
    """Configurable server size/plan options for hosting nodes"""
    provider = models.ForeignKey(CloudProvider, on_delete=models.CASCADE, related_name='sizes')

    name = models.CharField(max_length=100)  # "Small", "Medium", "Large"
    display_name = models.CharField(max_length=100)  # "2 vCPU / 4GB RAM / 40GB"

    # Provider-specific type identifier
    provider_type_id = models.CharField(max_length=50)  # "cpx21", "cpx41", etc.

    # Specs for display
    vcpus = models.PositiveIntegerField()
    memory_gb = models.PositiveIntegerField()
    disk_gb = models.PositiveIntegerField()

    # Pricing (for cost tracking)
    hourly_cost_eur = models.DecimalField(max_digits=10, decimal_places=4)
    monthly_cost_eur = models.DecimalField(max_digits=10, decimal_places=2)

    # Capacity limits for Virtualmin
    max_domains = models.PositiveIntegerField(default=50)
    max_bandwidth_gb = models.PositiveIntegerField(default=1000)

    is_active = models.BooleanField(default=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['provider', 'sort_order']
        unique_together = [['provider', 'provider_type_id']]


class NodeRegion(models.Model):
    """Available deployment regions per provider"""
    provider = models.ForeignKey(CloudProvider, on_delete=models.CASCADE, related_name='regions')

    name = models.CharField(max_length=100)  # "Falkenstein", "Helsinki"
    provider_region_id = models.CharField(max_length=50)  # Provider's native: "fsn1", "us-east-1", "ewr"

    # Normalized 4-character code for hostname generation
    # Examples: fsn1, ash1, nyc1, ewr1, use1, ane1
    normalized_code = models.CharField(max_length=4)

    # Geographic info (ISO 3166-1 alpha-2 for country)
    country_code = models.CharField(max_length=2)  # de, fi, us, nl, sg, etc.
    city = models.CharField(max_length=100)

    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = [['provider', 'provider_region_id']]
        indexes = [
            models.Index(fields=['provider', 'normalized_code']),
            models.Index(fields=['country_code']),
        ]


class PanelType(models.Model):
    """Supported control panels (Virtualmin, Blesta, etc.)"""
    PANEL_CHOICES = [
        ('virtualmin', 'Virtualmin GPL'),
        ('blesta', 'Blesta'),  # TODO: future
    ]

    name = models.CharField(max_length=50, unique=True)
    panel_type = models.CharField(max_length=20, choices=PANEL_CHOICES)

    # Version pinning
    version = models.CharField(max_length=50, blank=True)  # "7.10.0"

    # Ansible playbook reference
    ansible_playbook = models.CharField(max_length=100)  # "virtualmin.yml"

    is_active = models.BooleanField(default=True)


class NodeDeployment(models.Model):
    """Tracks hosting node deployment lifecycle"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('provisioning_node', 'Provisioning Node'),
        ('configuring_dns', 'Configuring DNS'),
        ('installing_panel', 'Installing Panel'),
        ('configuring_backups', 'Configuring Backups'),
        ('validating', 'Validating'),
        ('registering', 'Registering Server'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('destroying', 'Destroying'),
        ('destroyed', 'Destroyed'),
    ]

    ENVIRONMENT_CHOICES = [
        ('prd', 'Production'),
        ('stg', 'Staging'),
        ('dev', 'Development'),
    ]

    NODE_TYPE_CHOICES = [
        ('sha', 'Shared Hosting'),      # Virtualmin - implemented
        ('vps', 'VPS Hosting'),          # TODO: future
        ('ctr', 'Container'),            # TODO: future (Docker)
        ('ded', 'Dedicated'),            # TODO: future
        ('app', 'Application Platform'), # TODO: future
    ]

    # Deployment configuration
    environment = models.CharField(max_length=3, choices=ENVIRONMENT_CHOICES, default='prd')
    node_type = models.CharField(max_length=3, choices=NODE_TYPE_CHOICES, default='sha')
    provider = models.ForeignKey(CloudProvider, on_delete=models.PROTECT)
    node_size = models.ForeignKey(NodeSize, on_delete=models.PROTECT)
    region = models.ForeignKey(NodeRegion, on_delete=models.PROTECT)
    panel_type = models.ForeignKey(PanelType, on_delete=models.PROTECT)

    # Node identity (auto-generated from naming convention)
    # Format: {env}-{type}-{provider.code}-{region.country_code}-{region.normalized_code}-{number}
    # Example: prd-sha-het-de-fsn1-001
    hostname = models.CharField(max_length=23, unique=True)  # Fixed 23 chars
    node_number = models.PositiveIntegerField()  # 1-999, stored as int, formatted as 001
    display_name = models.CharField(max_length=100, blank=True)  # Optional friendly name

    # Current status
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='pending')
    status_message = models.TextField(blank=True)
    last_successful_phase = models.CharField(max_length=50, blank=True)  # For retry logic

    # Provisioned resources (populated after creation)
    external_node_id = models.CharField(max_length=100, blank=True)  # Hetzner server ID
    ipv4_address = models.GenericIPAddressField(null=True, blank=True)
    ipv6_address = models.GenericIPAddressField(null=True, blank=True, protocol='IPv6')

    # SSH key reference (stored in CredentialVault)
    ssh_key_credential_id = models.CharField(max_length=100, blank=True)

    # DNS configuration
    dns_zone = models.CharField(max_length=255, blank=True)  # Zone used for this node
    dns_record_ids = models.JSONField(default=list)  # Created DNS record IDs

    # Linked VirtualminServer (after successful registration)
    virtualmin_server = models.OneToOneField(
        'VirtualminServer',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='node_deployment'
    )

    # Terraform state reference
    terraform_state_path = models.CharField(max_length=500, blank=True)
    terraform_state_backend = models.CharField(max_length=20, default='local')  # 'local' or 's3'

    # Backup configuration (snapshot at deployment time)
    backup_enabled = models.BooleanField(default=True)
    backup_storage = models.CharField(max_length=20, default='local')  # 'local' or 's3'

    # Cost tracking
    total_cost_eur = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    # Failover tracking (for future automation)
    triggered_by_failover = models.BooleanField(default=False)
    source_node = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='replacement_nodes',
        help_text='Original node this deployment is replacing (failover scenario)'
    )

    # Audit
    initiated_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='initiated_node_deployments'
    )
    correlation_id = models.UUIDField(default=uuid.uuid4)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    destroyed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        # Ensure unique node numbers within env/type/provider/region combination
        unique_together = [['environment', 'node_type', 'provider', 'region', 'node_number']]
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['environment', 'status']),
            models.Index(fields=['node_type', 'status']),
            models.Index(fields=['provider', 'status']),
            models.Index(fields=['environment', 'node_type', 'provider', 'region']),  # For next number lookup
            models.Index(fields=['initiated_by', 'created_at']),
            models.Index(fields=['triggered_by_failover', 'status']),
        ]

    def generate_hostname(self) -> str:
        """Generate hostname from naming convention"""
        return (
            f"{self.environment}-"
            f"{self.node_type}-"
            f"{self.provider.code}-"
            f"{self.region.country_code}-"
            f"{self.region.normalized_code}-"
            f"{self.node_number:03d}"
        )

    def save(self, *args, **kwargs):
        """Auto-generate hostname on save"""
        if not self.hostname:
            self.hostname = self.generate_hostname()
        super().save(*args, **kwargs)

    @classmethod
    def get_next_node_number(
        cls, environment: str, node_type: str, provider: CloudProvider, region: NodeRegion
    ) -> int:
        """Get the next available node number for the given env/type/provider/region"""
        last = cls.objects.filter(
            environment=environment,
            node_type=node_type,
            provider=provider,
            region=region
        ).order_by('-node_number').first()
        return (last.node_number + 1) if last else 1


class NodeDeploymentLog(models.Model):
    """Detailed logs for deployment steps"""
    LEVEL_CHOICES = [
        ('debug', 'Debug'),
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
    ]

    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name='logs'
    )

    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='info')
    phase = models.CharField(max_length=50)  # 'terraform', 'ansible', 'dns', 'backup', etc.
    message = models.TextField()
    details = models.JSONField(default=dict)  # Additional structured data
    duration_seconds = models.FloatField(null=True, blank=True)  # Phase duration

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']


class NodeDeploymentCostRecord(models.Model):
    """Track costs over time for cost analysis"""
    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name='cost_records'
    )

    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    cost_eur = models.DecimalField(max_digits=10, decimal_places=4)

    # Breakdown
    compute_cost = models.DecimalField(max_digits=10, decimal_places=4, default=0)
    bandwidth_cost = models.DecimalField(max_digits=10, decimal_places=4, default=0)
    storage_cost = models.DecimalField(max_digits=10, decimal_places=4, default=0)

    created_at = models.DateTimeField(auto_now_add=True)
```

---

## Service Layer Design

### NodeDeploymentService

Main orchestration service that coordinates the deployment workflow:

```python
class NodeDeploymentService:
    """
    Orchestrates full hosting node deployment lifecycle:
    1. Validate inputs and permissions
    2. Generate SSH key pair (store in CredentialVault)
    3. Execute Terraform (provision VPS + firewall)
    4. Configure DNS via Cloudflare
    5. Execute Ansible (install Virtualmin GPL)
    6. Configure local backups
    7. Validate node health
    8. Register as VirtualminServer
    9. Update deployment status
    """

    def create_deployment(
        self,
        config: NodeDeploymentConfig,
        initiated_by: User
    ) -> Result[NodeDeployment, str]:
        """Create and queue new node deployment"""

    def execute_deployment(
        self,
        deployment: NodeDeployment
    ) -> Result[NodeDeployment, str]:
        """Execute full deployment pipeline (called by async task)"""

    def upgrade_deployment(
        self,
        deployment: NodeDeployment,
        new_size: NodeSize,
        initiated_by: User
    ) -> Result[NodeDeployment, str]:
        """Resize/upgrade existing node"""

    def destroy_deployment(
        self,
        deployment: NodeDeployment,
        initiated_by: User,
        reason: str
    ) -> Result[NodeDeployment, str]:
        """Destroy node and clean up resources"""

    def retry_failed_deployment(
        self,
        deployment: NodeDeployment,
        initiated_by: User
    ) -> Result[NodeDeployment, str]:
        """Retry failed deployment from last successful phase"""
```

### TerraformService

Wrapper for executing Terraform commands with configurable state backend:

```python
class TerraformService:
    """
    Manages Terraform execution for node provisioning.

    Responsibilities:
    - Generate deployment-specific tfvars
    - Configure state backend (local or S3) based on settings
    - Execute terraform init/plan/apply/destroy
    - Parse outputs for IP addresses, resource IDs
    - Manage state files per deployment
    """

    def __init__(self):
        self.settings = SettingsService()
        self.state_backend = self.settings.get('node_deployment.terraform.state_backend', 'local')

    def _generate_backend_config(self, deployment: NodeDeployment) -> str:
        """Generate backend.tf based on settings"""
        if self.state_backend == 's3':
            # TODO: S3_BACKEND - Implement S3 backend configuration
            # bucket = self.settings.get('node_deployment.terraform.s3_bucket')
            # region = self.settings.get('node_deployment.terraform.s3_region')
            # key = f"{self.settings.get('node_deployment.terraform.s3_key_prefix')}{deployment.id}/terraform.tfstate"
            raise NotImplementedError("S3 backend not yet implemented")
        else:
            return self._generate_local_backend(deployment)

    def init_deployment(self, deployment: NodeDeployment) -> Result[None, str]:
        """Initialize Terraform workspace for deployment"""

    def plan(self, deployment: NodeDeployment) -> Result[TerraformPlan, str]:
        """Generate and return execution plan"""

    def apply(self, deployment: NodeDeployment) -> Result[TerraformOutputs, str]:
        """Apply Terraform configuration"""

    def destroy(self, deployment: NodeDeployment) -> Result[None, str]:
        """Destroy all Terraform-managed resources"""

    def get_outputs(self, deployment: NodeDeployment) -> Result[TerraformOutputs, str]:
        """Read outputs from current state"""
```

### AnsibleService

Wrapper for executing Ansible playbooks:

```python
class AnsibleService:
    """
    Manages Ansible execution for panel installation.

    Responsibilities:
    - Generate dynamic inventory
    - Execute playbooks with proper variables
    - Stream output to deployment logs
    - Handle retry logic for transient failures
    """

    def run_playbook(
        self,
        deployment: NodeDeployment,
        playbook: str,
        extra_vars: dict
    ) -> Result[AnsibleResult, str]:
        """Execute Ansible playbook"""

    def check_connectivity(
        self,
        deployment: NodeDeployment
    ) -> Result[bool, str]:
        """Verify SSH connectivity before running playbooks"""
```

### DNSProvisioningService

Cloudflare DNS integration:

```python
class DNSProvisioningService:
    """
    Manages DNS records via Cloudflare API.

    Uses default zone from settings: node_deployment.dns.default_zone
    """

    def __init__(self):
        self.settings = SettingsService()
        self.default_zone = self.settings.get('node_deployment.dns.default_zone')
        self.zone_id = self.settings.get('node_deployment.dns.cloudflare_zone_id')

    def create_node_dns(
        self,
        deployment: NodeDeployment,
        hostname: str,
        ipv4: str,
        ipv6: str | None
    ) -> Result[list[str], str]:  # Returns DNS record IDs
        """Create DNS records for new node in default zone"""

    def delete_node_dns(
        self,
        deployment: NodeDeployment
    ) -> Result[None, str]:
        """Remove DNS records"""
```

### NodeValidationService

Validates deployed node is operational:

```python
class NodeValidationService:
    """
    Validates node is production-ready before registration.

    Checks:
    - SSH connectivity
    - Virtualmin API responds
    - SSL certificate valid
    - Required ports open
    - Basic resource availability
    - Backup configuration (if enabled)
    """

    def validate_deployment(
        self,
        deployment: NodeDeployment
    ) -> Result[ValidationReport, str]:
        """Run all validation checks"""

    def check_virtualmin_api(
        self,
        hostname: str,
        credentials: VirtualminCredentials
    ) -> Result[bool, str]:
        """Test Virtualmin API connectivity"""

    def check_backup_config(
        self,
        deployment: NodeDeployment
    ) -> Result[bool, str]:
        """Verify backup is configured correctly"""
```

---

## Provider Abstraction

### BaseCloudProvider (Abstract)

```python
class BaseCloudProvider(ABC):
    """Abstract base for cloud provider implementations"""

    @abstractmethod
    def get_available_sizes(self) -> list[NodeSizeInfo]:
        """List available server sizes/plans"""

    @abstractmethod
    def get_available_regions(self) -> list[RegionInfo]:
        """List available deployment regions"""

    @abstractmethod
    def generate_terraform_vars(
        self,
        deployment: NodeDeployment
    ) -> dict:
        """Generate provider-specific Terraform variables"""

    @abstractmethod
    def parse_terraform_outputs(
        self,
        outputs: dict
    ) -> ProviderOutputs:
        """Parse Terraform outputs into structured data"""
```

### HetznerProvider

```python
class HetznerProvider(BaseCloudProvider):
    """Hetzner Cloud provider implementation"""

    # Hetzner-specific implementation
    # Uses Terraform hcloud provider
    # Supports cloud firewall configuration
```

---

## Panel Abstraction

### BasePanelInstaller (Abstract)

```python
class BasePanelInstaller(ABC):
    """Abstract base for control panel installers"""

    @abstractmethod
    def get_ansible_playbook(self) -> str:
        """Return playbook filename"""

    @abstractmethod
    def get_ansible_vars(
        self,
        deployment: NodeDeployment
    ) -> dict:
        """Generate panel-specific Ansible variables"""

    @abstractmethod
    def get_api_credentials(
        self,
        deployment: NodeDeployment
    ) -> PanelCredentials:
        """Extract credentials for API access"""

    @abstractmethod
    def register_in_platform(
        self,
        deployment: NodeDeployment
    ) -> Result[Any, str]:
        """Register panel server in PRAHO"""
```

### VirtualminInstaller

```python
class VirtualminInstaller(BasePanelInstaller):
    """Virtualmin GPL installation and registration"""

    def get_ansible_vars(self, deployment: NodeDeployment) -> dict:
        return {
            'virtualmin_version': self.pinned_version,  # e.g., "7.10.0"
            'virtualmin_license': 'gpl',
            'webmin_version': self.pinned_webmin_version,
            # Backup configuration
            'backup_enabled': deployment.backup_enabled,
            'backup_storage': deployment.backup_storage,
            'backup_retention_days': self.settings.get('node_deployment.backup.retention_days', 7),
            'backup_schedule': self.settings.get('node_deployment.backup.schedule', '0 2 * * *'),
            # TODO: S3_BACKUP - Add S3 backup configuration when implemented
            # 'backup_s3_bucket': self.settings.get('node_deployment.backup.s3_bucket'),
        }

    def register_in_platform(
        self,
        deployment: NodeDeployment
    ) -> Result[VirtualminServer, str]:
        """
        Create VirtualminServer record with:
        - API credentials in CredentialVault
        - Capacity settings from NodeSize
        - Health check enabled
        """
```

---

## SSH Key Management

### Strategy

1. **Per-deployment key (primary)**: Generated for each deployment, stored in CredentialVault
2. **Master key (fallback)**: Optional environment variable `INFRASTRUCTURE_MASTER_SSH_KEY` for emergency access

```python
class SSHKeyManager:
    """Manages SSH keys for node deployments"""

    def generate_deployment_key(
        self,
        deployment: NodeDeployment
    ) -> Result[SSHKeyPair, str]:
        """
        Generate ED25519 key pair for deployment.
        Store private key in CredentialVault.
        Return public key for Terraform.
        """

    def get_deployment_key(
        self,
        deployment: NodeDeployment
    ) -> Result[str, str]:
        """Retrieve private key from CredentialVault"""

    def get_master_key(self) -> str | None:
        """Get master key from environment (fallback)"""
        return os.environ.get('INFRASTRUCTURE_MASTER_SSH_KEY')

    def delete_deployment_key(
        self,
        deployment: NodeDeployment
    ) -> Result[None, str]:
        """Remove key from vault on deployment destruction"""
```

---

## Security Configuration

### Hetzner Cloud Firewall (via Terraform)

SSH is open to all IPs (no restriction) as requested:

```hcl
# terraform/modules/hetzner/firewall.tf

resource "hcloud_firewall" "node" {
  name = "node-${var.deployment_id}"

  # SSH - Open to all
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Webmin/Virtualmin HTTPS
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10000"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # HTTP/HTTPS for hosted sites
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Mail ports (SMTP, IMAP, POP3 with SSL)
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "25"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "465"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "587"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "993"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "995"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # FTP (passive mode range)
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "21"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "40000-40100"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # DNS (if server is DNS)
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}
```

### Ansible Security Hardening

```yaml
# ansible/roles/security/tasks/main.yml

- name: Configure fail2ban for SSH
  template:
    src: jail.local.j2
    dest: /etc/fail2ban/jail.local
  notify: Restart fail2ban

- name: Disable password authentication
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^#?PasswordAuthentication'
    line: 'PasswordAuthentication no'
  notify: Restart sshd

- name: Disable root password login (key-only)
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^#?PermitRootLogin'
    line: 'PermitRootLogin prohibit-password'
  notify: Restart sshd

- name: Configure automatic security updates
  apt:
    name: unattended-upgrades
    state: present

- name: Enable automatic security updates
  copy:
    src: 20auto-upgrades
    dest: /etc/apt/apt.conf.d/20auto-upgrades
```

### Ansible Backup Configuration

```yaml
# ansible/roles/virtualmin_backup/tasks/main.yml

- name: Create local backup directory
  file:
    path: /var/backups/virtualmin
    state: directory
    owner: root
    group: root
    mode: '0700'
  when: backup_enabled and backup_storage == 'local'

- name: Configure Virtualmin scheduled backup
  template:
    src: backup_schedule.j2
    dest: /etc/webmin/virtual-server/schedule.pl
  when: backup_enabled

# TODO: S3_BACKUP - Add S3 backup destination configuration
# - name: Configure S3 backup destination
#   template:
#     src: s3_backup_dest.j2
#     dest: /etc/webmin/virtual-server/s3-backup.conf
#   when: backup_enabled and backup_storage == 's3'

- name: Set backup retention policy
  lineinfile:
    path: /etc/webmin/virtual-server/config
    regexp: '^backup_retention='
    line: 'backup_retention={{ backup_retention_days }}'
  when: backup_enabled
```

---

## Role-Based Access Control

### Permission Levels

Based on existing staff roles, define operation permissions:

| Operation | Admin | Manager | Billing | Support |
|-----------|-------|---------|---------|---------|
| View deployments | ✓ | ✓ | ✓ | ✓ |
| Create deployment | ✓ | ✓ | ✗ | ✗ |
| Upgrade deployment | ✓ | ✓ | ✗ | ✗ |
| Destroy deployment | ✓ | ✗ | ✗ | ✗ |
| View logs | ✓ | ✓ | ✓ | ✓ |
| Retry failed | ✓ | ✓ | ✗ | ✗ |
| Manage providers | ✓ | ✗ | ✗ | ✗ |
| Manage sizes | ✓ | ✓ | ✗ | ✗ |
| Configure settings | ✓ | ✗ | ✗ | ✗ |

### Implementation

```python
# decorators.py

def node_deployment_permission(operation: str):
    """Decorator for node deployment operation permissions"""

    PERMISSIONS = {
        'view': ['admin', 'manager', 'billing', 'support'],
        'create': ['admin', 'manager'],
        'upgrade': ['admin', 'manager'],
        'destroy': ['admin'],  # Most destructive - admin only
        'retry': ['admin', 'manager'],
        'manage_providers': ['admin'],
        'manage_sizes': ['admin', 'manager'],
        'configure_settings': ['admin'],
    }

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            if not user.is_staff:
                return HttpResponseForbidden()

            allowed_roles = PERMISSIONS.get(operation, [])
            if user.staff_role not in allowed_roles:
                messages.error(
                    request,
                    f"Operation '{operation}' requires one of: {', '.join(allowed_roles)}"
                )
                return redirect('provisioning:node_deployments_list')

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
```

---

## Audit Integration

### New Audit Events

Add to existing audit event types:

```python
# nodes/signals.py

NODE_DEPLOYMENT_AUDIT_EVENTS = [
    # Deployment lifecycle
    'node_deployment_created',
    'node_deployment_started',
    'node_deployment_provisioned',
    'node_deployment_dns_configured',
    'node_deployment_panel_installed',
    'node_deployment_backups_configured',
    'node_deployment_validated',
    'node_deployment_registered',
    'node_deployment_completed',
    'node_deployment_failed',

    # Upgrade operations
    'node_deployment_upgrade_started',
    'node_deployment_upgrade_completed',
    'node_deployment_upgrade_failed',

    # Destruction
    'node_deployment_destroy_started',
    'node_deployment_destroyed',

    # Configuration changes
    'node_provider_created',
    'node_provider_updated',
    'node_size_created',
    'node_size_updated',
    'node_region_created',
    'node_region_updated',

    # SSH key management
    'node_ssh_key_generated',
    'node_ssh_key_accessed',
    'node_ssh_key_deleted',

    # Settings changes
    'node_deployment_settings_updated',
]
```

### Signal Handlers

```python
@receiver(post_save, sender=NodeDeployment)
def audit_node_deployment_changes(sender, instance, created, **kwargs):
    """Log all deployment status changes"""
    if created:
        AuditService.log_event(
            AuditEventData(
                action='node_deployment_created',
                category='business_operation',
                severity='medium',
                user=instance.initiated_by,
                content_object=instance,
                metadata={
                    'provider': instance.provider.name,
                    'region': instance.region.name,
                    'node_size': instance.node_size.name,
                    'hostname': instance.hostname,
                    'triggered_by_failover': instance.triggered_by_failover,
                }
            )
        )
    else:
        # Log status transitions
        ...
```

---

## Other System Integrations

### Systems to Integrate With

1. **Audit System** (detailed above)
   - Full deployment lifecycle logging
   - SSH key access tracking
   - Configuration changes

2. **Notification System** (`apps/notifications/`)
   - Email alerts on deployment completion/failure
   - Slack/webhook notifications for critical events

3. **Settings System** (`apps/settings/`)
   - Node deployment configuration section
   - Terraform state backend settings
   - DNS zone configuration
   - Backup settings

4. **Billing System** (`apps/billing/`)
   - TODO: Track deployment costs in invoicing
   - TODO: Associate infrastructure costs with customers

5. **Tickets System** (`apps/tickets/`)
   - TODO: Auto-create tickets on deployment failures
   - Link deployment issues to support workflow

### Feature Flags

```python
# settings.py

FEATURE_FLAGS = {
    'NODE_DEPLOYMENT_ENABLED': env.bool('FEATURE_NODE_DEPLOYMENT', default=False),
    'NODE_DEPLOYMENT_AUTO_REGISTRATION': env.bool('FEATURE_NODE_AUTO_REGISTER', default=True),
    'NODE_DEPLOYMENT_COST_TRACKING': env.bool('FEATURE_NODE_COSTS', default=True),
}
```

---

## UI Design

### Navigation Menu Addition

Add to existing navigation structure in `common/context_processors.py`:

```python
# In staff dropdown under "Business" section:
{
    'text': _('Node Deployments'),
    'url': reverse('provisioning:node_deployments_list'),
    'icon': 'server',  # or appropriate icon
    'badge': pending_deployments_count,  # Show pending count
    'permission': 'view_node_deployments',
}
```

### Views/Pages

#### 1. Node Deployment Dashboard (`node_deployments_list.html`)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│ Node Deployments                                            [+ Deploy New Node]     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ Overview Cards:                                                                      │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                │
│ │ Total: 12    │ │ Active: 10   │ │ Pending: 1   │ │ Failed: 1    │                │
│ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ Filters: [Env ▼] [Type ▼] [Provider ▼] [Country ▼] [Status ▼] [Search...]  [Apply] │
├─────────────────────────────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│ │ Hostname                │ Env │ Type│ Provider │ Country│ Region│ Status│Created│ │
│ ├─────────────────────────────────────────────────────────────────────────────────┤ │
│ │ prd-sha-het-de-fsn1-001 │ prd │ sha │ Hetzner  │ DE     │ fsn1  │✓ Act. │ 2d ago│ │
│ │ prd-sha-het-fi-hel1-001 │ prd │ sha │ Hetzner  │ FI     │ hel1  │✓ Act. │ 1d ago│ │
│ │ stg-sha-het-de-fsn1-001 │ stg │ sha │ Hetzner  │ DE     │ fsn1  │⏳ Inst│ 5m ago│ │
│ │ dev-sha-het-de-nbg1-001 │ dev │ sha │ Hetzner  │ DE     │ nbg1  │✗ Fail │ 1h ago│ │
│ └─────────────────────────────────────────────────────────────────────────────────┘ │
│ Pagination: [< Prev] 1 2 3 [Next >]                                                 │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

#### 2. New Node Deployment Form (`node_deployment_create.html`)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Deploy New Hosting Node                                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│ Step 1: Environment & Type                                                    │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ Environment: ● Production  ○ Staging  ○ Development                      │ │
│ │                                                                           │ │
│ │ Node Type:                                                                │ │
│ │ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                 │ │
│ │ │ ● Shared (sha) │ │ ○ VPS (vps)   │ │ ○ Container   │                 │ │
│ │ │   Virtualmin   │ │   [TODO]       │ │   (ctr) [TODO] │                 │ │
│ │ └────────────────┘ └────────────────┘ └────────────────┘                 │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────┤
│ Step 2: Provider & Panel                                                      │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ Provider:    [Hetzner Cloud ▼]                                           │ │
│ │ Panel:       [Virtualmin GPL ▼]  (auto-selected based on node type)      │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────┤
│ Step 3: Region                                                                │
│ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                     │
│ │ ● Falkenstein │ │ ○ Nuremberg   │ │ ○ Helsinki     │                     │
│ │ DE · fsn1     │ │ DE · nbg1     │ │ FI · hel1      │                     │
│ └────────────────┘ └────────────────┘ └────────────────┘                     │
│ ┌────────────────┐ ┌────────────────┐                                        │
│ │ ○ Ashburn     │ │ ○ Hillsboro   │                                        │
│ │ US · ash1     │ │ US · hil1     │                                        │
│ └────────────────┘ └────────────────┘                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ Step 4: Node Size                                                             │
│ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                     │
│ │ ○ Small       │ │ ● Medium      │ │ ○ Large        │                     │
│ │ 2 vCPU        │ │ 4 vCPU        │ │ 8 vCPU         │                     │
│ │ 4 GB RAM      │ │ 8 GB RAM      │ │ 16 GB RAM      │                     │
│ │ 40 GB Disk    │ │ 80 GB Disk    │ │ 160 GB Disk    │                     │
│ │ €5.83/mo      │ │ €11.86/mo     │ │ €23.72/mo      │                     │
│ │ ~50 domains   │ │ ~100 domains  │ │ ~200 domains   │                     │
│ └────────────────┘ └────────────────┘ └────────────────┘                     │
├──────────────────────────────────────────────────────────────────────────────┤
│ Step 5: Options                                                               │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ Display Name: [Main Production Server (optional)                    ]    │ │
│ │ [✓] Enable automatic backups (local storage)                             │ │
│ │     Retention: 7 days | Schedule: Daily at 2:00 AM                       │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────┤
│ Preview                                                                       │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ Hostname: prd-sha-het-de-fsn1-003                                        │ │
│ │ FQDN:     prd-sha-het-de-fsn1-003.infra.example.com                      │ │
│ │ (Next available number for prd/sha/het/de/fsn1)                          │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────┤
│                              [Cancel]  [Start Deployment]                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### 3. Node Deployment Detail (`node_deployment_detail.html`)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ prd-sha-het-de-fsn1-003                                 [Upgrade] [Destroy]  │
│ Display Name: Main Production Server                                         │
│ Status: ✓ Completed                                                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ Configuration                       │ Resources                              │
│ ───────────────────────────────────│──────────────────────────────────────  │
│ Environment: Production (prd)       │ IPv4: 116.203.xxx.xxx                  │
│ Type: Shared Hosting (sha)          │ IPv6: 2a01:4f8:xxx::1                  │
│ Provider: Hetzner Cloud (het)       │ Hetzner ID: 12345678                   │
│ Country: Germany (DE)               │ Virtualmin Server: #42                 │
│ Region: Falkenstein (fsn1)          │                                        │
│ Size: CPX41 (4 vCPU, 8GB)           │ FQDN:                                  │
│ Panel: Virtualmin GPL 7.10.0        │ prd-sha-het-de-fsn1-003.infra.example. │
│ Backups: Local (7 days)             │                                        │
│ Created: 2024-01-15 14:30           │                                        │
│ Initiated by: admin@example.com     │                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ Cost Tracking                                                                 │
│ ───────────────────────────────────────────────────────────────────────────  │
│ Monthly estimate: €11.86            │ Total to date: €5.93                    │
├──────────────────────────────────────────────────────────────────────────────┤
│ Deployment Progress                                                           │
│ ───────────────────────────────────────────────────────────────────────────  │
│ ✓ Node Provisioned         14:30:15    2m 34s                                │
│ ✓ DNS Configured           14:32:49    0m 12s                                │
│ ✓ Panel Installed          14:33:01    8m 45s                                │
│ ✓ Backups Configured       14:41:46    0m 18s                                │
│ ✓ Validation Passed        14:42:04    0m 23s                                │
│ ✓ Server Registered        14:42:27    0m 05s                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ Deployment Logs                                             [Refresh]        │
│ ───────────────────────────────────────────────────────────────────────────  │
│ 14:30:15 [INFO] terraform: Creating Hetzner server...                        │
│ 14:30:45 [INFO] terraform: Server created: 116.203.xxx.xxx                   │
│ 14:32:49 [INFO] dns: Created A record for prd-sha-het-de-fsn1-003            │
│ 14:33:01 [INFO] ansible: Starting Virtualmin GPL installation...             │
│ 14:41:46 [INFO] ansible: Configuring local backups...                        │
│ 14:42:04 [INFO] validation: All checks passed                                │
│ 14:42:27 [INFO] registration: VirtualminServer #42 created                   │
│ [Show full logs...]                                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### 4. Configuration Pages

- **Node Sizes** (`node_sizes.html`) - CRUD for NodeSize
- **Regions** (`node_regions.html`) - Enable/disable regions
- **Providers** (`node_providers.html`) - Provider management (admin only)
- **Settings** (`/settings/node-deployment/`) - System-wide configuration

---

## Async Task Implementation

### Django-Q2 Tasks

```python
# tasks.py

from django_q.tasks import async_task
from apps.common.types import Result


def deploy_node_async(deployment_id: int) -> None:
    """Main async node deployment task"""
    async_task(
        'apps.provisioning.nodes.tasks.execute_node_deployment',
        deployment_id,
        task_name=f'node-deploy-{deployment_id}',
        timeout=3600,  # 1 hour max
        hook='apps.provisioning.nodes.tasks.deployment_complete_hook'
    )


def execute_node_deployment(deployment_id: int) -> dict:
    """
    Execute full deployment pipeline.
    Called asynchronously by Django-Q2.
    """
    deployment = NodeDeployment.objects.get(id=deployment_id)
    service = NodeDeploymentService()

    result = service.execute_deployment(deployment)

    if result.is_err():
        return {'success': False, 'error': result.unwrap_err()}

    return {'success': True, 'deployment_id': deployment_id}


def deployment_complete_hook(task):
    """Called when deployment task completes"""
    # Send notifications, update dashboards, etc.
    ...
```

---

## Future Automation (TODO Hints)

Leave these TODOs in the code for future failover automation:

```python
# deployment_service.py

class NodeDeploymentService:

    def create_deployment(self, ...):
        ...
        # TODO: FAILOVER_AUTOMATION
        # When triggered by failover system:
        # 1. Accept source_node parameter
        # 2. Determine appropriate size based on source
        # 3. Set triggered_by_failover=True
        # 4. Queue customer migration after completion
        # 5. See: apps.provisioning.nodes.failover


    def execute_deployment(self, ...):
        ...
        # TODO: FAILOVER_AUTOMATION
        # After successful registration:
        # 1. Check if deployment.triggered_by_failover
        # 2. If yes, trigger customer migration pipeline
        # 3. Emit 'failover_node_deployment_ready' event
```

```python
# TODO: Future failover module structure
# apps/provisioning/nodes/failover/
# ├── __init__.py
# ├── detector.py      # Health check failure detection
# ├── orchestrator.py  # Failover decision making
# ├── migrator.py      # Customer migration service
# └── tasks.py         # Async failover tasks
```

```yaml
# TODO: S3_BACKUP - ansible/roles/virtualmin_backup/tasks/s3.yml
# Future S3 backup configuration tasks
# - Configure AWS credentials
# - Set S3 bucket as backup destination
# - Configure lifecycle policies
```

---

## Implementation Phases

### Phase 1: Foundation (Core Models & Services) ✅ COMPLETED
- [x] Create node deployment models (CloudProvider, NodeSize, Region, etc.)
- [x] Implement NodeDeployment model with status tracking
- [x] Create NodeDeploymentLog model
- [x] Create NodeDeploymentCostRecord model
- [x] Set up `apps/infrastructure/` app structure
- [x] Database migrations (0001_initial.py)

### Phase 2: System Settings Integration ✅ COMPLETED
- [x] Add node deployment settings section to Settings app (17 settings)
- [x] Update dashboard.html with icon/name/description
- [x] Update manage.html with tab icon
- [x] Add descriptions and help texts to setup command

### Phase 3: Terraform Integration ✅ COMPLETED
- [x] Create Terraform module structure (infrastructure/terraform/)
- [x] Implement Hetzner module with firewall (main.tf, variables.tf, firewall.tf, outputs.tf)
- [x] Implement Cloudflare DNS module (main.tf, variables.tf, outputs.tf)
- [x] Create backend templates (local.tf.tpl, s3.tf.tpl)
- [x] Add .gitignore for terraform files
- [x] Add README with documentation
- [ ] Create TerraformService wrapper with local state backend (Phase 7)
- [ ] Test VPS provisioning (Phase 12)

### Phase 4: Ansible Integration ✅ COMPLETED
- [x] Create Ansible playbook structure (infrastructure/ansible/)
- [x] ansible.cfg with optimized settings
- [x] requirements.yml with Galaxy dependencies
- [x] group_vars/all.yml with default variables
- [x] playbooks/common_base.yml - Base server setup
- [x] playbooks/virtualmin.yml - Virtualmin GPL installation (v7.10.0 pinned)
- [x] playbooks/virtualmin_harden.yml - Security hardening (fail2ban, UFW, sysctl)
- [x] playbooks/virtualmin_backup.yml - Local backup configuration
- [x] templates/ for jail.local, unattended-upgrades, backup schedule
- [x] README with documentation
- [ ] Create AnsibleService wrapper (Phase 7)
- [ ] Test end-to-end installation (Phase 12)

### Phase 5: SSH Key Management ✅ COMPLETED
- [x] Implement SSHKeyManager (apps/infrastructure/ssh_key_manager.py)
- [x] ED25519 key pair generation
- [x] Integrate with CredentialVault for secure storage
- [x] Implement master key fallback from environment variables
- [x] Key retrieval methods for Terraform (public key) and Ansible (private key file)
- [x] Key deletion on deployment destruction
- [ ] Test key generation and retrieval (Phase 12)

### Phase 6: Node Registration ✅ COMPLETED
- [x] Implement NodeValidationService (validation_service.py)
  - SSH connectivity check using deployment SSH key
  - Required ports check (22, 80, 443, 10000)
  - Virtualmin API accessibility check
  - SSL certificate check
  - Quick health check for monitoring
- [x] Implement NodeRegistrationService (registration_service.py)
  - Register deployed nodes as VirtualminServer
  - Store credentials in CredentialVault
  - Unregister/deactivate on destruction
- [ ] Test auto-registration flow (Phase 12)

### Phase 7: Orchestration & Async ✅ COMPLETED
- [x] Implement TerraformService wrapper (terraform_service.py)
  - Generate deployment-specific tfvars
  - Configure local state backend
  - Execute terraform init/plan/apply/destroy
  - Parse outputs (IPs, server ID)
- [x] Implement AnsibleService wrapper (ansible_service.py)
  - Generate dynamic inventory
  - Run playbooks (common_base, virtualmin, harden, backup)
  - Capture output and stats
- [x] Implement NodeDeploymentService orchestration (deployment_service.py)
  - Full deployment pipeline with 13 stages
  - Progress tracking with callbacks
  - State transitions and logging
  - Destroy and retry operations
- [x] Create Django-Q2 tasks (tasks.py)
  - deploy_node_task, destroy_node_task, retry_deployment_task
  - validate_node_task, bulk_validate_nodes_task
  - cleanup_failed_deployments_task
  - Queue helpers and completion hooks
- [x] Update __init__.py with all exports
- [ ] Test full deployment pipeline (Phase 12)

### Phase 8: UI Implementation ✅ COMPLETED
- [x] Create list view with filters (deployment_list.html with env/type/provider/status/search filters)
- [x] Create deployment form (deployment_create.html with Alpine.js multi-step wizard)
- [x] Create detail view with logs (deployment_detail.html with HTMX auto-refresh)
- [x] Create configuration pages (provider_list/form, size_list/form, region_list)
- [x] Add URL routing (infrastructure/urls.py with full CRUD)
- [x] Add forms (forms.py with NodeDeploymentForm, CloudProviderForm, NodeSizeForm)
- [x] Add views (views.py with dashboard, deployments, providers, sizes, regions)
- [x] Create partials for HTMX (deployment_status.html, deployment_logs.html, region_row.html)
- [ ] Add navigation menu item (deferred - requires base.html modification)

### Phase 9: Audit & Permissions ✅ COMPLETED
- [x] Add audit event types to AuditEvent model (24 new infrastructure actions)
- [x] Implement InfrastructureAuditService (audit_service.py)
  - Deployment lifecycle events (created, started, completed, failed, retry)
  - Destruction events (started, completed, failed)
  - Provider/size/region management events
  - SSH key generation/revocation events
- [x] Implement Django signals (signals.py)
  - NodeDeployment post_save signal for creation audit
  - CloudProvider pre/post_save for change tracking
  - NodeSize pre/post_save for change tracking
  - NodeRegion pre/post_save for toggle detection
- [x] Implement role-based permission decorators (permissions.py)
  - @require_infrastructure_view (basic view access)
  - @require_deployment_management (manage deployments)
  - @require_deploy_permission (create new deployments)
  - @require_destroy_permission (destroy nodes)
  - @require_provider_management, @require_size_management, @require_region_management
- [x] Update views.py with permission decorators
- [x] Update apps.py to connect signals on ready()

### Phase 10: Lifecycle Operations
- [ ] Implement upgrade functionality
- [ ] Implement destroy functionality
- [ ] Implement retry failed deployments

### Phase 11: Cost Tracking
- [ ] Implement cost calculation
- [ ] Create cost tracking records
- [ ] Display costs in UI

### Phase 12: Testing & Documentation
- [ ] Unit tests for services
- [ ] Integration tests for deployment pipeline
- [ ] Update API documentation
- [ ] Create operational runbook

---

## Environment Variables

```bash
# Hetzner
HETZNER_API_TOKEN=xxx

# Cloudflare
CLOUDFLARE_API_TOKEN=xxx

# Terraform
TERRAFORM_WORKING_DIR=/path/to/terraform

# Ansible
ANSIBLE_WORKING_DIR=/path/to/ansible
ANSIBLE_CONFIG=/path/to/ansible.cfg

# SSH Master Key (optional fallback)
INFRASTRUCTURE_MASTER_SSH_KEY=/path/to/key

# Feature flags
FEATURE_NODE_DEPLOYMENT=true
FEATURE_NODE_AUTO_REGISTER=true
FEATURE_NODE_COSTS=true
```

---

## Decisions Made

1. **Terraform State**: Local by default, configurable to S3 via system settings (S3 TODO for later)
2. **Virtualmin License**: GPL
3. **SSH Restriction**: None (open to all IPs)
4. **Backups**: Local storage enabled by default with 7-day retention (S3 TODO for later)
5. **DNS Zone**: `infra.example.com` style (configurable), generic name for all node types
6. **Monitoring**: Not included (may add later)
7. **Naming**: "Node Deployment" throughout (not VPS Deployment)
8. **Node Types**: Future-proofed with type code in hostname (sha, vps, ctr, ded, app)
9. **Hostname Format**: 23 characters fixed: `{env}-{type}-{provider}-{country}-{region}-{number}`
   - Example: `prd-sha-het-de-fsn1-001`
   - Initial implementation: `sha` (shared hosting with Virtualmin) only
   - Other types are placeholders for future expansion

---

## References

- Existing Virtualmin Integration: `apps/provisioning/virtualmin_*.py`
- Credential Vault: `apps/common/credential_vault.py`
- Audit System: `apps/audit/`
- Settings System: `apps/settings/`
- UI Components: `apps/ui/`
- Staff Roles: `apps/users/models.py` (STAFF_ROLE_CHOICES)
