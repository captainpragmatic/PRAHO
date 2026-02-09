# Generated manually for Infrastructure App - Node Deployment System

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("provisioning", "0002_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # CloudProvider model
        migrations.CreateModel(
            name="CloudProvider",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        max_length=50, unique=True, verbose_name="Provider Name"
                    ),
                ),
                (
                    "provider_type",
                    models.CharField(
                        choices=[
                            ("hetzner", "Hetzner Cloud"),
                            ("digitalocean", "DigitalOcean"),
                            ("vultr", "Vultr"),
                            ("linode", "Linode"),
                            ("aws", "Amazon Web Services"),
                            ("gcp", "Google Cloud Platform"),
                        ],
                        max_length=20,
                        verbose_name="Provider Type",
                    ),
                ),
                (
                    "code",
                    models.CharField(
                        help_text="3-letter code for hostname generation (e.g., het, dig, vul)",
                        max_length=3,
                        unique=True,
                        verbose_name="Provider Code",
                    ),
                ),
                ("is_active", models.BooleanField(default=True, verbose_name="Active")),
                (
                    "credential_identifier",
                    models.CharField(
                        help_text="Identifier for API credentials in CredentialVault",
                        max_length=100,
                        verbose_name="Credential Identifier",
                    ),
                ),
                (
                    "config",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Provider-specific configuration",
                        verbose_name="Configuration",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Cloud Provider",
                "verbose_name_plural": "Cloud Providers",
                "ordering": ["name"],
            },
        ),
        # NodeRegion model
        migrations.CreateModel(
            name="NodeRegion",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text='Display name (e.g., "Falkenstein", "Helsinki")',
                        max_length=100,
                        verbose_name="Region Name",
                    ),
                ),
                (
                    "provider_region_id",
                    models.CharField(
                        help_text='Provider\'s native ID (e.g., "fsn1", "us-east-1", "ewr")',
                        max_length=50,
                        verbose_name="Provider Region ID",
                    ),
                ),
                (
                    "normalized_code",
                    models.CharField(
                        help_text="4-character normalized code for hostname (e.g., fsn1, nyc1, use1)",
                        max_length=4,
                        verbose_name="Normalized Code",
                    ),
                ),
                (
                    "country_code",
                    models.CharField(
                        help_text="ISO 3166-1 alpha-2 country code (e.g., de, fi, us)",
                        max_length=2,
                        verbose_name="Country Code",
                    ),
                ),
                (
                    "city",
                    models.CharField(
                        help_text="Datacenter city", max_length=100, verbose_name="City"
                    ),
                ),
                ("is_active", models.BooleanField(default=True, verbose_name="Active")),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="regions",
                        to="infrastructure.cloudprovider",
                        verbose_name="Provider",
                    ),
                ),
            ],
            options={
                "verbose_name": "Node Region",
                "verbose_name_plural": "Node Regions",
                "ordering": ["provider", "country_code", "name"],
                "unique_together": {("provider", "provider_region_id")},
            },
        ),
        migrations.AddIndex(
            model_name="noderegion",
            index=models.Index(
                fields=["provider", "normalized_code"],
                name="infra_region_provider_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="noderegion",
            index=models.Index(
                fields=["country_code"], name="infra_region_country_idx"
            ),
        ),
        # NodeSize model
        migrations.CreateModel(
            name="NodeSize",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text='Internal name (e.g., "Small", "Medium", "Large")',
                        max_length=100,
                        verbose_name="Size Name",
                    ),
                ),
                (
                    "display_name",
                    models.CharField(
                        help_text='UI display (e.g., "2 vCPU / 4GB RAM / 40GB")',
                        max_length=100,
                        verbose_name="Display Name",
                    ),
                ),
                (
                    "provider_type_id",
                    models.CharField(
                        help_text='Provider\'s type ID (e.g., "cpx21", "cpx41")',
                        max_length=50,
                        verbose_name="Provider Type ID",
                    ),
                ),
                ("vcpus", models.PositiveIntegerField(verbose_name="vCPUs")),
                ("memory_gb", models.PositiveIntegerField(verbose_name="Memory (GB)")),
                ("disk_gb", models.PositiveIntegerField(verbose_name="Disk (GB)")),
                (
                    "hourly_cost_eur",
                    models.DecimalField(
                        decimal_places=4, max_digits=10, verbose_name="Hourly Cost (EUR)"
                    ),
                ),
                (
                    "monthly_cost_eur",
                    models.DecimalField(
                        decimal_places=2, max_digits=10, verbose_name="Monthly Cost (EUR)"
                    ),
                ),
                (
                    "max_domains",
                    models.PositiveIntegerField(
                        default=50,
                        help_text="Estimated max domains for this size",
                        verbose_name="Max Domains",
                    ),
                ),
                (
                    "max_bandwidth_gb",
                    models.PositiveIntegerField(
                        default=1000, verbose_name="Max Bandwidth (GB)"
                    ),
                ),
                ("is_active", models.BooleanField(default=True, verbose_name="Active")),
                (
                    "sort_order",
                    models.PositiveIntegerField(default=0, verbose_name="Sort Order"),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sizes",
                        to="infrastructure.cloudprovider",
                        verbose_name="Provider",
                    ),
                ),
            ],
            options={
                "verbose_name": "Node Size",
                "verbose_name_plural": "Node Sizes",
                "ordering": ["provider", "sort_order"],
                "unique_together": {("provider", "provider_type_id")},
            },
        ),
        # PanelType model
        migrations.CreateModel(
            name="PanelType",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        max_length=50, unique=True, verbose_name="Panel Name"
                    ),
                ),
                (
                    "panel_type",
                    models.CharField(
                        choices=[("virtualmin", "Virtualmin GPL"), ("blesta", "Blesta")],
                        max_length=20,
                        verbose_name="Panel Type",
                    ),
                ),
                (
                    "version",
                    models.CharField(
                        blank=True,
                        help_text='Pinned version (e.g., "7.10.0")',
                        max_length=50,
                        verbose_name="Version",
                    ),
                ),
                (
                    "ansible_playbook",
                    models.CharField(
                        help_text='Playbook filename (e.g., "virtualmin.yml")',
                        max_length=100,
                        verbose_name="Ansible Playbook",
                    ),
                ),
                ("is_active", models.BooleanField(default=True, verbose_name="Active")),
            ],
            options={
                "verbose_name": "Panel Type",
                "verbose_name_plural": "Panel Types",
                "ordering": ["name"],
            },
        ),
        # NodeDeployment model
        migrations.CreateModel(
            name="NodeDeployment",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "environment",
                    models.CharField(
                        choices=[
                            ("prd", "Production"),
                            ("stg", "Staging"),
                            ("dev", "Development"),
                        ],
                        default="prd",
                        max_length=3,
                        verbose_name="Environment",
                    ),
                ),
                (
                    "node_type",
                    models.CharField(
                        choices=[
                            ("sha", "Shared Hosting"),
                            ("vps", "VPS Hosting"),
                            ("ctr", "Container"),
                            ("ded", "Dedicated"),
                            ("app", "Application Platform"),
                        ],
                        default="sha",
                        max_length=3,
                        verbose_name="Node Type",
                    ),
                ),
                (
                    "hostname",
                    models.CharField(
                        help_text="Auto-generated 23-char hostname",
                        max_length=23,
                        unique=True,
                        verbose_name="Hostname",
                    ),
                ),
                (
                    "node_number",
                    models.PositiveIntegerField(
                        help_text="Sequential number (1-999)", verbose_name="Node Number"
                    ),
                ),
                (
                    "display_name",
                    models.CharField(
                        blank=True,
                        help_text="Optional friendly name",
                        max_length=100,
                        verbose_name="Display Name",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("provisioning_node", "Provisioning Node"),
                            ("configuring_dns", "Configuring DNS"),
                            ("installing_panel", "Installing Panel"),
                            ("configuring_backups", "Configuring Backups"),
                            ("validating", "Validating"),
                            ("registering", "Registering Server"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                            ("destroying", "Destroying"),
                            ("destroyed", "Destroyed"),
                        ],
                        default="pending",
                        max_length=30,
                        verbose_name="Status",
                    ),
                ),
                (
                    "status_message",
                    models.TextField(blank=True, verbose_name="Status Message"),
                ),
                (
                    "last_successful_phase",
                    models.CharField(
                        blank=True,
                        help_text="For retry logic",
                        max_length=50,
                        verbose_name="Last Successful Phase",
                    ),
                ),
                (
                    "external_node_id",
                    models.CharField(
                        blank=True,
                        help_text="Provider's server ID (e.g., Hetzner server ID)",
                        max_length=100,
                        verbose_name="External Node ID",
                    ),
                ),
                (
                    "ipv4_address",
                    models.GenericIPAddressField(
                        blank=True,
                        null=True,
                        protocol="IPv4",
                        verbose_name="IPv4 Address",
                    ),
                ),
                (
                    "ipv6_address",
                    models.GenericIPAddressField(
                        blank=True,
                        null=True,
                        protocol="IPv6",
                        verbose_name="IPv6 Address",
                    ),
                ),
                (
                    "ssh_key_credential_id",
                    models.CharField(
                        blank=True, max_length=100, verbose_name="SSH Key Credential ID"
                    ),
                ),
                (
                    "dns_zone",
                    models.CharField(
                        blank=True,
                        help_text="Zone used for this node",
                        max_length=255,
                        verbose_name="DNS Zone",
                    ),
                ),
                (
                    "dns_record_ids",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Created DNS record IDs",
                        verbose_name="DNS Record IDs",
                    ),
                ),
                (
                    "terraform_state_path",
                    models.CharField(
                        blank=True, max_length=500, verbose_name="Terraform State Path"
                    ),
                ),
                (
                    "terraform_state_backend",
                    models.CharField(
                        default="local",
                        help_text="'local' or 's3'",
                        max_length=20,
                        verbose_name="Terraform State Backend",
                    ),
                ),
                (
                    "backup_enabled",
                    models.BooleanField(default=True, verbose_name="Backup Enabled"),
                ),
                (
                    "backup_storage",
                    models.CharField(
                        default="local",
                        help_text="'local' or 's3'",
                        max_length=20,
                        verbose_name="Backup Storage",
                    ),
                ),
                (
                    "total_cost_eur",
                    models.DecimalField(
                        decimal_places=2,
                        default=0,
                        max_digits=10,
                        verbose_name="Total Cost (EUR)",
                    ),
                ),
                (
                    "triggered_by_failover",
                    models.BooleanField(default=False, verbose_name="Triggered by Failover"),
                ),
                (
                    "correlation_id",
                    models.UUIDField(default=uuid.uuid4, verbose_name="Correlation ID"),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "started_at",
                    models.DateTimeField(blank=True, null=True, verbose_name="Started At"),
                ),
                (
                    "completed_at",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="Completed At"
                    ),
                ),
                (
                    "destroyed_at",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="Destroyed At"
                    ),
                ),
                (
                    "initiated_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="initiated_node_deployments",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="Initiated By",
                    ),
                ),
                (
                    "node_size",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="deployments",
                        to="infrastructure.nodesize",
                        verbose_name="Node Size",
                    ),
                ),
                (
                    "panel_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="deployments",
                        to="infrastructure.paneltype",
                        verbose_name="Panel Type",
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="deployments",
                        to="infrastructure.cloudprovider",
                        verbose_name="Provider",
                    ),
                ),
                (
                    "region",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="deployments",
                        to="infrastructure.noderegion",
                        verbose_name="Region",
                    ),
                ),
                (
                    "source_node",
                    models.ForeignKey(
                        blank=True,
                        help_text="Original node this deployment is replacing (failover scenario)",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="replacement_nodes",
                        to="infrastructure.nodedeployment",
                        verbose_name="Source Node",
                    ),
                ),
                (
                    "virtualmin_server",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="node_deployment",
                        to="provisioning.virtualminserver",
                        verbose_name="Virtualmin Server",
                    ),
                ),
            ],
            options={
                "verbose_name": "Node Deployment",
                "verbose_name_plural": "Node Deployments",
                "ordering": ["-created_at"],
                "unique_together": {
                    ("environment", "node_type", "provider", "region", "node_number")
                },
            },
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["status", "created_at"], name="infra_nd_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["environment", "status"], name="infra_nd_env_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["node_type", "status"], name="infra_nd_type_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["provider", "status"], name="infra_nd_prov_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["environment", "node_type", "provider", "region"],
                name="infra_nd_next_num_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["initiated_by", "created_at"],
                name="infra_nd_initiated_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeployment",
            index=models.Index(
                fields=["triggered_by_failover", "status"],
                name="infra_nd_failover_idx",
            ),
        ),
        # NodeDeploymentLog model
        migrations.CreateModel(
            name="NodeDeploymentLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "level",
                    models.CharField(
                        choices=[
                            ("debug", "Debug"),
                            ("info", "Info"),
                            ("warning", "Warning"),
                            ("error", "Error"),
                        ],
                        default="info",
                        max_length=10,
                        verbose_name="Level",
                    ),
                ),
                (
                    "phase",
                    models.CharField(
                        help_text="'terraform', 'ansible', 'dns', 'backup', etc.",
                        max_length=50,
                        verbose_name="Phase",
                    ),
                ),
                ("message", models.TextField(verbose_name="Message")),
                (
                    "details",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Additional structured data",
                        verbose_name="Details",
                    ),
                ),
                (
                    "duration_seconds",
                    models.FloatField(
                        blank=True,
                        help_text="Phase duration",
                        null=True,
                        verbose_name="Duration (seconds)",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "deployment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="logs",
                        to="infrastructure.nodedeployment",
                        verbose_name="Deployment",
                    ),
                ),
            ],
            options={
                "verbose_name": "Node Deployment Log",
                "verbose_name_plural": "Node Deployment Logs",
                "ordering": ["created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="nodedeploymentlog",
            index=models.Index(
                fields=["deployment", "level"], name="infra_ndlog_level_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="nodedeploymentlog",
            index=models.Index(
                fields=["deployment", "phase"], name="infra_ndlog_phase_idx"
            ),
        ),
        # NodeDeploymentCostRecord model
        migrations.CreateModel(
            name="NodeDeploymentCostRecord",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("period_start", models.DateTimeField(verbose_name="Period Start")),
                ("period_end", models.DateTimeField(verbose_name="Period End")),
                (
                    "cost_eur",
                    models.DecimalField(
                        decimal_places=4, max_digits=10, verbose_name="Cost (EUR)"
                    ),
                ),
                (
                    "compute_cost",
                    models.DecimalField(
                        decimal_places=4,
                        default=0,
                        max_digits=10,
                        verbose_name="Compute Cost",
                    ),
                ),
                (
                    "bandwidth_cost",
                    models.DecimalField(
                        decimal_places=4,
                        default=0,
                        max_digits=10,
                        verbose_name="Bandwidth Cost",
                    ),
                ),
                (
                    "storage_cost",
                    models.DecimalField(
                        decimal_places=4,
                        default=0,
                        max_digits=10,
                        verbose_name="Storage Cost",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "deployment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cost_records",
                        to="infrastructure.nodedeployment",
                        verbose_name="Deployment",
                    ),
                ),
            ],
            options={
                "verbose_name": "Node Deployment Cost Record",
                "verbose_name_plural": "Node Deployment Cost Records",
                "ordering": ["-period_end"],
            },
        ),
        migrations.AddIndex(
            model_name="nodedeploymentcostrecord",
            index=models.Index(
                fields=["deployment", "period_start"],
                name="infra_ndcost_period_idx",
            ),
        ),
    ]
