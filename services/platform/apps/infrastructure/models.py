"""
Infrastructure Models

Models for automated infrastructure deployment:
- CloudProvider: Supported cloud providers (Hetzner, DigitalOcean, etc.)
- NodeSize: Server size/plan options
- NodeRegion: Available deployment regions
- PanelType: Control panels (Virtualmin, Blesta, etc.)
- NodeDeployment: Deployment lifecycle tracking
- NodeDeploymentLog: Detailed deployment logs
- NodeDeploymentCostRecord: Cost tracking
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise


# Hostname format validator: prd-sha-het-de-fsn1-001
HOSTNAME_PATTERN = re.compile(r"^[a-z]{3}-[a-z]{3}-[a-z]{3}-[a-z]{2}-[a-z0-9]{4}-\d{3}$")

# Default max domains for a hosting node (used in NodeSize and NodeDeployment)
DEFAULT_MAX_DOMAINS = 50


def validate_hostname_format(value: str) -> None:
    """Validate hostname matches the expected format."""
    if not HOSTNAME_PATTERN.match(value):
        raise ValidationError(
            _("Hostname must match format: prd-sha-het-de-fsn1-001 (env-type-provider-country-region-number)")
        )


class CloudProvider(models.Model):
    """Supported cloud providers (Hetzner, DigitalOcean, etc.)"""

    PROVIDER_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("hetzner", "Hetzner Cloud"),
        ("digitalocean", "DigitalOcean"),
        ("vultr", "Vultr"),
        ("linode", "Linode"),
        ("aws", "Amazon Web Services"),
        ("gcp", "Google Cloud Platform"),
    ]

    name = models.CharField(max_length=50, unique=True, verbose_name=_("Provider Name"))
    provider_type = models.CharField(
        max_length=20,
        choices=PROVIDER_CHOICES,
        verbose_name=_("Provider Type"),
    )

    # 3-letter code for hostname generation (het, dig, vul, lin, aws, gcp)
    code = models.CharField(
        max_length=3,
        unique=True,
        verbose_name=_("Provider Code"),
        help_text=_("3-letter code for hostname generation (e.g., het, dig, vul)"),
    )

    is_active = models.BooleanField(default=True, verbose_name=_("Active"))

    # API credentials stored in CredentialVault
    credential_identifier = models.CharField(
        max_length=100,
        verbose_name=_("Credential Identifier"),
        help_text=_("Identifier for API credentials in CredentialVault"),
    )

    # Provider-specific config (JSON)
    config = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Configuration"),
        help_text=_("Provider-specific configuration"),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("Cloud Provider")
        verbose_name_plural = _("Cloud Providers")
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.code})"


class NodeRegion(models.Model):
    """Available deployment regions per provider"""

    provider = models.ForeignKey(
        CloudProvider,
        on_delete=models.CASCADE,
        related_name="regions",
        verbose_name=_("Provider"),
    )

    name = models.CharField(
        max_length=100,
        verbose_name=_("Region Name"),
        help_text=_('Display name (e.g., "Falkenstein", "Helsinki")'),
    )

    provider_region_id = models.CharField(
        max_length=50,
        verbose_name=_("Provider Region ID"),
        help_text=_('Provider\'s native ID (e.g., "fsn1", "us-east-1", "ewr")'),
    )

    # Normalized 4-character code for hostname generation
    # Examples: fsn1, ash1, nyc1, ewr1, use1, ane1
    normalized_code = models.CharField(
        max_length=4,
        verbose_name=_("Normalized Code"),
        help_text=_("4-character normalized code for hostname (e.g., fsn1, nyc1, use1)"),
    )

    # Geographic info (ISO 3166-1 alpha-2 for country)
    country_code = models.CharField(
        max_length=2,
        verbose_name=_("Country Code"),
        help_text=_("ISO 3166-1 alpha-2 country code (e.g., de, fi, us)"),
    )

    city = models.CharField(
        max_length=100,
        verbose_name=_("City"),
        help_text=_("Datacenter city"),
    )

    is_active = models.BooleanField(default=True, verbose_name=_("Active"))

    class Meta:
        verbose_name = _("Node Region")
        verbose_name_plural = _("Node Regions")
        unique_together = [["provider", "provider_region_id"]]
        ordering = ["provider", "country_code", "name"]
        indexes = [
            models.Index(fields=["provider", "normalized_code"]),
            models.Index(fields=["country_code"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.country_code.upper()}/{self.normalized_code})"


class NodeSize(models.Model):
    """Configurable server size/plan options for hosting nodes"""

    provider = models.ForeignKey(
        CloudProvider,
        on_delete=models.CASCADE,
        related_name="sizes",
        verbose_name=_("Provider"),
    )

    name = models.CharField(
        max_length=100,
        verbose_name=_("Size Name"),
        help_text=_('Internal name (e.g., "Small", "Medium", "Large")'),
    )

    display_name = models.CharField(
        max_length=100,
        verbose_name=_("Display Name"),
        help_text=_('UI display (e.g., "2 vCPU / 4GB RAM / 40GB")'),
    )

    # Provider-specific type identifier
    provider_type_id = models.CharField(
        max_length=50,
        verbose_name=_("Provider Type ID"),
        help_text=_('Provider\'s type ID (e.g., "cpx21", "cpx41")'),
    )

    # Specs for display
    vcpus = models.PositiveIntegerField(verbose_name=_("vCPUs"))
    memory_gb = models.PositiveIntegerField(verbose_name=_("Memory (GB)"))
    disk_gb = models.PositiveIntegerField(verbose_name=_("Disk (GB)"))

    # Pricing (for cost tracking)
    hourly_cost_eur = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        verbose_name=_("Hourly Cost (EUR)"),
    )
    monthly_cost_eur = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name=_("Monthly Cost (EUR)"),
    )

    # Capacity limits for Virtualmin
    max_domains = models.PositiveIntegerField(
        default=DEFAULT_MAX_DOMAINS,
        verbose_name=_("Max Domains"),
        help_text=_("Estimated max domains for this size"),
    )
    max_bandwidth_gb = models.PositiveIntegerField(
        default=1000,
        verbose_name=_("Max Bandwidth (GB)"),
    )

    is_active = models.BooleanField(default=True, verbose_name=_("Active"))
    sort_order = models.PositiveIntegerField(default=0, verbose_name=_("Sort Order"))

    class Meta:
        verbose_name = _("Node Size")
        verbose_name_plural = _("Node Sizes")
        ordering = ["provider", "sort_order"]
        unique_together = [["provider", "provider_type_id"]]

    def __str__(self) -> str:
        return f"{self.display_name} ({self.provider.code})"


class PanelType(models.Model):
    """Supported control panels (Virtualmin, Blesta, etc.)"""

    PANEL_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("virtualmin", "Virtualmin GPL"),
        ("blesta", "Blesta"),
    ]

    name = models.CharField(max_length=50, unique=True, verbose_name=_("Panel Name"))
    panel_type = models.CharField(
        max_length=20,
        choices=PANEL_CHOICES,
        verbose_name=_("Panel Type"),
    )

    # Version pinning
    version = models.CharField(
        max_length=50,
        blank=True,
        verbose_name=_("Version"),
        help_text=_('Pinned version (e.g., "7.10.0")'),
    )

    # Ansible playbook reference
    ansible_playbook = models.CharField(
        max_length=100,
        verbose_name=_("Ansible Playbook"),
        help_text=_('Playbook filename (e.g., "virtualmin.yml")'),
    )

    is_active = models.BooleanField(default=True, verbose_name=_("Active"))

    class Meta:
        verbose_name = _("Panel Type")
        verbose_name_plural = _("Panel Types")
        ordering = ["name"]

    def __str__(self) -> str:
        version_str = f" v{self.version}" if self.version else ""
        return f"{self.name}{version_str}"


class NodeDeployment(models.Model):
    """Tracks hosting node deployment lifecycle"""

    STATUS_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("pending", _("Pending")),
        ("provisioning_node", _("Provisioning Node")),
        ("configuring_dns", _("Configuring DNS")),
        ("installing_panel", _("Installing Panel")),
        ("configuring_backups", _("Configuring Backups")),
        ("validating", _("Validating")),
        ("registering", _("Registering Server")),
        ("completed", _("Completed")),
        ("stopped", _("Stopped")),
        ("failed", _("Failed")),
        ("destroying", _("Destroying")),
        ("destroyed", _("Destroyed")),
    ]

    ENVIRONMENT_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("prd", _("Production")),
        ("stg", _("Staging")),
        ("dev", _("Development")),
    ]

    NODE_TYPE_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("sha", _("Shared Hosting")),  # Virtualmin - implemented
        ("vps", _("VPS Hosting")),
        ("ctr", _("Container")),
        ("ded", _("Dedicated")),
        ("app", _("Application Platform")),
    ]

    # Deployment configuration
    environment = models.CharField(
        max_length=3,
        choices=ENVIRONMENT_CHOICES,
        default="prd",
        verbose_name=_("Environment"),
    )

    node_type = models.CharField(
        max_length=3,
        choices=NODE_TYPE_CHOICES,
        default="sha",
        verbose_name=_("Node Type"),
    )

    provider = models.ForeignKey(
        CloudProvider,
        on_delete=models.PROTECT,
        related_name="deployments",
        verbose_name=_("Provider"),
    )

    node_size = models.ForeignKey(
        NodeSize,
        on_delete=models.PROTECT,
        related_name="deployments",
        verbose_name=_("Node Size"),
    )

    region = models.ForeignKey(
        NodeRegion,
        on_delete=models.PROTECT,
        related_name="deployments",
        verbose_name=_("Region"),
    )

    panel_type = models.ForeignKey(
        PanelType,
        on_delete=models.PROTECT,
        related_name="deployments",
        verbose_name=_("Panel Type"),
    )

    hostname = models.CharField(
        max_length=23,
        unique=True,
        verbose_name=_("Hostname"),
        help_text=_("Auto-generated 23-char hostname"),
        validators=[validate_hostname_format],
    )

    node_number = models.PositiveIntegerField(
        verbose_name=_("Node Number"),
        help_text=_("Sequential number (1-999)"),
        validators=[MinValueValidator(1), MaxValueValidator(999)],
    )

    display_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_("Display Name"),
        help_text=_("Optional friendly name"),
    )

    # Current status
    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="pending",
        verbose_name=_("Status"),
    )

    status_message = models.TextField(
        blank=True,
        verbose_name=_("Status Message"),
    )

    last_successful_phase = models.CharField(
        max_length=50,
        blank=True,
        verbose_name=_("Last Successful Phase"),
        help_text=_("For retry logic"),
    )

    # Provisioned resources (populated after creation)
    external_node_id = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_("External Node ID"),
        help_text=_("Provider's server ID (e.g., Hetzner server ID)"),
    )

    ipv4_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        protocol="IPv4",
        verbose_name=_("IPv4 Address"),
    )

    ipv6_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        protocol="IPv6",
        verbose_name=_("IPv6 Address"),
    )

    # SSH key reference (stored in CredentialVault)
    ssh_key_credential_id = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_("SSH Key Credential ID"),
    )

    # DNS configuration
    dns_zone = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("DNS Zone"),
        help_text=_("Zone used for this node"),
    )

    dns_record_ids = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_("DNS Record IDs"),
        help_text=_("Created DNS record IDs"),
    )

    # Linked VirtualminServer (after successful registration)
    virtualmin_server = models.OneToOneField(
        "provisioning.VirtualminServer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="node_deployment",
        verbose_name=_("Virtualmin Server"),
    )

    # Per-deployment max_domains override (defaults based on server size)
    max_domains = models.PositiveIntegerField(
        default=DEFAULT_MAX_DOMAINS,
        verbose_name=_("Max Domains"),
        help_text=_("Maximum domains for this deployment. Default based on server size."),
    )

    # Backup configuration (snapshot at deployment time)
    backup_enabled = models.BooleanField(
        default=True,
        verbose_name=_("Backup Enabled"),
    )

    backup_storage = models.CharField(
        max_length=20,
        default="local",
        verbose_name=_("Backup Storage"),
        help_text=_("'local' or 's3'"),
    )

    # Cost tracking
    total_cost_eur = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        verbose_name=_("Total Cost (EUR)"),
    )

    # Retry tracking
    retry_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Retry Count"),
        help_text=_("Number of retry attempts for this deployment"),
    )

    # Failover tracking (for future automation)
    triggered_by_failover = models.BooleanField(
        default=False,
        verbose_name=_("Triggered by Failover"),
    )

    source_node = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="replacement_nodes",
        verbose_name=_("Source Node"),
        help_text=_("Original node this deployment is replacing (failover scenario)"),
    )

    # Audit
    initiated_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="initiated_node_deployments",
        verbose_name=_("Initiated By"),
    )

    correlation_id = models.UUIDField(
        default=uuid.uuid4,
        verbose_name=_("Correlation ID"),
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Started At"))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Completed At"))
    destroyed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Destroyed At"))

    class Meta:
        verbose_name = _("Node Deployment")
        verbose_name_plural = _("Node Deployments")
        ordering = ["-created_at"]
        # Ensure unique node numbers within env/type/provider/region combination
        unique_together = [["environment", "node_type", "provider", "region", "node_number"]]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["environment", "status"]),
            models.Index(fields=["node_type", "status"]),
            models.Index(fields=["provider", "status"]),
            models.Index(fields=["environment", "node_type", "provider", "region"]),
            models.Index(fields=["initiated_by", "created_at"]),
            models.Index(fields=["triggered_by_failover", "status"]),
        ]

    def __str__(self) -> str:
        return self.hostname

    # Size-based max_domains defaults
    MAX_DOMAINS_BY_MEMORY: ClassVar[list[tuple[int, int]]] = [
        (2, 25),
        (4, 50),
        (8, 100),
        (16, 200),
        (32, 500),
    ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Auto-generate hostname and set max_domains on save"""
        if not self.hostname:
            self.hostname = self.generate_hostname()
        # Set max_domains from size on creation if still at default
        if not self.pk and self.max_domains == DEFAULT_MAX_DOMAINS and self.node_size:
            self.set_max_domains_from_size()
        super().save(*args, **kwargs)

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

    def set_max_domains_from_size(self) -> None:
        """Set max_domains based on node_size memory if not explicitly overridden."""
        if not self.node_size:
            return
        memory_gb = self.node_size.memory_gb
        for threshold, domains in reversed(self.MAX_DOMAINS_BY_MEMORY):
            if memory_gb >= threshold:
                self.max_domains = domains
                return
        self.max_domains = 25  # Minimum default

    @classmethod
    def get_next_node_number(
        cls,
        environment: str,
        node_type: str,
        provider: CloudProvider,
        region: NodeRegion,
    ) -> int:
        """Get the next available node number for the given env/type/provider/region.

        Uses select_for_update() to prevent concurrent allocations. When no rows
        exist yet (first deployment), two concurrent callers could both get 1.
        The caller's unique constraint on (environment, node_type, provider,
        region, node_number) catches this — we retry once on IntegrityError.
        """
        for attempt in range(2):
            try:
                with transaction.atomic():
                    last = (
                        cls.objects.select_for_update()
                        .filter(
                            environment=environment,
                            node_type=node_type,
                            provider=provider,
                            region=region,
                        )
                        .order_by("-node_number")
                        .first()
                    )
                    return (last.node_number + 1) if last else 1
            except IntegrityError:
                if attempt == 0:
                    continue
                raise
        raise IntegrityError("get_next_node_number: exhausted retries")

    @property
    def fqdn(self) -> str:
        """Get fully qualified domain name"""
        if self.dns_zone:
            return f"{self.hostname}.{self.dns_zone}"
        return self.hostname

    @property
    def is_active(self) -> bool:
        """Check if deployment is in an active state"""
        return self.status == "completed"

    @property
    def is_in_progress(self) -> bool:
        """Check if deployment is currently in progress"""
        return self.status in (
            "pending",
            "provisioning_node",
            "configuring_dns",
            "installing_panel",
            "configuring_backups",
            "validating",
            "registering",
        )

    @property
    def is_failed(self) -> bool:
        """Check if deployment has failed"""
        return self.status == "failed"

    @property
    def is_destroyed(self) -> bool:
        """Check if deployment has been destroyed"""
        return self.status in ("destroyed", "destroying")

    @property
    def can_be_destroyed(self) -> bool:
        """Check if deployment can be destroyed"""
        return self.status in ("completed", "failed", "stopped")

    @property
    def can_retry(self) -> bool:
        """Check if deployment can be retried"""
        return self.status == "failed" and self.last_successful_phase != ""

    # Valid state transitions map
    VALID_TRANSITIONS: ClassVar[dict[str, list[str]]] = {
        "pending": ["provisioning_node", "failed"],
        "provisioning_node": ["configuring_dns", "failed"],
        "configuring_dns": ["installing_panel", "failed"],
        "installing_panel": ["configuring_backups", "failed"],
        "configuring_backups": ["validating", "failed"],
        "validating": ["registering", "failed"],
        "registering": ["completed", "failed"],
        "completed": ["stopped", "destroying"],
        "stopped": ["completed", "destroying", "failed"],
        "failed": ["pending", "destroying"],  # Can retry or destroy
        "destroying": ["destroyed", "failed"],
        "destroyed": [],  # Terminal state
    }

    def is_valid_transition(self, new_status: str) -> bool:
        """Check if transitioning to new_status is valid"""
        valid_next_states = self.VALID_TRANSITIONS.get(self.status, [])
        return new_status in valid_next_states

    def transition_to(self, new_status: str, message: str = "") -> None:
        """Transition to a new status with validation"""
        if not self.is_valid_transition(new_status):
            raise ValidationError(_(f"Cannot transition from '{self.status}' to '{new_status}'"))
        self.status = new_status
        if message:
            self.status_message = message
        self.save(update_fields=["status", "status_message", "updated_at"])

    def calculate_running_hours(self) -> float:
        """Calculate hours the node has been running"""

        if not self.started_at:
            return 0.0

        end_time = self.destroyed_at or self.completed_at or timezone.now()
        if self.status in ("pending", "failed"):
            return 0.0

        delta = end_time - self.started_at
        return delta.total_seconds() / 3600

    def estimate_cost(self) -> float:
        """Estimate current cost based on running hours and node size"""
        if not self.node_size:
            return 0.0

        hours = self.calculate_running_hours()
        hourly_rate = float(self.node_size.hourly_cost_eur)
        return round(hours * hourly_rate, 4)


class NodeDeploymentLog(models.Model):
    """Detailed logs for deployment steps"""

    LEVEL_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("debug", _("Debug")),
        ("info", _("Info")),
        ("warning", _("Warning")),
        ("error", _("Error")),
    ]

    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="logs",
        verbose_name=_("Deployment"),
    )

    level = models.CharField(
        max_length=10,
        choices=LEVEL_CHOICES,
        default="info",
        verbose_name=_("Level"),
    )

    phase = models.CharField(
        max_length=50,
        verbose_name=_("Phase"),
        help_text=_("'provision', 'ansible', 'dns', 'backup', etc."),
    )

    message = models.TextField(verbose_name=_("Message"))

    details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Details"),
        help_text=_("Additional structured data"),
    )

    duration_seconds = models.FloatField(
        null=True,
        blank=True,
        verbose_name=_("Duration (seconds)"),
        help_text=_("Phase duration"),
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Node Deployment Log")
        verbose_name_plural = _("Node Deployment Logs")
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["deployment", "level"]),
            models.Index(fields=["deployment", "phase"]),
        ]

    def __str__(self) -> str:
        return f"[{self.level.upper()}] {self.phase}: {self.message[:50]}"


class NodeDeploymentCostRecord(models.Model):
    """Track costs over time for cost analysis"""

    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="cost_records",
        verbose_name=_("Deployment"),
    )

    period_start = models.DateTimeField(verbose_name=_("Period Start"))
    period_end = models.DateTimeField(verbose_name=_("Period End"))

    cost_eur = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        verbose_name=_("Cost (EUR)"),
    )

    # Breakdown
    compute_cost = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        default=0,
        verbose_name=_("Compute Cost"),
    )

    bandwidth_cost = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        default=0,
        verbose_name=_("Bandwidth Cost"),
    )

    storage_cost = models.DecimalField(
        max_digits=10,
        decimal_places=4,
        default=0,
        verbose_name=_("Storage Cost"),
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Node Deployment Cost Record")
        verbose_name_plural = _("Node Deployment Cost Records")
        ordering = ["-period_end"]
        indexes = [
            models.Index(fields=["deployment", "period_start"]),
        ]

    def __str__(self) -> str:
        return f"{self.deployment.hostname}: {self.cost_eur} EUR ({self.period_start.date()})"


class DriftCheck(models.Model):
    """Represents a single drift scan execution for one deployment."""

    CHECK_TYPE_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("cloud", _("Cloud Provider")),
        ("network", _("Network")),
        ("application", _("Application")),
    ]
    STATUS_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("running", _("Running")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
    ]

    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="drift_checks",
        verbose_name=_("Deployment"),
    )
    check_type = models.CharField(max_length=20, choices=CHECK_TYPE_CHOICES, verbose_name=_("Check Type"))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="running", verbose_name=_("Status"))
    started_at = models.DateTimeField(default=timezone.now, verbose_name=_("Started At"))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Completed At"))
    error_message = models.TextField(blank=True, verbose_name=_("Error Message"))
    findings_count = models.PositiveIntegerField(default=0, verbose_name=_("Findings Count"))
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Drift Check")
        verbose_name_plural = _("Drift Checks")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["deployment", "check_type", "-created_at"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"DriftCheck({self.deployment.hostname}, {self.check_type}, {self.status})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        # started_at defaults to timezone.now at field level, so bulk_create works too
        super().save(*args, **kwargs)


class DriftReport(models.Model):
    """Individual drift finding within a check."""

    SEVERITY_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("critical", _("Critical")),
        ("high", _("High")),
        ("moderate", _("Moderate")),
        ("low", _("Low")),
        ("info", _("Info")),
    ]
    CATEGORY_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("server_state", _("Server State")),
        ("network", _("Network")),
        ("firewall", _("Firewall")),
        ("application", _("Application")),
        ("capacity", _("Capacity")),
    ]
    RESOLUTION_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("auto_sync", _("Auto Sync")),
        ("remediated", _("Remediated")),
        ("accepted", _("Accepted")),
        ("ignored", _("Ignored")),
    ]

    drift_check = models.ForeignKey(
        "DriftCheck",
        on_delete=models.CASCADE,
        related_name="reports",
        verbose_name=_("Drift Check"),
    )
    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="drift_reports",
        verbose_name=_("Deployment"),
    )
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, verbose_name=_("Severity"))
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, verbose_name=_("Category"))
    field_name = models.CharField(max_length=100, verbose_name=_("Field Name"))
    expected_value = models.TextField(verbose_name=_("Expected Value"))
    actual_value = models.TextField(verbose_name=_("Actual Value"))
    auto_resolvable = models.BooleanField(default=False, verbose_name=_("Auto Resolvable"))
    resolved = models.BooleanField(default=False, verbose_name=_("Resolved"))
    resolved_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Resolved At"))
    resolved_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_("Resolved By"),
    )
    resolution_type = models.CharField(
        max_length=20, choices=RESOLUTION_CHOICES, blank=True, verbose_name=_("Resolution Type")
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Drift Report")
        verbose_name_plural = _("Drift Reports")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["deployment", "severity", "-created_at"]),
            models.Index(fields=["resolved", "severity"]),
        ]

    def __str__(self) -> str:
        return f"DriftReport({self.deployment.hostname}, {self.field_name}, {self.severity})"


class DriftRemediationRequest(models.Model):
    """Tracks the approval workflow for fixing HIGH/CRITICAL drift."""

    ACTION_TYPE_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("apply_desired", _("Apply Desired State")),
        ("accept_actual", _("Accept Actual State")),
        ("schedule", _("Schedule")),
        ("ignore", _("Ignore")),
    ]
    STATUS_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("pending_approval", _("Pending Approval")),
        ("approved", _("Approved")),
        ("rejected", _("Rejected")),
        ("scheduled", _("Scheduled")),
        ("in_progress", _("In Progress")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
        ("rolled_back", _("Rolled Back")),
        ("rollback_failed", _("Rollback Failed")),
    ]

    report = models.ForeignKey(
        "DriftReport",
        on_delete=models.CASCADE,
        related_name="remediation_requests",
        verbose_name=_("Drift Report"),
    )
    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="remediation_requests",
        verbose_name=_("Deployment"),
    )
    action_type = models.CharField(max_length=20, choices=ACTION_TYPE_CHOICES, verbose_name=_("Action Type"))
    action_details = models.JSONField(default=dict, verbose_name=_("Action Details"))
    requires_approval = models.BooleanField(default=True, verbose_name=_("Requires Approval"))
    requires_restart = models.BooleanField(default=False, verbose_name=_("Requires Restart"))
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending_approval", verbose_name=_("Status")
    )
    requested_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="drift_requests_created",
        verbose_name=_("Requested By"),
    )
    approved_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="drift_requests_approved",
        verbose_name=_("Approved By"),
    )
    approved_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Approved At"))
    rejected_reason = models.TextField(blank=True, verbose_name=_("Rejected Reason"))
    scheduled_for = models.DateTimeField(null=True, blank=True, verbose_name=_("Scheduled For"))
    snapshot_id = models.CharField(max_length=100, blank=True, verbose_name=_("Snapshot ID"))
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Started At"))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Completed At"))
    error_message = models.TextField(blank=True, verbose_name=_("Error Message"))
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("Drift Remediation Request")
        verbose_name_plural = _("Drift Remediation Requests")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["deployment", "status"]),
            models.Index(fields=["scheduled_for"]),
        ]

    def __str__(self) -> str:
        return f"Remediation({self.deployment.hostname}, {self.action_type}, {self.status})"


class DriftSnapshot(models.Model):
    """Tracks cloud snapshots created for rollback safety."""

    SNAPSHOT_TYPE_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("pre_remediation", _("Pre-Remediation")),
        ("scheduled", _("Scheduled")),
        ("manual", _("Manual")),
    ]
    STATUS_CHOICES: ClassVar[list[tuple[str, str | _StrPromise]]] = [
        ("creating", _("Creating")),
        ("available", _("Available")),
        ("restoring", _("Restoring")),
        ("deleted", _("Deleted")),
        ("failed", _("Failed")),
    ]

    deployment = models.ForeignKey(
        NodeDeployment,
        on_delete=models.CASCADE,
        related_name="drift_snapshots",
        verbose_name=_("Deployment"),
    )
    provider_snapshot_id = models.CharField(max_length=100, verbose_name=_("Provider Snapshot ID"))
    snapshot_type = models.CharField(max_length=20, choices=SNAPSHOT_TYPE_CHOICES, verbose_name=_("Snapshot Type"))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="creating", verbose_name=_("Status"))
    size_gb = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, verbose_name=_("Size (GB)"))
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Expires At"))

    class Meta:
        verbose_name = _("Drift Snapshot")
        verbose_name_plural = _("Drift Snapshots")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["deployment", "status"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self) -> str:
        return f"Snapshot({self.deployment.hostname}, {self.snapshot_type}, {self.status})"
