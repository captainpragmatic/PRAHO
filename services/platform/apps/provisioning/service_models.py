"""
Core provisioning models for PRAHO Platform
Service plans, servers, services, and provisioning tasks.
"""

from decimal import Decimal
from typing import Any, ClassVar

from dateutil.relativedelta import relativedelta
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class ServicePlan(models.Model):
    """Hosting service plans/packages"""

    PLAN_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("shared_hosting", _("Shared Web Hosting")),
        ("vps", _("VPS")),
        ("dedicated", _("Dedicated Server")),
        ("cloud", _("Cloud Hosting")),
        ("domain", _("Domain")),
        ("ssl", _("SSL Certificate")),
        ("email", _("Email Hosting")),
        ("backup", _("Backup")),
        ("maintenance", _("Maintenance")),
    )

    # Basic information
    name = models.CharField(max_length=100, verbose_name=_("Plan Name"))
    plan_type = models.CharField(max_length=30, choices=PLAN_TYPE_CHOICES, verbose_name=_("Plan Type"))
    description = models.TextField(blank=True, verbose_name=_("Description"))

    # Pricing (Romanian Lei)
    price_monthly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal("0.00"))],
        verbose_name=_("Monthly Price (RON)"),
    )
    price_quarterly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0.00"))],
        verbose_name=_("Quarterly Price (RON)"),
    )
    price_annual = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0.00"))],
        verbose_name=_("Annual Price (RON)"),
    )

    # Setup/installation fee
    setup_fee = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal("0.00"), verbose_name=_("Setup Fee (RON)")
    )

    # Features/specifications (JSON for flexibility)
    features = models.JSONField(
        default=dict, help_text=_("Technical specifications and features in JSON format"), verbose_name=_("Features")
    )

    # Limits and quotas
    disk_space_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Disk Space (GB)"))
    bandwidth_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Monthly Traffic (GB)"))
    email_accounts = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Email Accounts"))
    databases = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Databases"))
    domains = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Domains"))

    # Server specifications (for VPS/Dedicated)
    cpu_cores = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("CPU Cores"))
    ram_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("RAM (GB)"))

    # Romanian specific
    includes_vat = models.BooleanField(default=False, verbose_name=_("Price Includes VAT"))

    # Availability
    is_active = models.BooleanField(default=True, verbose_name=_("Active"))
    is_public = models.BooleanField(default=True, verbose_name=_("Public on Website"))
    sort_order = models.PositiveIntegerField(default=0, verbose_name=_("Sort Order"))

    # Auto-provisioning
    auto_provision = models.BooleanField(default=False, verbose_name=_("Auto Provision"))
    provisioning_script = models.TextField(blank=True, verbose_name=_("Provisioning Script"))

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "service_plans"
        verbose_name = _("Service Plan")
        verbose_name_plural = _("Service Plans")
        ordering: ClassVar[tuple[str, ...]] = ("plan_type", "sort_order", "price_monthly")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["plan_type", "is_active"]),
            models.Index(fields=["is_public", "is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.get_plan_type_display()})"

    def get_effective_price(self, billing_cycle: str = "monthly") -> Decimal:
        """Get price for specific billing cycle"""
        if billing_cycle == "quarterly" and self.price_quarterly:
            return self.price_quarterly
        elif billing_cycle == "annual" and self.price_annual:
            return self.price_annual
        return self.price_monthly

    def get_monthly_equivalent_price(self, billing_cycle: str = "monthly") -> Decimal:
        """Get monthly equivalent price for comparison"""
        price = self.get_effective_price(billing_cycle)
        if billing_cycle == "quarterly":
            return price / 3
        elif billing_cycle == "annual":
            return price / 12
        return price


class Server(models.Model):
    """Physical/virtual servers for hosting services"""

    SERVER_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("shared", _("Shared Server")),
        ("vps_host", _("VPS Host")),
        ("dedicated", _("Dedicated Server")),
        ("cloud", _("Cloud Node")),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("active", _("Active")),
        ("maintenance", _("Under Maintenance")),
        ("offline", _("Offline")),
        ("decommissioned", _("Decommissioned")),
    )

    # Basic information
    name = models.CharField(max_length=100, verbose_name=_("Server Name"))
    hostname = models.CharField(max_length=255, unique=True, verbose_name=_("Hostname"))
    server_type = models.CharField(max_length=20, choices=SERVER_TYPE_CHOICES, verbose_name=_("Server Type"))

    # Network
    primary_ip = models.GenericIPAddressField(verbose_name=_("Primary IP"))
    secondary_ips = models.JSONField(default=list, blank=True, verbose_name=_("Secondary IPs"))
    location = models.CharField(max_length=100, verbose_name=_("Location"))
    datacenter = models.CharField(max_length=100, verbose_name=_("Datacenter"))

    # Hardware specifications
    cpu_model = models.CharField(max_length=200, verbose_name=_("CPU Model"))
    cpu_cores = models.PositiveIntegerField(verbose_name=_("CPU Cores"))
    ram_gb = models.PositiveIntegerField(verbose_name=_("RAM (GB)"))
    disk_type = models.CharField(max_length=50, verbose_name=_("Disk Type"))  # SSD, HDD, NVMe
    disk_capacity_gb = models.PositiveIntegerField(verbose_name=_("Disk Capacity (GB)"))

    # Status and monitoring
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active", verbose_name=_("Status"))

    # Resource utilization (updated by monitoring)
    cpu_usage_percent = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True, verbose_name=_("CPU Usage (%)")
    )
    ram_usage_percent = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True, verbose_name=_("RAM Usage (%)")
    )
    disk_usage_percent = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True, verbose_name=_("Disk Usage (%)")
    )

    # Limits for resource allocation
    max_services = models.PositiveIntegerField(null=True, blank=True, verbose_name=_("Maximum Services"))

    # Management
    os_type = models.CharField(max_length=100, verbose_name=_("Operating System"))
    control_panel = models.CharField(max_length=100, blank=True, verbose_name=_("Control Panel"))

    # Management API configuration (stored encrypted at rest via service layer)
    management_api_url = models.URLField(blank=True, verbose_name=_("Management API URL"))
    management_api_key = models.TextField(blank=True, default="", verbose_name=_("Encrypted API Key"))
    management_api_secret = models.TextField(blank=True, default="", verbose_name=_("Encrypted API Secret"))
    management_webhook_secret = models.CharField(
        max_length=255, blank=True, default="", verbose_name=_("Webhook Secret for signature verification")
    )

    # Provider information (for cloud servers)
    provider = models.CharField(max_length=100, blank=True, verbose_name=_("Provider"))
    provider_instance_id = models.CharField(max_length=100, blank=True, verbose_name=_("Instance ID"))

    # Cost tracking
    monthly_cost = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal("0.00"), verbose_name=_("Monthly Cost (RON)")
    )

    # Maintenance
    last_maintenance = models.DateTimeField(null=True, blank=True, verbose_name=_("Last Maintenance"))
    next_maintenance = models.DateTimeField(null=True, blank=True, verbose_name=_("Next Maintenance"))

    is_active = models.BooleanField(default=True, verbose_name=_("Active"))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "servers"
        verbose_name = _("Server")
        verbose_name_plural = _("Servers")
        ordering: ClassVar[tuple[str, ...]] = ("location", "name")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["status", "server_type"]),
            models.Index(fields=["location"]),
            models.Index(fields=["primary_ip"]),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.hostname})"

    def get_management_api_credentials(self) -> tuple[str, str]:
        """Return decrypted API credentials (placeholder: values are stored already encrypted)."""
        # In test/dev, these may be empty; gateway will handle missing credentials.
        return self.management_api_key or "", self.management_api_secret or ""

    @property
    def active_services_count(self) -> int:
        """Count of active services on this server"""
        return self.services.filter(status="active").count()

    @property
    def resource_usage_average(self) -> float:
        """Average resource usage across CPU, RAM, disk"""
        usage_values = [self.cpu_usage_percent or 0, self.ram_usage_percent or 0, self.disk_usage_percent or 0]
        return sum(float(v) for v in usage_values) / len(usage_values)

    def can_host_service(self, service_plan: "ServicePlan") -> bool:
        """Check if server can host a new service"""
        if not self.is_active or self.status != "active":
            return False

        if self.max_services and self.active_services_count >= self.max_services:
            return False

        # Check resource requirements
        if service_plan.ram_gb and self.ram_gb < service_plan.ram_gb:
            return False

        return not (service_plan.cpu_cores and self.cpu_cores < service_plan.cpu_cores)


class Service(models.Model):
    """Customer services (hosting accounts, domains, etc.)"""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("provisioning", _("Provisioning")),
        ("active", _("Active")),
        ("suspended", _("Suspended")),
        ("failed", _("Provisioning Failed")),
        ("terminated", _("Terminated")),
        ("expired", _("Expired")),
    )

    BILLING_CYCLE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("monthly", _("Monthly")),
        ("quarterly", _("Quarterly")),
        ("semi_annual", _("Semi-Annual")),
        ("annual", _("Annual")),
    )

    # Basic information
    customer = models.ForeignKey(
        "customers.Customer", on_delete=models.CASCADE, related_name="services", verbose_name=_("Customer")
    )
    service_plan = models.ForeignKey(ServicePlan, on_delete=models.PROTECT, verbose_name=_("Service Plan"))
    server = models.ForeignKey(
        Server, on_delete=models.SET_NULL, null=True, blank=True, related_name="services", verbose_name=_("Server")
    )

    # Service identification
    service_name = models.CharField(max_length=200, verbose_name=_("Service Name"))
    domain = models.CharField(max_length=255, blank=True, verbose_name=_("Primary Domain"))
    username = models.CharField(max_length=100, unique=True, verbose_name=_("System Username"))

    # Billing
    billing_cycle = models.CharField(
        max_length=20, choices=BILLING_CYCLE_CHOICES, default="monthly", verbose_name=_("Billing Cycle")
    )
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name=_("Price (RON)"))
    setup_fee_paid = models.BooleanField(default=False, verbose_name=_("Setup Fee Paid"))

    # Service lifecycle
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending", verbose_name=_("Status"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created At"))
    activated_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Activated At"))
    suspended_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Suspended At"))
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Expires At"))

    # Provisioning details
    provisioning_data = models.JSONField(default=dict, blank=True, verbose_name=_("Provisioning Data"))
    last_provisioning_attempt = models.DateTimeField(null=True, blank=True, verbose_name=_("Last Provisioning Attempt"))
    provisioning_errors = models.TextField(blank=True, verbose_name=_("Provisioning Errors"))
    provisioning_task_id = models.CharField(max_length=100, blank=True, verbose_name=_("Provisioning Task ID"))

    # Resource usage/configuration
    disk_usage_mb = models.PositiveIntegerField(default=0, verbose_name=_("Disk Usage (MB)"))
    bandwidth_usage_mb = models.PositiveIntegerField(default=0, verbose_name=_("Bandwidth Used (MB)"))
    email_accounts_used = models.PositiveIntegerField(default=0, verbose_name=_("Email Accounts Used"))
    databases_used = models.PositiveIntegerField(default=0, verbose_name=_("Databases Used"))

    # Romanian specific
    auto_renew = models.BooleanField(default=True, verbose_name=_("Auto Renew"))

    # Notes
    admin_notes = models.TextField(blank=True, verbose_name=_("Admin Notes"))
    suspension_reason = models.TextField(blank=True, verbose_name=_("Suspension Reason"))

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "services"
        verbose_name = _("Service")
        verbose_name_plural = _("Services")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "status"]),
            models.Index(fields=["server", "status"]),
            models.Index(fields=["status", "expires_at"]),
            models.Index(fields=["domain"]),
            models.Index(fields=["username"]),
            # 🚀 Performance: Auto-renewal processing optimization
            models.Index(fields=["auto_renew", "expires_at", "status"]),
            # 🚀 Performance: Plan usage analytics
            models.Index(fields=["service_plan", "status"]),
            # 🚀 Performance: Billing cycle reporting
            models.Index(fields=["billing_cycle", "status", "-created_at"]),
        )

    def __str__(self) -> str:
        return f"{self.service_name} - {self.customer.get_display_name()}"

    def get_next_billing_date(self) -> Any | None:
        """Calculate next billing date based on cycle"""
        if not self.activated_at:
            return None

        base_date = self.activated_at.date()

        if self.billing_cycle == "monthly":
            return base_date + relativedelta(months=1)
        elif self.billing_cycle == "quarterly":
            return base_date + relativedelta(months=3)
        elif self.billing_cycle == "semi_annual":
            return base_date + relativedelta(months=6)
        elif self.billing_cycle == "annual":
            return base_date + relativedelta(years=1)

        return None

    @property
    def is_overdue(self) -> bool:
        """Check if service payment is overdue"""
        if not self.expires_at:
            return False

        return timezone.now() > self.expires_at

    @property
    def days_until_expiry(self) -> int:
        """Days until service expires"""
        if not self.expires_at:
            return 999999  # Very large number for no expiry

        delta = self.expires_at - timezone.now()
        return max(0, delta.days)

    def suspend(self, reason: str = "") -> None:
        """Suspend service"""
        self.status = "suspended"
        self.suspended_at = timezone.now()
        self.suspension_reason = reason
        self.save(update_fields=["status", "suspended_at", "suspension_reason"])

    def activate(self) -> None:
        """Activate service"""
        self.status = "active"
        if not self.activated_at:
            self.activated_at = timezone.now()
        self.suspended_at = None
        self.suspension_reason = ""
        self.save(update_fields=["status", "activated_at", "suspended_at", "suspension_reason"])

    def requires_hosting_account(self) -> bool:
        """
        Check if this service requires a hosting account (Virtualmin).

        Cross-app integration helper for billing → provisioning triggers.
        """
        # Check if service plan is a hosting type that needs control panel account
        hosting_plan_types = ["shared_hosting", "vps", "dedicated", "reseller"]
        return (
            self.service_plan.plan_type in hosting_plan_types
            and self.status in ["active", "provisioning"]
            and bool(self.domain)  # Must have a domain
        )

    def get_primary_domain(self) -> str | None:
        """
        Get the primary domain for this service.

        Cross-app integration helper for provisioning and domain sync.
        """
        if self.domain:
            return self.domain

        # Check if there are associated domains through ServiceDomain
        try:
            from .relationship_models import ServiceDomain  # noqa: PLC0415

            service_domain = ServiceDomain.objects.filter(service=self, domain_type="primary").first()
            if service_domain:
                return service_domain.full_domain_name
        except ImportError:
            pass

        return None

    def get_customer_membership(self) -> Any | None:
        """
        Get the CustomerMembership for this service's customer.

        Cross-app integration helper for linking services to customer access control.
        """
        try:
            from apps.users.models import CustomerMembership  # noqa: PLC0415

            return CustomerMembership.objects.filter(customer=self.customer, is_primary=True).first()
        except ImportError:
            return None


class ProvisioningTask(models.Model):
    """Automated provisioning tasks queue"""

    TASK_STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("running", _("Running")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
        ("retrying", _("Retrying")),
    )

    TASK_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("create_service", _("Create Service")),
        ("suspend_service", _("Suspend Service")),
        ("unsuspend_service", _("Unsuspend Service")),
        ("terminate_service", _("Terminate Service")),
        ("update_service", _("Update Service")),
        ("backup_service", _("Backup Service")),
    )

    service = models.ForeignKey(
        Service, on_delete=models.CASCADE, related_name="provisioning_tasks", verbose_name=_("Service")
    )

    task_type = models.CharField(max_length=30, choices=TASK_TYPE_CHOICES, verbose_name=_("Task Type"))
    status = models.CharField(max_length=20, choices=TASK_STATUS_CHOICES, default="pending", verbose_name=_("Status"))

    # Task parameters (JSON)
    parameters = models.JSONField(default=dict, blank=True, verbose_name=_("Parameters"))

    # Execution tracking
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Started At"))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Completed At"))

    # Results and errors
    result = models.JSONField(default=dict, blank=True, verbose_name=_("Result"))
    error_message = models.TextField(blank=True, verbose_name=_("Error Message"))

    # Retry logic
    retry_count = models.PositiveIntegerField(default=0, verbose_name=_("Retry Count"))
    max_retries = models.PositiveIntegerField(default=3, verbose_name=_("Max Retries"))
    next_retry_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Next Retry At"))

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_tasks"
        verbose_name = _("Provisioning Task")
        verbose_name_plural = _("Provisioning Tasks")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["service", "task_type"]),
            models.Index(fields=["next_retry_at"]),
            # 🚀 Performance: Failed task retry processing
            models.Index(fields=["status", "next_retry_at"]),
            # 🚀 Performance: Task type analytics and monitoring
            models.Index(fields=["task_type", "status", "-created_at"]),
        )

    def __str__(self) -> str:
        return f"{self.get_task_type_display()} - {self.service.service_name}"

    @property
    def can_retry(self) -> bool:
        """Check if task can be retried"""
        return self.status == "failed" and self.retry_count < self.max_retries

    @property
    def duration_seconds(self) -> int:
        """Task execution duration in seconds"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return 0
