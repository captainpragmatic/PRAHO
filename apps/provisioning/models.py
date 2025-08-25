"""
Service provisioning models for PRAHO Platform
Romanian hosting provider service management and provisioning.
"""

from decimal import Decimal

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class ServicePlan(models.Model):
    """Hosting service plans/packages"""

    PLAN_TYPE_CHOICES = [
        ('shared_hosting', _('Shared Web Hosting')),
        ('vps', _('VPS')),
        ('dedicated', _('Dedicated Server')),
        ('cloud', _('Cloud Hosting')),
        ('domain', _('Domain')),
        ('ssl', _('SSL Certificate')),
        ('email', _('Email Hosting')),
        ('backup', _('Backup')),
        ('maintenance', _('Maintenance')),
    ]

    # Basic information
    name = models.CharField(max_length=100, verbose_name=_('Plan Name'))
    plan_type = models.CharField(
        max_length=30,
        choices=PLAN_TYPE_CHOICES,
        verbose_name=_('Plan Type')
    )
    description = models.TextField(blank=True, verbose_name=_('Description'))

    # Pricing (Romanian Lei)
    price_monthly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        verbose_name=_('Monthly Price (RON)')
    )
    price_quarterly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))],
        verbose_name=_('Quarterly Price (RON)')
    )
    price_annual = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))],
        verbose_name=_('Annual Price (RON)')
    )

    # Setup/installation fee
    setup_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        verbose_name=_('Setup Fee (RON)')
    )

    # Features/specifications (JSON for flexibility)
    features = models.JSONField(
        default=dict,
        help_text=_('Technical specifications and features in JSON format'),
        verbose_name=_('Features')
    )

    # Limits and quotas
    disk_space_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('Disk Space (GB)'))
    bandwidth_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('Monthly Traffic (GB)'))
    email_accounts = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('Email Accounts'))
    databases = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('Databases'))
    domains = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('Domains'))

    # Server specifications (for VPS/Dedicated)
    cpu_cores = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('CPU Cores'))
    ram_gb = models.PositiveIntegerField(null=True, blank=True, verbose_name=_('RAM (GB)'))

    # Romanian specific
    includes_vat = models.BooleanField(default=False, verbose_name=_('Price Includes VAT'))

    # Availability
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    is_public = models.BooleanField(default=True, verbose_name=_('Public on Website'))
    sort_order = models.PositiveIntegerField(default=0, verbose_name=_('Sort Order'))

    # Auto-provisioning
    auto_provision = models.BooleanField(default=False, verbose_name=_('Auto Provision'))
    provisioning_script = models.TextField(blank=True, verbose_name=_('Provisioning Script'))

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'service_plans'
        verbose_name = _('Service Plan')
        verbose_name_plural = _('Service Plans')
        ordering = ['plan_type', 'sort_order', 'price_monthly']
        indexes = [
            models.Index(fields=['plan_type', 'is_active']),
            models.Index(fields=['is_public', 'is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_plan_type_display()})"

    def get_effective_price(self, billing_cycle: str = 'monthly') -> Decimal:
        """Get price for specific billing cycle"""
        if billing_cycle == 'quarterly' and self.price_quarterly:
            return self.price_quarterly
        elif billing_cycle == 'annual' and self.price_annual:
            return self.price_annual
        return self.price_monthly

    def get_monthly_equivalent_price(self, billing_cycle: str = 'monthly') -> Decimal:
        """Get monthly equivalent price for comparison"""
        price = self.get_effective_price(billing_cycle)
        if billing_cycle == 'quarterly':
            return price / 3
        elif billing_cycle == 'annual':
            return price / 12
        return price


class Server(models.Model):
    """Physical/virtual servers for hosting services"""

    SERVER_TYPE_CHOICES = [
        ('shared', _('Shared Server')),
        ('vps_host', _('VPS Host')),
        ('dedicated', _('Dedicated Server')),
        ('cloud', _('Cloud Node')),
    ]

    STATUS_CHOICES = [
        ('active', _('Active')),
        ('maintenance', _('Under Maintenance')),
        ('offline', _('Offline')),
        ('decommissioned', _('Decommissioned')),
    ]

    # Basic information
    name = models.CharField(max_length=100, verbose_name=_('Server Name'))
    hostname = models.CharField(max_length=255, unique=True, verbose_name=_('Hostname'))
    server_type = models.CharField(
        max_length=20,
        choices=SERVER_TYPE_CHOICES,
        verbose_name=_('Server Type')
    )

    # Network
    primary_ip = models.GenericIPAddressField(verbose_name=_('Primary IP'))
    secondary_ips = models.JSONField(default=list, blank=True, verbose_name=_('Secondary IPs'))
    location = models.CharField(max_length=100, verbose_name=_('Location'))
    datacenter = models.CharField(max_length=100, verbose_name=_('Datacenter'))

    # Hardware specifications
    cpu_model = models.CharField(max_length=200, verbose_name=_('CPU Model'))
    cpu_cores = models.PositiveIntegerField(verbose_name=_('CPU Cores'))
    ram_gb = models.PositiveIntegerField(verbose_name=_('RAM (GB)'))
    disk_type = models.CharField(max_length=50, verbose_name=_('Disk Type'))  # SSD, HDD, NVMe
    disk_capacity_gb = models.PositiveIntegerField(verbose_name=_('Disk Capacity (GB)'))

    # Status and monitoring
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        verbose_name=_('Status')
    )

    # Resource utilization (updated by monitoring)
    cpu_usage_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_('CPU Usage (%)')
    )
    ram_usage_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_('RAM Usage (%)')
    )
    disk_usage_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_('Disk Usage (%)')
    )

    # Limits for resource allocation
    max_services = models.PositiveIntegerField(
        null=True,
        blank=True,
        verbose_name=_('Maximum Services')
    )

    # Management
    os_type = models.CharField(max_length=100, verbose_name=_('Operating System'))
    control_panel = models.CharField(max_length=100, blank=True, verbose_name=_('Control Panel'))

    # Provider information (for cloud servers)
    provider = models.CharField(max_length=100, blank=True, verbose_name=_('Provider'))
    provider_instance_id = models.CharField(max_length=100, blank=True, verbose_name=_('Instance ID'))

    # Cost tracking
    monthly_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        verbose_name=_('Monthly Cost (RON)')
    )

    # Maintenance
    last_maintenance = models.DateTimeField(null=True, blank=True, verbose_name=_('Last Maintenance'))
    next_maintenance = models.DateTimeField(null=True, blank=True, verbose_name=_('Next Maintenance'))

    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'servers'
        verbose_name = _('Server')
        verbose_name_plural = _('Servers')
        ordering = ['location', 'name']
        indexes = [
            models.Index(fields=['status', 'server_type']),
            models.Index(fields=['location']),
            models.Index(fields=['primary_ip']),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.hostname})"

    @property
    def active_services_count(self) -> int:
        """Count of active services on this server"""
        return self.services.filter(status='active').count()

    @property
    def resource_usage_average(self) -> float:
        """Average resource usage across CPU, RAM, disk"""
        usage_values = [
            self.cpu_usage_percent or 0,
            self.ram_usage_percent or 0,
            self.disk_usage_percent or 0
        ]
        return sum(float(v) for v in usage_values) / len(usage_values)

    def can_host_service(self, service_plan: ServicePlan) -> bool:
        """Check if server can host a new service"""
        if not self.is_active or self.status != 'active':
            return False

        if self.max_services and self.active_services_count >= self.max_services:
            return False

        # Check resource requirements
        if service_plan.ram_gb and self.ram_gb < service_plan.ram_gb:
            return False

        if service_plan.cpu_cores and self.cpu_cores < service_plan.cpu_cores:
            return False

        return True


class Service(models.Model):
    """Customer services (hosting accounts, domains, etc.)"""

    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('provisioning', _('Provisioning')),
        ('active', _('Active')),
        ('suspended', _('Suspended')),
        ('terminated', _('Terminated')),
        ('expired', _('Expired')),
    ]

    BILLING_CYCLE_CHOICES = [
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
        ('semi_annual', _('Semi-Annual')),
        ('annual', _('Annual')),
    ]

    # Basic information
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.CASCADE,
        related_name='services',
        verbose_name=_('Customer')
    )
    service_plan = models.ForeignKey(
        ServicePlan,
        on_delete=models.PROTECT,
        verbose_name=_('Service Plan')
    )
    server = models.ForeignKey(
        Server,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='services',
        verbose_name='Server'
    )

    # Service identification
    service_name = models.CharField(max_length=200, verbose_name=_('Service Name'))
    domain = models.CharField(max_length=255, blank=True, verbose_name=_('Primary Domain'))
    username = models.CharField(max_length=100, unique=True, verbose_name=_('System Username'))

    # Billing
    billing_cycle = models.CharField(
        max_length=20,
        choices=BILLING_CYCLE_CHOICES,
        default='monthly',
        verbose_name=_('Billing Cycle')
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        verbose_name=_('Price (RON)')
    )
    setup_fee_paid = models.BooleanField(default=False, verbose_name=_('Setup Fee Paid'))

    # Service lifecycle
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        verbose_name=_('Status')
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    activated_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Activated At'))
    suspended_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Suspended At'))
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Expires At'))

    # Provisioning details
    provisioning_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Provisioning Data')
    )
    last_provisioning_attempt = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Last Provisioning Attempt')
    )
    provisioning_errors = models.TextField(blank=True, verbose_name=_('Provisioning Errors'))

    # Resource usage/configuration
    disk_usage_mb = models.PositiveIntegerField(default=0, verbose_name=_('Disk Usage (MB)'))
    bandwidth_usage_mb = models.PositiveIntegerField(default=0, verbose_name=_('Bandwidth Used (MB)'))
    email_accounts_used = models.PositiveIntegerField(default=0, verbose_name=_('Email Accounts Used'))
    databases_used = models.PositiveIntegerField(default=0, verbose_name=_('Databases Used'))

    # Romanian specific
    auto_renew = models.BooleanField(default=True, verbose_name=_('Auto Renew'))

    # Notes
    admin_notes = models.TextField(blank=True, verbose_name=_('Admin Notes'))
    suspension_reason = models.TextField(blank=True, verbose_name=_('Suspension Reason'))

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'services'
        verbose_name = _('Service')
        verbose_name_plural = _('Services')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['server', 'status']),
            models.Index(fields=['status', 'expires_at']),
            models.Index(fields=['domain']),
            models.Index(fields=['username']),
            # 🚀 Performance: Auto-renewal processing optimization
            models.Index(fields=['auto_renew', 'expires_at', 'status']),
            # 🚀 Performance: Plan usage analytics
            models.Index(fields=['service_plan', 'status']),
            # 🚀 Performance: Billing cycle reporting
            models.Index(fields=['billing_cycle', 'status', '-created_at']),
        ]

    def __str__(self) -> str:
        return f"{self.service_name} - {self.customer.get_display_name()}"

    def get_next_billing_date(self):
        """Calculate next billing date based on cycle"""
        if not self.activated_at:
            return None

        from dateutil.relativedelta import relativedelta
        base_date = self.activated_at.date()

        if self.billing_cycle == 'monthly':
            return base_date + relativedelta(months=1)
        elif self.billing_cycle == 'quarterly':
            return base_date + relativedelta(months=3)
        elif self.billing_cycle == 'semi_annual':
            return base_date + relativedelta(months=6)
        elif self.billing_cycle == 'annual':
            return base_date + relativedelta(years=1)

        return None

    @property
    def is_overdue(self) -> bool:
        """Check if service payment is overdue"""
        if not self.expires_at:
            return False

        from django.utils import timezone
        return timezone.now() > self.expires_at

    @property
    def days_until_expiry(self) -> int:
        """Days until service expires"""
        if not self.expires_at:
            return 999999  # Very large number for no expiry

        from django.utils import timezone
        delta = self.expires_at - timezone.now()
        return max(0, delta.days)

    def suspend(self, reason: str = ''):
        """Suspend service"""
        from django.utils import timezone

        self.status = 'suspended'
        self.suspended_at = timezone.now()
        self.suspension_reason = reason
        self.save(update_fields=['status', 'suspended_at', 'suspension_reason'])

    def activate(self):
        """Activate service"""
        from django.utils import timezone

        self.status = 'active'
        if not self.activated_at:
            self.activated_at = timezone.now()
        self.suspended_at = None
        self.suspension_reason = ''
        self.save(update_fields=['status', 'activated_at', 'suspended_at', 'suspension_reason'])


class ProvisioningTask(models.Model):
    """Automated provisioning tasks queue"""

    TASK_STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('running', _('Running')),
        ('completed', _('Completed')),
        ('failed', _('Failed')),
        ('retrying', _('Retrying')),
    ]

    TASK_TYPE_CHOICES = [
        ('create_service', _('Create Service')),
        ('suspend_service', _('Suspend Service')),
        ('unsuspend_service', _('Unsuspend Service')),
        ('terminate_service', _('Terminate Service')),
        ('update_service', _('Update Service')),
        ('backup_service', _('Backup Service')),
    ]

    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='provisioning_tasks',
        verbose_name=_('Service')
    )

    task_type = models.CharField(
        max_length=30,
        choices=TASK_TYPE_CHOICES,
        verbose_name=_('Task Type')
    )
    status = models.CharField(
        max_length=20,
        choices=TASK_STATUS_CHOICES,
        default='pending',
        verbose_name=_('Status')
    )

    # Task parameters (JSON)
    parameters = models.JSONField(default=dict, blank=True, verbose_name=_('Parameters'))

    # Execution tracking
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Started At'))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Completed At'))

    # Results and errors
    result = models.JSONField(default=dict, blank=True, verbose_name=_('Result'))
    error_message = models.TextField(blank=True, verbose_name=_('Error Message'))

    # Retry logic
    retry_count = models.PositiveIntegerField(default=0, verbose_name=_('Retry Count'))
    max_retries = models.PositiveIntegerField(default=3, verbose_name=_('Max Retries'))
    next_retry_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Next Retry At'))

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'provisioning_tasks'
        verbose_name = _('Provisioning Task')
        verbose_name_plural = _('Provisioning Tasks')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['service', 'task_type']),
            models.Index(fields=['next_retry_at']),
            # 🚀 Performance: Failed task retry processing
            models.Index(fields=['status', 'next_retry_at']),
            # 🚀 Performance: Task type analytics and monitoring
            models.Index(fields=['task_type', 'status', '-created_at']),
        ]

    def __str__(self) -> str:
        return f"{self.get_task_type_display()} - {self.service.service_name}"

    @property
    def can_retry(self) -> bool:
        """Check if task can be retried"""
        return (
            self.status == 'failed' and
            self.retry_count < self.max_retries
        )

    @property
    def duration_seconds(self) -> int:
        """Task execution duration in seconds"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return 0


# ===============================================================================
# SERVICE RELATIONSHIPS & DEPENDENCIES
# ===============================================================================

class ServiceRelationship(models.Model):
    """
    🔗 Service relationships and dependencies
    
    Manages complex service hierarchies for hosting packages:
    - Parent-child relationships (VPS → Domain → SSL)
    - Add-on services (Backup, Monitoring, Security)
    - Service dependencies and billing relationships
    """

    RELATIONSHIP_TYPE_CHOICES = [
        ('addon', _('🔧 Add-on Service')),           # Backup, SSL, monitoring
        ('included', _('📦 Included Service')),       # Free subdomain, basic SSL
        ('dependency', _('⚡ Required Dependency')),  # Domain for hosting
        ('upgrade', _('⬆️ Service Upgrade')),         # VPS to dedicated server
        ('bundle', _('🎁 Bundle Component')),         # Part of package deal
    ]

    BILLING_IMPACT_CHOICES = [
        ('separate', _('💳 Billed Separately')),      # Additional charges
        ('included', _('🆓 Included in Parent')),     # No extra cost
        ('discounted', _('💰 Discounted Rate')),      # Reduced pricing
        ('prorated', _('📊 Prorated Billing')),       # Time-based billing
    ]

    # Core relationship
    parent_service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='child_relationships',
        help_text=_("Primary service (e.g., VPS hosting)")
    )
    child_service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='parent_relationships',
        help_text=_("Related service (e.g., domain, SSL, backup)")
    )

    # Relationship configuration
    relationship_type = models.CharField(
        max_length=20,
        choices=RELATIONSHIP_TYPE_CHOICES,
        help_text=_("Type of service relationship")
    )
    billing_impact = models.CharField(
        max_length=20,
        choices=BILLING_IMPACT_CHOICES,
        default='separate',
        help_text=_("How this affects customer billing")
    )

    # Dependency rules
    is_required = models.BooleanField(
        default=False,
        help_text=_("Child service is required for parent to function")
    )
    auto_provision = models.BooleanField(
        default=False,
        help_text=_("Automatically provision child when parent is created")
    )
    cascade_suspend = models.BooleanField(
        default=False,
        help_text=_("Suspend child service when parent is suspended")
    )
    cascade_terminate = models.BooleanField(
        default=False,
        help_text=_("Terminate child service when parent is terminated")
    )

    # Pricing adjustments
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Discount percentage for bundle pricing")
    )
    fixed_discount_cents = models.BigIntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text=_("Fixed discount amount in cents")
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('🔗 Service Relationship')
        verbose_name_plural = _('🔗 Service Relationships')
        unique_together = ('parent_service', 'child_service')
        ordering = ['-created_at']

        indexes = [
            models.Index(
                fields=['parent_service', 'relationship_type'],
                name='service_rel_parent_idx'
            ),
            models.Index(
                fields=['child_service', 'is_required'],
                name='service_rel_child_idx'
            ),
        ]

    def __str__(self):
        return f"{self.parent_service} → {self.child_service} ({self.get_relationship_type_display()})"

    def clean(self):
        """🔍 Validate service relationship"""
        if self.parent_service == self.child_service:
            raise ValidationError(_("Service cannot be related to itself"))

        # Check for circular dependencies
        if self._creates_circular_dependency():
            raise ValidationError(_("This relationship would create a circular dependency"))

    def _creates_circular_dependency(self):
        """🔄 Check for circular dependency chains"""
        visited = set()
        stack = [self.child_service]

        while stack:
            current = stack.pop()
            if current == self.parent_service:
                return True

            if current.id in visited:
                continue
            visited.add(current.id)

            # Add child services to stack
            child_relationships = ServiceRelationship.objects.filter(
                parent_service=current,
                is_active=True
            ).exclude(id=self.id if self.id else None)

            for rel in child_relationships:
                stack.append(rel.child_service)

        return False


# ===============================================================================
# SERVICE DOMAIN BINDING
# ===============================================================================

class ServiceDomain(models.Model):
    """
    🌐 Service-domain binding and DNS management
    
    Links domains to hosting services for:
    - Primary domain assignment
    - Add-on domains on same hosting
    - Subdomain management
    - SSL certificate domain mapping
    """

    DOMAIN_TYPE_CHOICES = [
        ('primary', _('🎯 Primary Domain')),          # Main website domain
        ('addon', _('➕ Add-on Domain')),            # Additional domain on same hosting
        ('subdomain', _('🔗 Subdomain')),            # blog.example.com
        ('redirect', _('↩️ Domain Redirect')),        # Forward to primary domain
        ('parking', _('🅿️ Parked Domain')),          # Placeholder page
    ]

    # Core relationships
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='domains',
        help_text=_("Hosting service for this domain")
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='services',
        help_text=_("Domain assigned to service")
    )

    # Domain configuration
    domain_type = models.CharField(
        max_length=20,
        choices=DOMAIN_TYPE_CHOICES,
        default='primary',
        help_text=_("How domain is used with service")
    )
    subdomain = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Subdomain prefix (e.g., 'blog' for blog.example.com)")
    )

    # DNS and hosting settings
    dns_management = models.BooleanField(
        default=True,
        help_text=_("Manage DNS records for this domain")
    )
    ssl_enabled = models.BooleanField(
        default=False,
        help_text=_("SSL certificate enabled for this domain")
    )
    ssl_type = models.CharField(
        max_length=20,
        choices=[
            ('none', _('No SSL')),
            ('shared', _('Shared SSL')),
            ('dedicated', _('Dedicated SSL')),
            ('wildcard', _('Wildcard SSL')),
        ],
        default='none'
    )

    # Redirect configuration
    redirect_url = models.URLField(
        blank=True,
        help_text=_("Redirect target URL (for redirect type)")
    )
    redirect_type = models.CharField(
        max_length=20,
        choices=[
            ('301', _('301 Permanent')),
            ('302', _('302 Temporary')),
        ],
        default='301',
        blank=True
    )

    # Email configuration
    email_routing = models.BooleanField(
        default=False,
        help_text=_("Handle email for this domain")
    )
    catch_all_email = models.EmailField(
        blank=True,
        help_text=_("Catch-all email address")
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('🌐 Service Domain')
        verbose_name_plural = _('🌐 Service Domains')
        unique_together = ('service', 'domain', 'subdomain')
        ordering = ['-created_at']

        indexes = [
            models.Index(
                fields=['service', 'domain_type'],
                name='service_domain_type_idx'
            ),
            models.Index(
                fields=['domain', 'is_active'],
                name='service_domain_active_idx'
            ),
        ]

    def __str__(self):
        domain_name = self.full_domain_name
        type_display = self.get_domain_type_display()
        return f"{domain_name} ({type_display})"

    @property
    def full_domain_name(self):
        """🌐 Full domain name including subdomain"""
        if self.subdomain:
            return f"{self.subdomain}.{self.domain.name}"
        return self.domain.name

    def clean(self):
        """🔍 Validate service domain configuration"""
        # Validate subdomain format
        if self.subdomain:
            if not self.subdomain.replace('-', '').isalnum():
                raise ValidationError(_("Subdomain contains invalid characters"))

        # Validate redirect configuration
        if self.domain_type == 'redirect' and not self.redirect_url:
            raise ValidationError(_("Redirect domains must have a redirect URL"))


# ===============================================================================
# SERVICE GROUPS & PACKAGES
# ===============================================================================

class ServiceGroup(models.Model):
    """
    📦 Service groups for complex hosting packages
    
    Groups related services for coordinated management:
    - VPS + Domain + SSL packages
    - Multi-server clusters
    - Reseller hosting packages
    - Development/staging environments
    """

    GROUP_TYPE_CHOICES = [
        ('package', _('📦 Hosting Package')),         # VPS + Domain + SSL
        ('cluster', _('🔗 Service Cluster')),         # Load-balanced services
        ('bundle', _('🎁 Product Bundle')),           # Marketing bundle
        ('environment', _('🏗️ Environment')),         # Dev/staging/prod
        ('reseller', _('👥 Reseller Package')),       # Reseller hosting
    ]

    STATUS_CHOICES = [
        ('active', _('🟢 Active')),
        ('suspended', _('🟡 Suspended')),
        ('cancelled', _('🔴 Cancelled')),
        ('pending', _('⏳ Pending Setup')),
    ]

    # Basic information
    name = models.CharField(
        max_length=100,
        help_text=_("Service group name")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Description of service group")
    )

    # Group configuration
    group_type = models.CharField(
        max_length=20,
        choices=GROUP_TYPE_CHOICES,
        help_text=_("Type of service group")
    )
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.CASCADE,
        related_name='service_groups',
        help_text=_("Customer owning this service group")
    )

    # Status and lifecycle
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    # Billing configuration
    billing_cycle = models.CharField(
        max_length=20,
        choices=[
            ('monthly', _('Monthly')),
            ('quarterly', _('Quarterly')),
            ('yearly', _('Yearly')),
            ('one_time', _('One Time')),
        ],
        default='monthly'
    )

    # Group settings
    auto_provision = models.BooleanField(
        default=True,
        help_text=_("Automatically provision all services in group")
    )
    coordinated_billing = models.BooleanField(
        default=True,
        help_text=_("Generate single invoice for all services")
    )

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('📦 Service Group')
        verbose_name_plural = _('📦 Service Groups')
        ordering = ['-created_at']

        indexes = [
            models.Index(
                fields=['customer', 'status'],
                name='service_group_customer_idx'
            ),
            models.Index(
                fields=['group_type', 'status'],
                name='service_group_type_idx'
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_group_type_display()})"

    @property
    def total_services(self):
        """📊 Total number of services in group"""
        return self.members.count()

    @property
    def active_services(self):
        """🟢 Number of active services in group"""
        return self.members.filter(service__status='active').count()


class ServiceGroupMember(models.Model):
    """
    👥 Service group membership and coordination
    
    Manages services within groups with:
    - Order of operations for provisioning
    - Role-based service coordination
    - Custom billing rules per service
    """

    MEMBER_ROLE_CHOICES = [
        ('primary', _('🎯 Primary Service')),         # Main service in group
        ('dependency', _('⚡ Dependency')),           # Required for primary
        ('addon', _('🔧 Add-on')),                   # Optional enhancement
        ('backup', _('💾 Backup Service')),          # Backup/redundancy
    ]

    # Core relationships
    group = models.ForeignKey(
        ServiceGroup,
        on_delete=models.CASCADE,
        related_name='members',
        help_text=_("Service group")
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='group_memberships',
        help_text=_("Service in group")
    )

    # Member configuration
    member_role = models.CharField(
        max_length=20,
        choices=MEMBER_ROLE_CHOICES,
        default='primary',
        help_text=_("Role of service in group")
    )
    provision_order = models.PositiveIntegerField(
        default=1,
        help_text=_("Order for provisioning (1 = first)")
    )

    # Billing overrides
    billing_override = models.BooleanField(
        default=False,
        help_text=_("Override individual service billing")
    )
    custom_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Custom price for this service in group")
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('👥 Service Group Member')
        verbose_name_plural = _('👥 Service Group Members')
        unique_together = ('group', 'service')
        ordering = ['provision_order', 'joined_at']

        indexes = [
            models.Index(
                fields=['group', 'provision_order'],
                name='service_member_order_idx'
            ),
            models.Index(
                fields=['service', 'is_active'],
                name='service_member_active_idx'
            ),
        ]

    def __str__(self):
        return f"{self.service} in {self.group} ({self.get_member_role_display()})"

    @property
    def custom_price(self):
        """💰 Custom price in RON"""
        if self.custom_price_cents:
            return self.custom_price_cents / 100
        return None

    def clean(self):
        """🔍 Validate group membership"""
        # Ensure service belongs to same customer as group
        if self.service.customer != self.group.customer:
            raise ValidationError(_("Service must belong to same customer as group"))
