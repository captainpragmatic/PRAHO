"""
Service relationship and grouping models
Complex service hierarchies, dependencies, and domain binding.
"""

from decimal import Decimal
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class ServiceRelationship(models.Model):
    """
    🔗 Service relationships and dependencies

    Manages complex service hierarchies for hosting packages:
    - Parent-child relationships (VPS → Domain → SSL)
    - Add-on services (Backup, Monitoring, Security)
    - Service dependencies and billing relationships
    """

    RELATIONSHIP_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("addon", _("🔧 Add-on Service")),  # Backup, SSL, monitoring
        ("included", _("📦 Included Service")),  # Free subdomain, basic SSL
        ("dependency", _("⚡ Required Dependency")),  # Domain for hosting
        ("upgrade", _("⬆️ Service Upgrade")),  # VPS to dedicated server
        ("bundle", _("🎁 Bundle Component")),  # Part of package deal
    )

    BILLING_IMPACT_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("separate", _("💳 Billed Separately")),  # Additional charges
        ("included", _("🆓 Included in Parent")),  # No extra cost
        ("discounted", _("💰 Discounted Rate")),  # Reduced pricing
        ("prorated", _("📊 Prorated Billing")),  # Time-based billing
    )

    # Core relationship
    parent_service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.CASCADE,
        related_name="child_relationships",
        help_text=_("Primary service (e.g., VPS hosting)"),
    )
    child_service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.CASCADE,
        related_name="parent_relationships",
        help_text=_("Related service (e.g., domain, SSL, backup)"),
    )

    # Relationship configuration
    relationship_type = models.CharField(
        max_length=20, choices=RELATIONSHIP_TYPE_CHOICES, help_text=_("Type of service relationship")
    )
    billing_impact = models.CharField(
        max_length=20,
        choices=BILLING_IMPACT_CHOICES,
        default="separate",
        help_text=_("How this affects customer billing"),
    )

    # Dependency rules
    is_required = models.BooleanField(default=False, help_text=_("Child service is required for parent to function"))
    auto_provision = models.BooleanField(
        default=False, help_text=_("Automatically provision child when parent is created")
    )
    cascade_suspend = models.BooleanField(default=False, help_text=_("Suspend child service when parent is suspended"))
    cascade_terminate = models.BooleanField(
        default=False, help_text=_("Terminate child service when parent is terminated")
    )

    # Pricing adjustments
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("0.00"),
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_("Discount percentage for bundle pricing"),
    )
    fixed_discount_cents = models.BigIntegerField(
        default=0, validators=[MinValueValidator(0)], help_text=_("Fixed discount amount in cents")
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("🔗 Service Relationship")
        verbose_name_plural = _("🔗 Service Relationships")
        unique_together: ClassVar[list[list[str]]] = [["parent_service", "child_service"]]
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["parent_service", "relationship_type"], name="service_rel_parent_idx"),
            models.Index(fields=["child_service", "is_required"], name="service_rel_child_idx"),
        )

    def __str__(self) -> str:
        return f"{self.parent_service} → {self.child_service} ({self.get_relationship_type_display()})"

    def clean(self) -> None:
        """🔍 Validate service relationship"""
        if self.parent_service == self.child_service:
            raise ValidationError(_("Service cannot be related to itself"))

        # Check for circular dependencies
        if self._creates_circular_dependency():
            raise ValidationError(_("This relationship would create a circular dependency"))

    def _creates_circular_dependency(self) -> bool:
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
            child_relationships = ServiceRelationship.objects.filter(parent_service=current, is_active=True).exclude(
                id=self.id if self.id is not None else None
            )

            # ⚡ PERFORMANCE: Use list extend for better performance than multiple appends
            stack.extend(rel.child_service for rel in child_relationships)

        return False


class ServiceDomain(models.Model):
    """
    🌐 Service-domain binding and DNS management

    Links domains to hosting services for:
    - Primary domain assignment
    - Add-on domains on same hosting
    - Subdomain management
    - SSL certificate domain mapping
    """

    DOMAIN_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("primary", _("🎯 Primary Domain")),  # Main website domain
        ("addon", _("+ Add-on Domain")),  # Additional domain on same hosting
        ("subdomain", _("🔗 Subdomain")),  # blog.example.com
        ("redirect", _("↩️ Domain Redirect")),  # Forward to primary domain
        ("parking", _("🅿️ Parked Domain")),  # Placeholder page
    )

    # Core relationships
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.CASCADE,
        related_name="domains",
        help_text=_("Hosting service for this domain"),
    )
    domain = models.ForeignKey(
        "domains.Domain", on_delete=models.CASCADE, related_name="services", help_text=_("Domain assigned to service")
    )

    # Domain configuration
    domain_type = models.CharField(
        max_length=20, choices=DOMAIN_TYPE_CHOICES, default="primary", help_text=_("How domain is used with service")
    )
    subdomain = models.CharField(
        max_length=100, blank=True, help_text=_("Subdomain prefix (e.g., 'blog' for blog.example.com)")
    )

    # DNS and hosting settings
    dns_management = models.BooleanField(default=True, help_text=_("Manage DNS records for this domain"))
    ssl_enabled = models.BooleanField(default=False, help_text=_("SSL certificate enabled for this domain"))
    ssl_type = models.CharField(
        max_length=20,
        choices=[
            ("none", _("No SSL")),
            ("shared", _("Shared SSL")),
            ("dedicated", _("Dedicated SSL")),
            ("wildcard", _("Wildcard SSL")),
        ],
        default="none",
    )

    # Redirect configuration
    redirect_url = models.URLField(blank=True, help_text=_("Redirect target URL (for redirect type)"))
    redirect_type = models.CharField(
        max_length=20,
        choices=[
            ("301", _("301 Permanent")),
            ("302", _("302 Temporary")),
        ],
        default="301",
        blank=True,
    )

    # Email configuration
    email_routing = models.BooleanField(default=False, help_text=_("Handle email for this domain"))
    catch_all_email = models.EmailField(blank=True, help_text=_("Catch-all email address"))

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("🌐 Service Domain")
        verbose_name_plural = _("🌐 Service Domains")
        unique_together: ClassVar[list[list[str]]] = [["service", "domain", "subdomain"]]
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["service", "domain_type"], name="service_domain_type_idx"),
            models.Index(fields=["domain", "is_active"], name="service_domain_active_idx"),
        )

    def __str__(self) -> str:
        domain_name = self.full_domain_name
        type_display = self.get_domain_type_display()
        return f"{domain_name} ({type_display})"

    @property
    def full_domain_name(self) -> str:
        """🌐 Full domain name including subdomain"""
        if self.subdomain:
            return f"{self.subdomain}.{self.domain.name}"
        return self.domain.name

    def clean(self) -> None:
        """🔍 Validate service domain configuration"""
        # Validate subdomain format
        if self.subdomain and not self.subdomain.replace("-", "").isalnum():
            raise ValidationError(_("Subdomain contains invalid characters"))

        # Validate redirect configuration
        if self.domain_type == "redirect" and not self.redirect_url:
            raise ValidationError(_("Redirect domains must have a redirect URL"))


class ServiceGroup(models.Model):
    """
    📦 Service groups for complex hosting packages

    Groups related services for coordinated management:
    - VPS + Domain + SSL packages
    - Multi-server clusters
    - Reseller hosting packages
    - Development/staging environments
    """

    GROUP_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("package", _("📦 Hosting Package")),  # VPS + Domain + SSL
        ("cluster", _("🔗 Service Cluster")),  # Load-balanced services
        ("bundle", _("🎁 Product Bundle")),  # Marketing bundle
        ("environment", _("🏗️ Environment")),  # Dev/staging/prod
        ("reseller", _("👥 Reseller Package")),  # Reseller hosting
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("active", _("🟢 Active")),
        ("suspended", _("🟡 Suspended")),
        ("cancelled", _("🔴 Cancelled")),
        ("pending", _("⏳ Pending Setup")),
    )

    # Basic information
    name = models.CharField(max_length=100, help_text=_("Service group name"))
    description = models.TextField(blank=True, help_text=_("Description of service group"))

    # Group configuration
    group_type = models.CharField(max_length=20, choices=GROUP_TYPE_CHOICES, help_text=_("Type of service group"))
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="service_groups",
        help_text=_("Customer owning this service group"),
    )

    # Status and lifecycle
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Billing configuration
    billing_cycle = models.CharField(
        max_length=20,
        choices=[
            ("monthly", _("Monthly")),
            ("quarterly", _("Quarterly")),
            ("yearly", _("Yearly")),
            ("one_time", _("One Time")),
        ],
        default="monthly",
    )

    # Group settings
    auto_provision = models.BooleanField(default=True, help_text=_("Automatically provision all services in group"))
    coordinated_billing = models.BooleanField(default=True, help_text=_("Generate single invoice for all services"))

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("📦 Service Group")
        verbose_name_plural = _("📦 Service Groups")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "status"], name="service_group_customer_idx"),
            models.Index(fields=["group_type", "status"], name="service_group_type_idx"),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.get_group_type_display()})"

    @property
    def total_services(self) -> int:
        """📊 Total number of services in group"""
        return self.members.count()

    @property
    def active_services(self) -> int:
        """🟢 Number of active services in group"""
        return self.members.filter(service__status="active").count()


class ServiceGroupMember(models.Model):
    """
    👥 Service group membership and coordination

    Manages services within groups with:
    - Order of operations for provisioning
    - Role-based service coordination
    - Custom billing rules per service
    """

    MEMBER_ROLE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("primary", _("🎯 Primary Service")),  # Main service in group
        ("dependency", _("⚡ Dependency")),  # Required for primary
        ("addon", _("🔧 Add-on")),  # Optional enhancement
        ("backup", _("💾 Backup Service")),  # Backup/redundancy
    )

    # Core relationships
    group = models.ForeignKey(
        ServiceGroup, on_delete=models.CASCADE, related_name="members", help_text=_("Service group")
    )
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.CASCADE,
        related_name="group_memberships",
        help_text=_("Service in group"),
    )

    # Member configuration
    member_role = models.CharField(
        max_length=20, choices=MEMBER_ROLE_CHOICES, default="primary", help_text=_("Role of service in group")
    )
    provision_order = models.PositiveIntegerField(default=1, help_text=_("Order for provisioning (1 = first)"))

    # Billing overrides
    billing_override = models.BooleanField(default=False, help_text=_("Override individual service billing"))
    custom_price_cents = models.BigIntegerField(
        null=True, blank=True, validators=[MinValueValidator(0)], help_text=_("Custom price for this service in group")
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    notes = models.TextField(blank=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("👥 Service Group Member")
        verbose_name_plural = _("👥 Service Group Members")
        unique_together: ClassVar[list[list[str]]] = [["group", "service"]]
        ordering: ClassVar[tuple[str, ...]] = ("provision_order", "joined_at")

        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["group", "provision_order"], name="service_member_order_idx"),
            models.Index(fields=["service", "is_active"], name="service_member_active_idx"),
        )

    def __str__(self) -> str:
        return f"{self.service} in {self.group} ({self.get_member_role_display()})"

    @property
    def custom_price(self) -> float | None:
        """💰 Custom price in RON"""
        if self.custom_price_cents:
            return self.custom_price_cents / 100
        return None

    def clean(self) -> None:
        """🔍 Validate group membership"""
        # Ensure service belongs to same customer as group
        if self.service.customer != self.group.customer:
            raise ValidationError(_("Service must belong to same customer as group"))
