from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

from apps.common.encryption import decrypt_value, encrypt_sensitive_data

# ===============================================================================
# TLD (TOP-LEVEL DOMAIN) MANAGEMENT
# ===============================================================================


class TLD(models.Model):
    """
    🌐 Top-Level Domain configuration and pricing

    Manages TLD definitions, pricing, and registrar assignments:
    - International TLDs: .com, .net, .org
    - Romanian TLDs: .ro, .com.ro
    - European TLDs: .eu
    - Special TLDs: .tech, .online, .site
    """

    # Core TLD information
    extension = models.CharField(max_length=10, unique=True, help_text=_("TLD extension (e.g., 'com', 'ro', 'eu')"))
    description = models.CharField(max_length=200, help_text=_("Human-readable description of TLD"))

    # Pricing (in cents to avoid floating point issues)
    registration_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Registration price in cents (customer pays)")
    )
    renewal_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Renewal price in cents (customer pays)")
    )
    transfer_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Transfer price in cents (customer pays)")
    )

    # Registrar costs (for profit calculation)
    registrar_cost_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], default=0, help_text=_("Cost from registrar in cents")
    )

    # TLD configuration
    min_registration_period = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text=_("Minimum registration period in years"),
    )
    max_registration_period = models.PositiveIntegerField(
        default=10,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text=_("Maximum registration period in years"),
    )

    # Domain features
    whois_privacy_available = models.BooleanField(
        default=True, help_text=_("Whether WHOIS privacy is available for this TLD")
    )
    grace_period_days = models.PositiveIntegerField(
        default=30, help_text=_("Grace period for renewal after expiration")
    )
    redemption_fee_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], default=0, help_text=_("Additional fee for domain redemption")
    )

    # Romanian-specific fields
    requires_local_presence = models.BooleanField(
        default=False, help_text=_("Requires local presence (e.g., .ro domains)")
    )
    special_requirements = models.TextField(blank=True, help_text=_("Special registration requirements"))

    # Status
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False, help_text=_("Show in featured TLD list"))

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_tlds"
        verbose_name = _("🌐 TLD")
        verbose_name_plural = _("🌐 TLDs")
        ordering: ClassVar[tuple[str, ...]] = ("extension",)

    def __str__(self) -> str:
        return f".{self.extension}"

    @property
    def registration_price(self) -> float:
        """💰 Registration price in RON"""
        return self.registration_price_cents / 100

    @property
    def renewal_price(self) -> float:
        """💰 Renewal price in RON"""
        return self.renewal_price_cents / 100

    @property
    def profit_margin_cents(self) -> int:
        """📊 Profit margin in cents"""
        return self.registration_price_cents - self.registrar_cost_cents

    @property
    def profit_margin_percentage(self) -> float:
        """📊 Profit margin as percentage"""
        if self.registrar_cost_cents > 0:
            return (self.profit_margin_cents / self.registrar_cost_cents) * 100
        return 0

    # Signal-related attributes for change tracking
    _original_tld_values: dict[str, str | None] | None = None


# ===============================================================================
# REGISTRAR MANAGEMENT
# ===============================================================================


class Registrar(models.Model):
    """
    🏢 Domain registrar configuration and API management

    Supports multiple registrars for different TLDs:
    - Namecheap: International domains
    - GoDaddy: Backup for international
    - ROTLD: Romanian .ro domains
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("active", _("🟢 Active")),
        ("suspended", _("🟡 Suspended")),
        ("disabled", _("🔴 Disabled")),
    )

    # Basic information
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=100)
    website_url = models.URLField()

    # API configuration
    api_endpoint = models.URLField(help_text=_("Base API endpoint URL"))
    api_username = models.CharField(max_length=100, blank=True)
    api_key = models.CharField(max_length=500, blank=True, help_text=_("AES-256-GCM encrypted"))
    api_secret = models.CharField(max_length=500, blank=True, help_text=_("AES-256-GCM encrypted"))

    # Webhook configuration
    webhook_secret = models.CharField(
        max_length=500, blank=True, help_text=_("AES-256-GCM encrypted — webhook signature verification")
    )
    webhook_endpoint = models.URLField(blank=True, help_text=_("Our webhook endpoint for this registrar"))

    # Operational settings
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    default_nameservers = models.JSONField(default=list, blank=True, help_text=_("Default nameservers for new domains"))

    # Cost tracking
    currency = models.CharField(max_length=3, default="USD")
    monthly_fee_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], default=0, help_text=_("Monthly account fee in cents")
    )

    # Statistics
    total_domains = models.PositiveIntegerField(default=0)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_registrars"
        verbose_name = _("🏢 Registrar")
        verbose_name_plural = _("🏢 Registrars")
        ordering: ClassVar[tuple[str, ...]] = ("name",)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Accept legacy kwargs for backward compatibility with tests."""
        # Only apply transformations when creating new instances, not loading from database
        if kwargs and not (args and len(args) > 1):
            # Handle legacy field names from old test files
            if "api_url" in kwargs:
                kwargs["api_endpoint"] = kwargs.pop("api_url")

            # Handle legacy boolean is_active to status mapping
            if "is_active" in kwargs:
                is_active = kwargs.pop("is_active")
                kwargs["status"] = "active" if is_active else "disabled"

        super().__init__(*args, **kwargs)

    def __str__(self) -> str:
        return self.display_name

    def get_supported_tlds(self) -> QuerySet[TLD]:
        """🌐 Get TLDs supported by this registrar"""
        return TLD.objects.filter(registrar_assignments__registrar=self)

    def get_api_credentials(self) -> tuple[str, str]:
        """Get decrypted API credentials (username, key) for this registrar."""
        return (self.api_username or "", decrypt_value(self.api_key) if self.api_key else "")

    def get_decrypted_api_secret(self) -> str:
        """Get decrypted API secret."""
        return decrypt_value(self.api_secret) if self.api_secret else ""

    def get_decrypted_webhook_secret(self) -> str:
        """Get decrypted webhook secret for signature verification."""
        return decrypt_value(self.webhook_secret) if self.webhook_secret else ""

    def set_encrypted_credentials(self, *, api_key: str = "", api_secret: str = "", webhook_secret: str = "") -> None:
        """Encrypt and store API credentials."""
        if api_key:
            self.api_key = encrypt_sensitive_data(api_key)
        if api_secret:
            self.api_secret = encrypt_sensitive_data(api_secret)
        if webhook_secret:
            self.webhook_secret = encrypt_sensitive_data(webhook_secret)

    # Signal-related attributes for change tracking
    _original_registrar_values: dict[str, str | None] | None = None


# ===============================================================================
# TLD-REGISTRAR ASSIGNMENTS
# ===============================================================================


class TLDRegistrarAssignment(models.Model):
    """
    🔗 Assignment of TLDs to registrars with fallbacks

    Allows multiple registrars per TLD for redundancy:
    - Primary registrar for normal operations
    - Fallback registrars if primary fails
    """

    tld = models.ForeignKey(TLD, on_delete=models.CASCADE, related_name="registrar_assignments")
    registrar = models.ForeignKey(Registrar, on_delete=models.CASCADE, related_name="tld_assignments")

    # Assignment configuration
    is_primary = models.BooleanField(default=False, help_text=_("Primary registrar for this TLD"))
    priority = models.PositiveIntegerField(default=1, help_text=_("Priority order (1 = highest)"))

    # Cost override (if different from TLD default)
    cost_override_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        null=True,
        blank=True,
        help_text=_("Override cost for this registrar-TLD combination"),
    )

    # Status
    is_active = models.BooleanField(default=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_tld_registrar_assignments"
        verbose_name = _("🔗 TLD-Registrar Assignment")
        verbose_name_plural = _("🔗 TLD-Registrar Assignments")
        unique_together: ClassVar[tuple[tuple[str, ...]]] = (("tld", "registrar"),)
        ordering: ClassVar[tuple[str, ...]] = ("tld__extension", "priority")

    def __str__(self) -> str:
        primary = " (Primary)" if self.is_primary else ""
        return f"{self.tld} → {self.registrar}{primary}"


# ===============================================================================
# DOMAIN MANAGEMENT
# ===============================================================================


class Domain(ConcurrentTransitionMixin, models.Model):
    """
    🌍 Complete domain lifecycle management

    Tracks domains from registration through renewal/expiration:
    - Registration and transfer tracking
    - Expiration monitoring and auto-renewal
    - WHOIS privacy and lock status
    - Nameserver management
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("⏳ Pending Registration")),
        ("active", _("🟢 Active")),
        ("expired", _("🔴 Expired")),
        ("suspended", _("🟡 Suspended")),
        ("transfer_in", _("📥 Transfer In Progress")),
        ("transfer_out", _("📤 Transfer Out Progress")),
        ("cancelled", _("❌ Cancelled")),
    )

    # Core domain information
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True, help_text=_("Full domain name (e.g., 'example.com')"))
    tld = models.ForeignKey(TLD, on_delete=models.PROTECT, related_name="domains")
    registrar = models.ForeignKey(Registrar, on_delete=models.PROTECT, related_name="domains")

    # Customer relationship
    customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT, related_name="domains")

    # Domain status and lifecycle
    status = FSMField(max_length=20, choices=STATUS_CHOICES, default="pending", protected=True)
    registered_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    # Registrar information
    registrar_domain_id = models.CharField(max_length=100, blank=True, help_text=_("Domain ID at registrar"))
    epp_code = models.CharField(
        max_length=300, blank=True, help_text=_("AES-256-GCM encrypted EPP/Auth code for transfers")
    )

    # Domain settings
    auto_renew = models.BooleanField(default=True, help_text=_("Automatically renew domain before expiration"))
    whois_privacy = models.BooleanField(default=False, help_text=_("WHOIS privacy protection enabled"))
    locked = models.BooleanField(default=True, help_text=_("Domain lock to prevent unauthorized transfers"))

    # Nameservers
    nameservers = models.JSONField(default=list, blank=True, help_text=_("Current nameservers for domain"))

    # Notifications
    renewal_notices_sent = models.PositiveIntegerField(default=0)
    last_renewal_notice = models.DateTimeField(null=True, blank=True)

    # Costs and billing
    last_paid_amount_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], default=0, help_text=_("Last amount paid for this domain")
    )

    # Metadata
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domains"
        verbose_name = _("🌍 Domain")
        verbose_name_plural = _("🌍 Domains")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

        indexes: ClassVar[tuple[models.Index, ...]] = (
            # Query domains expiring soon
            models.Index(fields=["status", "expires_at"], name="domain_expiring_idx"),
            # Query customer domains
            models.Index(fields=["customer", "-created_at"], name="domain_customer_idx"),
            # Query by registrar
            models.Index(fields=["registrar", "status"], name="domain_registrar_idx"),
            # 🚀 Performance: Auto-renewal processing optimization
            models.Index(fields=["auto_renew", "expires_at", "status"], name="domain_auto_renew_idx"),
            # 🚀 Performance: Registrar management queries
            models.Index(fields=["registrar", "status", "-expires_at"], name="domain_registrar_expiry_idx"),
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=["pending", "active", "expired", "suspended", "transfer_in", "transfer_out", "cancelled"]
                ),
                name="domain_status_valid_values",
            ),
        ]

    def __str__(self) -> str:
        return self.name

    @property
    def days_until_expiry(self) -> int | None:
        """📅 Days until domain expires"""
        if self.expires_at:
            delta = self.expires_at - timezone.now()
            return delta.days
        return None

    @property
    def is_expired(self) -> bool:
        """🔴 Check if domain is expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    def is_expiring_soon(self, days: int = 30) -> bool:
        """⚠️ Check if domain expires within specified days"""
        days_left = self.days_until_expiry
        return days_left is not None and 0 <= days_left <= days

    @property
    def last_paid_amount(self) -> float:
        """💰 Last paid amount in RON"""
        return self.last_paid_amount_cents / 100

    def get_decrypted_epp_code(self) -> str:
        """Get decrypted EPP/Auth code for domain transfers."""
        return decrypt_value(self.epp_code) if self.epp_code else ""

    def set_encrypted_epp_code(self, code: str) -> None:
        """Encrypt and store EPP/Auth code."""
        self.epp_code = encrypt_sensitive_data(code) if code else ""

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[Domain] | None = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        See orders.Order.refresh_from_db for the full explanation.
        """
        fsm_fields = ["status"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @transition(field=status, source=["pending", "transfer_in", "expired", "suspended"], target="active")
    def activate(self) -> None:
        """Activate the domain (after registration, renewal, transfer-in, or unsuspend)."""

    @transition(field=status, source="active", target="expired")
    def expire(self) -> None:
        """Mark domain as expired."""

    @transition(field=status, source="active", target="suspended")
    def suspend(self) -> None:
        """Suspend the domain."""

    @transition(field=status, source="active", target="transfer_out")
    def start_transfer_out(self) -> None:
        """Start outbound transfer."""

    @transition(field=status, source="pending", target="transfer_in")
    def start_transfer_in(self) -> None:
        """Start inbound transfer."""

    @transition(
        field=status,
        source=["pending", "expired", "suspended", "transfer_in", "transfer_out"],
        target="cancelled",
    )
    def cancel(self) -> None:
        """Cancel the domain."""

    def clean(self) -> None:
        """🔍 Validate domain data"""
        if self.name:
            # Basic domain validation
            if not self.name.replace("-", "").replace(".", "").isalnum():
                raise ValidationError(_("Domain name contains invalid characters"))

            # Extract TLD from domain name if not set
            if not self.tld_id and "." in self.name:
                domain_tld = self.name.split(".")[-1].lower()
                try:
                    self.tld = TLD.objects.get(extension=domain_tld)
                except TLD.DoesNotExist:
                    raise ValidationError(_(f"TLD '.{domain_tld}' is not supported")) from None

    # Signal-related attributes for change tracking
    _original_domain_values: dict[str, str | None] | None = None


# ===============================================================================
# DOMAIN OPERATIONS (ASYNC TASK TRACKING)
# ===============================================================================


class DomainOperation(models.Model):
    """Tracks async domain operations submitted to registrar APIs.

    Mirrors the ProvisioningTask pattern from apps/provisioning.
    Two-phase: create record + submit to registrar (phase 1),
    confirm via webhook or polling (phase 2).
    """

    OPERATION_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("transfer_in", _("Transfer In")),
        ("transfer_out", _("Transfer Out")),
        ("nameserver_update", _("Nameserver Update")),
        ("lock_update", _("Lock Status Update")),
        ("whois_update", _("WHOIS Privacy Update")),
        ("domain_info", _("Domain Info Sync")),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("submitted", _("Submitted to Registrar")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
        ("retrying", _("Retrying")),
        ("cancelled", _("Cancelled")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="operations")
    registrar = models.ForeignKey(Registrar, on_delete=models.PROTECT, related_name="domain_operations")

    operation_type = models.CharField(max_length=30, choices=OPERATION_TYPE_CHOICES)
    state = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Operation parameters (e.g. nameservers list, lock state, epp_code)
    parameters = models.JSONField(default=dict, blank=True)

    # Execution tracking
    submitted_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Registrar reference (e.g. transfer ID, operation ID)
    registrar_operation_id = models.CharField(max_length=200, blank=True)

    # Results and errors
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    # Retry logic
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_operations"
        verbose_name = _("Domain Operation")
        verbose_name_plural = _("Domain Operations")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["state", "created_at"], name="domainop_state_created_idx"),
            models.Index(fields=["domain", "operation_type"], name="domainop_domain_type_idx"),
            models.Index(fields=["state", "next_retry_at"], name="domainop_retry_idx"),
        )

    def __str__(self) -> str:
        return f"{self.get_operation_type_display()} {self.domain.name} [{self.state}]"

    @property
    def can_retry(self) -> bool:
        return self.state == "failed" and self.retry_count < self.max_retries

    @property
    def duration_seconds(self) -> int:
        if self.submitted_at and self.completed_at:
            return int((self.completed_at - self.submitted_at).total_seconds())
        return 0

    def mark_submitted(self, registrar_operation_id: str = "") -> None:
        """Transition to submitted state."""
        self.state = "submitted"
        self.submitted_at = timezone.now()
        self.registrar_operation_id = registrar_operation_id

    def mark_completed(self, result_data: dict[str, Any] | None = None) -> None:
        """Transition to completed state."""
        self.state = "completed"
        self.completed_at = timezone.now()
        if result_data:
            self.result = result_data

    def mark_failed(self, error: str) -> None:
        """Transition to failed state."""
        self.state = "failed"
        self.error_message = error


# ===============================================================================
# DOMAIN ORDER ITEMS
# ===============================================================================


class DomainOrderItem(models.Model):
    """
    🛒 Domain items in e-commerce orders

    Links domains to the order system for:
    - Domain registrations in cart
    - Domain renewals and transfers
    - Multi-year purchases
    """

    ACTION_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("register", _("🆕 Register")),
        ("renew", _("🔄 Renew")),
        ("transfer", _("📥 Transfer")),
    )

    # Order relationship
    order = models.ForeignKey("orders.Order", on_delete=models.CASCADE, related_name="domain_items")

    # Domain information
    domain_name = models.CharField(max_length=255, help_text=_("Domain name to register/renew/transfer"))
    tld = models.ForeignKey(TLD, on_delete=models.PROTECT, related_name="order_items")

    # Action and pricing
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    years = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        default=1,
        help_text=_("Registration/renewal period in years"),
    )

    # Pricing (at time of order)
    unit_price_cents = models.BigIntegerField(validators=[MinValueValidator(0)], help_text=_("Price per year in cents"))
    total_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Total price for all years")
    )

    # Domain options
    whois_privacy = models.BooleanField(default=False, help_text=_("Include WHOIS privacy protection"))
    auto_renew = models.BooleanField(default=True, help_text=_("Enable auto-renewal for this domain"))

    # Transfer-specific fields
    epp_code = models.CharField(
        max_length=300, blank=True, help_text=_("AES-256-GCM encrypted EPP/Auth code for domain transfer")
    )

    # Linked domain (after processing)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="order_items",
        help_text=_("Created/renewed domain after order processing"),
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Private attributes for signal handling
    _original_order_item_values: dict[str, Any] | None = None

    class Meta:
        db_table = "domain_order_items"
        verbose_name = _("🛒 Domain Order Item")
        verbose_name_plural = _("🛒 Domain Order Items")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

    def __str__(self) -> str:
        action_display = self.get_action_display()
        return f"{action_display} {self.domain_name} ({self.years} years)"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """💾 Calculate total price on save"""
        if self.unit_price_cents and self.years:
            self.total_price_cents = self.unit_price_cents * self.years
        super().save(*args, **kwargs)

    @property
    def unit_price(self) -> float:
        """💰 Unit price in RON"""
        return self.unit_price_cents / 100

    @property
    def total_price(self) -> float:
        """💰 Total price in RON"""
        return self.total_price_cents / 100

    def get_decrypted_epp_code(self) -> str:
        """Get decrypted EPP/Auth code for domain transfer."""
        return decrypt_value(self.epp_code) if self.epp_code else ""

    def set_encrypted_epp_code(self, code: str) -> None:
        """Encrypt and store EPP/Auth code."""
        self.epp_code = encrypt_sensitive_data(code) if code else ""
