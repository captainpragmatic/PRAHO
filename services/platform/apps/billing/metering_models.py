"""
Usage Metering models for PRAHO Platform
Comprehensive usage-based billing with metering, aggregation, and rating.

Based on industry best practices for SaaS usage-based billing:
- Event-driven metering with idempotency
- Flexible aggregation (sum, count, max, last, unique)
- Tiered and volume-based pricing
- Real-time usage tracking and alerts
- Stripe Meter integration support
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from decimal import Decimal
from typing import Any, ClassVar

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.db.models import F, Sum
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .currency_models import Currency

logger = logging.getLogger(__name__)


# ===============================================================================
# USAGE METER DEFINITIONS
# ===============================================================================


class UsageMeter(models.Model):
    """
    Definition of a billable usage metric.

    Examples:
    - disk_usage_gb: Disk space used in GB
    - bandwidth_gb: Monthly bandwidth transfer in GB
    - api_requests: Number of API requests
    - email_sent: Number of emails sent
    - cpu_hours: CPU hours consumed
    - storage_objects: Number of storage objects

    Aggregation types:
    - sum: Total of all values (e.g., bandwidth, API calls)
    - count: Number of events (e.g., emails sent)
    - max: Maximum value in period (e.g., peak concurrent users)
    - last: Last reported value (e.g., current disk usage)
    - unique: Unique count (e.g., unique active users)
    """

    AGGREGATION_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("sum", _("Sum")),
        ("count", _("Count")),
        ("max", _("Maximum")),
        ("last", _("Last Value")),
        ("unique", _("Unique Count")),
    )

    UNIT_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        # Data units
        ("bytes", _("Bytes")),
        ("kb", _("Kilobytes")),
        ("mb", _("Megabytes")),
        ("gb", _("Gigabytes")),
        ("tb", _("Terabytes")),
        # Time units
        ("seconds", _("Seconds")),
        ("minutes", _("Minutes")),
        ("hours", _("Hours")),
        # Count units
        ("count", _("Count")),
        ("requests", _("Requests")),
        ("emails", _("Emails")),
        ("messages", _("Messages")),
        # Compute units
        ("cpu_hours", _("CPU Hours")),
        ("gpu_hours", _("GPU Hours")),
        # Custom
        ("custom", _("Custom Unit")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Meter identification
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Internal meter name (e.g., 'disk_usage_gb', 'api_requests')")
    )
    display_name = models.CharField(
        max_length=200,
        help_text=_("Human-readable name (e.g., 'Disk Space Usage')")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Detailed description of what this meter tracks")
    )

    # Stripe integration
    stripe_meter_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Stripe Meter ID for external billing sync")
    )
    stripe_meter_event_name = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Event name configured in Stripe Meter")
    )

    # Aggregation configuration
    aggregation_type = models.CharField(
        max_length=20,
        choices=AGGREGATION_CHOICES,
        default="sum",
        help_text=_("How to aggregate usage events over billing period")
    )

    # Units
    unit = models.CharField(
        max_length=20,
        choices=UNIT_CHOICES,
        default="count",
        help_text=_("Unit of measurement")
    )
    unit_display = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Custom unit display name (e.g., 'GB', 'requests')")
    )

    # Decimal precision
    decimal_places = models.PositiveSmallIntegerField(
        default=2,
        validators=[MaxValueValidator(8)],
        help_text=_("Decimal places for usage values")
    )

    # Rounding
    ROUNDING_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("none", _("No Rounding")),
        ("up", _("Round Up")),
        ("down", _("Round Down")),
        ("nearest", _("Round to Nearest")),
    )
    rounding_mode = models.CharField(
        max_length=10,
        choices=ROUNDING_CHOICES,
        default="up",
        help_text=_("How to round usage for billing (up favors provider)")
    )
    rounding_increment = models.DecimalField(
        max_digits=12,
        decimal_places=6,
        default=Decimal("1"),
        help_text=_("Minimum billable increment (e.g., 0.001 for GB)")
    )

    # Hosting-specific meter types
    METER_CATEGORY_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("storage", _("Storage")),
        ("bandwidth", _("Bandwidth/Transfer")),
        ("compute", _("Compute Resources")),
        ("email", _("Email")),
        ("database", _("Database")),
        ("api", _("API Usage")),
        ("domain", _("Domains")),
        ("ssl", _("SSL Certificates")),
        ("backup", _("Backups")),
        ("other", _("Other")),
    )
    category = models.CharField(
        max_length=20,
        choices=METER_CATEGORY_CHOICES,
        default="other",
        help_text=_("Category for grouping and display")
    )

    # Configuration
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this meter is actively collecting events")
    )
    is_billable = models.BooleanField(
        default=True,
        help_text=_("Whether usage from this meter generates charges")
    )

    # Event processing
    event_grace_period_hours = models.PositiveIntegerField(
        default=24,
        help_text=_("Hours in past to accept late events")
    )

    # Metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional meter configuration")
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usage_meters"
        verbose_name = _("Usage Meter")
        verbose_name_plural = _("Usage Meters")
        ordering = ("category", "name")
        indexes = (
            models.Index(fields=["name"]),
            models.Index(fields=["category", "is_active"]),
            models.Index(fields=["stripe_meter_id"]),
        )

    def __str__(self) -> str:
        return f"{self.display_name} ({self.name})"

    def get_unit_display_text(self) -> str:
        """Get the display text for the unit"""
        if self.unit_display:
            return self.unit_display
        return self.get_unit_display()


class UsageEvent(models.Model):
    """
    Individual usage event record.

    Events are immutable once created. Each event represents a single
    billable occurrence (e.g., 1 API request, 0.5 GB bandwidth used).

    Idempotency is enforced via the idempotency_key field to prevent
    duplicate billing from retried submissions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Event identification
    meter = models.ForeignKey(
        UsageMeter,
        on_delete=models.PROTECT,
        related_name="events",
        help_text=_("Which meter this event belongs to")
    )
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="usage_events",
        help_text=_("Customer who generated this usage")
    )
    subscription = models.ForeignKey(
        "billing.Subscription",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_events",
        help_text=_("Subscription this usage is billed against")
    )
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_events",
        help_text=_("Service that generated this usage")
    )

    # Idempotency
    idempotency_key = models.CharField(
        max_length=255,
        db_index=True,
        help_text=_("Unique key to prevent duplicate event processing")
    )

    # Event data
    value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        help_text=_("Usage value (interpretation depends on meter aggregation)")
    )

    # Timestamps
    timestamp = models.DateTimeField(
        db_index=True,
        help_text=_("When the usage occurred (may differ from created_at)")
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # Event metadata for debugging and detailed tracking
    properties = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional event properties (e.g., endpoint, resource_id)")
    )

    # Source tracking
    source = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Source system (e.g., 'virtualmin', 'api_gateway', 'manual')")
    )
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=_("IP address of event source")
    )

    # Processing status
    is_processed = models.BooleanField(
        default=False,
        help_text=_("Whether event has been included in aggregation")
    )
    processed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When event was processed into aggregation")
    )
    aggregation = models.ForeignKey(
        "billing.UsageAggregation",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="events",
        help_text=_("Aggregation record this event was processed into")
    )

    class Meta:
        db_table = "usage_events"
        verbose_name = _("Usage Event")
        verbose_name_plural = _("Usage Events")
        ordering = ("-timestamp",)
        # Enforce idempotency at database level
        constraints = [
            models.UniqueConstraint(
                fields=["meter", "customer", "idempotency_key"],
                name="unique_usage_event_idempotency"
            ),
        ]
        indexes = (
            models.Index(fields=["customer", "-timestamp"]),
            models.Index(fields=["meter", "-timestamp"]),
            models.Index(fields=["subscription", "-timestamp"]),
            models.Index(fields=["service", "-timestamp"]),
            models.Index(fields=["is_processed", "-timestamp"]),
            models.Index(fields=["meter", "customer", "timestamp"]),
            # For aggregation queries
            models.Index(
                fields=["meter", "customer", "is_processed"],
                name="usage_evt_pending_agg"
            ),
        )

    def __str__(self) -> str:
        return f"{self.meter.name}: {self.value} @ {self.timestamp}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        # Generate idempotency key if not provided
        if not self.idempotency_key:
            self.idempotency_key = self.generate_idempotency_key()
        super().save(*args, **kwargs)

    def generate_idempotency_key(self) -> str:
        """Generate a unique idempotency key based on event properties"""
        key_parts = [
            str(self.meter_id),
            str(self.customer_id),
            str(self.timestamp.isoformat()),
            str(self.value),
            self.source or "",
            str(self.properties),
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:64]


# ===============================================================================
# USAGE AGGREGATION
# ===============================================================================


class UsageAggregation(models.Model):
    """
    Aggregated usage for a billing period.

    Events are aggregated into these records for efficient billing calculations.
    Each record represents total usage for one meter/customer/period combination.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Aggregation scope
    meter = models.ForeignKey(
        UsageMeter,
        on_delete=models.PROTECT,
        related_name="aggregations"
    )
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="usage_aggregations"
    )
    subscription = models.ForeignKey(
        "billing.Subscription",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_aggregations"
    )
    billing_cycle = models.ForeignKey(
        "billing.BillingCycle",
        on_delete=models.CASCADE,
        related_name="usage_aggregations",
        help_text=_("Billing cycle this aggregation belongs to")
    )

    # Period definition
    period_start = models.DateTimeField(
        help_text=_("Start of aggregation period")
    )
    period_end = models.DateTimeField(
        help_text=_("End of aggregation period")
    )

    # Aggregated values
    total_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        default=Decimal("0"),
        help_text=_("Aggregated usage value for the period")
    )
    event_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of events aggregated")
    )

    # For unique aggregation
    unique_values = models.JSONField(
        default=list,
        blank=True,
        help_text=_("Set of unique values for unique-count aggregation")
    )

    # For max aggregation
    max_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        null=True,
        blank=True,
        help_text=_("Maximum value seen in period (for max aggregation)")
    )

    # For last aggregation
    last_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        null=True,
        blank=True,
        help_text=_("Most recent value (for last aggregation)")
    )
    last_value_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp of last value")
    )

    # Billing calculation
    billable_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        default=Decimal("0"),
        help_text=_("Final billable amount after rounding")
    )
    included_allowance = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        default=Decimal("0"),
        help_text=_("Usage included in subscription (no charge)")
    )
    overage_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        default=Decimal("0"),
        help_text=_("Usage above included allowance (billable)")
    )

    # Charge calculation (populated by rating engine)
    charge_cents = models.BigIntegerField(
        default=0,
        help_text=_("Calculated charge in cents")
    )
    charge_calculated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When charge was last calculated")
    )

    # Status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("accumulating", _("Accumulating")),
        ("pending_rating", _("Pending Rating")),
        ("rated", _("Rated")),
        ("invoiced", _("Invoiced")),
        ("finalized", _("Finalized")),
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="accumulating"
    )

    # Invoice link
    invoice_line = models.ForeignKey(
        "billing.InvoiceLine",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_aggregations",
        help_text=_("Invoice line generated from this aggregation")
    )

    # Stripe sync
    stripe_usage_record_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Stripe usage record ID for reconciliation")
    )
    stripe_synced_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When usage was synced to Stripe")
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "usage_aggregations"
        verbose_name = _("Usage Aggregation")
        verbose_name_plural = _("Usage Aggregations")
        ordering = ("-period_start",)
        constraints = [
            models.UniqueConstraint(
                fields=["meter", "customer", "billing_cycle"],
                name="unique_meter_customer_cycle"
            ),
        ]
        indexes = (
            models.Index(fields=["customer", "-period_start"]),
            models.Index(fields=["meter", "status"]),
            models.Index(fields=["billing_cycle", "status"]),
            models.Index(fields=["status", "-period_start"]),
            # For invoice generation queries
            models.Index(
                fields=["status", "customer"],
                condition=models.Q(status="rated"),
                name="usage_agg_ready_invoice"
            ),
        )

    def __str__(self) -> str:
        return f"{self.meter.name} - {self.customer} ({self.period_start.date()} to {self.period_end.date()})"

    @property
    def charge(self) -> Decimal:
        """Return charge as Decimal"""
        return Decimal(self.charge_cents) / 100

    def recalculate_from_events(self) -> None:
        """Recalculate aggregation from underlying events"""
        events = self.events.all()

        if self.meter.aggregation_type == "sum":
            self.total_value = events.aggregate(total=Sum("value"))["total"] or Decimal("0")
        elif self.meter.aggregation_type == "count":
            self.total_value = Decimal(events.count())
        elif self.meter.aggregation_type == "max":
            from django.db.models import Max
            result = events.aggregate(max_val=Max("value"))
            self.max_value = result["max_val"]
            self.total_value = self.max_value or Decimal("0")
        elif self.meter.aggregation_type == "last":
            last_event = events.order_by("-timestamp").first()
            if last_event:
                self.last_value = last_event.value
                self.last_value_at = last_event.timestamp
                self.total_value = self.last_value
        elif self.meter.aggregation_type == "unique":
            unique_vals = list(events.values_list("value", flat=True).distinct())
            self.unique_values = [str(v) for v in unique_vals]
            self.total_value = Decimal(len(unique_vals))

        self.event_count = events.count()
        self.save()


# ===============================================================================
# SUBSCRIPTION & BILLING CYCLE MODELS
# ===============================================================================


class Subscription(models.Model):
    """
    Customer subscription to a service plan with usage-based components.

    Combines fixed recurring charges with metered usage billing.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("trialing", _("Trialing")),
        ("active", _("Active")),
        ("past_due", _("Past Due")),
        ("paused", _("Paused")),
        ("canceled", _("Canceled")),
        ("expired", _("Expired")),
    )

    BILLING_INTERVAL_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("monthly", _("Monthly")),
        ("quarterly", _("Quarterly")),
        ("semi_annual", _("Semi-Annual")),
        ("annual", _("Annual")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Core relationships
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="subscriptions"
    )
    service_plan = models.ForeignKey(
        "provisioning.ServicePlan",
        on_delete=models.PROTECT,
        related_name="subscriptions"
    )
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subscriptions",
        help_text=_("Linked provisioned service")
    )

    # Stripe integration
    stripe_subscription_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text=_("Stripe Subscription ID")
    )
    stripe_customer_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Stripe Customer ID")
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="active"
    )

    # Billing configuration
    billing_interval = models.CharField(
        max_length=20,
        choices=BILLING_INTERVAL_CHOICES,
        default="monthly"
    )
    currency = models.ForeignKey(
        Currency,
        on_delete=models.PROTECT,
        help_text=_("Billing currency")
    )

    # Pricing
    base_price_cents = models.BigIntegerField(
        default=0,
        help_text=_("Fixed recurring charge per billing period")
    )

    # Lifecycle dates
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription became active")
    )
    trial_ends_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When trial period ends")
    )
    current_period_start = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Start of current billing period")
    )
    current_period_end = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("End of current billing period")
    )
    canceled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription was canceled")
    )
    cancel_at_period_end = models.BooleanField(
        default=False,
        help_text=_("Cancel at end of current period (not immediately)")
    )
    ended_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription fully ended")
    )

    # Payment
    payment_method = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Default payment method for this subscription")
    )
    auto_renew = models.BooleanField(
        default=True,
        help_text=_("Automatically renew at period end")
    )

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "subscriptions"
        verbose_name = _("Subscription")
        verbose_name_plural = _("Subscriptions")
        ordering = ("-created_at",)
        indexes = (
            models.Index(fields=["customer", "status"]),
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["stripe_subscription_id"]),
            models.Index(fields=["current_period_end", "status"]),
            models.Index(fields=["service_plan", "status"]),
        )

    def __str__(self) -> str:
        return f"{self.customer} - {self.service_plan.name} ({self.status})"

    @property
    def base_price(self) -> Decimal:
        """Return base price as Decimal"""
        return Decimal(self.base_price_cents) / 100

    @property
    def is_active(self) -> bool:
        """Check if subscription is active or trialing"""
        return self.status in ("active", "trialing")

    def get_current_billing_cycle(self) -> "BillingCycle | None":
        """Get the current billing cycle for this subscription"""
        return self.billing_cycles.filter(
            period_start__lte=timezone.now(),
            period_end__gt=timezone.now()
        ).first()


class SubscriptionItem(models.Model):
    """
    Individual metered component of a subscription.

    Links a subscription to a usage meter with pricing configuration.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="items"
    )
    meter = models.ForeignKey(
        UsageMeter,
        on_delete=models.PROTECT,
        related_name="subscription_items"
    )

    # Stripe integration
    stripe_subscription_item_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Stripe Subscription Item ID")
    )
    stripe_price_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Stripe Price ID for this metered item")
    )

    # Included allowance (from plan)
    included_quantity = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        default=Decimal("0"),
        help_text=_("Quantity included in base subscription (no extra charge)")
    )

    # Pricing tier reference
    pricing_tier = models.ForeignKey(
        "billing.PricingTier",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subscription_items",
        help_text=_("Pricing tier for overage charges")
    )

    # Override pricing (if not using tier)
    unit_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        help_text=_("Override price per unit in cents")
    )

    # Configuration
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "subscription_items"
        verbose_name = _("Subscription Item")
        verbose_name_plural = _("Subscription Items")
        constraints = [
            models.UniqueConstraint(
                fields=["subscription", "meter"],
                name="unique_subscription_meter"
            ),
        ]
        indexes = (
            models.Index(fields=["subscription", "is_active"]),
            models.Index(fields=["meter", "is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.subscription} - {self.meter.name}"

    @property
    def unit_price(self) -> Decimal | None:
        """Return unit price as Decimal"""
        if self.unit_price_cents is not None:
            return Decimal(self.unit_price_cents) / 100
        return None


class BillingCycle(models.Model):
    """
    A single billing period for a subscription.

    Tracks the complete lifecycle of a billing period from open to invoiced.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("upcoming", _("Upcoming")),
        ("active", _("Active")),
        ("closing", _("Closing")),
        ("closed", _("Closed")),
        ("invoiced", _("Invoiced")),
        ("finalized", _("Finalized")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="billing_cycles"
    )

    # Period
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()

    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="upcoming"
    )

    # Totals (calculated during closing)
    base_charge_cents = models.BigIntegerField(
        default=0,
        help_text=_("Fixed subscription charge for this period")
    )
    usage_charge_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total usage-based charges for this period")
    )
    discount_cents = models.BigIntegerField(
        default=0,
        help_text=_("Discounts applied")
    )
    credit_applied_cents = models.BigIntegerField(
        default=0,
        help_text=_("Customer credit applied")
    )
    tax_cents = models.BigIntegerField(
        default=0,
        help_text=_("Tax amount")
    )
    total_cents = models.BigIntegerField(
        default=0,
        help_text=_("Total amount due for this cycle")
    )

    # Invoice
    invoice = models.ForeignKey(
        "billing.Invoice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="billing_cycles"
    )

    # Processing timestamps
    closed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When cycle was closed for new events")
    )
    invoiced_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When invoice was generated")
    )
    finalized_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When cycle was fully finalized")
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "billing_cycles"
        verbose_name = _("Billing Cycle")
        verbose_name_plural = _("Billing Cycles")
        ordering = ("-period_start",)
        constraints = [
            models.UniqueConstraint(
                fields=["subscription", "period_start"],
                name="unique_subscription_period"
            ),
        ]
        indexes = (
            models.Index(fields=["subscription", "-period_start"]),
            models.Index(fields=["status", "period_end"]),
            models.Index(fields=["status", "-period_start"]),
        )

    def __str__(self) -> str:
        return f"{self.subscription} - {self.period_start.date()} to {self.period_end.date()}"

    @property
    def base_charge(self) -> Decimal:
        return Decimal(self.base_charge_cents) / 100

    @property
    def usage_charge(self) -> Decimal:
        return Decimal(self.usage_charge_cents) / 100

    @property
    def discount(self) -> Decimal:
        return Decimal(self.discount_cents) / 100

    @property
    def credit_applied(self) -> Decimal:
        return Decimal(self.credit_applied_cents) / 100

    @property
    def tax(self) -> Decimal:
        return Decimal(self.tax_cents) / 100

    @property
    def total(self) -> Decimal:
        return Decimal(self.total_cents) / 100

    @property
    def is_current(self) -> bool:
        """Check if this is the current billing period"""
        now = timezone.now()
        return self.period_start <= now < self.period_end

    def close(self) -> None:
        """Close the billing cycle for new events"""
        self.status = "closed"
        self.closed_at = timezone.now()
        self.save(update_fields=["status", "closed_at", "updated_at"])


# ===============================================================================
# PRICING MODELS
# ===============================================================================


class PricingTier(models.Model):
    """
    Tiered pricing configuration for usage-based billing.

    Supports:
    - Volume pricing: Rate based on total volume (all units same price)
    - Graduated/Tiered pricing: Different rates for different volume ranges
    - Package pricing: Fixed price for a package of units
    """

    PRICING_MODEL_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("per_unit", _("Per Unit")),
        ("volume", _("Volume")),
        ("graduated", _("Graduated/Tiered")),
        ("package", _("Package")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Identification
    name = models.CharField(
        max_length=100,
        help_text=_("Pricing tier name (e.g., 'Standard Bandwidth')")
    )
    description = models.TextField(blank=True)

    # Meter association
    meter = models.ForeignKey(
        UsageMeter,
        on_delete=models.CASCADE,
        related_name="pricing_tiers"
    )

    # Pricing model
    pricing_model = models.CharField(
        max_length=20,
        choices=PRICING_MODEL_CHOICES,
        default="per_unit"
    )

    # Currency
    currency = models.ForeignKey(
        Currency,
        on_delete=models.PROTECT
    )

    # Simple per-unit pricing
    unit_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        help_text=_("Price per unit in cents (for per_unit model)")
    )

    # Minimum charge
    minimum_charge_cents = models.BigIntegerField(
        default=0,
        help_text=_("Minimum charge regardless of usage")
    )

    # Configuration
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(
        default=False,
        help_text=_("Default tier for this meter")
    )

    # Validity period
    valid_from = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this pricing becomes effective")
    )
    valid_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this pricing expires")
    )

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "pricing_tiers"
        verbose_name = _("Pricing Tier")
        verbose_name_plural = _("Pricing Tiers")
        ordering = ("meter", "name")
        indexes = (
            models.Index(fields=["meter", "is_active"]),
            models.Index(fields=["meter", "is_default"]),
        )

    def __str__(self) -> str:
        return f"{self.name} - {self.meter.name}"

    @property
    def unit_price(self) -> Decimal | None:
        if self.unit_price_cents is not None:
            return Decimal(self.unit_price_cents) / 100
        return None

    @property
    def minimum_charge(self) -> Decimal:
        return Decimal(self.minimum_charge_cents) / 100


class PricingTierBracket(models.Model):
    """
    Individual bracket within a tiered pricing structure.

    For graduated pricing, each bracket defines a range and its rate.
    Example:
    - 0-100 GB: $0.10/GB
    - 101-500 GB: $0.08/GB
    - 501+ GB: $0.05/GB
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    pricing_tier = models.ForeignKey(
        PricingTier,
        on_delete=models.CASCADE,
        related_name="brackets"
    )

    # Range definition
    from_quantity = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        help_text=_("Start of bracket (inclusive)")
    )
    to_quantity = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        null=True,
        blank=True,
        help_text=_("End of bracket (null = unlimited)")
    )

    # Pricing
    unit_price_cents = models.BigIntegerField(
        help_text=_("Price per unit in this bracket")
    )
    flat_fee_cents = models.BigIntegerField(
        default=0,
        help_text=_("Flat fee for this bracket (package pricing)")
    )

    # Ordering
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "pricing_tier_brackets"
        verbose_name = _("Pricing Bracket")
        verbose_name_plural = _("Pricing Brackets")
        ordering = ("pricing_tier", "sort_order", "from_quantity")
        constraints = [
            models.UniqueConstraint(
                fields=["pricing_tier", "from_quantity"],
                name="unique_tier_bracket_start"
            ),
        ]

    def __str__(self) -> str:
        if self.to_quantity:
            return f"{self.from_quantity} - {self.to_quantity}: {self.unit_price}/unit"
        return f"{self.from_quantity}+: {self.unit_price}/unit"

    @property
    def unit_price(self) -> Decimal:
        return Decimal(self.unit_price_cents) / 100

    @property
    def flat_fee(self) -> Decimal:
        return Decimal(self.flat_fee_cents) / 100


# ===============================================================================
# USAGE ALERTS & THRESHOLDS
# ===============================================================================


class UsageThreshold(models.Model):
    """
    Configurable usage alert thresholds.

    Triggers notifications when usage reaches specified percentages
    of included allowance or absolute values.
    """

    THRESHOLD_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("percentage", _("Percentage of Allowance")),
        ("absolute", _("Absolute Value")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Scope
    meter = models.ForeignKey(
        UsageMeter,
        on_delete=models.CASCADE,
        related_name="thresholds"
    )
    service_plan = models.ForeignKey(
        "provisioning.ServicePlan",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="usage_thresholds",
        help_text=_("Apply to specific plan (null = all plans)")
    )

    # Threshold definition
    threshold_type = models.CharField(
        max_length=20,
        choices=THRESHOLD_TYPE_CHOICES,
        default="percentage"
    )
    threshold_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        help_text=_("Threshold value (percentage or absolute)")
    )

    # Notification configuration
    notify_customer = models.BooleanField(
        default=True,
        help_text=_("Send notification to customer")
    )
    notify_staff = models.BooleanField(
        default=False,
        help_text=_("Send notification to staff")
    )
    email_template = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Email template to use for notification")
    )

    # Actions
    action_on_breach = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ("", _("No Action")),
            ("warn", _("Warning Only")),
            ("throttle", _("Throttle Service")),
            ("suspend", _("Suspend Service")),
            ("block_new", _("Block New Usage")),
        ],
        help_text=_("Action to take when threshold is breached")
    )

    # Repeat settings
    repeat_notification = models.BooleanField(
        default=False,
        help_text=_("Send notification again if threshold remains breached")
    )
    repeat_interval_hours = models.PositiveIntegerField(
        default=24,
        help_text=_("Hours between repeat notifications")
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usage_thresholds"
        verbose_name = _("Usage Threshold")
        verbose_name_plural = _("Usage Thresholds")
        ordering = ("meter", "threshold_value")
        indexes = (
            models.Index(fields=["meter", "is_active"]),
            models.Index(fields=["service_plan", "is_active"]),
        )

    def __str__(self) -> str:
        if self.threshold_type == "percentage":
            return f"{self.meter.name}: {self.threshold_value}%"
        return f"{self.meter.name}: {self.threshold_value} {self.meter.unit}"


class UsageAlert(models.Model):
    """
    Record of usage alerts sent to customers.

    Tracks all threshold breach notifications for audit and
    preventing duplicate notifications.
    """

    ALERT_STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("sent", _("Sent")),
        ("failed", _("Failed")),
        ("acknowledged", _("Acknowledged")),
        ("resolved", _("Resolved")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # References
    threshold = models.ForeignKey(
        UsageThreshold,
        on_delete=models.CASCADE,
        related_name="alerts"
    )
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="usage_alerts"
    )
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_alerts"
    )
    aggregation = models.ForeignKey(
        UsageAggregation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alerts"
    )

    # Alert details
    status = models.CharField(
        max_length=20,
        choices=ALERT_STATUS_CHOICES,
        default="pending"
    )

    # Usage at time of alert
    usage_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        help_text=_("Usage value when alert was triggered")
    )
    usage_percentage = models.DecimalField(
        max_digits=8,
        decimal_places=4,
        null=True,
        blank=True,
        help_text=_("Usage as percentage of allowance")
    )
    allowance_value = models.DecimalField(
        max_digits=18,
        decimal_places=8,
        null=True,
        blank=True,
        help_text=_("Total allowance at time of alert")
    )

    # Notification tracking
    notified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When notification was sent")
    )
    notification_channel = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("How notification was sent (email, sms, webhook)")
    )
    notification_error = models.TextField(
        blank=True,
        help_text=_("Error message if notification failed")
    )

    # Action taken
    action_taken = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Action taken in response to threshold breach")
    )
    action_at = models.DateTimeField(null=True, blank=True)

    # Resolution
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resolved_usage_alerts"
    )
    resolution_notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "usage_alerts"
        verbose_name = _("Usage Alert")
        verbose_name_plural = _("Usage Alerts")
        ordering = ("-created_at",)
        indexes = (
            models.Index(fields=["customer", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["threshold", "-created_at"]),
            # For finding unresolved alerts
            models.Index(
                fields=["status", "customer"],
                condition=models.Q(status__in=["pending", "sent"]),
                name="usage_alert_unresolved"
            ),
        )

    def __str__(self) -> str:
        return f"Alert: {self.threshold} for {self.customer} ({self.status})"

    def mark_sent(self, channel: str = "email") -> None:
        """Mark alert as sent"""
        self.status = "sent"
        self.notified_at = timezone.now()
        self.notification_channel = channel
        self.save(update_fields=["status", "notified_at", "notification_channel", "updated_at"])

    def mark_failed(self, error: str) -> None:
        """Mark alert as failed"""
        self.status = "failed"
        self.notification_error = error
        self.save(update_fields=["status", "notification_error", "updated_at"])

    def resolve(self, user: Any = None, notes: str = "") -> None:
        """Mark alert as resolved"""
        self.status = "resolved"
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.resolution_notes = notes
        self.save(update_fields=[
            "status", "resolved_at", "resolved_by", "resolution_notes", "updated_at"
        ])
