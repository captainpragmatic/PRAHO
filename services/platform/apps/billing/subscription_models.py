"""
Subscription models for PRAHO Platform
Comprehensive recurring billing with subscription lifecycle management.

Supports:
- Multiple billing cycles (monthly, quarterly, yearly, custom)
- Trial periods with automatic conversion
- Price grandfathering for existing customers
- Proration for mid-cycle changes
- Dunning and grace periods
- Usage-based billing integration
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from decimal import ROUND_UP, Decimal
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.db.models import F, Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    pass

from .currency_models import Currency
from .validators import log_security_event, validate_financial_amount

logger = logging.getLogger(__name__)

# ===============================================================================
# CONSTANTS
# ===============================================================================

# Billing cycle days
BILLING_CYCLE_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "semi_annual": 180,
    "yearly": 365,
}

# Grace period before suspension (days) — module-level fallback for model field default
_DEFAULT_GRACE_PERIOD_DAYS = 7
DEFAULT_GRACE_PERIOD_DAYS = _DEFAULT_GRACE_PERIOD_DAYS

# Maximum retry attempts before cancellation — module-level fallback
_DEFAULT_MAX_PAYMENT_RETRY_ATTEMPTS = 5
MAX_PAYMENT_RETRY_ATTEMPTS = _DEFAULT_MAX_PAYMENT_RETRY_ATTEMPTS


def get_subscription_grace_period_days() -> int:
    """Get grace period days from SettingsService (runtime)."""
    try:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        return max(
            1, SettingsService.get_integer_setting("billing.subscription_grace_period_days", _DEFAULT_GRACE_PERIOD_DAYS)
        )
    except Exception:
        return _DEFAULT_GRACE_PERIOD_DAYS


def get_max_payment_retry_attempts() -> int:
    """Get max payment retry attempts from SettingsService (runtime)."""
    try:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        return max(
            1,
            SettingsService.get_integer_setting(
                "billing.max_payment_retry_attempts", _DEFAULT_MAX_PAYMENT_RETRY_ATTEMPTS
            ),
        )
    except Exception:
        return _DEFAULT_MAX_PAYMENT_RETRY_ATTEMPTS


# ===============================================================================
# SUBSCRIPTION MODEL
# ===============================================================================


class Subscription(models.Model):
    """
    Core subscription model for recurring billing.

    Manages the complete subscription lifecycle:
    - Trialing → Active → Past Due → Cancelled/Expired

    Supports grandfathered pricing and mid-cycle changes with proration.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("trialing", _("Trialing")),
        ("active", _("Active")),
        ("past_due", _("Past Due")),
        ("paused", _("Paused")),
        ("cancelled", _("Cancelled")),
        ("expired", _("Expired")),
        ("pending", _("Pending Activation")),
    )

    BILLING_CYCLE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("monthly", _("Monthly")),
        ("quarterly", _("Quarterly")),
        ("semi_annual", _("Semi-Annual")),
        ("yearly", _("Yearly")),
        ("custom", _("Custom")),
    )

    CANCELLATION_REASON_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("customer_request", _("Customer Request")),
        ("non_payment", _("Non-Payment")),
        ("fraud", _("Fraud")),
        ("service_issue", _("Service Issue")),
        ("upgrade", _("Upgrade to Different Plan")),
        ("downgrade", _("Downgrade to Different Plan")),
        ("business_closed", _("Business Closed")),
        ("competitor", _("Switched to Competitor")),
        ("other", _("Other")),
    )

    # Primary key
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Core relationships
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.PROTECT,
        related_name="subscriptions",
        help_text=_("Customer who owns this subscription"),
    )
    product = models.ForeignKey(
        "products.Product",
        on_delete=models.PROTECT,
        related_name="subscriptions",
        help_text=_("Product/plan being subscribed to"),
    )

    # Subscription identification
    subscription_number = models.CharField(
        max_length=50,
        unique=True,
        help_text=_("Unique subscription identifier (e.g., SUB-000001)"),
    )

    # Status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
        db_index=True,
    )

    # Billing configuration
    billing_cycle = models.CharField(
        max_length=20,
        choices=BILLING_CYCLE_CHOICES,
        default="monthly",
    )
    custom_cycle_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(730)],
        help_text=_("Custom billing cycle in days (only if billing_cycle='custom')"),
    )

    # Currency and pricing
    currency = models.ForeignKey(
        Currency,
        on_delete=models.PROTECT,
        help_text=_("Currency for this subscription"),
    )

    # Regular price (from product, may differ if grandfathered)
    unit_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text=_("Current billing amount per cycle in cents"),
    )

    # Grandfathered/locked price (if different from current product price)
    locked_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
        help_text=_("Grandfathered price if customer is on legacy pricing"),
    )
    locked_price_reason = models.CharField(
        max_length=200,
        blank=True,
        help_text=_("Reason for locked pricing (e.g., 'Early adopter discount')"),
    )
    locked_price_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When grandfathered pricing expires (null = never)"),
    )

    # Quantity (for per-seat or quantity-based billing)
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)],
        help_text=_("Number of units (e.g., seats, domains, GB)"),
    )

    # Billing period tracking
    current_period_start = models.DateTimeField(
        help_text=_("Start of current billing period"),
    )
    current_period_end = models.DateTimeField(
        help_text=_("End of current billing period"),
    )
    next_billing_date = models.DateTimeField(
        db_index=True,
        help_text=_("Date when next invoice will be generated"),
    )

    # Trial configuration
    trial_start = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When trial period started"),
    )
    trial_end = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When trial period ends"),
    )
    trial_converted = models.BooleanField(
        default=False,
        help_text=_("Whether trial has converted to paid subscription"),
    )

    # Lifecycle dates
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription became active"),
    )
    cancelled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription was cancelled"),
    )
    cancel_at_period_end = models.BooleanField(
        default=False,
        help_text=_("If true, cancel at end of current period instead of immediately"),
    )
    cancellation_reason = models.CharField(
        max_length=50,
        choices=CANCELLATION_REASON_CHOICES,
        blank=True,
    )
    cancellation_feedback = models.TextField(
        blank=True,
        help_text=_("Customer feedback on cancellation"),
    )
    paused_at = models.DateTimeField(
        null=True,
        blank=True,
    )
    resume_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Scheduled date to resume paused subscription"),
    )
    ended_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When subscription actually ended"),
    )

    # Payment tracking
    payment_method_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Stripe PaymentMethod ID or other gateway reference"),
    )
    last_payment_date = models.DateTimeField(
        null=True,
        blank=True,
    )
    last_payment_amount_cents = models.BigIntegerField(
        null=True,
        blank=True,
    )
    failed_payment_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Consecutive failed payment attempts"),
    )

    # Grace period and dunning
    grace_period_days = models.PositiveIntegerField(
        default=DEFAULT_GRACE_PERIOD_DAYS,
        help_text=_("Days of grace after payment failure before suspension"),
    )
    grace_period_ends_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When grace period expires (set on payment failure)"),
    )

    # External references
    stripe_subscription_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text=_("Stripe Subscription ID for syncing"),
    )
    external_reference = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("External system reference if applicable"),
    )

    # Metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional subscription metadata"),
    )
    notes = models.TextField(
        blank=True,
        help_text=_("Internal notes about this subscription"),
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_subscriptions",
    )

    class Meta:
        db_table = "subscriptions"
        verbose_name = _("Subscription")
        verbose_name_plural = _("Subscriptions")
        ordering = ("-created_at",)
        indexes = (
            models.Index(fields=["customer", "status"]),
            models.Index(fields=["status", "next_billing_date"]),
            models.Index(fields=["product", "status"]),
            models.Index(fields=["stripe_subscription_id"]),
            models.Index(
                fields=["status", "next_billing_date"],
                condition=Q(status="active"),
                name="idx_active_billing_date",
            ),
        )
        constraints: ClassVar[list] = [
            models.CheckConstraint(
                condition=Q(unit_price_cents__gte=0),
                name="subscription_price_non_negative",
            ),
            models.CheckConstraint(
                condition=Q(quantity__gte=1),
                name="subscription_quantity_positive",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.subscription_number} - {self.customer} ({self.status})"

    def clean(self) -> None:
        """Validate subscription data."""
        super().clean()

        # Validate custom cycle
        if self.billing_cycle == "custom" and not self.custom_cycle_days:
            raise ValidationError(_("Custom billing cycle requires custom_cycle_days to be set"))

        # Validate price
        validate_financial_amount(self.unit_price_cents, "Unit price")
        if self.locked_price_cents:
            validate_financial_amount(self.locked_price_cents, "Locked price")

        # Validate period dates
        if (
            self.current_period_end
            and self.current_period_start
            and self.current_period_end <= self.current_period_start
        ):
            raise ValidationError(_("Period end must be after period start"))

    def save(self, *args: Any, **kwargs: Any) -> None:  # noqa: DJ012
        """Generate subscription number if not set."""
        if not self.subscription_number:
            self.subscription_number = self._generate_subscription_number()

        self.clean()
        super().save(*args, **kwargs)

    def _generate_subscription_number(self) -> str:
        """Generate unique subscription number."""
        from .invoice_models import InvoiceSequence  # noqa: PLC0415

        sequence, _ = InvoiceSequence.objects.get_or_create(scope="subscription")
        return sequence.get_next_number("SUB")

    # =========================================================================
    # PRICE PROPERTIES
    # =========================================================================

    @property
    def effective_price_cents(self) -> int:
        """Get the effective price (locked if grandfathered, otherwise regular)."""
        if self.locked_price_cents is not None:
            # Check if lock has expired
            if self.locked_price_expires_at and timezone.now() > self.locked_price_expires_at:
                return self.unit_price_cents
            return self.locked_price_cents
        return self.unit_price_cents

    @property
    def effective_price(self) -> Decimal:
        """Get effective price as Decimal."""
        return Decimal(self.effective_price_cents) / 100

    @property
    def total_price_cents(self) -> int:
        """Get total price including quantity."""
        return self.effective_price_cents * self.quantity

    @property
    def total_price(self) -> Decimal:
        """Get total price as Decimal."""
        return Decimal(self.total_price_cents) / 100

    @property
    def is_grandfathered(self) -> bool:
        """Check if subscription has grandfathered pricing."""
        if self.locked_price_cents is None:
            return False
        return not (self.locked_price_expires_at and timezone.now() > self.locked_price_expires_at)

    # =========================================================================
    # STATUS PROPERTIES
    # =========================================================================

    @property
    def is_active(self) -> bool:
        """Check if subscription is currently active."""
        return self.status in ("active", "trialing")

    @property
    def is_trialing(self) -> bool:
        """Check if subscription is in trial period."""
        if self.status != "trialing":
            return False
        if not self.trial_end:
            return False
        return timezone.now() < self.trial_end

    @property
    def is_past_due(self) -> bool:
        """Check if subscription has past due payments."""
        return self.status == "past_due"

    @property
    def is_cancelled(self) -> bool:
        """Check if subscription is cancelled."""
        return self.status == "cancelled"

    @property
    def will_cancel_at_period_end(self) -> bool:
        """Check if subscription will cancel at end of period."""
        return self.cancel_at_period_end and not self.is_cancelled

    @property
    def days_until_renewal(self) -> int:
        """Calculate days until next billing date."""
        if not self.next_billing_date:
            return 0
        delta = self.next_billing_date - timezone.now()
        return max(0, delta.days)

    @property
    def cycle_days(self) -> int:
        """Get billing cycle length in days."""
        if self.billing_cycle == "custom":
            return self.custom_cycle_days or 30
        return BILLING_CYCLE_DAYS.get(self.billing_cycle, 30)

    # =========================================================================
    # LIFECYCLE METHODS
    # =========================================================================

    def activate(self, user: Any = None) -> None:
        """Activate the subscription."""
        now = timezone.now()

        with transaction.atomic():
            self.status = "active"
            self.started_at = self.started_at or now
            self.current_period_start = now
            self.current_period_end = now + timedelta(days=self.cycle_days)
            self.next_billing_date = self.current_period_end
            self.save()

            log_security_event(
                event_type="subscription_activated",
                details={
                    "subscription_id": str(self.id),
                    "subscription_number": self.subscription_number,
                    "customer_id": str(self.customer_id),
                    "product_id": str(self.product_id),
                    "effective_price_cents": self.effective_price_cents,
                },
                user_email=user.email if user else None,
            )

    def start_trial(self, trial_days: int, user: Any = None) -> None:
        """Start a trial period."""
        now = timezone.now()

        with transaction.atomic():
            self.status = "trialing"
            self.trial_start = now
            self.trial_end = now + timedelta(days=trial_days)
            self.current_period_start = now
            self.current_period_end = self.trial_end
            self.next_billing_date = self.trial_end
            self.save()

            log_security_event(
                event_type="subscription_trial_started",
                details={
                    "subscription_id": str(self.id),
                    "trial_days": trial_days,
                    "trial_end": self.trial_end.isoformat(),
                },
                user_email=user.email if user else None,
            )

    def convert_trial(self, user: Any = None) -> None:
        """Convert trial to paid subscription."""
        if self.status != "trialing":
            raise ValidationError(_("Can only convert subscriptions in trial status"))

        with transaction.atomic():
            self.trial_converted = True
            self.activate(user)

            log_security_event(
                event_type="subscription_trial_converted",
                details={
                    "subscription_id": str(self.id),
                    "subscription_number": self.subscription_number,
                },
                user_email=user.email if user else None,
            )

    def cancel(
        self,
        reason: str = "customer_request",
        at_period_end: bool = True,
        feedback: str = "",
        user: Any = None,
    ) -> None:
        """Cancel the subscription."""
        with transaction.atomic():
            self.cancelled_at = timezone.now()
            self.cancellation_reason = reason
            self.cancellation_feedback = feedback

            if at_period_end:
                self.cancel_at_period_end = True
            else:
                self.status = "cancelled"
                self.ended_at = timezone.now()

            self.save()

            log_security_event(
                event_type="subscription_cancelled",
                details={
                    "subscription_id": str(self.id),
                    "subscription_number": self.subscription_number,
                    "reason": reason,
                    "at_period_end": at_period_end,
                    "critical_financial_operation": True,
                },
                user_email=user.email if user else None,
            )

    def pause(self, resume_date: Any = None, user: Any = None) -> None:
        """Pause the subscription."""
        with transaction.atomic():
            self.status = "paused"
            self.paused_at = timezone.now()
            self.resume_at = resume_date
            self.save()

            log_security_event(
                event_type="subscription_paused",
                details={
                    "subscription_id": str(self.id),
                    "resume_at": resume_date.isoformat() if resume_date else None,
                },
                user_email=user.email if user else None,
            )

    def resume(self, user: Any = None) -> None:
        """Resume a paused subscription."""
        if self.status != "paused":
            raise ValidationError(_("Can only resume paused subscriptions"))

        with transaction.atomic():
            self.status = "active"

            # Extend period by paused duration (must happen before clearing paused_at)
            if self.paused_at:
                paused_duration = timezone.now() - self.paused_at
                self.current_period_end += paused_duration
                self.next_billing_date += paused_duration

            self.paused_at = None
            self.resume_at = None

            self.save()

            log_security_event(
                event_type="subscription_resumed",
                details={"subscription_id": str(self.id)},
                user_email=user.email if user else None,
            )

    def renew(self, user: Any = None) -> None:
        """Renew subscription for next billing period."""
        with transaction.atomic():
            self.current_period_start = self.current_period_end
            self.current_period_end = self.current_period_start + timedelta(days=self.cycle_days)
            self.next_billing_date = self.current_period_end
            self.failed_payment_count = 0
            self.grace_period_ends_at = None
            self.save()

            log_security_event(
                event_type="subscription_renewed",
                details={
                    "subscription_id": str(self.id),
                    "new_period_end": self.current_period_end.isoformat(),
                },
                user_email=user.email if user else None,
            )

    def mark_payment_failed(self) -> None:
        """Record a failed payment attempt."""
        with transaction.atomic():
            self.failed_payment_count = F("failed_payment_count") + 1
            self.save(update_fields=["failed_payment_count", "updated_at"])
            self.refresh_from_db()

            # Enter past due status if first failure
            if self.status == "active":
                self.status = "past_due"
                self.grace_period_ends_at = timezone.now() + timedelta(days=self.grace_period_days)
                self.save(update_fields=["status", "grace_period_ends_at", "updated_at"])

            log_security_event(
                event_type="subscription_payment_failed",
                details={
                    "subscription_id": str(self.id),
                    "failed_count": self.failed_payment_count,
                    "grace_period_ends_at": self.grace_period_ends_at.isoformat()
                    if self.grace_period_ends_at
                    else None,
                },
            )

    def record_payment(self, amount_cents: int, user: Any = None) -> None:
        """Record a successful payment."""
        with transaction.atomic():
            self.last_payment_date = timezone.now()
            self.last_payment_amount_cents = amount_cents
            self.failed_payment_count = 0
            self.grace_period_ends_at = None

            if self.status == "past_due":
                self.status = "active"

            self.save()

            log_security_event(
                event_type="subscription_payment_recorded",
                details={
                    "subscription_id": str(self.id),
                    "amount_cents": amount_cents,
                    "critical_financial_operation": True,
                },
                user_email=user.email if user else None,
            )

    def apply_grandfathered_price(
        self,
        locked_price_cents: int,
        reason: str,
        expires_at: Any = None,
        user: Any = None,
    ) -> None:
        """Lock in a grandfathered price for this subscription."""
        with transaction.atomic():
            self.locked_price_cents = locked_price_cents
            self.locked_price_reason = reason
            self.locked_price_expires_at = expires_at
            self.save()

            log_security_event(
                event_type="subscription_price_grandfathered",
                details={
                    "subscription_id": str(self.id),
                    "locked_price_cents": locked_price_cents,
                    "reason": reason,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                    "critical_financial_operation": True,
                },
                user_email=user.email if user else None,
            )


# ===============================================================================
# SUBSCRIPTION CHANGE/UPGRADE MODEL
# ===============================================================================


class SubscriptionChange(models.Model):
    """
    Tracks subscription changes (upgrades, downgrades, quantity changes).
    Calculates and stores proration amounts.
    """

    CHANGE_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("upgrade", _("Upgrade")),
        ("downgrade", _("Downgrade")),
        ("quantity_increase", _("Quantity Increase")),
        ("quantity_decrease", _("Quantity Decrease")),
        ("billing_cycle_change", _("Billing Cycle Change")),
        ("price_change", _("Price Change")),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("applied", _("Applied")),
        ("cancelled", _("Cancelled")),
        ("failed", _("Failed")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationships
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="changes",
    )

    # Change details
    change_type = models.CharField(max_length=30, choices=CHANGE_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Old values
    old_product = models.ForeignKey(
        "products.Product",
        on_delete=models.SET_NULL,
        null=True,
        related_name="subscription_changes_from",
    )
    old_price_cents = models.BigIntegerField()
    old_quantity = models.PositiveIntegerField()
    old_billing_cycle = models.CharField(max_length=20)

    # New values
    new_product = models.ForeignKey(
        "products.Product",
        on_delete=models.SET_NULL,
        null=True,
        related_name="subscription_changes_to",
    )
    new_price_cents = models.BigIntegerField()
    new_quantity = models.PositiveIntegerField()
    new_billing_cycle = models.CharField(max_length=20)

    # Proration
    prorate = models.BooleanField(
        default=True,
        help_text=_("Whether to prorate the change"),
    )
    proration_amount_cents = models.BigIntegerField(
        default=0,
        help_text=_("Proration amount (positive = charge, negative = credit)"),
    )
    unused_credit_cents = models.BigIntegerField(
        default=0,
        help_text=_("Credit for unused portion of old plan"),
    )
    new_charge_cents = models.BigIntegerField(
        default=0,
        help_text=_("Charge for remaining portion of new plan"),
    )

    # Timing
    effective_date = models.DateTimeField(
        help_text=_("When change takes effect"),
    )
    apply_immediately = models.BooleanField(
        default=True,
        help_text=_("Apply immediately vs at next billing cycle"),
    )

    # Invoice reference
    invoice = models.ForeignKey(
        "billing.Invoice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subscription_changes",
        help_text=_("Invoice generated for proration charge"),
    )

    # Metadata
    reason = models.TextField(blank=True)
    meta = models.JSONField(default=dict, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    applied_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="subscription_changes_created",
    )

    class Meta:
        db_table = "subscription_changes"
        verbose_name = _("Subscription Change")
        verbose_name_plural = _("Subscription Changes")
        ordering = ("-created_at",)
        indexes = (
            models.Index(fields=["subscription", "-created_at"]),
            models.Index(fields=["status", "effective_date"]),
        )

    def __str__(self) -> str:
        return f"{self.subscription.subscription_number} - {self.change_type} ({self.status})"

    @property
    def proration_amount(self) -> Decimal:
        """Get proration amount as Decimal."""
        return Decimal(self.proration_amount_cents) / 100

    def calculate_proration(self) -> None:
        """Calculate proration amounts for this change."""
        if not self.prorate:
            self.proration_amount_cents = 0
            self.unused_credit_cents = 0
            self.new_charge_cents = 0
            return

        sub = self.subscription
        now = timezone.now()

        # Calculate days remaining in current period
        days_remaining = 0 if sub.current_period_end <= now else (sub.current_period_end - now).days

        days_in_period = sub.cycle_days

        if days_in_period <= 0:
            days_in_period = 30  # Fallback

        # Calculate unused credit from old plan
        old_daily_rate = (self.old_price_cents * self.old_quantity) / days_in_period
        self.unused_credit_cents = int(old_daily_rate * days_remaining)

        # Calculate charge for new plan
        new_daily_rate = (self.new_price_cents * self.new_quantity) / days_in_period
        self.new_charge_cents = int(new_daily_rate * days_remaining)

        # Net proration (positive = customer pays, negative = credit)
        self.proration_amount_cents = self.new_charge_cents - self.unused_credit_cents

    def apply(self, user: Any = None) -> None:
        """Apply the subscription change."""
        if self.status != "pending":
            raise ValidationError(_("Cannot apply change with status: %(status)s") % {"status": self.status})

        with transaction.atomic():
            sub = self.subscription

            # Update subscription
            if self.new_product:
                sub.product = self.new_product
            sub.unit_price_cents = self.new_price_cents
            sub.quantity = self.new_quantity
            sub.billing_cycle = self.new_billing_cycle
            sub.save()

            # Mark change as applied
            self.status = "applied"
            self.applied_at = timezone.now()
            self.save()

            log_security_event(
                event_type="subscription_change_applied",
                details={
                    "subscription_id": str(sub.id),
                    "change_id": str(self.id),
                    "change_type": self.change_type,
                    "proration_amount_cents": self.proration_amount_cents,
                    "critical_financial_operation": True,
                },
                user_email=user.email if user else None,
            )


# ===============================================================================
# PRICE GRANDFATHERING MODEL
# ===============================================================================


class PriceGrandfathering(models.Model):
    """
    Explicit price grandfathering rules for products.
    When product prices change, customers with grandfathering get to keep old prices.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Target
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="grandfathered_prices",
    )
    product = models.ForeignKey(
        "products.Product",
        on_delete=models.CASCADE,
        related_name="grandfathered_customers",
    )

    # Locked pricing
    locked_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text=_("The grandfathered price in cents"),
    )
    original_price_cents = models.BigIntegerField(
        help_text=_("Price at time of grandfathering (for reference)"),
    )
    current_product_price_cents = models.BigIntegerField(
        help_text=_("Current product price at time of grandfathering"),
    )

    # Validity
    locked_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("When price was locked"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When grandfathering expires (null = never)"),
    )
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether grandfathering is currently active"),
    )

    # Reason and tracking
    reason = models.CharField(
        max_length=200,
        help_text=_("Reason for grandfathering (e.g., 'Early adopter', 'Loyalty reward')"),
    )
    price_increase_id = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Reference to the price increase that triggered grandfathering"),
    )
    campaign = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Campaign or promotion that granted grandfathering"),
    )

    # Notifications
    expiry_notified = models.BooleanField(
        default=False,
        help_text=_("Whether expiry notification has been sent"),
    )
    expiry_notified_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_grandfathering",
    )

    class Meta:
        db_table = "price_grandfathering"
        verbose_name = _("Price Grandfathering")
        verbose_name_plural = _("Price Grandfatherings")
        unique_together = (("customer", "product"),)
        indexes = (
            models.Index(fields=["customer", "is_active"]),
            models.Index(fields=["product", "is_active"]),
            models.Index(fields=["expires_at", "is_active"]),
        )

    def __str__(self) -> str:
        return f"{self.customer} - {self.product} @ {self.locked_price_cents/100:.2f}"

    @property
    def locked_price(self) -> Decimal:
        """Get locked price as Decimal."""
        return Decimal(self.locked_price_cents) / 100

    @property
    def savings_cents(self) -> int:
        """Calculate savings compared to current price."""
        return self.current_product_price_cents - self.locked_price_cents

    @property
    def savings_percent(self) -> Decimal:
        """Calculate savings percentage."""
        if self.current_product_price_cents == 0:
            return Decimal("0")
        return (Decimal(self.savings_cents) / Decimal(self.current_product_price_cents) * 100).quantize(
            Decimal("0.01"), rounding=ROUND_UP
        )

    @property
    def is_expired(self) -> bool:
        """Check if grandfathering has expired."""
        if not self.is_active:
            return True
        return bool(self.expires_at and timezone.now() > self.expires_at)

    def expire(self, user: Any = None) -> None:
        """Manually expire this grandfathering."""
        self.is_active = False
        self.save(update_fields=["is_active", "updated_at"])

        log_security_event(
            event_type="grandfathering_expired",
            details={
                "grandfathering_id": str(self.id),
                "customer_id": str(self.customer_id),
                "product_id": str(self.product_id),
                "locked_price_cents": self.locked_price_cents,
            },
            user_email=user.email if user else None,
        )


# ===============================================================================
# SUBSCRIPTION ITEM MODEL (FOR MULTI-PRODUCT SUBSCRIPTIONS)
# ===============================================================================


class SubscriptionItem(models.Model):
    """
    Individual items within a subscription.
    Supports subscriptions with multiple products/add-ons.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="items",
    )
    product = models.ForeignKey(
        "products.Product",
        on_delete=models.PROTECT,
        related_name="subscription_items",
    )

    # Pricing
    unit_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)],
    )
    locked_price_cents = models.BigIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0)],
    )
    quantity = models.PositiveIntegerField(default=1)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "subscription_items"
        verbose_name = _("Subscription Item")
        verbose_name_plural = _("Subscription Items")
        unique_together = (("subscription", "product"),)

    def __str__(self) -> str:
        return f"{self.subscription.subscription_number} - {self.product}"

    @property
    def effective_price_cents(self) -> int:
        """Get effective price."""
        return self.locked_price_cents if self.locked_price_cents else self.unit_price_cents

    @property
    def line_total_cents(self) -> int:
        """Get line total."""
        return self.effective_price_cents * self.quantity
