"""
Payment models for PRAHO Platform
Payment tracking, credit ledger functionality, and retry policies.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, ClassVar, TypedDict

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransition, ConcurrentTransitionMixin, FSMField, TransitionNotAllowed, transition

from .currency_models import Currency

logger = logging.getLogger(__name__)

# All statuses from which a payment MUST NOT transition.
# Includes "cancelled"/"canceled" for safety (Stripe uses "canceled", some legacy code uses "cancelled").
TERMINAL_PAYMENT_STATUSES: frozenset[str] = frozenset(
    {
        "succeeded",
        "failed",
        "refunded",
        "partially_refunded",
        "cancelled",
        "canceled",
        "disputed",
    }
)


# TypedDict definitions for private tracking attributes
class _PaymentSnapshot(TypedDict, total=False):
    """Snapshot of payment state for change tracking"""

    status: str
    amount_cents: int


# Maps internal payment status names to FSM transition method names on Payment.
_GATEWAY_TRANSITION_MAP: dict[str, str] = {
    "succeeded": "succeed",
    "failed": "fail_payment",
    "refunded": "refund_payment",
    "partially_refunded": "partially_refund",
}


# ===============================================================================
# PAYMENT & CREDIT MODELS
# ===============================================================================


class Payment(ConcurrentTransitionMixin, models.Model):
    """
    Enhanced payment tracking aligned with PostgreSQL schema.
    Updated to support multiple payment methods and gateway responses.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("succeeded", _("Succeeded")),  # Changed from 'completed'
        ("failed", _("Failed")),
        ("refunded", _("Refunded")),
        ("partially_refunded", _("Partially Refunded")),
    )

    METHOD_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("stripe", _("Stripe")),
        ("bank", _("Bank Transfer")),
        ("paypal", _("PayPal")),
        ("cash", _("Cash")),
        ("other", _("Other")),
    )

    # Core relationships
    customer = models.ForeignKey("customers.Customer", on_delete=models.RESTRICT, related_name="payments")
    invoice = models.ForeignKey(
        "billing.Invoice", on_delete=models.SET_NULL, null=True, blank=True, related_name="payments"
    )
    # Proforma linked at payment creation, before conversion to invoice
    proforma = models.ForeignKey(
        "billing.ProformaInvoice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="payments",
    )

    # Payment details
    status = FSMField(max_length=20, choices=STATUS_CHOICES, default="pending", protected=True)
    payment_method = models.CharField(max_length=20, choices=METHOD_CHOICES, default="stripe")
    amount_cents = models.BigIntegerField(validators=[MinValueValidator(0)], default=0)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)

    # Gateway/external tracking
    gateway_txn_id = models.CharField(max_length=255, blank=True, null=True, unique=True, default=None)
    reference_number = models.CharField(max_length=100, blank=True)

    # Idempotency for safe retries and deduplication
    idempotency_key = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=_("Unique key to prevent duplicate payment processing"),
    )

    # Dates
    received_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    # Audit
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, related_name="created_payments")

    # Private attributes for change tracking (not DB fields - annotations only)
    _original_payment_values: _PaymentSnapshot | None = None

    class Meta:
        db_table = "billing_payments"
        verbose_name = _("Payment")
        verbose_name_plural = _("Payments")
        indexes = (
            models.Index(fields=["customer", "-received_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["payment_method"]),
            models.Index(fields=["gateway_txn_id"]),
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(amount_cents__gte=0),
                name="payment_amount_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["pending", "succeeded", "failed", "refunded", "partially_refunded"]),
                name="payment_status_valid_values",
            ),
        ]

    def __str__(self) -> str:
        return f"Payment {self.amount} {self.currency.code} for {self.customer}"

    @property
    def amount(self) -> Decimal:
        return Decimal(self.amount_cents) / 100

    @property
    def stripe_payment_intent_id(self) -> str | None:
        """Get Stripe PaymentIntent ID from meta or gateway_txn_id"""
        if self.payment_method == "stripe":
            # Check meta first for new records
            stripe_id: str | None = self.meta.get("payment_intent_id")
            if stripe_id:
                return stripe_id
            # Fallback to gateway_txn_id for existing records
            if self.gateway_txn_id and self.gateway_txn_id.startswith("pi_"):
                return self.gateway_txn_id
        return None

    @property
    def stripe_customer_id(self) -> str | None:
        """Get Stripe customer ID from metadata"""
        return self.meta.get("stripe_customer_id") if self.payment_method == "stripe" else None

    # =========================================================================
    # FSM TRANSITION METHODS
    # =========================================================================

    @transition(field=status, source="pending", target="succeeded")
    def succeed(self) -> None:
        """Mark payment as succeeded."""

    @transition(field=status, source="pending", target="failed")
    def fail_payment(self) -> None:
        """Mark payment as failed."""

    @transition(field=status, source="succeeded", target="refunded")
    def refund_payment(self) -> None:
        """Mark payment as fully refunded."""

    @transition(field=status, source="succeeded", target="partially_refunded")
    def partially_refund(self) -> None:
        """Mark payment as partially refunded."""

    @transition(field=status, source="partially_refunded", target="refunded")
    def complete_refund(self) -> None:
        """Complete refund on partially refunded payment."""

    # =========================================================================
    # STRIPE / GATEWAY INTEGRATION
    # =========================================================================

    def update_from_stripe_payment_intent(self, payment_intent: dict[str, Any]) -> None:
        """Update payment from Stripe PaymentIntent data.

        This method mutates ``self.meta`` and may call an FSM transition (e.g.
        ``succeed()`` or ``fail_payment()``).  It does **not** call
        ``self.save()`` — the caller is responsible for persisting the changes,
        e.g.::

            payment.update_from_stripe_payment_intent(pi)
            payment.save(update_fields=["status", "meta", "updated_at"])

        Prefer :meth:`apply_gateway_event` for webhook handlers — it handles
        idempotency, terminal-state guards, and persistence internally.
        """
        if self.payment_method != "stripe":
            return

        # Update meta with Stripe data
        self.meta.update(
            {
                "payment_intent_id": payment_intent.get("id"),
                "stripe_status": payment_intent.get("status"),
                "payment_method_details": payment_intent.get("payment_method"),
                "stripe_amount_received": payment_intent.get("amount_received"),
                "updated_from_stripe_at": timezone.now().isoformat(),
            }
        )

        # Map Stripe status to our status via FSM transitions.
        # pending → pending is a no-op (Stripe "processing" / "requires_*" keep us in pending).
        stripe_status = payment_intent.get("status")
        if stripe_status == "succeeded" and self.status == "pending":
            self.succeed()
        elif stripe_status in ["canceled"] and self.status == "pending":
            self.fail_payment()
        # requires_payment_method / requires_confirmation / requires_action / processing
        # all map to "pending" which is already the default — no transition needed.

    def is_stripe_payment(self) -> bool:
        """Check if this is a Stripe payment"""
        return self.payment_method == "stripe"

    def apply_gateway_event(self, new_status: str, meta_update: dict | None = None) -> bool:
        """Apply a gateway status transition with idempotency guard.

        Must be called on a row locked with select_for_update() inside
        transaction.atomic(). Returns True if status changed, False if
        already in terminal state or if the transition is not allowed
        from the current state (idempotent no-op).
        """
        if self.status in TERMINAL_PAYMENT_STATUSES:
            return False

        # State-aware routing: a partially_refunded payment completing a full
        # refund must use complete_refund() (source: partially_refunded), not
        # refund_payment() which requires source: succeeded.
        if new_status == "refunded" and self.status == "partially_refunded":
            method_name = "complete_refund"
        else:
            method_name = _GATEWAY_TRANSITION_MAP.get(new_status)

        if method_name:
            transition_fn = getattr(self, method_name)
            try:
                transition_fn()
            except (TransitionNotAllowed, ConcurrentTransition):
                logger.warning(
                    "⚠️ [Payment] Transition to '%s' not allowed from '%s' for payment %s",
                    new_status,
                    self.status,
                    self.pk,
                )
                return False
        else:
            logger.warning(
                "⚠️ [Payment] Unmapped gateway status '%s' for payment %s — no transition applied",
                new_status,
                self.pk,
            )
            return False

        if meta_update:
            self.meta = {**(self.meta or {}), **meta_update}
        self.save(update_fields=["status", "meta", "updated_at"])
        return True

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Any = None,
        from_queryset: Any = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        django-fsm protected fields block setattr via the descriptor. Django's
        refresh_from_db uses setattr internally, which would raise AttributeError
        if the field is already in __dict__. Temporarily removing the protected
        field from __dict__ lets Django's setattr path bypass the descriptor
        guard and populate the field from the database.
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

    @classmethod
    def generate_idempotency_key(cls, prefix: str = "pay") -> str:
        """Generate a unique idempotency key."""
        return f"{prefix}_{secrets.token_hex(24)}"

    def set_idempotency_key(self, key: str | None = None) -> None:
        """Set idempotency key, generating one if not provided."""
        if key:
            self.idempotency_key = key
        elif not self.idempotency_key:
            self.idempotency_key = self.generate_idempotency_key()

    @classmethod
    def get_by_idempotency_key(cls, key: str) -> Payment | None:
        """Find payment by idempotency key for deduplication."""
        try:
            return cls.objects.get(idempotency_key=key)
        except cls.DoesNotExist:
            return None


class CreditLedger(models.Model):
    """
    Customer credit/balance tracking ledger.
    New model from PostgreSQL schema for prepayments, refunds, adjustments.
    """

    customer = models.ForeignKey("customers.Customer", on_delete=models.CASCADE, related_name="credit_entries")
    invoice = models.ForeignKey("billing.Invoice", on_delete=models.SET_NULL, null=True, blank=True)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)

    # Credit change (positive = credit added, negative = credit used)
    delta_cents = models.BigIntegerField()
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    # Audit
    created_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, related_name="created_credit_entries"
    )

    class Meta:
        db_table = "billing_credit_ledgers"
        verbose_name = _("Credit Entry")
        verbose_name_plural = _("Credit Entries")
        indexes = (models.Index(fields=["customer", "-created_at"]),)

    def __str__(self) -> str:
        return f"{self.customer} - {self.delta} ({self.reason})"

    @property
    def delta(self) -> Decimal:
        return Decimal(self.delta_cents) / 100


# ===============================================================================
# PAYMENT RETRY & COLLECTION MODELS
# ===============================================================================


class PaymentRetryPolicy(models.Model):
    """
    Configurable dunning schedules for failed payment recovery.
    Handles automatic retry of failed payments, crucial for revenue recovery.
    Romanian businesses need this for subscription services and recurring billing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Policy identification
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Human-readable policy name (e.g., 'Standard Hosting', 'VIP Customer')"),
    )
    description = models.TextField(blank=True, help_text=_("Description of when this policy applies"))

    # Retry configuration
    retry_intervals_days = models.JSONField(
        default=list, help_text=_("Days after failure to retry (e.g., [1, 3, 7, 14, 30])")
    )
    max_attempts = models.IntegerField(
        default=4,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text=_("Maximum number of retry attempts"),
    )

    # Escalation rules
    suspend_service_after_days = models.IntegerField(
        null=True, blank=True, help_text=_("Days after final failure to suspend service (null = never)")
    )
    terminate_service_after_days = models.IntegerField(
        null=True, blank=True, help_text=_("Days after final failure to terminate service (null = never)")
    )

    # Communication settings
    send_dunning_emails = models.BooleanField(
        default=True, help_text=_("Whether to send email notifications during dunning")
    )
    email_template_prefix = models.CharField(
        max_length=50, default="dunning", help_text=_("Template prefix for dunning emails (e.g., 'dunning_vip')")
    )

    # Policy scope
    is_default = models.BooleanField(default=False, help_text=_("Whether this is the default policy for new customers"))
    is_active = models.BooleanField(default=True, help_text=_("Whether this policy is currently active"))

    # Configuration
    meta = models.JSONField(default=dict, blank=True, help_text=_("Additional policy configuration"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_payment_retry_policies"
        verbose_name = _("Payment Retry Policy")
        verbose_name_plural = _("Payment Retry Policies")
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} ({len(self.retry_intervals_days)} attempts)"

    def get_next_retry_date(self, failure_date: datetime, attempt_number: int) -> datetime | None:
        """Calculate next retry date based on policy"""
        if attempt_number >= len(self.retry_intervals_days):
            return None

        days_to_wait = self.retry_intervals_days[attempt_number]
        return failure_date + timedelta(days=days_to_wait)


class PaymentRetryAttempt(models.Model):
    """
    Individual retry attempts for failed payments.
    Tracks the complete dunning history for audit and compliance.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Payment reference
    payment = models.ForeignKey(
        "Payment", on_delete=models.CASCADE, related_name="retry_attempts", help_text=_("Original failed payment")
    )
    policy = models.ForeignKey(
        PaymentRetryPolicy, on_delete=models.PROTECT, help_text=_("Retry policy used for this attempt")
    )

    # Attempt tracking
    attempt_number = models.PositiveIntegerField(help_text=_("Sequence number of this retry attempt (1, 2, 3...)"))
    scheduled_at = models.DateTimeField(help_text=_("When this retry was scheduled to run"))
    executed_at = models.DateTimeField(null=True, blank=True, help_text=_("When this retry was actually executed"))

    # Results
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", _("Pending")),
            ("processing", _("Processing")),
            ("success", _("Success")),
            ("failed", _("Failed")),
            ("skipped", _("Skipped")),
            ("cancelled", _("Cancelled")),
        ],
        default="pending",
    )

    # Payment gateway response
    gateway_response = models.JSONField(default=dict, blank=True, help_text=_("Payment gateway response for audit"))
    failure_reason = models.TextField(blank=True, help_text=_("Reason for failure if retry was unsuccessful"))

    # Communication tracking
    dunning_email_sent = models.BooleanField(
        default=False, help_text=_("Whether dunning email was sent for this attempt")
    )
    dunning_email_sent_at = models.DateTimeField(null=True, blank=True, help_text=_("When dunning email was sent"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Private attributes for change tracking (not DB fields - annotations only)
    _original_retry_status: str | None = None

    class Meta:
        db_table = "billing_payment_retry_attempts"
        verbose_name = _("Payment Retry Attempt")
        verbose_name_plural = _("Payment Retry Attempts")
        unique_together = (("payment", "attempt_number"),)
        indexes = (
            models.Index(fields=["scheduled_at", "status"]),
            models.Index(fields=["payment", "-attempt_number"]),
            models.Index(fields=["status", "executed_at"]),
        )
        ordering = ("payment", "attempt_number")

    def __str__(self) -> str:
        return f"Attempt {self.attempt_number} for Payment {self.payment.id} - {self.status}"


class PaymentCollectionRun(models.Model):
    """
    Batch processing of failed payments for dunning campaigns.
    Tracks execution of collection runs for monitoring and audit.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Run identification
    run_type = models.CharField(
        max_length=20,
        choices=[
            ("automatic", _("Automatic Scheduled")),
            ("manual", _("Manual Trigger")),
            ("test", _("Test Run")),
        ],
        default="automatic",
    )
    triggered_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, help_text=_("User who triggered manual run")
    )

    # Execution window
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True, help_text=_("When collection run completed"))

    # Execution results
    total_scheduled = models.PositiveIntegerField(default=0, help_text=_("Total retry attempts scheduled in this run"))
    total_processed = models.PositiveIntegerField(default=0, help_text=_("Total retry attempts processed"))
    total_successful = models.PositiveIntegerField(default=0, help_text=_("Total successful payment recoveries"))
    total_failed = models.PositiveIntegerField(default=0, help_text=_("Total failed retry attempts"))

    # Financial impact
    amount_recovered_cents = models.BigIntegerField(default=0, help_text=_("Total amount recovered in cents"))
    fees_charged_cents = models.BigIntegerField(default=0, help_text=_("Total fees charged by payment processor"))

    # Execution status
    status = models.CharField(
        max_length=20,
        choices=[
            ("running", _("Running")),
            ("completed", _("Completed")),
            ("failed", _("Failed")),
            ("cancelled", _("Cancelled")),
        ],
        default="running",
    )
    error_message = models.TextField(blank=True, help_text=_("Error message if run failed"))

    # Configuration snapshot
    config_snapshot = models.JSONField(default=dict, blank=True, help_text=_("Configuration used for this run"))

    class Meta:
        db_table = "billing_payment_collections"
        verbose_name = _("Payment Collection Run")
        verbose_name_plural = _("Payment Collection Runs")
        indexes = (
            models.Index(fields=["-started_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["run_type", "-started_at"]),
        )
        ordering = ("-started_at",)

    def __str__(self) -> str:
        duration = ""
        if self.completed_at:
            duration = f" ({(self.completed_at - self.started_at).total_seconds():.0f}s)"
        return f"{self.run_type} Collection Run {self.started_at.strftime('%Y-%m-%d %H:%M')} - {self.status}{duration}"

    @property
    def duration_minutes(self) -> int | None:
        """Calculate run duration in minutes"""
        if not self.completed_at:
            return None
        delta = self.completed_at - self.started_at
        return int(delta.total_seconds() / 60)

    @property
    def amount_recovered(self) -> Decimal:
        """Amount recovered as Decimal"""
        return Decimal(self.amount_recovered_cents) / 100

    @property
    def fees_charged(self) -> Decimal:
        """Fees charged as Decimal"""
        return Decimal(self.fees_charged_cents) / 100

    @property
    def net_recovery(self) -> Decimal:
        """Net amount recovered after fees"""
        return self.amount_recovered - self.fees_charged
