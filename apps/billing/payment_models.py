"""
Payment models for PRAHO Platform
Payment tracking, credit ledger functionality, and retry policies.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, ClassVar, TypedDict

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .currency_models import Currency


# TypedDict definitions for private tracking attributes
class _PaymentSnapshot(TypedDict, total=False):
    """Snapshot of payment state for change tracking"""

    status: str
    amount_cents: int


# ===============================================================================
# PAYMENT & CREDIT MODELS
# ===============================================================================


class Payment(models.Model):
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

    # Payment details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    payment_method = models.CharField(max_length=20, choices=METHOD_CHOICES, default="stripe")
    amount_cents = models.BigIntegerField(validators=[MinValueValidator(1)], default=0)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)

    # Gateway/external tracking
    gateway_txn_id = models.CharField(max_length=255, blank=True)
    reference_number = models.CharField(max_length=100, blank=True)

    # Dates
    received_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    # Metadata
    meta = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    # Audit
    created_by = models.ForeignKey("users.User", on_delete=models.SET_NULL, null=True, related_name="created_payments")

    # Private attributes for change tracking (not DB fields - annotations only)
    _original_payment_values: _PaymentSnapshot | None = None

    class Meta:
        db_table = "payment"
        verbose_name = _("Payment")
        verbose_name_plural = _("Payments")
        indexes = (
            models.Index(fields=["customer", "-received_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["payment_method"]),
            models.Index(fields=["gateway_txn_id"]),
        )

    def __str__(self) -> str:
        return f"Payment {self.amount} {self.currency.code} for {self.customer}"

    @property
    def amount(self) -> Decimal:
        return Decimal(self.amount_cents) / 100


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
        db_table = "credit_ledger"
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
        db_table = "payment_retry_policies"
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
        db_table = "payment_retry_attempts"
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
        db_table = "payment_collection_runs"
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
