import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any, ClassVar

from django.core.validators import MinValueValidator
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# ===============================================================================
# WEBHOOK DEDUPLICATION SYSTEM
# ===============================================================================


class WebhookEvent(models.Model):
    """
    🔄 Webhook event deduplication and tracking

    Prevents double-processing of webhooks from external services like:
    - Stripe payments (payment.succeeded, invoice.payment_failed)
    - Virtualmin server events (domain.created, account.suspended)
    - Domain registrar events (domain.registered, domain.expired)
    - PayPal payments, bank notifications, etc.

    Critical for production reliability - prevents duplicate charges,
    double provisioning, and data corruption from retried webhooks.
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", _("⏳ Pending")),
        ("processed", _("✅ Processed")),
        ("failed", _("❌ Failed")),
        ("skipped", _("⏭️ Skipped")),  # Duplicate or irrelevant
    )

    SOURCE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("stripe", _("💳 Stripe")),
        ("paypal", _("🟡 PayPal")),
        ("virtualmin", _("🖥️ Virtualmin")),
        ("cpanel", _("🌐 cPanel")),
        ("registrar_namecheap", _("🏷️ Namecheap")),
        ("registrar_godaddy", _("🏷️ GoDaddy")),
        ("bank_bt", _("🏦 Banca Transilvania")),
        ("bank_bcr", _("🏦 BCR")),
        ("efactura", _("🇷🇴 e-Factura")),
        ("other", _("🔌 Other")),
    )

    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(
        max_length=50, choices=SOURCE_CHOICES, help_text=_("External service that sent the webhook")
    )
    event_id = models.CharField(max_length=255, help_text=_("Unique event ID from the external service"))
    event_type = models.CharField(
        max_length=100, help_text=_("Type of event (e.g., 'payment.succeeded', 'domain.created')")
    )

    # Processing status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    # Timing
    received_at = models.DateTimeField(default=timezone.now, help_text=_("When webhook was received by our system"))
    processed_at = models.DateTimeField(null=True, blank=True, help_text=_("When webhook processing completed"))

    # Data storage
    payload = models.JSONField(help_text=_("Complete webhook payload from external service"))
    signature = models.TextField(blank=True, help_text=_("Webhook signature for verification (e.g., Stripe signature)"))

    # Error handling
    error_message = models.TextField(blank=True, help_text=_("Error details if processing failed"))
    retry_count = models.PositiveIntegerField(
        default=0, validators=[MinValueValidator(0)], help_text=_("Number of processing attempts")
    )
    next_retry_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When to retry processing (for failed webhooks)")
    )

    # Metadata
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, help_text=_("IP address webhook was received from")
    )
    user_agent = models.TextField(blank=True, help_text=_("User agent of webhook sender"))
    headers = models.JSONField(default=dict, blank=True, help_text=_("HTTP headers from webhook request"))

    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("🔄 Webhook Event")
        verbose_name_plural = _("🔄 Webhook Events")

        # Prevent duplicate processing
        unique_together: ClassVar[list[list[str]]] = ("source", "event_id")

        indexes: ClassVar[tuple[models.Index, ...]] = (
            # Query pending webhooks for processing
            models.Index(
                fields=["status", "received_at"], name="webhook_pending_idx", condition=models.Q(status="pending")
            ),
            # Query failed webhooks for retry
            models.Index(
                fields=["status", "next_retry_at"],
                name="webhook_retry_idx",
                condition=models.Q(status="failed", next_retry_at__isnull=False),
            ),
            # Query by source and event type
            models.Index(fields=["source", "event_type", "received_at"], name="webhook_source_type_idx"),
        )

        ordering: ClassVar[tuple[str, ...]] = ("-received_at",)

    def __str__(self) -> str:
        return f"🔄 {self.get_source_display()} | {self.event_type} | {self.status}"

    @property
    def payload_hash(self) -> str:
        """📋 Generate hash of payload for deduplication by content"""
        payload_str = json.dumps(self.payload, sort_keys=True)
        return hashlib.sha256(payload_str.encode()).hexdigest()[:16]

    @property
    def processing_duration(self) -> Any | None:
        """⏱️ Time taken to process webhook"""
        if self.processed_at and self.received_at:
            return self.processed_at - self.received_at
        return None

    def mark_processed(self, save: bool = True) -> None:
        """✅ Mark webhook as successfully processed"""
        self.status = "processed"
        self.processed_at = timezone.now()
        if save:
            self.save(update_fields=["status", "processed_at", "updated_at"])

    def mark_failed(self, error_message: str, save: bool = True) -> None:
        """❌ Mark webhook as failed with error details"""
        self.status = "failed"
        self.error_message = error_message
        self.retry_count += 1
        self.processed_at = timezone.now()

        # Calculate next retry (exponential backoff)
        retry_delays = [300, 900, 3600, 7200, 21600]  # 5m, 15m, 1h, 2h, 6h
        if self.retry_count <= len(retry_delays):
            delay_seconds = retry_delays[self.retry_count - 1]
            self.next_retry_at = timezone.now() + timedelta(seconds=delay_seconds)

        if save:
            self.save(
                update_fields=["status", "error_message", "retry_count", "processed_at", "next_retry_at", "updated_at"]
            )

    def mark_skipped(self, reason: str = "Duplicate or irrelevant", save: bool = True) -> None:
        """⏭️ Mark webhook as skipped (duplicate/irrelevant)"""
        self.status = "skipped"
        self.error_message = reason
        self.processed_at = timezone.now()
        if save:
            self.save(update_fields=["status", "error_message", "processed_at", "updated_at"])

    @classmethod
    def is_duplicate(cls, source: str, event_id: str) -> bool:
        """🔍 Check if webhook has already been received"""
        return cls.objects.filter(source=source, event_id=event_id).exists()

    @classmethod
    def get_pending_webhooks(cls, source: str | None = None, limit: int = 100) -> QuerySet["WebhookEvent"]:
        """📋 Get pending webhooks for processing"""
        queryset = cls.objects.filter(status="pending").order_by("received_at")
        if source:
            queryset = queryset.filter(source=source)
        return queryset[:limit]

    @classmethod
    def get_failed_webhooks_for_retry(cls, source: str | None = None) -> QuerySet["WebhookEvent"]:
        """🔄 Get failed webhooks ready for retry"""
        now = timezone.now()
        queryset = cls.objects.filter(status="failed", next_retry_at__isnull=False, next_retry_at__lte=now).order_by(
            "next_retry_at"
        )
        if source:
            queryset = queryset.filter(source=source)
        return queryset


# ===============================================================================
# WEBHOOK DELIVERY TRACKING
# ===============================================================================


class WebhookDelivery(models.Model):
    """
    📤 Track outgoing webhook deliveries to customer endpoints

    For customers who want to receive webhooks about their services:
    - invoice.created, invoice.paid
    - service.provisioned, service.suspended
    - domain.registered, domain.expired
    """

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", _("⏳ Pending")),
        ("delivered", _("✅ Delivered")),
        ("failed", _("❌ Failed")),
        ("disabled", _("🚫 Disabled")),
    )

    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Customer endpoint
    customer = models.ForeignKey("customers.Customer", on_delete=models.CASCADE, related_name="webhook_deliveries")
    endpoint_url = models.URLField(help_text=_("Customer's webhook endpoint URL"))

    # Event details
    event_type = models.CharField(max_length=100, help_text=_("Type of event being delivered"))
    payload = models.JSONField(help_text=_("Webhook payload sent to customer"))

    # Delivery tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    http_status = models.PositiveIntegerField(
        null=True, blank=True, help_text=_("HTTP response status from customer endpoint")
    )
    response_body = models.TextField(blank=True, help_text=_("Response body from customer endpoint"))

    # Timing
    scheduled_at = models.DateTimeField(default=timezone.now)
    delivered_at = models.DateTimeField(null=True, blank=True)

    # Retry logic
    retry_count = models.PositiveIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("📤 Webhook Delivery")
        verbose_name_plural = _("📤 Webhook Deliveries")
        ordering: ClassVar[tuple[str, ...]] = ("-scheduled_at",)

        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["status", "scheduled_at"], name="delivery_pending_idx"),
            models.Index(fields=["customer", "event_type", "scheduled_at"], name="delivery_customer_idx"),
        )

    def __str__(self) -> str:
        return f"📤 {self.customer} | {self.event_type} | {self.status}"
