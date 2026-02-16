import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, cast

from django.db import transaction
from django.utils import timezone

from apps.common.constants import DAYS_PER_WEEK
from apps.common.types import Err, Ok, Result
from apps.integrations.models import WebhookEvent

logger = logging.getLogger(__name__)

# Webhook signature parsing constants
EXPECTED_KEY_VALUE_PARTS = 2  # Expected parts when splitting key=value format


class SecurityError(Exception):
    """🔒 Security-related errors in webhook processing"""


# ===============================================================================
# WEBHOOK PROCESSING RESULT TYPES
# ===============================================================================


@dataclass(frozen=True)
class WebhookProcessingResult:
    """Result of webhook processing with success flag, message, and optional event."""

    success: bool
    message: str
    webhook_event: WebhookEvent | None = None

    def to_tuple(self) -> tuple[bool, str, WebhookEvent | None]:
        """Convert to legacy tuple format for backward compatibility."""
        return (self.success, self.message, self.webhook_event)

    @classmethod
    def success_result(cls, message: str, event: WebhookEvent) -> "WebhookProcessingResult":
        """Create a successful result."""
        return cls(success=True, message=message, webhook_event=event)

    @classmethod
    def error_result(cls, message: str, event: WebhookEvent | None = None) -> "WebhookProcessingResult":
        """Create an error result."""
        return cls(success=False, message=message, webhook_event=event)


@dataclass(frozen=True)
class WebhookContext:
    """Context for webhook event processing."""

    payload: dict[str, Any]
    signature: str
    headers: dict[str, str]
    raw_body: bytes | None
    ip_address: str | None
    user_agent: str | None
    event_info: dict[str, str]


@dataclass(frozen=True)
class WebhookRequestMetadata:
    """Metadata extracted from webhook request."""

    signature: str
    headers: dict[str, str]
    raw_body: bytes | None
    ip_address: str | None
    user_agent: str | None


# ===============================================================================
# BASE WEBHOOK PROCESSING
# ===============================================================================


class BaseWebhookProcessor(ABC):
    """
    🔧 Abstract base class for webhook processing with deduplication

    Provides common functionality for all webhook sources:
    - Signature verification
    - Deduplication checking
    - Error handling and retry logic
    - Audit logging
    """

    source_name: str | None = None  # Override in subclasses

    def __init__(self) -> None:
        # Enforce abstract contract via ABC for verify_signature
        if not self.source_name:
            # Keep defensive check, but ABC prevents direct instantiation anyway
            self.source_name = self.__class__.__name__.lower()

        # Validate that signature implementation is secure
        self._validate_signature_implementation()

    def process_webhook(
        self,
        payload: dict[str, Any],
        signature: str = "",
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, str, WebhookEvent | None]:
        """
        🔄 Main webhook processing pipeline

        Returns:
            (success: bool, message: str, webhook_event: WebhookEvent)
        """
        headers = headers or {}

        try:
            metadata = WebhookRequestMetadata(signature, headers, raw_body, ip_address, user_agent)
            result = (
                self._validate_payload(payload)
                .and_then(lambda event_info: self._check_duplicates(event_info))
                .and_then(lambda event_info: self._create_context(payload, metadata, event_info))
                .and_then(lambda context: self._verify_signature_with_context(context))
                .and_then(lambda context: self._create_and_process_event(context))
            )

            # Type-safe handling of Result union types using match statement
            match result:
                case Ok(processing_result):
                    # result is Ok[WebhookProcessingResult] - safe to access .value
                    return cast("tuple[bool, str, WebhookEvent | None]", processing_result.to_tuple())
                case Err(error_message):
                    # result is Err[str] - safe to access .error
                    # Handle special duplicate case
                    if error_message.startswith("DUPLICATE:"):
                        event_id = error_message[10:]  # Remove "DUPLICATE:" prefix
                        # source_name is guaranteed to be not None after __init__ validation
                        assert self.source_name is not None
                        existing = WebhookEvent.objects.get(source=self.source_name, event_id=event_id)
                        return WebhookProcessingResult.success_result(
                            f"⏭️ Duplicate webhook skipped: {event_id}", existing
                        ).to_tuple()

                    return WebhookProcessingResult.error_result(error_message).to_tuple()

        except Exception:
            logger.exception(f"💥 Critical error processing {self.source_name} webhook")
            # SECURITY: Never expose internal exception details
            return WebhookProcessingResult.error_result("Critical error: internal processing failure").to_tuple()

    def _validate_payload(self, payload: dict[str, Any]) -> Result[dict[str, str], str]:
        """Step 1: Validate payload and extract event information."""
        event_id = self.extract_event_id(payload)
        event_type = self.extract_event_type(payload)

        if not event_id:
            return Err("❌ Missing event ID in payload")

        if not event_type:
            return Err("❌ Missing event type in payload")

        return Ok({"event_id": event_id, "event_type": event_type})

    def _check_duplicates(self, event_info: dict[str, str]) -> Result[dict[str, str], str]:
        """Step 2: Check for duplicate webhook processing.

        Note: This is a preliminary check only. The authoritative duplicate check
        happens inside _create_and_process_event within the atomic block, which uses
        database constraints (unique_together) to prevent race conditions.
        """
        event_id = event_info["event_id"]

        # source_name is guaranteed to be not None after __init__ validation
        assert self.source_name is not None
        if WebhookEvent.is_duplicate(self.source_name, event_id):
            logger.info(f"🔄 Duplicate webhook {self.source_name}:{event_id} - skipping")
            # Return special error that will be handled as success
            return Err(f"DUPLICATE:{event_id}")

        return Ok(event_info)

    def _create_context(
        self, payload: dict[str, Any], metadata: WebhookRequestMetadata, event_info: dict[str, str]
    ) -> Result[WebhookContext, str]:
        """Step 3: Create webhook processing context."""
        context = WebhookContext(
            payload=payload,
            signature=metadata.signature,
            headers=metadata.headers,
            raw_body=metadata.raw_body,
            ip_address=metadata.ip_address,
            user_agent=metadata.user_agent,
            event_info=event_info,
        )
        return Ok(context)

    def _verify_signature_with_context(self, context: WebhookContext) -> Result[WebhookContext, str]:
        """Step 4: Verify webhook signature using context."""
        if not self.verify_signature(context.payload, context.signature, context.headers, context.raw_body):
            return Err("❌ Invalid webhook signature")

        return Ok(context)

    def _create_and_process_event(self, context: WebhookContext) -> Result[WebhookProcessingResult, str]:
        """Step 5: Create webhook event record and process it.

        Uses database unique constraint (source, event_id) to prevent race conditions.
        If a concurrent request creates the same event, IntegrityError is caught and
        handled as a duplicate.
        """
        from django.db import IntegrityError

        event_id = context.event_info["event_id"]
        event_type = context.event_info["event_type"]

        # source_name is guaranteed to be not None after __init__ validation
        assert self.source_name is not None

        try:
            with transaction.atomic():
                # Use select_for_update with NOWAIT or try-create pattern
                # The unique_together constraint on (source, event_id) prevents duplicates
                webhook_event = WebhookEvent.objects.create(
                    source=self.source_name,
                    event_id=event_id,
                    event_type=event_type,
                    payload=context.payload,
                    signature_hash=(
                        hashlib.sha256(context.signature.encode()).hexdigest() if context.signature else ""
                    ),
                    ip_address=context.ip_address,
                    user_agent=context.user_agent or "",  # Convert None to empty string for TextField
                    headers=self._sanitize_headers(context.headers),
                    status="pending",
                )

                try:
                    success, message = self.handle_event(webhook_event)

                    if success:
                        webhook_event.mark_processed()
                        logger.info(f"✅ Processed {self.source_name} webhook {event_id}: {message}")
                        return Ok(WebhookProcessingResult.success_result(message, webhook_event))
                    else:
                        webhook_event.mark_failed(message)
                        logger.error(f"❌ Failed {self.source_name} webhook {event_id}: {message}")
                        return Ok(WebhookProcessingResult.error_result(message, webhook_event))

                except Exception:
                    # SECURITY: Log full details internally but don't expose to caller
                    error_msg = "Processing error: internal failure"
                    webhook_event.mark_failed(error_msg)
                    logger.exception(f"💥 Exception processing {self.source_name} webhook {event_id}")
                    return Ok(WebhookProcessingResult.error_result(error_msg, webhook_event))

        except IntegrityError:
            # Race condition: another request created this event first
            # This is expected behavior - treat as duplicate
            logger.info(f"🔄 Duplicate webhook {self.source_name}:{event_id} detected via constraint - skipping")
            existing = WebhookEvent.objects.get(source=self.source_name, event_id=event_id)
            return Ok(WebhookProcessingResult.success_result(f"⏭️ Duplicate webhook skipped: {event_id}", existing))

    def extract_event_id(self, payload: dict[str, Any]) -> str | None:
        """🔍 Extract unique event ID from payload - override in subclasses"""
        return payload.get("id")

    def extract_event_type(self, payload: dict[str, Any]) -> str | None:
        """🏷️ Extract event type from payload - override in subclasses"""
        return payload.get("type")

    @abstractmethod
    def verify_signature(
        self, payload: dict[str, Any], signature: str, headers: dict[str, str], raw_body: bytes | None = None
    ) -> bool:
        """🔐 Verify webhook signature - must be implemented by subclasses"""

    @staticmethod
    def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
        """Redact sensitive headers before storing."""
        if not headers:
            return {}
        sensitive = {
            "authorization",
            "cookie",
            "set-cookie",
            "stripe-signature",
            "paypal-auth-assertion",
            "x-signature",
            "x-hub-signature",
            "x-hub-signature-256",
        }
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            if key.lower() in sensitive:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        return sanitized

    def handle_event(self, webhook_event: WebhookEvent) -> tuple[bool, str]:
        """
        🎯 Handle specific webhook event - override in subclasses

        Returns:
            (success: bool, message: str)
        """
        raise NotImplementedError("Subclasses must implement handle_event")

    # --- Security enforcement helpers (required by tests) ---
    def _validate_signature_implementation(self) -> None:
        """Validate that verify_signature is not overly permissive.

        Raises SecurityError if the implementation appears to accept obviously invalid signatures.
        """
        try:
            # Obviously invalid combinations that should never verify
            always_false_cases = [
                ({}, "", {}),
                ({"test": "data"}, "obviously_invalid_signature_12345", {}),
                ({}, "short", {"X-Test": "1"}),
            ]

            for payload, signature, headers in always_false_cases:
                if self.verify_signature(payload, signature, headers):
                    raise SecurityError("Overly permissive signature verification detected")
        except SecurityError:
            raise
        except Exception:
            # Any exception implies not permissive (or properly failing) in this context
            return


# ===============================================================================
# WEBHOOK SIGNATURE VERIFICATION UTILITIES
# ===============================================================================


def verify_hmac_signature(payload_body: bytes, signature: str, secret: str, algorithm: str = "sha256") -> bool:
    """
    🔐 Verify HMAC signature for webhook authenticity

    Used by services like Stripe, PayPal, etc.
    """
    if not signature or not secret:
        return False

    try:
        # Calculate expected signature
        mac = hmac.new(secret.encode("utf-8"), payload_body, getattr(hashlib, algorithm))
        expected_signature = mac.hexdigest()

        # Compare signatures (timing-safe)
        return hmac.compare_digest(signature, expected_signature)

    except Exception as e:
        logger.error(f"❌ Signature verification error: {e}")
        return False


def verify_stripe_signature(
    payload_body: bytes, stripe_signature: str, webhook_secret: str, tolerance: int = 300
) -> bool:
    """
    🔐 Verify Stripe webhook signature with timestamp validation

    Stripe signature format: t=timestamp,v1=signature
    """
    if not stripe_signature or not webhook_secret:
        return False

    try:
        # Parse Stripe signature header
        elements = stripe_signature.split(",")
        timestamp = None
        signature = None

        for element in elements:
            if "=" not in element:
                continue  # Skip malformed elements
            parts = element.split("=", 1)
            if len(parts) != EXPECTED_KEY_VALUE_PARTS:
                continue  # Skip malformed elements
            key, value = parts
            if key == "t":
                timestamp = int(value)
            elif key == "v1":
                signature = value

        if not timestamp or not signature:
            return False

        # Check timestamp (prevent replay attacks)
        current_time = int(timezone.now().timestamp())
        if current_time - timestamp > tolerance:
            logger.warning(f"⏰ Stripe webhook timestamp too old: {current_time - timestamp}s")
            return False

        # Verify signature
        payload_for_signature = f"{timestamp}.{payload_body.decode('utf-8')}"
        expected_signature = hmac.new(
            webhook_secret.encode("utf-8"), payload_for_signature.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)

    except Exception as e:
        logger.error(f"❌ Stripe signature verification error: {e}")
        return False


# ===============================================================================
# WEBHOOK RETRY UTILITIES
# ===============================================================================


def calculate_retry_delay(retry_count: int) -> int:
    """
    ⏱️ Calculate exponential backoff delay for webhook retries

    Returns delay in seconds:
    - Attempt 1: 5 minutes
    - Attempt 2: 15 minutes
    - Attempt 3: 1 hour
    - Attempt 4: 2 hours
    - Attempt 5: 6 hours
    """
    delays = [300, 900, 3600, 7200, 21600]  # 5m, 15m, 1h, 2h, 6h

    if retry_count <= len(delays):
        return delays[retry_count - 1]

    # After max retries, delay 24 hours
    return 86400


def should_retry_webhook(webhook_event: WebhookEvent, max_retries: int = 5) -> bool:
    """
    🔄 Determine if webhook should be retried based on failure count and age
    """
    # Don't retry if already processed or skipped
    if webhook_event.status in ["processed", "skipped"]:
        return False

    # Don't retry if exceeded max attempts
    if webhook_event.retry_count >= max_retries:
        return False

    # Don't retry if webhook is too old (7 days)
    age_days = (timezone.now() - webhook_event.received_at).days
    return not age_days > DAYS_PER_WEEK


# ===============================================================================
# WEBHOOK PROCESSING QUEUE
# ===============================================================================


def process_pending_webhooks(source: str | None = None, limit: int = 100) -> dict[str, int]:
    """
    🔄 Process pending webhooks in queue

    Returns stats: {processed: int, failed: int, skipped: int}
    """
    stats = {"processed": 0, "failed": 0, "skipped": 0}

    pending_webhooks = WebhookEvent.get_pending_webhooks(source=source, limit=limit)

    for webhook_event in pending_webhooks:
        try:
            # Dynamically get processor for this source
            processor = get_webhook_processor(webhook_event.source)

            if not processor:
                webhook_event.mark_failed(f"No processor found for source: {webhook_event.source}")
                stats["failed"] += 1
                continue

            # Process the webhook
            success, message = processor.handle_event(webhook_event)

            if success:
                webhook_event.mark_processed()
                stats["processed"] += 1
            else:
                webhook_event.mark_failed(message)
                stats["failed"] += 1

        except Exception as e:
            webhook_event.mark_failed(f"Processing exception: {e!s}")
            stats["failed"] += 1
            logger.exception(f"💥 Error processing webhook {webhook_event.id}")

    return stats


def retry_failed_webhooks(source: str | None = None) -> dict[str, int]:
    """
    🔄 Retry failed webhooks that are ready for retry

    Returns stats: {retried: int, failed: int, abandoned: int}
    """
    stats = {"retried": 0, "failed": 0, "abandoned": 0}

    failed_webhooks = WebhookEvent.get_failed_webhooks_for_retry(source=source)

    for webhook_event in failed_webhooks:
        if not should_retry_webhook(webhook_event):
            webhook_event.mark_skipped("Max retries exceeded or too old")
            stats["abandoned"] += 1
            continue

        try:
            # Reset to pending for retry
            webhook_event.status = "pending"
            webhook_event.next_retry_at = None
            webhook_event.save(update_fields=["status", "next_retry_at", "updated_at"])

            # Process the webhook
            processor = get_webhook_processor(webhook_event.source)
            if not processor:
                webhook_event.mark_failed(f"No processor found for source: {webhook_event.source}")
                stats["failed"] += 1
                continue

            success, message = processor.handle_event(webhook_event)

            if success:
                webhook_event.mark_processed()
                stats["retried"] += 1
            else:
                webhook_event.mark_failed(message)
                stats["failed"] += 1

        except Exception as e:
            webhook_event.mark_failed(f"Retry exception: {e!s}")
            stats["failed"] += 1
            logger.exception(f"💥 Error retrying webhook {webhook_event.id}")

    return stats


def get_webhook_processor(source: str) -> BaseWebhookProcessor | None:
    """
    🏭 Factory function to get appropriate webhook processor
    """
    # Import here to avoid circular imports
    from .efactura import EFacturaWebhookProcessor  # noqa: PLC0415
    from .stripe import StripeWebhookProcessor  # noqa: PLC0415

    processors = {
        "stripe": StripeWebhookProcessor,
        "efactura": EFacturaWebhookProcessor,
    }

    processor_class = processors.get(source)
    if processor_class:
        return processor_class()

    return None
