import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from django.db import DatabaseError, transaction
from django.utils import timezone

from apps.common.constants import DAYS_PER_WEEK
from apps.common.types import Err, Ok, Result
from apps.integrations.models import WebhookEvent

logger = logging.getLogger(__name__)

# Webhook signature parsing constants
EXPECTED_KEY_VALUE_PARTS = 2  # Expected parts when splitting key=value format


class WebhookHandlerError(Exception):
    """A refused handler must roll back its database effects."""


class SecurityError(Exception):
    """🔒 Security-related errors in webhook processing"""


class WebhookConfigurationError(Exception):
    """The endpoint cannot verify deliveries (its secret is unreadable): the operator's fault to fix.

    It is not a forged request, so the sender is told to try again (503), not that its signature is bad.
    """


WEBHOOK_CONFIGURATION_ERROR = "Webhook endpoint unavailable; try again later"


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

    def process_webhook(  # webhook handler parameters  # noqa: PLR0913  # Business logic parameters
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
                .and_then(lambda event_info: self._create_context(payload, metadata, event_info))
                .and_then(self._verify_signature_with_context)
                .and_then(self._check_duplicates)
                .and_then(self._create_and_process_event)
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

    def _check_duplicates(self, context: WebhookContext) -> Result[WebhookContext, str]:
        """Step 4: Check for duplicate webhook processing.

        This runs only after the signature has been verified. Answering "already processed"
        to an unauthenticated caller would confirm that an event id exists and hand back the
        internal id of the stored event.

        Note: This is a preliminary check only. The authoritative duplicate check
        happens inside _create_and_process_event within the atomic block, which uses
        database constraints (unique_together) to prevent race conditions.
        """
        event_id = context.event_info["event_id"]

        # source_name is guaranteed to be not None after __init__ validation
        assert self.source_name is not None
        if WebhookEvent.is_duplicate(self.source_name, event_id):
            logger.info(f"🔄 Duplicate webhook {self.source_name}:{event_id} - skipping")
            # Return special error that will be handled as success
            return Err(f"DUPLICATE:{event_id}")

        return Ok(context)

    def _create_context(
        self, payload: dict[str, Any], metadata: WebhookRequestMetadata, event_info: dict[str, str]
    ) -> Result[WebhookContext, str]:
        """Step 2: Create webhook processing context."""
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
        """Step 3: Verify webhook signature using context."""
        try:
            verified = self.verify_signature(context.payload, context.signature, context.headers, context.raw_body)
        except WebhookConfigurationError as error:
            # Logged here, once per delivery: the self-test at construction swallows it silently.
            logger.critical(
                f"🔥 [Webhooks] {self.source_name} webhook secret cannot be read, deliveries get 503: {error}"
            )
            return Err(WEBHOOK_CONFIGURATION_ERROR)
        if not verified:
            return Err("❌ Invalid webhook signature")

        return Ok(context)

    def _create_and_process_event(self, context: WebhookContext) -> Result[WebhookProcessingResult, str]:
        """Step 5: Create webhook event record and process it.

        Uses database unique constraint (source, event_id) to prevent race conditions.
        If a concurrent request creates the same event, IntegrityError is caught and
        handled as a duplicate.
        """
        from django.db import (  # noqa: PLC0415  # Deferred: avoids circular import
            IntegrityError,  # Deferred: exception used in except clause  # Deferred: avoids circular import
        )

        event_id = context.event_info["event_id"]
        event_type = context.event_info["event_type"]

        # source_name is guaranteed to be not None after __init__ validation
        assert self.source_name is not None

        signature_hash = hashlib.sha256(context.signature.encode()).hexdigest() if context.signature else ""

        try:
            with transaction.atomic():
                # get_or_create keyed on the unique (source, event_id): a first delivery inserts a
                # pending row; a redelivery of a non-processed event returns the existing one so it
                # can be reprocessed in place rather than colliding with the constraint (#234).
                # _check_duplicates has already filtered out events that reached "processed", so
                # anything reaching here is either new or a previously-failed/pending redelivery.
                webhook_event, created = WebhookEvent.objects.select_for_update().get_or_create(
                    source=self.source_name,
                    event_id=event_id,
                    defaults={
                        "event_type": event_type,
                        "payload": context.payload,
                        "signature_hash": signature_hash,
                        "ip_address": context.ip_address,
                        "user_agent": context.user_agent or "",
                        "headers": self._sanitize_headers(context.headers),
                        "status": "pending",
                    },
                )

                # A concurrent request may have processed it between the duplicate check and the
                # row lock; re-check under the lock so we never re-run a completed handler. Note
                # this only guards against re-running a *completed* handler: two concurrent
                # redeliveries of a still-failed event can both reach handle_event, so handlers
                # must be idempotent (the payment handlers converge on gateway state and are). The
                # manual retry command (process_webhooks) already reprocessed failed events through
                # the same path, so this is a pre-existing contract, not a new requirement.
                if not created and webhook_event.status == "processed":
                    logger.info(f"🔄 Webhook {self.source_name}:{event_id} already processed - skipping")
                    return Ok(
                        WebhookProcessingResult.success_result(
                            f"⏭️ Duplicate webhook skipped: {event_id}", webhook_event
                        )
                    )

                return Ok(self._execute_locked(webhook_event))

        except IntegrityError:
            # get_or_create handles the (source, event_id) race internally, so this backstop is
            # near-unreachable; it stays as belt-and-braces. Re-read the row and only treat a
            # completed one as a duplicate. A non-processed row returns an error so the sender keeps
            # retrying rather than being told the event succeeded. The message is intentionally
            # generic (no internal state) since it reaches the external caller.
            logger.info(f"🔄 Concurrent webhook {self.source_name}:{event_id} detected via constraint")
            try:
                existing = WebhookEvent.objects.get(source=self.source_name, event_id=event_id)
            except WebhookEvent.DoesNotExist:
                # The conflicting transaction hasn't committed yet (or the IntegrityError came
                # from a different constraint) — tell the sender to retry rather than crash.
                return Ok(WebhookProcessingResult.error_result("Webhook is being processed; please retry"))
            if existing.status == "processed":
                return Ok(WebhookProcessingResult.success_result(f"⏭️ Duplicate webhook skipped: {event_id}", existing))
            return Ok(WebhookProcessingResult.error_result("Webhook is being processed; please retry", existing))

    def _execute_locked(self, event: WebhookEvent) -> WebhookProcessingResult:
        """Run effects in a savepoint while the caller retains the event claim.

        Refusal evidence recorded by the handler is written once the savepoint is settled, so it survives a
        refusal's rollback (record_refusal_evidence).
        """
        from apps.common.validators import (  # noqa: PLC0415  # Deferred: common imports users at module level
            refusal_evidence_kept,
            write_refusal_evidence,
        )

        with refusal_evidence_kept() as evidence:
            result = self._run_locked(event)
        write_refusal_evidence(evidence)
        return result

    def _run_locked(self, event: WebhookEvent) -> WebhookProcessingResult:
        try:
            with transaction.atomic():
                success, message = self.handle_event(event)
                if not success:
                    raise WebhookHandlerError(message)
        except Exception as error:
            # A database error must roll back before failure-recording SQL can run.
            event.refresh_from_db()
            message = str(error) if isinstance(error, WebhookHandlerError) else "Processing error: internal failure"
            event.mark_failed(message)
            try:
                with transaction.atomic():
                    self.on_failure(event, message)
            except Exception:
                logger.exception("Could not schedule failure follow-up for webhook %s", event.pk)
            if not isinstance(error, WebhookHandlerError):
                logger.exception("Webhook handler failed for event %s", event.pk)
            return WebhookProcessingResult.error_result(message, event)
        event.mark_processed()
        return WebhookProcessingResult.success_result(message, event)

    def on_failure(self, event: WebhookEvent, message: str) -> None:
        """Schedule source-specific follow-up after the failed state is persisted."""
        return None

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
        signatures: list[str] = []

        for element in elements:
            if "=" not in element:
                continue  # Skip malformed elements
            parts = element.split("=", 1)
            if len(parts) != EXPECTED_KEY_VALUE_PARTS:
                continue  # Skip malformed elements
            key, value = parts
            key, value = key.strip(), value.strip()
            if key == "t":
                timestamp = int(value)
            elif key == "v1":
                signatures.append(value)

        if timestamp is None or not signatures:
            return False

        # Check timestamp (prevent replay attacks)
        current_time = int(timezone.now().timestamp())
        if timestamp < current_time - tolerance:
            timestamp_age = current_time - timestamp
            logger.warning(f"⏰ Stripe webhook timestamp too old: {timestamp_age}s")
            return False

        # Stripe emits one v1 signature per active endpoint secret during rotation.
        payload_for_signature = f"{timestamp}.{payload_body.decode('utf-8')}"
        expected_signature = hmac.new(
            webhook_secret.encode("utf-8"), payload_for_signature.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return any(hmac.compare_digest(signature, expected_signature) for signature in signatures)

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

    for _attempt in range(max(0, limit)):
        with transaction.atomic():
            candidates = WebhookEvent.objects.filter(status="pending")
            if source:
                candidates = candidates.filter(source=source)
            event = candidates.order_by("received_at", "pk").select_for_update(skip_locked=True).first()
            if event is None:
                break
            processor = get_webhook_processor(event.source)
            if processor is None:
                event.mark_failed(f"No processor found for source: {event.source}")
                stats["failed"] += 1
                continue
            result = processor._execute_locked(event)
            stats["processed" if result.success else "failed"] += 1
    return stats


def retry_failed_webhooks(source: str | None = None) -> dict[str, int]:
    """Claim each due retry once, retaining the claim through status persistence."""
    stats = {"retried": 0, "failed": 0, "abandoned": 0}
    attempted: set[object] = set()
    while True:
        with transaction.atomic():
            candidates = WebhookEvent.get_failed_webhooks_for_retry(source=source).exclude(pk__in=attempted)
            event = candidates.order_by("received_at", "pk").select_for_update(skip_locked=True).first()
            if event is None:
                break
            attempted.add(event.pk)
            if not should_retry_webhook(event):
                event.mark_skipped("Max retries exceeded or too old")
                stats["abandoned"] += 1
                continue
            processor = get_webhook_processor(event.source)
            if processor is None:
                event.mark_failed(f"No processor found for source: {event.source}")
                stats["failed"] += 1
                continue
            result = processor._execute_locked(event)
            stats["retried" if result.success else "failed"] += 1
    return stats


WEBHOOK_BUSY = "Webhook is being processed; try again shortly"
WEBHOOK_NO_LONGER_FAILED = "Webhook is no longer failed; nothing to retry"


def reprocess_failed_event(event_pk: UUID | str) -> Result[WebhookProcessingResult, str]:
    """Retry one failed event as any other processing runs it (#751 follow-up, M8).

    The event is claimed under its row lock without waiting (a redelivery or a drain holding it means it is
    being processed now), re-checked under the lock, and run in the executor's savepoint, so a refusal keeps
    nothing and the failure follow-up runs.
    """
    with transaction.atomic():
        try:
            with transaction.atomic():  # Its own savepoint: a lock refusal must not poison the transaction
                event = WebhookEvent.objects.select_for_update(nowait=True).get(pk=event_pk)
        except WebhookEvent.DoesNotExist:
            return Err("Webhook not found")
        except DatabaseError:
            return Err(WEBHOOK_BUSY)
        if event.status != "failed":
            return Err(WEBHOOK_NO_LONGER_FAILED)
        processor = get_webhook_processor(event.source)
        if processor is None:
            return Err(f"No processor found for source: {event.source}")
        return Ok(processor._execute_locked(event))


def get_webhook_processor(source: str) -> BaseWebhookProcessor | None:
    """
    🏭 Factory function to get appropriate webhook processor
    """
    # Import here to avoid circular imports
    from .efactura import (  # noqa: PLC0415  # Deferred: avoids circular import
        EFacturaWebhookProcessor,  # Circular: factory pattern  # Deferred: avoids circular import
    )
    from .stripe import (  # noqa: PLC0415  # Deferred: avoids circular import
        StripeWebhookProcessor,  # Circular: factory pattern  # Deferred: avoids circular import
    )

    processors = {
        "stripe": StripeWebhookProcessor,
        "efactura": EFacturaWebhookProcessor,
    }

    processor_class = processors.get(source)
    if processor_class:
        return processor_class()

    return None
