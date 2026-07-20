import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable
from http import HTTPStatus
from typing import Any

import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.billing.models import Payment
from apps.customers.models import Customer
from apps.integrations.models import WebhookEvent

from .base import BaseWebhookProcessor, verify_stripe_signature

logger = logging.getLogger(__name__)


# ===============================================================================
# STRIPE EVENT HANDLER REGISTRY
# ===============================================================================

StripeEventHandler = Callable[[str, dict[str, Any]], tuple[bool, str]]


# ===============================================================================
# STRIPE WEBHOOK PROCESSOR
# ===============================================================================


class StripeWebhookProcessor(BaseWebhookProcessor):
    """
    💳 Stripe webhook processor with deduplication

    Handles Stripe events:
    - payment_intent.succeeded → Update Payment status
    - payment_intent.payment_failed → Mark payment failed
    - customer.created → Link Stripe customer to our Customer
    - charge.dispute.created → Alert for dispute handling
    """

    source_name = "stripe"

    def extract_event_id(self, payload: dict[str, Any]) -> str:
        """🔍 Extract Stripe event ID"""
        return str(payload.get("id", ""))

    def extract_event_type(self, payload: dict[str, Any]) -> str:
        """🏷️ Extract Stripe event type"""
        return str(payload.get("type", ""))

    def verify_signature(
        self, payload: dict[str, Any], signature: str, headers: dict[str, str], raw_body: bytes | None = None
    ) -> bool:
        """🔐 Verify Stripe webhook signature using settings system.

        SECURITY FIX: Uses raw request body (_raw_body) instead of re-serialized JSON
        when available. This prevents signature bypass attacks where JSON key ordering
        or whitespace differences between the original request and re-serialization
        could allow forged payloads to pass verification.
        """
        try:
            from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
                SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
            )

            # Get encrypted webhook secret from settings system
            webhook_secret = SettingsService.get_setting("integrations.stripe_webhook_secret")

            if not webhook_secret:
                # Fallback to Django settings
                webhook_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", None)

            if not webhook_secret:
                # Fail secure when secret is not configured
                logger.error("Stripe webhook secret not configured in settings system - failing secure")
                return False

            # SECURITY: Use raw body from request, NOT re-serialized JSON
            if raw_body is None:
                # Fallback for backwards compatibility, but log warning
                logger.warning(
                    "⚠️ No raw body available for signature verification - using re-serialized JSON (less secure)"
                )
                payload_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            else:
                payload_body = raw_body if isinstance(raw_body, bytes) else raw_body.encode("utf-8")

            return verify_stripe_signature(
                payload_body=payload_body, stripe_signature=signature, webhook_secret=str(webhook_secret)
            )
        except Exception as e:
            logger.error(f"🔥 Error verifying Stripe webhook signature: {e}")
            return False

    def __init__(self) -> None:
        super().__init__()
        # Event handler registry - maps event prefixes to handler methods
        self._event_handlers: dict[str, StripeEventHandler] = {
            "payment_intent.": self.handle_payment_intent_event,
            "refund.": self.handle_refund_event,
            "customer.": self.handle_customer_event,
            "charge.": self.handle_charge_event,
            "setup_intent.": self.handle_setup_intent_event,
        }

    def handle_event(self, webhook_event: WebhookEvent) -> tuple[bool, str]:
        """🎯 Handle Stripe webhook event using handler registry"""
        event_type = webhook_event.event_type
        payload = webhook_event.payload

        try:
            # Find appropriate handler using registry
            handler = self._find_event_handler(event_type)

            if handler:
                return handler(event_type, payload)
            else:
                # Unknown event type - skip
                logger.info(f"⏭️ Skipping unknown Stripe event type: {event_type}")
                return True, f"Skipped unknown event type: {event_type}"

        except Exception:
            logger.exception(f"💥 Error handling Stripe event {event_type}")
            # SECURITY: Never expose internal exception details
            return False, "Handler error: internal processing failure"

    def _find_event_handler(self, event_type: str) -> StripeEventHandler | None:
        """Find the appropriate handler for the given event type."""
        for prefix, handler in self._event_handlers.items():
            if event_type.startswith(prefix):
                return handler
        return None

    def _handle_payment_intent_succeeded(  # noqa: C901, PLR0911, PLR0912  # Explicit recovery prevents charged/no-invoice loss
        self,
        stripe_payment_id: str,
        payment_intent: dict[str, Any],
    ) -> tuple[bool, str]:
        """Validate success, then convert a proforma using Proforma -> Payment lock order."""
        from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415

        previous_status = (
            Payment.objects.filter(gateway_txn_id=stripe_payment_id).values_list("status", flat=True).first()
        )
        convergence = PaymentSuccessService.converge_gateway_success(
            stripe_payment_id,
            {
                "amount_received": payment_intent.get("amount_received"),
                "currency": payment_intent.get("currency"),
                "customer_id": payment_intent.get("customer"),
                "payment_method_id": payment_intent.get("payment_method"),
                "metadata": payment_intent.get("metadata"),
            },
        )
        if convergence.is_err():
            error = convergence.unwrap_err()
            if error.startswith("Payment not found"):
                metadata = payment_intent.get("metadata")
                if isinstance(metadata, dict) and metadata.get("source") == "recurring_billing":
                    logger.critical(
                        "Recurring Stripe success %s has no exact local pending payment: %s",
                        stripe_payment_id,
                        error,
                    )
                    return False, error
                logger.warning("⚠️ Payment not found for Stripe PaymentIntent: %s", stripe_payment_id)
                return True, f"Payment not found (external): {stripe_payment_id}"
            logger.critical("Stripe success convergence rejected for %s: %s", stripe_payment_id, error)
            return False, error
        payment = convergence.unwrap()

        if payment.proforma_id is None:
            proforma_id_from_meta = (payment.meta or {}).get("proforma_id")
            if proforma_id_from_meta:
                from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415

                try:
                    recovered_proforma = ProformaInvoice.objects.get(id=proforma_id_from_meta)
                except ProformaInvoice.DoesNotExist:
                    logger.error(
                        "🔥 [Stripe] Proforma %s in payment %s metadata was not found",
                        proforma_id_from_meta,
                        payment.id,
                    )
                else:
                    if recovered_proforma.status == "converted":
                        return True, f"Payment {payment.id} already processed (idempotent)"
                    payment.proforma = recovered_proforma
                    payment.save(update_fields=["proforma", "updated_at"])
                    logger.warning(
                        "⚠️ [Stripe] Re-linked proforma %s to payment %s from metadata",
                        recovered_proforma.number,
                        payment.id,
                    )

        if payment.proforma:
            payment.proforma.refresh_from_db()
            if payment.proforma.status == "converted":
                return True, f"Payment {payment.id} already processed (idempotent)"
            try:
                from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

                convert_result = ProformaPaymentService.record_payment_and_convert(
                    proforma_id=str(payment.proforma.id),
                    amount_cents=payment.amount_cents,
                    payment_method="stripe",
                    existing_payment=payment,
                )
                if convert_result.is_err():
                    error = convert_result.unwrap_err()
                    logger.critical(
                        "🔥 [Stripe] Proforma conversion failed for payment %s: %s",
                        payment.id,
                        error,
                    )
                    return False, f"conversion failed: {error}"
            except Exception as exc:
                logger.exception("🔥 [Stripe] Proforma auto-convert failed: %s", exc)
                return False, f"conversion failed: {exc}"
        elif previous_status == "succeeded":
            return True, f"Payment {payment.id} already processed (idempotent)"

        transaction.on_commit(lambda: self._notify_portal_payment_success(payment, payment_intent))
        logger.info("✅ Payment %s marked as succeeded from Stripe", payment.id)
        return True, f"Payment {payment.id} succeeded"

    def handle_payment_intent_event(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Locked success/failure outcomes
        self, event_type: str, payload: dict[str, Any]
    ) -> tuple[bool, str]:
        """💳 Handle PaymentIntent events with race condition protection.

        SECURITY FIX: Uses select_for_update() to prevent race conditions where
        concurrent webhook deliveries could corrupt payment state.
        """
        payment_intent = payload.get("data", {}).get("object", {})
        stripe_payment_id = payment_intent.get("id")

        if not stripe_payment_id:
            return False, "Missing PaymentIntent ID"

        if event_type == "payment_intent.succeeded":
            return self._handle_payment_intent_succeeded(stripe_payment_id, payment_intent)

        # SECURITY: Use atomic transaction with row locking to prevent race conditions
        with transaction.atomic():
            try:
                # Lock the payment row to prevent concurrent updates
                payment = Payment.objects.select_for_update(of=("self",)).get(gateway_txn_id=stripe_payment_id)
            except Payment.DoesNotExist:
                metadata = payment_intent.get("metadata")
                if event_type == "payment_intent.payment_failed" and (
                    isinstance(metadata, dict) and metadata.get("source") == "recurring_billing"
                ):
                    from apps.billing.payment_convergence import PaymentSuccessService  # noqa: PLC0415

                    recovery = PaymentSuccessService.recover_unlinked_recurring_attempt(
                        stripe_payment_id,
                        {
                            "amount_received": payment_intent.get("amount"),
                            "currency": payment_intent.get("currency"),
                            "customer_id": payment_intent.get("customer"),
                            "payment_method_id": payment_intent.get("payment_method"),
                            "metadata": metadata,
                        },
                    )
                    if recovery.is_err():
                        error = recovery.unwrap_err()
                        logger.critical(
                            "Recurring Stripe failure %s has no exact local pending payment: %s",
                            stripe_payment_id,
                            error,
                        )
                        return False, error
                    payment = recovery.unwrap()
                else:
                    # The PaymentIntent may have been created outside PRAHO.
                    logger.warning("⚠️ Payment not found for Stripe PaymentIntent: %s", stripe_payment_id)
                    return True, f"Payment not found (external): {stripe_payment_id}"

            if event_type == "payment_intent.payment_failed":
                failure_reason = payment_intent.get("last_payment_error", {}).get("message", "Unknown error")

                meta_update = {
                    "stripe_payment_intent": stripe_payment_id,
                    "stripe_failure_reason": failure_reason,
                }
                changed = payment.apply_gateway_event("failed", meta_update)

                if not changed:
                    logger.warning(f"⚠️ Payment {payment.id} already in terminal state, ignoring failure event")
                    return True, f"Payment {payment.id} already in terminal state, ignoring failure"

                if (payment.meta or {}).get("source") == "recurring_billing":
                    from apps.billing.payment_convergence import (  # noqa: PLC0415
                        converge_recurring_payment_failure,
                    )

                    cycle_count = converge_recurring_payment_failure(payment)
                    if cycle_count == 0:
                        transaction.set_rollback(True)
                        logger.critical(
                            "Recurring Stripe failure %s has no linked billing cycle",
                            stripe_payment_id,
                        )
                        return False, "Recurring payment has no linked billing cycle"

                # Trigger dunning process if this was an invoice payment
                if payment.invoice:
                    try:
                        from apps.billing.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
                            start_dunning_process_async,  # Circular: cross-app
                        )

                        start_dunning_process_async(str(payment.invoice.id))
                        logger.info(f"🔔 Triggered dunning process for invoice {payment.invoice.id}")
                    except Exception as dunning_error:
                        logger.warning(f"⚠️ Failed to trigger dunning: {dunning_error}")

                # B7: On card failure, send proforma email as fallback so customer
                # can pay via bank transfer instead
                if payment.proforma and payment.proforma.status in ("draft", "sent"):
                    try:
                        from django.db import transaction as txn  # noqa: PLC0415

                        from apps.billing.proforma_service import send_proforma_email  # noqa: PLC0415

                        _proforma = payment.proforma
                        _payment_id = payment.id

                        # Task 4.5 fix: Re-fetch proforma status inside on_commit because
                        # status may have changed between now and when the callback runs
                        # (e.g., concurrent bank payment converted the proforma to "converted").
                        # Task 4.4 fix: Catch exceptions so email failures don't silently
                        # vanish — log at ERROR level so alerts surface the failure.
                        def _send_proforma_email_on_commit(
                            proforma: Any = _proforma, payment_id: Any = _payment_id
                        ) -> None:
                            try:
                                proforma.refresh_from_db()
                                if proforma.status in ("draft", "sent"):
                                    send_proforma_email(proforma)
                                else:
                                    logger.info(
                                        "⏭️ [Stripe] Skipped proforma email for payment %s — "
                                        "proforma status changed to %s",
                                        payment_id,
                                        proforma.status,
                                    )
                            except Exception as email_exc:
                                logger.error(
                                    "🔥 [Stripe] Proforma email failed for payment %s: %s",
                                    payment_id,
                                    email_exc,
                                    exc_info=True,
                                )

                        txn.on_commit(_send_proforma_email_on_commit)
                        logger.info(
                            "📧 [Stripe] Queued proforma email fallback for failed payment %s",
                            payment.id,
                        )
                    except Exception as e:
                        logger.warning("⚠️ [Stripe] Failed to queue proforma email fallback: %s", e)

                logger.warning(f"❌ Payment {payment.id} marked as failed from Stripe")
                return True, f"Payment {payment.id} failed"

            else:
                return True, f"Skipped PaymentIntent event: {event_type}"

    def handle_customer_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """👤 Handle Stripe Customer events"""
        stripe_customer = payload.get("data", {}).get("object", {})
        stripe_customer_id = stripe_customer.get("id")

        if event_type == "customer.created":
            # Link Stripe customer to our customer record
            customer_email = stripe_customer.get("email")

            if customer_email:
                try:
                    with transaction.atomic():
                        customer = Customer.objects.select_for_update(of=("self",)).get(primary_email=customer_email)
                        customer_meta = dict(customer.meta or {})
                        existing_customer_id = customer_meta.get("stripe_customer_id")

                        if existing_customer_id and stripe_customer_id and existing_customer_id != stripe_customer_id:
                            logger.warning(
                                "⚠️ [Stripe] Ignoring customer.created ID %s for %s; already linked to %s",
                                stripe_customer_id,
                                customer.id,
                                existing_customer_id,
                            )
                        elif stripe_customer_id:
                            customer_meta["stripe_customer_id"] = stripe_customer_id

                        customer_meta["stripe_linked_at"] = timezone.now().isoformat()
                        customer.meta = customer_meta
                        customer.save(update_fields=["meta", "updated_at"])

                    logger.info(f"🔗 Linked Stripe customer {stripe_customer_id} to {customer}")
                    return True, f"Customer linked: {customer}"

                except Customer.DoesNotExist:
                    logger.warning(f"⚠️ Customer not found for Stripe customer: {customer_email}")
                    return True, f"Customer not found: {customer_email}"

        return True, f"Skipped Customer event: {event_type}"

    @staticmethod
    def _stripe_string(value: Any) -> str:
        """Normalize a Stripe string or expandable reference without coercion."""
        if isinstance(value, dict):
            value = value.get("id")
        return value if isinstance(value, str) else ""

    @staticmethod
    def _stripe_integer(value: Any) -> int:
        """Normalize a Stripe integer while rejecting bool's int subtype."""
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    def handle_refund_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """Converge modern Stripe Refund events into PRAHO's ledger."""
        refund_object = payload.get("data", {}).get("object", {})
        if not isinstance(refund_object, dict):
            return False, "Malformed Stripe refund object"
        from apps.billing.refund_service import (  # noqa: PLC0415
            RefundConvergenceService,
            RefundGatewayFacts,
        )

        facts = RefundGatewayFacts(
            refund_id=self._stripe_string(refund_object.get("id")),
            payment_intent_id=self._stripe_string(refund_object.get("payment_intent")),
            amount_cents=self._stripe_integer(refund_object.get("amount")),
            currency=self._stripe_string(refund_object.get("currency")),
            status=self._stripe_string(refund_object.get("status")),
            reason=self._stripe_string(refund_object.get("reason")),
            failure_reason=self._stripe_string(refund_object.get("failure_reason")),
            event_id=self._stripe_string(payload.get("id")),
            event_created=self._stripe_integer(payload.get("created")),
        )
        result = RefundConvergenceService.converge_gateway_refund(facts)
        if result.is_err():
            error = result.unwrap_err()
            logger.critical("Stripe refund convergence rejected: %s", error)
            return False, error
        refund = result.unwrap()
        if refund is None:
            return True, f"Refund not found (external): {refund_object.get('id')}"
        return True, f"Refund {refund.gateway_refund_id} converged to {refund.status}"

    def _handle_charge_refunded(
        self,
        event_type: str,
        payload: dict[str, Any],
        charge: dict[str, Any],
    ) -> tuple[bool, str]:
        """Converge the embedded refunds from the legacy charge event."""
        refund_list = charge.get("refunds", {}).get("data", [])
        if not isinstance(refund_list, list):
            return False, "Malformed Stripe charge refunds"
        for refund_object in refund_list:
            if not isinstance(refund_object, dict):
                return False, "Malformed embedded Stripe refund"
            normalized_refund = {
                **refund_object,
                "payment_intent": refund_object.get("payment_intent") or charge.get("payment_intent"),
                "currency": refund_object.get("currency") or charge.get("currency"),
            }
            normalized_payload = {**payload, "data": {"object": normalized_refund}}
            accepted, message = self.handle_refund_event(event_type, normalized_payload)
            if not accepted:
                return False, message
        return True, f"Charge refunds converged: {len(refund_list)}"

    @staticmethod
    def _handle_charge_dispute(charge: dict[str, Any], charge_id: Any) -> tuple[bool, str]:
        """Reconcile a dispute and send the existing urgent notification."""
        dispute_id = charge_id
        payment_intent_id = StripeWebhookProcessor._stripe_string(charge.get("payment_intent")) or None
        dispute_amount = charge.get("amount", 0)
        if isinstance(dispute_amount, bool) or not isinstance(dispute_amount, int | float):
            dispute_amount = 0
        dispute_currency = str(charge.get("currency") or "unknown").upper()

        logger.critical(
            "🚨 DISPUTE CREATED %s for PaymentIntent %s - manual review required!",
            dispute_id,
            payment_intent_id,
        )

        if payment_intent_id:
            with transaction.atomic():
                payment = (
                    Payment.objects.select_for_update(of=("self",)).filter(gateway_txn_id=payment_intent_id).first()
                )
                if payment is not None and payment.status != "disputed":
                    changed = payment.apply_gateway_event(
                        "disputed",
                        {
                            "dispute_id": dispute_id,
                            "dispute_charge_id": charge.get("charge"),
                            "dispute_reason": charge.get("reason"),
                            "dispute_amount_cents": dispute_amount,
                            "dispute_currency": dispute_currency,
                            "dispute_created_at": timezone.now().isoformat(),
                        },
                    )
                    if not changed:
                        logger.critical(
                            "Stripe dispute %s could not transition payment %s from %s",
                            dispute_id,
                            payment.id,
                            payment.status,
                        )
                        return False, f"Payment {payment.id} cannot transition to disputed"
        else:
            logger.critical("Stripe dispute %s did not identify a PaymentIntent", dispute_id)

        try:
            from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
                NotificationService,  # Circular: cross-app  # Deferred: avoids circular import
            )

            NotificationService.send_admin_alert(
                subject=f"URGENT: Stripe Dispute Created - {dispute_id}",
                message=f"A dispute has been created for PaymentIntent {payment_intent_id or 'unknown'}.\n"
                f"Amount: {dispute_amount / 100:.2f} {dispute_currency}\n"
                f"Reason: {charge.get('reason', 'Unknown')}\n"
                f"Please review immediately.",
                alert_type="dispute",
                metadata={
                    "dispute_id": dispute_id,
                    "charge_id": charge.get("charge"),
                    "payment_intent_id": payment_intent_id,
                },
            )
        except Exception as notify_error:
            logger.error(f"⚠️ Failed to send dispute notification: {notify_error}")

        return True, f"Dispute created: {dispute_id}"

    def handle_charge_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """💰 Handle Stripe Charge events"""
        if event_type == "charge.refund.updated":
            return self.handle_refund_event(event_type, payload)

        charge = payload.get("data", {}).get("object", {})
        charge_id = charge.get("id")
        if event_type == "charge.refunded":
            return self._handle_charge_refunded(event_type, payload, charge)
        if event_type == "charge.dispute.created":
            return self._handle_charge_dispute(charge, charge_id)
        if event_type == "charge.succeeded":
            logger.info(f"✅ Stripe charge succeeded: {charge_id}")
            return True, f"Charge succeeded: {charge_id}"
        if event_type == "charge.failed":
            failure_reason = charge.get("failure_message", "Unknown error")
            logger.warning(f"❌ Stripe charge failed: {charge_id} - {failure_reason}")
            return True, f"Charge failed: {charge_id}"
        return True, f"Skipped Charge event: {event_type}"

    def handle_setup_intent_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """🔧 Handle SetupIntent events (for saved payment methods)"""
        setup_intent = payload.get("data", {}).get("object", {})
        setup_intent_id = setup_intent.get("id")

        if event_type == "setup_intent.succeeded":
            # Payment method saved successfully
            payment_method = setup_intent.get("payment_method")
            customer_id = setup_intent.get("customer")

            logger.info(f"💾 Payment method saved: {payment_method} for customer {customer_id}")
            return True, f"SetupIntent succeeded: {setup_intent_id}"

        return True, f"Skipped SetupIntent event: {event_type}"

    def _notify_portal_payment_success(self, payment: object, payment_intent: dict[str, Any]) -> None:
        """
        🔔 Notify Portal service of payment success

        Args:
            payment: Payment model instance
            payment_intent: Stripe PaymentIntent data
        """
        try:
            # Extract order ID from payment metadata
            order_id = payment.meta.get("order_id")  # type: ignore[attr-defined]
            if not order_id:
                logger.warning("⚠️ No order_id in payment metadata - skipping Portal notification")
                return

            # Check if this payment was created via Portal
            created_via = payment.meta.get("created_via")  # type: ignore[attr-defined]
            if created_via != "portal_checkout":
                logger.info("⏭️ Payment not from Portal checkout - skipping notification")
                return

            # Prepare notification data
            notification_data = {
                "order_id": order_id,
                "payment_id": str(payment.id),  # type: ignore[attr-defined]
                "status": "succeeded",
                "stripe_payment_intent_id": payment_intent.get("id"),
                "amount_received": payment_intent.get("amount_received"),
                "currency": payment_intent.get("currency", "ron").upper(),
                "timestamp": timezone.now().isoformat(),
            }

            # Send notification to Portal
            self._send_portal_webhook(notification_data)

            logger.info(f"✅ Notified Portal of payment success for order {order_id}")

        except Exception as e:
            logger.error(f"🔥 Error notifying Portal of payment success: {e}")
            # Don't fail the webhook processing if Portal notification fails

    def _send_portal_webhook(self, data: dict[str, Any]) -> None:
        """Send HMAC-signed webhook notification to Portal service."""
        try:
            # Get Portal webhook URL from settings
            portal_webhook_url = getattr(settings, "PORTAL_PAYMENT_WEBHOOK_URL", None)
            if not portal_webhook_url:
                logger.warning("⚠️ PORTAL_PAYMENT_WEBHOOK_URL not configured - skipping notification")
                return

            webhook_secret = getattr(settings, "PLATFORM_TO_PORTAL_WEBHOOK_SECRET", "")
            if not webhook_secret:
                logger.error("🔥 PLATFORM_TO_PORTAL_WEBHOOK_SECRET not configured — cannot sign portal webhook")
                return

            # Compute HMAC-SHA256 signature: ts + "." + body (matches portal _verify_platform_webhook)
            body = json.dumps(data, separators=(",", ":")).encode()
            ts = str(int(time.time()))
            payload = ts.encode() + b"." + body
            signature = hmac.new(webhook_secret.encode(), payload, hashlib.sha256).hexdigest()

            # Send POST request to Portal via safe_request (internal service)
            from apps.common.outbound_http import (  # noqa: PLC0415  # Deferred: avoids circular import
                INTERNAL_SERVICE,
                safe_request,
            )

            response = safe_request(
                "POST",
                portal_webhook_url,
                policy=INTERNAL_SERVICE,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Platform-Signature": signature,
                    "X-Platform-Timestamp": ts,
                },
            )

            if response.status_code == HTTPStatus.OK:
                logger.info(f"✅ Successfully notified Portal: {response.status_code}")
            else:
                logger.warning(f"⚠️ Portal notification failed: {response.status_code} - {response.text}")

        except requests.exceptions.Timeout:
            logger.error("🕐 Portal notification timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 Portal notification request failed: {e}")
        except Exception as e:
            logger.error(f"🔥 Unexpected error sending Portal notification: {e}")
