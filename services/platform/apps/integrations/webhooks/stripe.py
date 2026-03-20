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
    - invoice.payment_succeeded → Update Invoice status
    - invoice.payment_failed → Trigger dunning process
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
            "invoice.": self.handle_invoice_event,
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

    def handle_payment_intent_event(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Complexity: payment_intent.succeeded/failed paths share state, extraction would fragment the lock scope
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

        # SECURITY: Use atomic transaction with row locking to prevent race conditions
        with transaction.atomic():
            try:
                # Lock the payment row to prevent concurrent updates
                payment = Payment.objects.select_for_update(of=("self",)).get(gateway_txn_id=stripe_payment_id)
            except Payment.DoesNotExist:
                # Payment not found - might be created outside our system
                logger.warning(f"⚠️ Payment not found for Stripe PaymentIntent: {stripe_payment_id}")
                return True, f"Payment not found (external): {stripe_payment_id}"

            if event_type == "payment_intent.succeeded":
                meta_update = {
                    "stripe_payment_intent": stripe_payment_id,
                    "stripe_payment_method": payment_intent.get("payment_method"),
                    "stripe_amount_received": payment_intent.get("amount_received"),
                }
                changed = payment.apply_gateway_event("succeeded", meta_update)

                if not changed:
                    logger.info(f"⏭️ Payment {payment.id} already in terminal state, skipping duplicate webhook")
                    return True, f"Payment {payment.id} already processed (idempotent)"

                # B7: If payment has a proforma, auto-convert proforma→invoice
                if payment.proforma:
                    try:
                        from apps.billing.proforma_service import (  # noqa: PLC0415
                            ProformaPaymentService,
                        )

                        convert_result = ProformaPaymentService.record_payment_and_convert(
                            proforma_id=str(payment.proforma.id),
                            amount_cents=payment.amount_cents,
                            payment_method="stripe",
                            existing_payment=payment,
                        )
                        if convert_result.is_ok():
                            logger.info(
                                "✅ [Stripe] Auto-converted proforma %s after payment %s succeeded",
                                payment.proforma.number,
                                payment.id,
                            )
                        else:
                            # C1: Return False so Stripe retries the webhook.
                            # Payment is already marked succeeded but invoice was not
                            # created — retry gives the conversion another chance.
                            err_msg = convert_result.unwrap_err() if convert_result.is_err() else "unknown"
                            logger.error(
                                "🔥 [Stripe] Proforma conversion failed for payment %s: %s",
                                payment.id,
                                err_msg,
                            )
                            return False, f"conversion failed: {err_msg}"
                    except Exception as e:
                        logger.exception("🔥 [Stripe] Proforma auto-convert failed: %s", e)
                        return False, f"conversion failed: {e}"

                # Update associated invoice if exists (fallback for non-proforma payments)
                elif payment.invoice:
                    payment.invoice.update_status_from_payments()

                # 🔔 Notify Portal of payment success
                self._notify_portal_payment_success(payment, payment_intent)

                logger.info(f"✅ Payment {payment.id} marked as succeeded from Stripe")
                return True, f"Payment {payment.id} succeeded"

            elif event_type == "payment_intent.payment_failed":
                failure_reason = payment_intent.get("last_payment_error", {}).get("message", "Unknown error")

                meta_update = {
                    "stripe_payment_intent": stripe_payment_id,
                    "stripe_failure_reason": failure_reason,
                }
                changed = payment.apply_gateway_event("failed", meta_update)

                if not changed:
                    logger.warning(f"⚠️ Payment {payment.id} already in terminal state, ignoring failure event")
                    return True, f"Payment {payment.id} already in terminal state, ignoring failure"

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
                        txn.on_commit(lambda: send_proforma_email(_proforma))
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

    def handle_invoice_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """🧾 Handle Stripe Invoice events"""
        stripe_invoice = payload.get("data", {}).get("object", {})
        stripe_invoice_id = stripe_invoice.get("id")

        if event_type == "invoice.payment_succeeded":
            # Find our invoice by Stripe ID or customer
            logger.info(f"🎉 Stripe invoice payment succeeded: {stripe_invoice_id}")
            return True, f"Invoice payment succeeded: {stripe_invoice_id}"

        elif event_type == "invoice.payment_failed":
            # Trigger dunning process
            logger.warning(f"❌ Stripe invoice payment failed: {stripe_invoice_id}")
            return True, f"Invoice payment failed: {stripe_invoice_id}"

        else:
            return True, f"Skipped Invoice event: {event_type}"

    def handle_customer_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """👤 Handle Stripe Customer events"""
        stripe_customer = payload.get("data", {}).get("object", {})
        stripe_customer_id = stripe_customer.get("id")

        if event_type == "customer.created":
            # Link Stripe customer to our customer record
            customer_email = stripe_customer.get("email")

            if customer_email:
                try:
                    customer = Customer.objects.get(primary_email=customer_email)

                    # Store Stripe customer ID in metadata
                    if hasattr(customer, "meta") and customer.meta is not None:
                        customer.meta["stripe_customer_id"] = stripe_customer_id
                        customer.meta["stripe_linked_at"] = timezone.now().isoformat()
                        customer.save(update_fields=["meta", "updated_at"])

                    logger.info(f"🔗 Linked Stripe customer {stripe_customer_id} to {customer}")
                    return True, f"Customer linked: {customer}"

                except Customer.DoesNotExist:
                    logger.warning(f"⚠️ Customer not found for Stripe customer: {customer_email}")
                    return True, f"Customer not found: {customer_email}"

        return True, f"Skipped Customer event: {event_type}"

    def handle_charge_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """💰 Handle Stripe Charge events"""
        charge = payload.get("data", {}).get("object", {})
        charge_id = charge.get("id")

        if event_type == "charge.dispute.created":
            # Alert for dispute handling
            logger.critical(f"🚨 DISPUTE CREATED for charge {charge_id} - manual review required!")

            # Send urgent notification to admin
            try:
                from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
                    NotificationService,  # Circular: cross-app  # Deferred: avoids circular import
                )

                dispute_amount = charge.get("dispute", {}).get("amount", charge.get("amount", 0))
                NotificationService.send_admin_alert(
                    subject=f"URGENT: Stripe Dispute Created - {charge_id}",
                    message=f"A dispute has been created for charge {charge_id}.\n"
                    f"Amount: ${dispute_amount / 100:.2f}\n"
                    f"Reason: {charge.get('dispute', {}).get('reason', 'Unknown')}\n"
                    f"Please review immediately.",
                    alert_type="dispute",
                    metadata={"charge_id": charge_id, "dispute": charge.get("dispute", {})},
                )
            except Exception as notify_error:
                logger.error(f"⚠️ Failed to send dispute notification: {notify_error}")

            # Update payment record with dispute flag
            try:
                with transaction.atomic():
                    payment = Payment.objects.select_for_update().filter(gateway_txn_id=charge_id).first()
                    if payment:
                        meta_update = {
                            "dispute_id": charge.get("dispute", {}).get("id"),
                            "dispute_reason": charge.get("dispute", {}).get("reason"),
                            "dispute_created_at": timezone.now().isoformat(),
                        }
                        payment.apply_gateway_event("disputed", meta_update)
                        logger.info(f"📝 Updated payment {payment.id} with dispute flag")
            except Exception as update_error:
                logger.error(f"⚠️ Failed to update payment with dispute: {update_error}")

            return True, f"Dispute created for charge: {charge_id}"

        elif event_type == "charge.succeeded":
            # Charge succeeded - payment completed
            logger.info(f"✅ Stripe charge succeeded: {charge_id}")
            return True, f"Charge succeeded: {charge_id}"

        elif event_type == "charge.failed":
            # Charge failed
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
