import json
import logging
from collections.abc import Callable
from typing import Any

from django.conf import settings
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

    def verify_signature(self, payload: dict[str, Any], signature: str, headers: dict[str, str]) -> bool:
        """🔐 Verify Stripe webhook signature using settings system"""
        try:
            from apps.settings.services import SettingsService

            # Get encrypted webhook secret from settings system
            webhook_secret = SettingsService.get("integrations.stripe_webhook_secret")

            if not webhook_secret:
                # Fail secure when secret is not configured
                logger.error("Stripe webhook secret not configured in settings system - failing secure")
                return False

            # Get raw payload for signature verification
            payload_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

            return verify_stripe_signature(
                payload_body=payload_body, stripe_signature=signature, webhook_secret=webhook_secret
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

        except Exception as e:
            logger.exception(f"💥 Error handling Stripe event {event_type}")
            return False, f"Handler error: {e!s}"

    def _find_event_handler(self, event_type: str) -> StripeEventHandler | None:
        """Find the appropriate handler for the given event type."""
        for prefix, handler in self._event_handlers.items():
            if event_type.startswith(prefix):
                return handler
        return None

    def handle_payment_intent_event(self, event_type: str, payload: dict[str, Any]) -> tuple[bool, str]:
        """💳 Handle PaymentIntent events"""
        payment_intent = payload.get("data", {}).get("object", {})
        stripe_payment_id = payment_intent.get("id")

        if not stripe_payment_id:
            return False, "Missing PaymentIntent ID"

        # Find our Payment record by Stripe ID
        try:
            payment = Payment.objects.get(gateway_txn_id=stripe_payment_id)
        except Payment.DoesNotExist:
            # Payment not found - might be created outside our system
            logger.warning(f"⚠️ Payment not found for Stripe PaymentIntent: {stripe_payment_id}")
            return True, f"Payment not found (external): {stripe_payment_id}"

        if event_type == "payment_intent.succeeded":
            # Payment succeeded
            payment.status = "succeeded"
            payment.meta.update(
                {
                    "stripe_payment_intent": stripe_payment_id,
                    "stripe_payment_method": payment_intent.get("payment_method"),
                    "stripe_amount_received": payment_intent.get("amount_received"),
                }
            )
            payment.save(update_fields=["status", "meta"])

            # Update associated invoice if exists
            if payment.invoice:
                payment.invoice.update_status_from_payments()

            # 🔔 NEW: Notify Portal of payment success
            self._notify_portal_payment_success(payment, payment_intent)

            logger.info(f"✅ Payment {payment.id} marked as succeeded from Stripe")
            return True, f"Payment {payment.id} succeeded"

        elif event_type == "payment_intent.payment_failed":
            # Payment failed
            failure_reason = payment_intent.get("last_payment_error", {}).get("message", "Unknown error")

            payment.status = "failed"
            payment.meta.update(
                {
                    "stripe_payment_intent": stripe_payment_id,
                    "stripe_failure_reason": failure_reason,
                }
            )
            payment.save(update_fields=["status", "meta"])

            # Trigger dunning process if this was an invoice payment
            if payment.invoice:
                # TODO: Trigger payment retry/dunning logic
                pass

            logger.warning(f"❌ Payment {payment.id} marked as failed from Stripe: {failure_reason}")
            return True, f"Payment {payment.id} failed: {failure_reason}"

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
                    # TODO: Store Stripe customer ID in metadata (requires meta JSONField)
                    logger.info(f"🔗 Linked Stripe customer {stripe_customer_id} to {customer.name}")

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

            # TODO: Send urgent notification to admin
            # TODO: Update payment record with dispute flag

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

    def _notify_portal_payment_success(self, payment, payment_intent: dict[str, Any]) -> None:
        """
        🔔 Notify Portal service of payment success

        Args:
            payment: Payment model instance
            payment_intent: Stripe PaymentIntent data
        """
        try:
            # Extract order ID from payment metadata
            order_id = payment.meta.get('order_id')
            if not order_id:
                logger.warning("⚠️ No order_id in payment metadata - skipping Portal notification")
                return

            # Check if this payment was created via Portal
            created_via = payment.meta.get('created_via')
            if created_via != 'portal_checkout':
                logger.info(f"⏭️ Payment not from Portal checkout - skipping notification")
                return

            # Prepare notification data
            notification_data = {
                'order_id': order_id,
                'payment_id': str(payment.id),
                'status': 'succeeded',
                'stripe_payment_intent_id': payment_intent.get('id'),
                'amount_received': payment_intent.get('amount_received'),
                'currency': payment_intent.get('currency', 'ron').upper(),
                'timestamp': timezone.now().isoformat()
            }

            # Send notification to Portal
            # TODO: In production, this should use a proper HTTP client or message queue
            # For now, we'll use a simple HTTP request
            self._send_portal_webhook(notification_data)

            logger.info(f"✅ Notified Portal of payment success for order {order_id}")

        except Exception as e:
            logger.error(f"🔥 Error notifying Portal of payment success: {e}")
            # Don't fail the webhook processing if Portal notification fails

    def _send_portal_webhook(self, data: dict[str, Any]) -> None:
        """Send webhook notification to Portal service"""
        try:
            import requests
            from django.conf import settings

            # Get Portal webhook URL from settings
            portal_webhook_url = getattr(settings, 'PORTAL_PAYMENT_WEBHOOK_URL', None)
            if not portal_webhook_url:
                logger.warning("⚠️ PORTAL_PAYMENT_WEBHOOK_URL not configured - skipping notification")
                return

            # Send POST request to Portal
            response = requests.post(
                portal_webhook_url,
                json=data,
                timeout=10,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'PRAHO-Platform/1.0'
                }
            )

            if response.status_code == 200:
                logger.info(f"✅ Successfully notified Portal: {response.status_code}")
            else:
                logger.warning(f"⚠️ Portal notification failed: {response.status_code} - {response.text}")

        except requests.exceptions.Timeout:
            logger.error("🕐 Portal notification timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"🔥 Portal notification request failed: {e}")
        except Exception as e:
            logger.error(f"🔥 Unexpected error sending Portal notification: {e}")
