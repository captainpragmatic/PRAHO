"""
Stripe Payment Gateway for PRAHO Platform
Production-ready Stripe integration with Romanian compliance.
"""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings

from .base import (
    BasePaymentGateway,
    PaymentConfirmResult,
    PaymentGatewayFactory,
    PaymentIntentResult,
    SubscriptionResult,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# STRIPE GATEWAY IMPLEMENTATION
# ===============================================================================


class StripeGateway(BasePaymentGateway):
    """
    💳 Stripe payment gateway implementation

    Features:
    - Payment Intent creation with Romanian VAT support
    - Subscription management for recurring billing
    - Webhook event processing
    - PCI compliant payment handling
    """

    def __init__(self) -> None:
        super().__init__()
        self._stripe = None
        self._initialize_stripe()

    def _initialize_stripe(self) -> None:
        """Initialize Stripe SDK with API keys from settings system"""
        try:
            import stripe
            from apps.settings.services import SettingsService

            # Get encrypted Stripe secret key from settings system
            api_key = SettingsService.get("integrations.stripe_secret_key")
            if not api_key:
                raise ValueError("Stripe secret key not configured in settings system")

            stripe.api_key = api_key
            self._stripe = stripe

            # Set API version for consistency
            stripe.api_version = "2023-10-16"

            self.logger.info("✅ Stripe SDK initialized successfully from settings system")

        except ImportError:
            raise ImportError("Stripe library not installed. Run: pip install stripe")
        except Exception as e:
            self.logger.error(f"🔥 Failed to initialize Stripe: {e}")
            raise

    @property
    def gateway_name(self) -> str:
        return 'stripe'

    def validate_configuration(self) -> bool:
        """Validate Stripe configuration from settings system"""
        try:
            from apps.settings.services import SettingsService

            # Check if Stripe integration is enabled
            stripe_enabled = SettingsService.get("integrations.stripe_enabled", default=False)
            if not stripe_enabled:
                self.logger.warning("⚠️ Stripe integration is disabled in settings")
                return False

            # Check required encrypted settings
            secret_key = SettingsService.get("integrations.stripe_secret_key")
            publishable_key = SettingsService.get("integrations.stripe_publishable_key")
            webhook_secret = SettingsService.get("integrations.stripe_webhook_secret")

            if not secret_key:
                self.logger.error("❌ Stripe secret key not configured in settings system")
                return False

            if not publishable_key:
                self.logger.error("❌ Stripe publishable key not configured in settings system")
                return False

            if not webhook_secret:
                self.logger.warning("⚠️ Stripe webhook secret not configured - webhooks will fail")

            # Test API connection
            self._stripe.Account.retrieve()
            self.logger.info("✅ Stripe configuration valid from settings system")
            return True

        except Exception as e:
            self.logger.error(f"❌ Stripe configuration invalid: {e}")
            return False

    def create_payment_intent(
        self,
        order_id: str,
        amount_cents: int,
        currency: str = 'RON',
        customer_id: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> PaymentIntentResult:
        """
        Create Stripe Payment Intent

        Args:
            order_id: PRAHO order ID
            amount_cents: Amount in cents (e.g., 2999 for 29.99 RON)
            currency: ISO currency code (RON, EUR, USD)
            customer_id: Stripe customer ID (optional)
            metadata: Additional metadata

        Returns:
            PaymentIntentResult with client_secret for frontend
        """
        try:
            # Prepare payment intent parameters
            payment_intent_params = {
                'amount': amount_cents,
                'currency': currency.lower(),
                'automatic_payment_methods': {'enabled': True},
                'metadata': {
                    'praho_order_id': order_id,
                    'platform': 'PRAHO',
                    'vat_rate': '21%',  # Romanian VAT rate
                    **(metadata or {})
                },
                # Romanian business compliance
                'statement_descriptor': 'PRAHO Hosting',
                'receipt_email': None  # Will be set from customer data
            }

            # Add customer if provided
            if customer_id:
                payment_intent_params['customer'] = customer_id

            # Create payment intent
            payment_intent = self._stripe.PaymentIntent.create(**payment_intent_params)

            self.logger.info(
                f"✅ Created Stripe PaymentIntent {payment_intent.id} "
                f"for order {order_id} ({amount_cents} {currency})"
            )

            return PaymentIntentResult(
                success=True,
                payment_intent_id=payment_intent.id,
                client_secret=payment_intent.client_secret,
                error=None
            )

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Stripe PaymentIntent creation failed: {e}")
            return PaymentIntentResult(
                success=False,
                payment_intent_id='',
                client_secret=None,
                error=str(e)
            )
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error creating PaymentIntent: {e}")
            return PaymentIntentResult(
                success=False,
                payment_intent_id='',
                client_secret=None,
                error=f"Unexpected error: {e}"
            )

    def confirm_payment(self, payment_intent_id: str) -> PaymentConfirmResult:
        """
        Retrieve and confirm payment intent status

        Args:
            payment_intent_id: Stripe PaymentIntent ID

        Returns:
            PaymentConfirmResult with current status
        """
        try:
            payment_intent = self._stripe.PaymentIntent.retrieve(payment_intent_id)

            self.logger.info(f"💳 Payment {payment_intent_id} status: {payment_intent.status}")

            return PaymentConfirmResult(
                success=True,
                status=payment_intent.status,
                error=None
            )

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Failed to retrieve PaymentIntent {payment_intent_id}: {e}")
            return PaymentConfirmResult(
                success=False,
                status='error',
                error=str(e)
            )
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error confirming payment: {e}")
            return PaymentConfirmResult(
                success=False,
                status='error',
                error=f"Unexpected error: {e}"
            )

    def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        metadata: dict[str, Any] | None = None
    ) -> SubscriptionResult:
        """
        Create Stripe subscription for recurring billing

        Args:
            customer_id: Stripe customer ID
            price_id: Stripe price ID (from Stripe Dashboard or API)
            metadata: Additional metadata

        Returns:
            SubscriptionResult with subscription details
        """
        try:
            subscription_params = {
                'customer': customer_id,
                'items': [{'price': price_id}],
                'payment_behavior': 'default_incomplete',
                'payment_settings': {
                    'save_default_payment_method': 'on_subscription'
                },
                'expand': ['latest_invoice.payment_intent'],
                'metadata': {
                    'platform': 'PRAHO',
                    **(metadata or {})
                }
            }

            subscription = self._stripe.Subscription.create(**subscription_params)

            self.logger.info(
                f"✅ Created Stripe subscription {subscription.id} "
                f"for customer {customer_id} (price: {price_id})"
            )

            return SubscriptionResult(
                success=True,
                subscription_id=subscription.id,
                status=subscription.status,
                error=None
            )

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Stripe subscription creation failed: {e}")
            return SubscriptionResult(
                success=False,
                subscription_id=None,
                status=None,
                error=str(e)
            )
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error creating subscription: {e}")
            return SubscriptionResult(
                success=False,
                subscription_id=None,
                status=None,
                error=f"Unexpected error: {e}"
            )

    def cancel_subscription(self, subscription_id: str) -> bool:
        """
        Cancel Stripe subscription

        Args:
            subscription_id: Stripe subscription ID

        Returns:
            True if cancelled successfully
        """
        try:
            subscription = self._stripe.Subscription.cancel(subscription_id)

            self.logger.info(f"✅ Cancelled Stripe subscription {subscription_id}")
            return True

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Failed to cancel subscription {subscription_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error cancelling subscription: {e}")
            return False

    def handle_webhook_event(self, event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """
        Handle Stripe webhook events

        This method provides basic event handling. The existing webhook processor
        in apps.integrations.webhooks.stripe provides more comprehensive handling.

        Args:
            event_type: Stripe event type (e.g., 'payment_intent.succeeded')
            event_data: Event payload data

        Returns:
            (success, message) tuple
        """
        try:
            if event_type.startswith('payment_intent.'):
                return self._handle_payment_intent_webhook(event_type, event_data)
            elif event_type.startswith('invoice.'):
                return self._handle_invoice_webhook(event_type, event_data)
            elif event_type.startswith('customer.subscription.'):
                return self._handle_subscription_webhook(event_type, event_data)
            else:
                self.logger.info(f"⏭️ Unhandled webhook event type: {event_type}")
                return True, f"Unhandled event type: {event_type}"

        except Exception as e:
            self.logger.error(f"🔥 Error handling webhook event {event_type}: {e}")
            return False, f"Error: {e}"

    def _handle_payment_intent_webhook(self, event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """Handle payment_intent.* webhook events"""
        payment_intent = event_data.get('object', {})
        payment_intent_id = payment_intent.get('id')

        if event_type == 'payment_intent.succeeded':
            self.logger.info(f"💰 Payment succeeded: {payment_intent_id}")
            # Update payment status in database would happen here
            # This is handled by the existing webhook processor
            return True, f"Payment succeeded: {payment_intent_id}"

        elif event_type == 'payment_intent.payment_failed':
            self.logger.warning(f"❌ Payment failed: {payment_intent_id}")
            return True, f"Payment failed: {payment_intent_id}"

        return True, f"Payment intent event: {event_type}"

    def _handle_invoice_webhook(self, event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """Handle invoice.* webhook events"""
        invoice = event_data.get('object', {})
        invoice_id = invoice.get('id')

        if event_type == 'invoice.payment_succeeded':
            self.logger.info(f"🧾 Invoice payment succeeded: {invoice_id}")
            return True, f"Invoice payment succeeded: {invoice_id}"

        elif event_type == 'invoice.payment_failed':
            self.logger.warning(f"📋 Invoice payment failed: {invoice_id}")
            return True, f"Invoice payment failed: {invoice_id}"

        return True, f"Invoice event: {event_type}"

    def _handle_subscription_webhook(self, event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """Handle customer.subscription.* webhook events"""
        subscription = event_data.get('object', {})
        subscription_id = subscription.get('id')

        if event_type == 'customer.subscription.created':
            self.logger.info(f"🔄 Subscription created: {subscription_id}")
            return True, f"Subscription created: {subscription_id}"

        elif event_type == 'customer.subscription.deleted':
            self.logger.info(f"🗑️ Subscription cancelled: {subscription_id}")
            return True, f"Subscription cancelled: {subscription_id}"

        return True, f"Subscription event: {event_type}"


# ===============================================================================
# GATEWAY REGISTRATION
# ===============================================================================

# Register Stripe gateway with factory
PaymentGatewayFactory.register_gateway('stripe', StripeGateway)