"""
Payment Service for PRAHO Platform
Gateway-agnostic payment orchestration with Romanian compliance.
"""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.common.validators import log_security_event
from apps.orders.models import Order

from .currency_models import Currency
from .gateways import PaymentGatewayFactory
from .gateways.base import PaymentConfirmResult, PaymentIntentResult, SubscriptionResult
from .models import Payment

logger = logging.getLogger(__name__)


# ===============================================================================
# PAYMENT ORCHESTRATION SERVICE
# ===============================================================================


class PaymentService:
    """
    💰 Gateway-agnostic payment orchestration service

    Provides unified interface for:
    - Payment creation and confirmation
    - Subscription management
    - Webhook event processing
    - Multiple payment gateway support
    """

    @staticmethod
    def create_payment_intent(
        order_id: str, gateway: str = "stripe", metadata: dict[str, Any] | None = None
    ) -> PaymentIntentResult:
        """
        Create payment intent for order

        Args:
            order_id: PRAHO order UUID
            gateway: Payment gateway to use ('stripe', 'bank', etc.)
            metadata: Additional metadata for payment

        Returns:
            PaymentIntentResult with client_secret for frontend integration
        """
        try:
            # Get order details
            order = Order.objects.select_related("customer").get(id=order_id)

            # Calculate total amount in cents (Romanian VAT included)
            amount_cents = order.total_cents
            currency = order.currency or "RON"

            logger.info(
                f"💳 Creating payment intent for order {order.order_number} "
                f"({amount_cents} {currency}) via {gateway}"
            )

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # Prepare metadata
            payment_metadata = {
                "order_number": order.order_number,
                "customer_id": str(order.customer.id),
                "platform": "PRAHO",
                **(metadata or {}),
            }

            # Create payment intent
            result = payment_gateway.create_payment_intent(
                order_id=str(order.id), amount_cents=amount_cents, currency=currency, metadata=payment_metadata
            )

            if result.get("success", False):
                # Create Payment record with pending status
                with transaction.atomic():
                    # Get or create currency object
                    currency_obj = None
                    if currency:
                        currency_obj, _ = Currency.objects.get_or_create(
                            code=currency.upper(),
                            defaults={
                                "name": currency.upper(),
                                "symbol": "RON" if currency.upper() == "RON" else currency.upper(),
                                "decimals": 2,
                            },
                        )

                    payment_intent_id = result.get("payment_intent_id", "")
                    client_secret = result.get("client_secret", "")

                    payment = Payment.objects.create(
                        invoice=None,  # Will be linked when order is processed
                        customer=order.customer,
                        payment_method=gateway,
                        amount_cents=amount_cents,
                        currency=currency_obj,
                        status="pending",
                        gateway_txn_id=payment_intent_id,
                        meta={
                            "payment_intent_id": payment_intent_id,
                            "client_secret": client_secret,
                            "order_id": str(order.id),
                            "gateway": gateway,
                            **payment_metadata,
                        },
                    )

                logger.info(f"✅ Created payment {payment.id} for order {order.order_number}")

                log_security_event(
                    "payment_intent_created",
                    {
                        "payment_id": str(payment.id),
                        "order_id": str(order.id),
                        "order_number": order.order_number,
                        "amount_cents": amount_cents,
                        "currency": currency,
                        "gateway": gateway,
                        "critical_financial_operation": True,
                    },
                )

            return result

        except Order.DoesNotExist:
            logger.error(f"❌ Order {order_id} not found")
            return PaymentIntentResult(
                success=False, payment_intent_id="", client_secret=None, error=f"Order {order_id} not found"
            )
        except Exception as e:
            logger.error(f"🔥 Error creating payment intent: {e}")
            return PaymentIntentResult(
                success=False, payment_intent_id="", client_secret=None, error=f"Payment creation failed: {e}"
            )

    @staticmethod
    def create_payment_intent_direct(
        order_id: str,
        amount_cents: int,
        currency: str = "RON",
        customer_id: str | int | None = None,
        order_number: str | None = None,
        gateway: str = "stripe",
        metadata: dict[str, Any] | None = None,
    ) -> PaymentIntentResult:
        """
        Create payment intent with direct order details (for cross-service calls)

        Args:
            order_id: Portal order UUID
            amount_cents: Amount in cents
            currency: ISO currency code (default: RON)
            customer_id: Customer ID for the payment
            order_number: Human-readable order number
            gateway: Payment gateway to use ('stripe', 'bank', etc.)
            metadata: Additional metadata for payment

        Returns:
            PaymentIntentResult with client_secret for frontend integration
        """
        try:
            logger.info(
                f"💳 Creating payment intent for Portal order {order_id} " f"({amount_cents} {currency}) via {gateway}"
            )

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # Prepare metadata
            payment_metadata = {
                "order_number": order_number or order_id,
                "customer_id": str(customer_id) if customer_id else "unknown",
                "platform": "PRAHO",
                "source": "portal_api",
                **(metadata or {}),
            }

            # Create payment intent
            result = payment_gateway.create_payment_intent(
                order_id=str(order_id), amount_cents=amount_cents, currency=currency, metadata=payment_metadata
            )

            if result.get("success", False):
                # Create Payment record with pending status (without linking to invoice)
                with transaction.atomic():
                    # Try to get customer from Platform database if customer_id provided
                    customer_obj = None
                    if customer_id:
                        try:
                            from apps.customers.models import Customer

                            customer_obj = Customer.objects.get(id=customer_id)
                        except Customer.DoesNotExist:
                            logger.warning(f"⚠️ Customer {customer_id} not found in Platform database")

                    # Get or create currency object
                    currency_obj = None
                    if currency:
                        currency_obj, _ = Currency.objects.get_or_create(
                            code=currency.upper(),
                            defaults={
                                "name": currency.upper(),
                                "symbol": "RON" if currency.upper() == "RON" else currency.upper(),
                                "decimals": 2,
                            },
                        )

                    payment_intent_id = result.get("payment_intent_id", "")
                    client_secret = result.get("client_secret", "")

                    payment = Payment.objects.create(
                        invoice=None,  # Will be linked when order is processed
                        customer=customer_obj,  # May be None for cross-service calls
                        payment_method=gateway,
                        amount_cents=amount_cents,
                        currency=currency_obj,
                        status="pending",
                        gateway_txn_id=payment_intent_id,
                        meta={
                            "client_secret": client_secret,
                            "order_id": str(order_id),
                            "gateway": gateway,
                            **payment_metadata,
                        },
                    )

                logger.info(f"✅ Created payment {payment.id} for Portal order {order_id}")

                log_security_event(
                    "payment_intent_created_direct",
                    {
                        "payment_id": str(payment.id),
                        "order_id": str(order_id),
                        "amount_cents": amount_cents,
                        "currency": currency,
                        "gateway": gateway,
                        "source": "portal_api",
                        "critical_financial_operation": True,
                    },
                )

            return result

        except Exception as e:
            logger.error(f"🔥 Error creating payment intent for Portal order {order_id}: {e}")
            return PaymentIntentResult(
                success=False, payment_intent_id="", client_secret=None, error=f"Payment creation failed: {e}"
            )

    @staticmethod
    def confirm_payment(payment_intent_id: str, gateway: str = "stripe") -> PaymentConfirmResult:
        """
        Confirm payment status

        Args:
            payment_intent_id: Gateway payment intent ID
            gateway: Payment gateway used

        Returns:
            PaymentConfirmResult with current status
        """
        try:
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)
            result = payment_gateway.confirm_payment(payment_intent_id)

            if result.get("success", False):
                # Update payment record status
                try:
                    payment = Payment.objects.get(gateway_txn_id=payment_intent_id)

                    # Map gateway status to our status
                    status_mapping = {
                        "succeeded": "succeeded",
                        "requires_payment_method": "pending",
                        "requires_confirmation": "pending",
                        "requires_action": "pending",
                        "processing": "pending",
                        "canceled": "failed",
                    }

                    result_status = result.get("status", "unknown")
                    new_status = status_mapping.get(result_status, "pending")

                    if payment.status != new_status:
                        old_status = payment.status
                        payment.status = new_status
                        payment.save(update_fields=["status"])

                        logger.info(f"💰 Updated payment {payment.id} status to {new_status}")

                        log_security_event(
                            "payment_status_changed",
                            {
                                "payment_id": str(payment.id),
                                "old_status": old_status,
                                "new_status": new_status,
                                "gateway_intent_id": payment_intent_id,
                                "critical_financial_operation": True,
                            },
                        )

                except Payment.DoesNotExist:
                    logger.warning(f"⚠️ Payment not found for intent {payment_intent_id}")

            return result

        except Exception as e:
            logger.error(f"🔥 Error confirming payment: {e}")
            return PaymentConfirmResult(success=False, status="error", error=f"Payment confirmation failed: {e}")

    @staticmethod
    def create_subscription(
        customer_id: str, price_id: str, gateway: str = "stripe", metadata: dict[str, Any] | None = None
    ) -> SubscriptionResult:
        """
        Create recurring subscription

        Args:
            customer_id: PRAHO customer ID
            price_id: Gateway price/plan ID
            gateway: Payment gateway to use
            metadata: Additional metadata

        Returns:
            SubscriptionResult with subscription details
        """
        try:
            from apps.customers.models import Customer

            customer = Customer.objects.get(id=customer_id)

            logger.info(f"🔄 Creating subscription for customer {customer.name} " f"(price: {price_id}) via {gateway}")

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # TODO: Get or create gateway customer ID
            # For now, using PRAHO customer ID as placeholder
            gateway_customer_id = f"cus_praho_{customer_id}"

            # Prepare metadata
            subscription_metadata = {
                "customer_id": str(customer.id),
                "customer_name": customer.name,
                "platform": "PRAHO",
                **(metadata or {}),
            }

            # Create subscription
            result = payment_gateway.create_subscription(
                customer_id=gateway_customer_id, price_id=price_id, metadata=subscription_metadata
            )

            if result.get("success", False):
                # TODO: Create subscription record in database
                subscription_id = result.get("subscription_id", "unknown")
                logger.info(f"✅ Created subscription {subscription_id} " f"for customer {customer.name}")

                log_security_event(
                    "gateway_subscription_created",
                    {
                        "subscription_id": subscription_id,
                        "customer_id": str(customer.id),
                        "price_id": price_id,
                        "gateway": gateway,
                        "critical_financial_operation": True,
                    },
                )

            return result

        except Customer.DoesNotExist:
            logger.error(f"❌ Customer {customer_id} not found")
            return SubscriptionResult(
                success=False, subscription_id=None, status=None, error=f"Customer {customer_id} not found"
            )
        except Exception as e:
            logger.error(f"🔥 Error creating subscription: {e}")
            return SubscriptionResult(
                success=False, subscription_id=None, status=None, error=f"Subscription creation failed: {e}"
            )

    @staticmethod
    def handle_webhook_payment(
        event_type: str, event_data: dict[str, Any], gateway: str = "stripe"
    ) -> tuple[bool, str]:
        """
        Handle webhook payment events

        This method is called by the webhook processor to update payment status.

        Args:
            event_type: Event type (e.g., 'payment_intent.succeeded')
            event_data: Event payload
            gateway: Payment gateway that sent the event

        Returns:
            (success, message) tuple
        """
        try:
            logger.info(f"🔔 Processing {gateway} webhook: {event_type}")

            if gateway == "stripe" and event_type.startswith("payment_intent."):
                return PaymentService._handle_stripe_payment_intent(event_type, event_data)

            # Add other gateway handlers here

            return True, f"Unhandled webhook event: {event_type}"

        except Exception as e:
            logger.error(f"🔥 Error handling webhook payment: {e}")
            return False, f"Webhook processing error: {e}"

    @staticmethod
    def _handle_stripe_payment_intent(event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """Handle Stripe payment_intent webhook events"""
        payment_intent = event_data.get("object", {})
        payment_intent_id = payment_intent.get("id")

        if not payment_intent_id:
            return False, "Missing payment intent ID"

        try:
            payment = Payment.objects.get(gateway_txn_id=payment_intent_id)

            if event_type == "payment_intent.succeeded":
                # Payment succeeded - update status
                payment.status = "succeeded"
                payment.meta.update(
                    {
                        "stripe_payment_method": payment_intent.get("payment_method"),
                        "stripe_amount_received": payment_intent.get("amount_received"),
                        "succeeded_at": timezone.now().isoformat(),
                    }
                )
                payment.save(update_fields=["status", "meta"])

                logger.info(f"💰 Payment {payment.id} marked as succeeded")

                log_security_event(
                    "payment_succeeded",
                    {
                        "payment_id": str(payment.id),
                        "amount_received": payment_intent.get("amount_received"),
                        "gateway": "stripe",
                        "critical_financial_operation": True,
                    },
                )

                # TODO: Trigger order completion workflow
                return True, f"Payment {payment.id} succeeded"

            elif event_type == "payment_intent.payment_failed":
                # Payment failed - update status
                failure_reason = payment_intent.get("last_payment_error", {}).get("message", "Unknown error")

                payment.status = "failed"
                payment.meta.update({"stripe_failure_reason": failure_reason, "failed_at": timezone.now().isoformat()})
                payment.save(update_fields=["status", "meta"])

                logger.warning(f"❌ Payment {payment.id} marked as failed: {failure_reason}")

                log_security_event(
                    "payment_failed",
                    {
                        "payment_id": str(payment.id),
                        "failure_reason": failure_reason,
                        "gateway": "stripe",
                        "critical_financial_operation": True,
                    },
                )

                # TODO: Trigger payment retry/dunning process
                return True, f"Payment {payment.id} failed: {failure_reason}"

            return True, f"Handled payment_intent event: {event_type}"

        except Payment.DoesNotExist:
            logger.warning(f"⚠️ Payment not found for Stripe PaymentIntent: {payment_intent_id}")
            return True, f"Payment not found (external): {payment_intent_id}"

    @staticmethod
    def get_available_payment_methods(customer_id: str | None = None) -> list[dict[str, Any]]:
        """
        Get available payment methods for customer

        Args:
            customer_id: PRAHO customer ID (optional)

        Returns:
            List of available payment methods
        """
        methods = [
            {
                "gateway": "stripe",
                "name": "Card Payment",
                "description": "Visa, Mastercard, American Express",
                "enabled": True,
                "supports_recurring": True,
            }
        ]

        # Add Romanian-specific methods
        if getattr(settings, "ENABLE_BANK_TRANSFER", False):
            methods.append(
                {
                    "gateway": "bank",
                    "name": "Bank Transfer",
                    "description": "Romanian bank transfer (IBAN)",
                    "enabled": True,
                    "supports_recurring": False,
                }
            )

        return methods

    @staticmethod
    def process_recurring_billing() -> dict[str, Any]:
        """
        Process recurring billing for all active subscriptions

        This method is called by scheduled tasks to handle:
        - Failed payment retries
        - Subscription renewals
        - Service suspension/termination

        Returns:
            Summary of processing results
        """
        logger.info("🔄 Processing recurring billing...")

        results = {"processed": 0, "succeeded": 0, "failed": 0, "suspended": 0, "errors": []}

        try:
            # TODO: Query active subscriptions that need billing
            # TODO: Process each subscription
            # TODO: Handle failed payments according to dunning rules
            # TODO: Update service statuses

            logger.info(f"✅ Recurring billing completed: {results}")
            return results

        except Exception as e:
            logger.error(f"🔥 Error processing recurring billing: {e}")
            results["errors"].append(str(e))
            return results
