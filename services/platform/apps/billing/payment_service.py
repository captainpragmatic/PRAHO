"""
Payment Service for PRAHO Platform
Gateway-agnostic payment orchestration with Romanian compliance.
"""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.db import transaction
from django_fsm import TransitionNotAllowed

from apps.common.validators import log_security_event
from apps.customers.models import (
    Customer,
)
from apps.orders.models import Order

from .currency_models import Currency
from .gateways import PaymentGatewayFactory
from .gateways.base import PaymentConfirmResult, PaymentIntentResult, SubscriptionResult
from .models import Payment
from .payment_models import TERMINAL_PAYMENT_STATUSES

# Maps internal payment status names to the FSM transition method names on Payment.
_PAYMENT_TRANSITION_MAP: dict[str, str] = {
    "succeeded": "succeed",
    "failed": "fail_payment",
    "refunded": "refund_payment",
    "partially_refunded": "partially_refund",
}

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
    - Multiple payment gateway support

    # Stripe webhook handling is in apps.integrations.webhooks.stripe.StripeWebhookProcessor
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
            currency = order.currency.code if order.currency else "RON"

            logger.info(
                f"💳 Creating payment intent for order {order.order_number} ({amount_cents} {currency}) via {gateway}"
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

                    payment = Payment.objects.create(  # type: ignore[misc]
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
    def create_payment_intent_direct(  # payment processing fields  # noqa: PLR0913  # Business logic parameters
        order_id: str,
        amount_cents: int | None = None,
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
            if not customer_id:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="customer_id is required",
                )

            try:
                customer_id_int = int(customer_id)
            except (TypeError, ValueError):
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="customer_id must be a valid integer",
                )

            # Security-critical: derive authoritative payment amount from the order.
            try:
                order = Order.objects.select_related("customer").get(id=order_id, customer_id=customer_id_int)
            except Order.DoesNotExist:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Order not found for this customer",
                )

            expected_amount_cents = int(order.total_cents)
            if amount_cents is not None and int(amount_cents) != expected_amount_cents:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="amount_cents does not match order total",
                )

            resolved_currency = (order.currency.code if order.currency else None) or currency or "RON"
            resolved_order_number = order_number or order.order_number

            logger.info(
                "💳 Creating payment intent for order %s (%s %s) via %s",
                order.id,
                expected_amount_cents,
                resolved_currency,
                gateway,
            )

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # Prepare metadata
            payment_metadata = {
                "order_number": resolved_order_number,
                "customer_id": str(customer_id_int),
                "platform": "PRAHO",
                "source": "portal_api",
                **(metadata or {}),
            }

            # Create payment intent
            result = payment_gateway.create_payment_intent(
                order_id=str(order_id),
                amount_cents=expected_amount_cents,
                currency=resolved_currency,
                metadata=payment_metadata,
            )

            if result.get("success", False):
                # Create Payment record with pending status (without linking to invoice)
                with transaction.atomic():
                    # Get or create currency object
                    currency_obj = None
                    if resolved_currency:
                        currency_obj, _ = Currency.objects.get_or_create(
                            code=resolved_currency.upper(),
                            defaults={
                                "name": resolved_currency.upper(),
                                "symbol": ("RON" if resolved_currency.upper() == "RON" else resolved_currency.upper()),
                                "decimals": 2,
                            },
                        )

                    payment_intent_id = result.get("payment_intent_id", "")
                    client_secret = result.get("client_secret", "")

                    payment = Payment.objects.create(  # type: ignore[misc]
                        invoice=None,  # Will be linked when order is processed
                        customer=order.customer,
                        payment_method=gateway,
                        amount_cents=expected_amount_cents,
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
                        "amount_cents": expected_amount_cents,
                        "currency": resolved_currency,
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
    def confirm_payment(
        payment_intent_id: str, gateway: str = "stripe", customer_id: str | int | None = None
    ) -> PaymentConfirmResult:
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
                    with transaction.atomic():
                        payment = Payment.objects.select_for_update().get(gateway_txn_id=payment_intent_id)

                        if customer_id is not None:
                            try:
                                expected_customer_id = int(customer_id)
                            except (TypeError, ValueError):
                                return PaymentConfirmResult(
                                    success=False,
                                    status="failed",
                                    error="customer_id must be a valid integer",
                                )
                            if payment.customer_id != expected_customer_id:
                                return PaymentConfirmResult(
                                    success=False,
                                    status="failed",
                                    error="Payment does not belong to this customer",
                                )

                        # Idempotency guard — skip if already in terminal state
                        if payment.status in TERMINAL_PAYMENT_STATUSES:
                            logger.info(
                                "💰 [PaymentService] confirm_payment: payment %s already in terminal state %s — skipping",
                                payment.id,
                                payment.status,
                            )
                            return result

                        # Map gateway status to our internal status
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
                            # Use FSM transition dispatch instead of direct assignment
                            method_name = _PAYMENT_TRANSITION_MAP.get(new_status)
                            if not method_name:
                                logger.warning(
                                    "⚠️ [PaymentService] confirm_payment: no FSM transition mapped "
                                    "for target status '%s' on payment %s",
                                    new_status,
                                    payment.id,
                                )
                            else:
                                try:
                                    getattr(payment, method_name)()
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
                                except TransitionNotAllowed:
                                    logger.warning(
                                        "⚠️ [PaymentService] confirm_payment: transition %s → %s not allowed "
                                        "for payment %s (already in state %s)",
                                        old_status,
                                        new_status,
                                        payment.id,
                                        payment.status,
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
            customer = Customer.objects.get(id=customer_id)

            logger.info(f"🔄 Creating subscription for customer {customer.name} (price: {price_id}) via {gateway}")

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # Get or create Stripe customer ID from customer meta
            customer_meta = customer.meta if hasattr(customer, "meta") and customer.meta else {}
            gateway_customer_id = customer_meta.get("stripe_customer_id", "")
            if not gateway_customer_id:
                # Create Stripe customer via gateway
                try:
                    stripe_gateway = PaymentGatewayFactory.create_gateway(gateway)
                    if hasattr(stripe_gateway, "_stripe"):
                        stripe_customer = stripe_gateway._stripe.Customer.create(
                            email=customer.primary_email or "",
                            name=customer.name or "",
                            metadata={"praho_customer_id": str(customer.id)},
                        )
                        gateway_customer_id = stripe_customer.id
                        # Store for future use; cast to Any to satisfy mypy for dynamic JSONField
                        customer_any: Any = customer
                        customer_any.meta = {**customer_meta, "stripe_customer_id": gateway_customer_id}
                        customer.save(update_fields=["meta"])
                except Exception as e:
                    logger.warning(f"⚠️ Could not create Stripe customer: {e}")
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
                # Create local Subscription record linked to gateway subscription
                subscription_id = result.get("subscription_id", "unknown")
                try:
                    latest_sub = customer.subscriptions.first() if customer.subscriptions.exists() else None
                    if latest_sub is not None:
                        from apps.billing.subscription_service import (  # noqa: PLC0415
                            SubscriptionService,
                        )

                        sub_result = SubscriptionService.create_subscription(
                            customer=customer,
                            product=latest_sub.product,
                            data={
                                "billing_cycle": "monthly",
                                "payment_method_id": price_id,
                                "metadata": {"gateway_subscription_id": subscription_id, "gateway": gateway},
                            },
                        )
                        if sub_result.is_err():
                            logger.warning(f"⚠️ Could not create local subscription record: {sub_result.unwrap_err()}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not create local subscription record: {e}")
                logger.info(f"✅ Created subscription {subscription_id} for customer {customer.name}")

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

        results: dict[str, Any] = {"processed": 0, "succeeded": 0, "failed": 0, "suspended": 0, "errors": []}

        try:
            # Delegate to RecurringBillingService which has the real implementation
            from apps.billing.subscription_service import (  # noqa: PLC0415
                RecurringBillingService,
            )

            billing_result = RecurringBillingService.run_billing_cycle()
            results["processed"] = billing_result["subscriptions_processed"]
            results["succeeded"] = billing_result["payments_succeeded"]
            results["failed"] = billing_result["payments_failed"]
            results["errors"] = billing_result["errors"]

            logger.info(f"✅ Recurring billing completed: {results}")
            return results

        except Exception as e:
            logger.error(f"🔥 Error processing recurring billing: {e}")
            results["errors"].append(str(e))
            return results
