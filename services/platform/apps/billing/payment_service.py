"""
Payment Service for PRAHO Platform
Gateway-agnostic payment orchestration with Romanian compliance.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import Case, IntegerField, Value, When

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

# Order statuses that permit a new payment intent to be created (H18).
_PAYABLE_ORDER_STATUSES: frozenset[str] = frozenset({"draft", "awaiting_payment"})

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
    def create_payment_intent_direct(  # payment processing fields  # noqa: C901, PLR0912, PLR0913, PLR0911
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
                order = Order.objects.select_related("customer", "proforma").get(
                    id=order_id, customer_id=customer_id_int
                )
            except Order.DoesNotExist:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Order not found for this customer",
                )

            # H18: Only allow payment intent creation for orders in a payable state.
            if order.status not in _PAYABLE_ORDER_STATUSES:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Order status '{order.status}' is not eligible for payment",
                )

            expected_amount_cents = int(order.total_cents)
            if amount_cents is not None and int(amount_cents) != expected_amount_cents:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="amount_cents does not match order total",
                )

            order_payment_filter = {
                "customer_id": customer_id_int,
                "payment_method": gateway,
                "meta__order_id": str(order.id),
            }
            attempt_number = Payment.objects.filter(**order_payment_filter).count() + 1
            resolved_currency = (order.currency.code if order.currency else None) or currency or "RON"
            resolved_order_number = order.order_number

            # H19: Reuse an existing pending or completed intent for this exact
            # order and gateway. A succeeded payment can temporarily coexist with
            # an awaiting-payment order while downstream invoice conversion retries.
            # Count first so a Payment inserted between these queries either gets
            # returned here or shares the attempt key derived below.
            existing_payment = (
                Payment.objects.filter(
                    **order_payment_filter,
                    status__in=("pending", "succeeded"),
                )
                .select_related("currency")
                .order_by(
                    Case(
                        When(status="succeeded", then=Value(0)),
                        default=Value(1),
                        output_field=IntegerField(),
                    ),
                    "-created_at",
                )
                .first()
            )

            if existing_payment is not None:
                existing_currency = existing_payment.currency.code if existing_payment.currency else ""
                if (
                    existing_payment.amount_cents != expected_amount_cents
                    or existing_currency.upper() != resolved_currency.upper()
                ):
                    logger.warning(
                        "⚠️ [PaymentService] Existing %s payment %s does not match order %s amount/currency",
                        existing_payment.status,
                        existing_payment.id,
                        order.id,
                    )
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=existing_payment.gateway_txn_id or "",
                        client_secret=None,
                        error="Existing payment does not match the authoritative order amount or currency",
                    )

                logger.info(
                    "♻️ [PaymentService] Returning existing %s payment %s for order %s",
                    existing_payment.status,
                    existing_payment.id,
                    order.id,
                )
                return PaymentIntentResult(
                    success=True,
                    payment_intent_id=existing_payment.gateway_txn_id or "",
                    client_secret=existing_payment.meta.get("client_secret"),
                    error=None,
                )

            logger.info(
                "💳 Creating payment intent for order %s (%s %s) via %s",
                order.id,
                expected_amount_cents,
                resolved_currency,
                gateway,
            )

            # Get payment gateway
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)

            # Keep the idempotent gateway request stable across local retries.
            # Caller metadata is persisted locally but is not sent to the gateway,
            # where changing it for the same key would be rejected by Stripe.
            gateway_metadata = {
                "order_number": resolved_order_number,
                "customer_id": str(customer_id_int),
                "platform": "PRAHO",
                "source": "portal_api",
                "order_id": str(order.id),
                "gateway": gateway,
            }
            payment_metadata = {**(metadata or {}), **gateway_metadata}
            idempotency_payload = {
                "gateway": gateway,
                "order_id": str(order.id),
                "attempt_number": attempt_number,
                "amount_cents": expected_amount_cents,
                "currency": resolved_currency,
                "metadata": gateway_metadata,
            }
            idempotency_key = hashlib.sha256(
                json.dumps(idempotency_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

            # Create payment intent
            result = payment_gateway.create_payment_intent(
                order_id=str(order.id),
                amount_cents=expected_amount_cents,
                currency=resolved_currency,
                metadata=gateway_metadata,
                idempotency_key=idempotency_key,
            )

            if order.proforma is None and expected_amount_cents > 0:
                logger.warning(
                    "⚠️ [PaymentService] Order %s has no proforma but total is %d cents — "
                    "order may not be in awaiting_payment yet",
                    order.order_number,
                    expected_amount_cents,
                )

            if result.get("success", False):
                # Create Payment record linked to the order's proforma (if present).
                # All paid orders follow: draft → awaiting_payment (proforma created) →
                # payment (Payment linked to proforma) → proforma converts to invoice →
                # order advances. The proforma link enables the Stripe webhook to convert
                # the proforma to an invoice automatically via record_payment_and_convert().
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

                    payment_meta: dict[str, Any] = {
                        **payment_metadata,
                        "client_secret": client_secret,
                        "order_id": str(order.id),
                        "gateway": gateway,
                        "customer_id": str(customer_id_int),
                    }
                    if order.proforma is not None:
                        payment_meta["proforma_id"] = str(order.proforma.id)

                    payment, payment_created = Payment.objects.get_or_create(
                        idempotency_key=idempotency_key,
                        defaults={
                            "invoice": None,
                            "proforma": order.proforma,
                            "customer": order.customer,
                            "payment_method": gateway,
                            "amount_cents": expected_amount_cents,
                            "currency": currency_obj,
                            "status": "pending",
                            "gateway_txn_id": payment_intent_id,
                            "meta": payment_meta,
                        },
                    )

                if not payment_created and payment.status not in {"pending", "succeeded"}:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id or "",
                        client_secret=payment.meta.get("client_secret"),
                        error=f"Payment attempt is {payment.status}; retry to create a new attempt",
                    )

                result = PaymentIntentResult(
                    success=True,
                    payment_intent_id=payment.gateway_txn_id or "",
                    client_secret=payment.meta.get("client_secret"),
                    error=None,
                )
                if payment_created:
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
    def confirm_payment(  # noqa: PLR0911  # Early-return guards for ownership + idempotency
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
            # Ownership check BEFORE gateway call — prevent IDOR where an attacker
            # confirms someone else's payment intent by guessing the ID.
            if customer_id is not None:
                try:
                    expected_customer_id = int(customer_id)
                except (TypeError, ValueError):
                    return PaymentConfirmResult(
                        success=False,
                        status="failed",
                        error="customer_id must be a valid integer",
                    )
                try:
                    pre_check = Payment.objects.only("customer_id").get(gateway_txn_id=payment_intent_id)
                except Payment.DoesNotExist:
                    return PaymentConfirmResult(
                        success=False,
                        status="failed",
                        error="Payment not found",
                    )
                if pre_check.customer_id != expected_customer_id:
                    return PaymentConfirmResult(
                        success=False,
                        status="failed",
                        error="Payment does not belong to this customer",
                    )

            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)
            result = payment_gateway.confirm_payment(payment_intent_id)

            if result.get("success", False):
                # Update payment record status
                try:
                    with transaction.atomic():
                        payment = Payment.objects.select_for_update(of=("self",)).get(gateway_txn_id=payment_intent_id)

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
                            changed = payment.apply_gateway_event(new_status)
                            if changed:
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
                            elif new_status not in ("pending",):
                                logger.warning(
                                    "⚠️ [PaymentService] confirm_payment: transition %s → %s not applied "
                                    "for payment %s (current state: %s)",
                                    old_status,
                                    new_status,
                                    payment.id,
                                    payment.status,
                                )
                                return PaymentConfirmResult(
                                    success=False,
                                    status="fsm_conflict",
                                    error=f"Payment {payment.id} cannot transition from "
                                    f"'{old_status}' to '{new_status}' — FSM transition blocked",
                                )

                except Payment.DoesNotExist:
                    logger.warning(f"⚠️ Payment not found for intent {payment_intent_id}")

            return result

        except Exception as e:
            logger.error(f"🔥 Error confirming payment: {e}")
            return PaymentConfirmResult(success=False, status="error", error=f"Payment confirmation failed: {e}")

    @staticmethod
    def _persist_gateway_customer_id(customer_id: str, gateway_customer_id: str) -> str:
        """Merge a new gateway customer ID into the latest customer metadata."""
        with transaction.atomic():
            customer = Customer.objects.select_for_update(of=("self",)).get(id=customer_id)
            customer_meta = dict(customer.meta or {})
            existing_gateway_customer_id = customer_meta.get("stripe_customer_id")
            if existing_gateway_customer_id:
                return str(existing_gateway_customer_id)

            customer_meta["stripe_customer_id"] = gateway_customer_id
            customer.meta = customer_meta
            customer.save(update_fields=["meta"])
            return gateway_customer_id

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
                created_gateway_customer_id = ""
                try:
                    stripe_gateway = PaymentGatewayFactory.create_gateway(gateway)
                    if hasattr(stripe_gateway, "_stripe"):
                        stripe_customer_metadata = {"praho_customer_id": str(customer.id)}
                        stripe_customer_payload = {
                            "customer_id": str(customer.id),
                            "email": customer.primary_email or "",
                            "name": customer.name or "",
                            "metadata": stripe_customer_metadata,
                        }
                        stripe_customer_idempotency_key = hashlib.sha256(
                            json.dumps(stripe_customer_payload, sort_keys=True, separators=(",", ":")).encode()
                        ).hexdigest()
                        stripe_customer = stripe_gateway._stripe.Customer.create(
                            email=customer.primary_email or "",
                            name=customer.name or "",
                            metadata=stripe_customer_metadata,
                            idempotency_key=stripe_customer_idempotency_key,
                        )
                        created_gateway_customer_id = str(stripe_customer.id)
                except Exception as e:
                    logger.warning(f"⚠️ Could not create Stripe customer: {e}")
                    gateway_customer_id = f"cus_praho_{customer_id}"
                else:
                    if created_gateway_customer_id:
                        gateway_customer_id = PaymentService._persist_gateway_customer_id(
                            customer_id, created_gateway_customer_id
                        )

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
