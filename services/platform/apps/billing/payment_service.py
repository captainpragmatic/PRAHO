"""
Payment Service for PRAHO Platform
Gateway-agnostic payment orchestration with Romanian compliance.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from django.db import transaction
from django.db.models import QuerySet

from apps.common.validators import log_security_event
from apps.customers.models import (
    CustomerPaymentMethod,
)
from apps.orders.models import Order

from .currency_models import Currency
from .gateways import PaymentGatewayFactory
from .gateways.base import GATEWAY_PAYMENT_METHODS, PaymentConfirmResult, PaymentIntentResult
from .models import Invoice, Payment
from .payment_convergence import PaymentSuccessService, converge_recurring_payment_failure
from .payment_models import TERMINAL_PAYMENT_STATUSES, PaymentRetryAttempt
from .recurring_billing import RecurringCollectionGate
from .recurring_locking import recurring_charge_submission_boundary

# Order statuses that permit a new payment intent to be created (H18).
_PAYABLE_ORDER_STATUSES: frozenset[str] = frozenset({"draft", "awaiting_payment"})
_PAYMENT_IDEMPOTENCY_KEY_MAX_LENGTH = 64

logger = logging.getLogger(__name__)


def _mark_invoice_payment_attempt_failed(payment_id: int, error: str | None, gateway_txn_id: str = "") -> None:
    """Terminally record a definitive gateway failure so a later retry gets a new key.

    The declined PaymentIntent's ID is persisted when the gateway surfaced one: Stripe will
    deliver a failure webhook for that intent, and with the ID on this (terminal) payment the
    webhook resolves HERE instead of entering the unlinked-recovery path, where it could bind
    to a later retry attempt's pending payment and record a real charge as failed.
    """
    with transaction.atomic():
        payment = Payment.objects.select_for_update(of=("self",)).get(id=payment_id)
        if gateway_txn_id and not payment.gateway_txn_id:
            payment.gateway_txn_id = gateway_txn_id
            payment.save(update_fields=["gateway_txn_id", "updated_at"])
        changed = payment.apply_gateway_event("failed", {"gateway_error": error or "unknown"})
        if changed:
            converge_recurring_payment_failure(payment)


def _abandon_unbound_payment_reservation(payment: Payment, reason: str) -> None:
    """Release a local reservation without treating it as a collection failure.

    A competing local payment may already have settled the document. Triggering
    recurring-payment dunning in that case would incorrectly penalize a paid
    customer. A gateway-bound attempt is never abandoned here because its
    external outcome must be reconciled instead.
    """
    if payment.status != "pending" or payment.gateway_txn_id:
        return
    changed = payment.apply_gateway_event(
        "failed",
        {
            "reservation_abandoned": True,
            "reservation_error": reason,
        },
    )
    if changed:
        log_security_event(
            "automatic_payment_reservation_abandoned",
            {
                "payment_id": str(payment.id),
                "invoice_id": str(payment.invoice_id or ""),
                "proforma_id": str(payment.proforma_id or ""),
                "reason": reason,
                "critical_financial_operation": True,
            },
        )


def _submit_recurring_charge_under_revocation_lock(
    *,
    customer_id: int,
    payment: Payment,
    revalidate: Callable[[], str | None],
    submit: Callable[[], PaymentIntentResult],
    reservation_is_resumed: bool = False,
) -> tuple[PaymentIntentResult, bool]:
    """Order revocation and gateway submission, returning whether submission was attempted.

    A RESUMED reservation (carried over from a prior attempt) may already have
    reached Stripe — the charge could have succeeded with its binding lost to a
    worker death and its success webhook not yet delivered. Such a reservation
    is never abandoned inline; its outcome is left to webhook reconciliation.
    Only a freshly-created reservation is provably pre-submit and safe to fail.
    """
    with recurring_charge_submission_boundary(customer_id) as boundary_error:
        if boundary_error is not None:
            if not reservation_is_resumed:
                _abandon_unbound_payment_reservation(payment, boundary_error)
            return (
                PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=boundary_error,
                ),
                False,
            )

        reservation_error = revalidate()
        if reservation_error is not None:
            return (
                PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=reservation_error,
                ),
                False,
            )
        return submit(), True


def _revalidate_invoice_payment_reservation(  # noqa: PLR0913  # Keyword-only reservation identity + abandon policy
    *,
    invoice_id: int,
    payment_id: int,
    expected_amount_cents: int,
    expected_currency_id: str,
    expected_saved_method_id: int,
    abandon_on_failure: bool = True,
) -> str | None:
    """Serialize the final local balance check immediately before collection."""
    with transaction.atomic():
        invoice = Invoice.objects.select_for_update(of=("self",)).get(id=invoice_id)
        payment = Payment.objects.select_for_update(of=("self",)).get(id=payment_id)

        if (
            invoice.status not in {"issued", "overdue"}
            or invoice.currency_id != expected_currency_id
            or invoice.get_remaining_amount() != expected_amount_cents
        ):
            reason = "Invoice balance changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        if (
            payment.status != "pending"
            or payment.invoice_id != invoice.id
            or payment.proforma_id is not None
            or payment.amount_cents != expected_amount_cents
            or payment.currency_id != expected_currency_id
            or payment.payment_method != "stripe"
            or payment.meta.get("source") != "recurring_billing"
        ):
            reason = "Invoice payment reservation changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        saved_method = (
            CustomerPaymentMethod.objects.select_for_update(of=("self",))
            .defer("bank_details")
            .filter(id=expected_saved_method_id, customer_id=invoice.customer_id, is_active=True)
            .first()
        )
        if saved_method is None:
            reason = "Recurring payment method became inactive before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        collection_authorization = RecurringCollectionGate.authorize_invoice(invoice, saved_method)
        if collection_authorization.is_err():
            reason = (
                "Recurring collection authorization changed before gateway collection: "
                f"{collection_authorization.unwrap_err()}"
            )
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
    return None


def _revalidate_order_payment_reservation(  # noqa: PLR0913  # Keyword-only reservation identity + abandon policy
    *,
    order_id: str,
    proforma_id: int,
    payment_id: int,
    expected_amount_cents: int,
    expected_currency_id: str,
    abandon_on_failure: bool = True,
) -> str | None:
    """Serialize order, document, and reservation immediately before checkout."""
    from .proforma_models import ProformaInvoice  # noqa: PLC0415

    with transaction.atomic():
        order = Order.objects.select_for_update(of=("self",)).get(id=order_id)
        proforma = ProformaInvoice.objects.select_for_update(of=("self",)).get(id=proforma_id)
        payment = Payment.objects.select_for_update(of=("self",)).get(id=payment_id)

        if (
            order.status not in _PAYABLE_ORDER_STATUSES
            or order.proforma_id != proforma.id
            or order.customer_id != proforma.customer_id
            or order.currency_id != expected_currency_id
            or proforma.status not in {"draft", "sent", "accepted"}
            or proforma.is_expired
            or proforma.currency_id != expected_currency_id
            or proforma.total_cents != expected_amount_cents
        ):
            reason = "Order billing document changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        if (
            payment.status != "pending"
            or payment.proforma_id != proforma.id
            or payment.invoice_id is not None
            or payment.customer_id != order.customer_id
            or payment.amount_cents != expected_amount_cents
            or payment.currency_id != expected_currency_id
            or payment.payment_method != "stripe"
            or payment.meta.get("source") != "portal_api"
            or payment.meta.get("order_id") != str(order.id)
        ):
            reason = "Order payment reservation changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
    return None


def _revalidate_proforma_payment_reservation(  # noqa: PLR0913  # Keyword-only reservation identity + abandon policy
    *,
    proforma_id: int,
    payment_id: int,
    expected_amount_cents: int,
    expected_currency_id: str,
    expected_saved_method_id: int,
    abandon_on_failure: bool = True,
) -> str | None:
    """Serialize the final proforma-state check immediately before collection."""
    from .proforma_models import ProformaInvoice  # noqa: PLC0415

    with transaction.atomic():
        proforma = ProformaInvoice.objects.select_for_update(of=("self",)).get(id=proforma_id)
        payment = Payment.objects.select_for_update(of=("self",)).get(id=payment_id)

        if (
            proforma.status not in {"draft", "sent", "accepted"}
            or proforma.is_expired
            or proforma.total_cents != expected_amount_cents
            or proforma.currency_id != expected_currency_id
        ):
            reason = "Proforma document changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        if (
            payment.status != "pending"
            or payment.proforma_id != proforma.id
            or payment.invoice_id is not None
            or payment.amount_cents != expected_amount_cents
            or payment.currency_id != expected_currency_id
            or payment.payment_method != "stripe"
            or payment.meta.get("source") != "recurring_billing"
        ):
            reason = "Proforma payment reservation changed before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        saved_method = (
            CustomerPaymentMethod.objects.select_for_update(of=("self",))
            .defer("bank_details")
            .filter(id=expected_saved_method_id, customer_id=proforma.customer_id, is_active=True)
            .first()
        )
        if saved_method is None:
            reason = "Recurring payment method became inactive before gateway collection"
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
        collection_authorization = RecurringCollectionGate.authorize_proforma(proforma, saved_method)
        if collection_authorization.is_err():
            reason = (
                "Recurring collection authorization changed before gateway collection: "
                f"{collection_authorization.unwrap_err()}"
            )
            if abandon_on_failure:
                _abandon_unbound_payment_reservation(payment, reason)
            return reason
    return None


def _preferred_existing_payment(payments: QuerySet[Payment]) -> Payment | None:
    """Prefer settled or gateway-bound truth over a newer incomplete duplicate."""
    succeeded = payments.filter(status="succeeded").order_by("-created_at").first()
    if succeeded is not None:
        return succeeded
    gateway_bound = (
        payments.exclude(gateway_txn_id__isnull=True).exclude(gateway_txn_id="").order_by("-created_at").first()
    )
    return gateway_bound or payments.order_by("-created_at").first()


def _bind_retry_result_before_gateway(payment: Payment, retry_attempt_id: UUID | None) -> str | None:
    """Make retry ownership visible before a synchronous gateway decline can converge."""
    if retry_attempt_id is None:
        return None

    with transaction.atomic():
        retry = (
            PaymentRetryAttempt.objects.select_for_update(of=("self",))
            .select_related("payment")
            .filter(id=retry_attempt_id)
            .first()
        )
        if retry is None:
            return "Payment retry attempt does not exist"
        original = retry.payment
        same_document = (
            original.invoice_id is not None
            and original.invoice_id == payment.invoice_id
            and payment.proforma_id is None
        ) or (
            original.proforma_id is not None
            and original.proforma_id == payment.proforma_id
            and payment.invoice_id is None
        )
        if (
            retry.status != "processing"
            or original.status != "failed"
            or original.id == payment.id
            or original.customer_id != payment.customer_id
            or original.currency_id != payment.currency_id
            or original.payment_method != payment.payment_method
            or not same_document
            or payment.status != "pending"
        ):
            return "Payment retry attempt does not own this recurring payment reservation"
        if retry.result_payment_id not in {None, payment.id}:
            return "Payment retry attempt is already bound to another payment"
        if retry.result_payment_id is None:
            retry.result_payment = payment
            retry.save(update_fields=["result_payment", "updated_at"])
    return None


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
        """Compatibility wrapper over the single hardened order-payment path."""
        try:
            order = Order.objects.only("customer_id").get(id=order_id)
        except Order.DoesNotExist:
            logger.error(f"❌ Order {order_id} not found")
            return PaymentIntentResult(
                success=False, payment_intent_id="", client_secret=None, error=f"Order {order_id} not found"
            )
        return PaymentService.create_payment_intent_direct(
            order_id=order_id,
            customer_id=order.customer_id,
            gateway=gateway,
            metadata=metadata,
        )

    @staticmethod
    def create_payment_intent_direct(  # noqa: C901, PLR0911, PLR0912, PLR0913, PLR0915  # Security guards
        order_id: str,
        amount_cents: int | None = None,
        currency: str = "RON",
        customer_id: str | int | None = None,
        order_number: str | None = None,
        gateway: str = "stripe",
        metadata: object | None = None,
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

            if metadata is not None and not isinstance(metadata, dict):
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="metadata must be an object",
                )

            if gateway not in GATEWAY_PAYMENT_METHODS:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Payment gateway '{gateway}' does not support PaymentIntents",
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

            # Security-critical: locate the order, then derive the amount from its
            # frozen proforma billing document.
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

            proforma = order.proforma
            if proforma is None and order.total_cents <= 0:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Order does not require a payment",
                )
            if proforma is None:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="A positive-value order requires an authoritative proforma before payment",
                )
            if (
                proforma.customer_id != order.customer_id
                or proforma.currency_id != order.currency_id
                or proforma.status not in {"draft", "sent", "accepted"}
                or proforma.is_expired
            ):
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Order billing snapshot does not match its payable proforma",
                )

            expected_amount_cents = int(proforma.total_cents)
            if amount_cents is not None and int(amount_cents) != expected_amount_cents:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="amount_cents does not match proforma total",
                )
            if expected_amount_cents <= 0:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Order does not require a payment",
                )

            resolved_currency = proforma.currency.code
            resolved_order_number = order.order_number
            payment_metadata = {
                **(metadata or {}),
                "order_number": resolved_order_number,
                "customer_id": str(customer_id_int),
                "platform": "PRAHO",
                "source": "portal_api",
            }
            currency_obj, _ = Currency.objects.get_or_create(
                code=resolved_currency.upper(),
                defaults={
                    "name": resolved_currency.upper(),
                    "symbol": "RON" if resolved_currency.upper() == "RON" else resolved_currency.upper(),
                    "decimals": 2,
                },
            )

            # H19: Reuse an exact existing order attempt. A local row with no
            # gateway ID represents an interrupted/uncertain create call and must
            # resume with its original idempotency key.
            exact_pending_payments = Payment.objects.filter(
                customer_id=customer_id_int,
                payment_method=gateway,
                status="pending",
                meta__order_id=str(order.id),
            )
            existing_payment = _preferred_existing_payment(exact_pending_payments)

            if existing_payment is not None and (
                existing_payment.amount_cents != expected_amount_cents
                or existing_payment.currency_id != currency_obj.id
                or existing_payment.proforma_id != (order.proforma_id or None)
            ):
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id=existing_payment.gateway_txn_id or "",
                    client_secret=None,
                    error="Existing pending payment is not a resumable attempt for this order",
                )

            if existing_payment is not None and existing_payment.gateway_txn_id:
                logger.info(
                    "♻️ [PaymentService] Returning existing pending payment %s for order %s",
                    existing_payment.id,
                    order.id,
                )
                return PaymentIntentResult(
                    success=True,
                    payment_intent_id=existing_payment.gateway_txn_id,
                    client_secret=existing_payment.meta.get("client_secret"),
                    error=None,
                )

            created = False
            if existing_payment is not None:
                if not existing_payment.idempotency_key:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Existing pending payment is not a resumable attempt for this order",
                    )
                payment = existing_payment
                idempotency_key = existing_payment.idempotency_key
            else:
                attempt_number = (
                    Payment.objects.filter(
                        customer_id=customer_id_int,
                        payment_method=gateway,
                        meta__order_id=str(order.id),
                    ).count()
                    + 1
                )
                idempotency_key = f"order:{order.id}:{gateway}:{attempt_number}"
                payment_meta: dict[str, Any] = {
                    "client_secret": None,
                    "order_id": str(order.id),
                    "gateway": gateway,
                    **payment_metadata,
                }
                if order.proforma is not None:
                    payment_meta["proforma_id"] = str(order.proforma.id)
                with transaction.atomic():
                    payment, created = Payment.objects.get_or_create(
                        idempotency_key=idempotency_key,
                        defaults={
                            "invoice": None,
                            "proforma": order.proforma,
                            "customer": order.customer,
                            "payment_method": gateway,
                            "amount_cents": expected_amount_cents,
                            "currency": currency_obj,
                            "status": "pending",
                            "gateway_txn_id": None,
                            "meta": payment_meta,
                        },
                    )
                if not created and (
                    payment.customer_id != order.customer_id
                    or payment.amount_cents != expected_amount_cents
                    or payment.currency_id != currency_obj.id
                    or (payment.meta or {}).get("order_id") != str(order.id)
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Payment idempotency key conflicts with an existing payment",
                    )

            logger.info(
                "💳 Creating payment intent for order %s (%s %s) via %s",
                order.id,
                expected_amount_cents,
                resolved_currency,
                gateway,
            )
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)
            reservation_error = _revalidate_order_payment_reservation(
                order_id=str(order.id),
                proforma_id=proforma.id,
                payment_id=payment.id,
                expected_amount_cents=expected_amount_cents,
                expected_currency_id=currency_obj.id,
            )
            if reservation_error is not None:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=reservation_error,
                )
            # #240/#294 replay safety: a resumed attempt reuses its original idempotency
            # key, and Stripe rejects a key replay whose request differs. The gateway
            # request therefore derives from the attempt's STORED snapshot — identical to
            # payment_metadata on a fresh attempt, and the original request on a resume,
            # no matter what metadata the retry caller passes.
            snapshot_metadata = {
                k: v
                for k, v in (payment.meta or {}).items()
                if k not in ("client_secret", "order_id", "gateway") and v is not None
            }
            result = payment_gateway.create_payment_intent(
                order_id=str(order.id),
                amount_cents=expected_amount_cents,
                currency=resolved_currency,
                metadata=snapshot_metadata,
                idempotency_key=idempotency_key,
            )
            if not result.get("success", False):
                return result

            payment_intent_id = result.get("payment_intent_id", "")
            if not payment_intent_id:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Payment gateway returned success without a transaction ID",
                )

            with transaction.atomic():
                payment = Payment.objects.select_for_update(of=("self",)).get(id=payment.id)
                if payment.gateway_txn_id and payment.gateway_txn_id != payment_intent_id:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id,
                        client_secret=payment.meta.get("client_secret"),
                        error="Payment attempt is already bound to a different gateway transaction",
                    )
                if Payment.objects.filter(gateway_txn_id=payment_intent_id).exclude(id=payment.id).exists():
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Payment gateway transaction conflicts with an existing payment",
                    )
                payment.gateway_txn_id = payment_intent_id
                payment.meta = {**(payment.meta or {}), "client_secret": result.get("client_secret")}
                payment.save(update_fields=["gateway_txn_id", "meta", "updated_at"])

            logger.info("✅ Reconciled payment %s for Portal order %s", payment.id, order.id)
            if created:
                log_security_event(
                    "payment_intent_created_direct",
                    {
                        "payment_id": str(payment.id),
                        "order_id": str(order.id),
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
    def create_payment_intent_for_invoice(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Financial guards are explicit
        invoice_id: int,
        payment_method_id: str,
        gateway: str = "stripe",
        retry_attempt_id: UUID | None = None,
    ) -> PaymentIntentResult:
        """Create an idempotent off-session payment for an issued invoice.

        Customer, currency, and outstanding amount are loaded from the invoice.
        The supplied saved method must be active and belong to that customer.
        """
        try:
            if gateway not in GATEWAY_PAYMENT_METHODS:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Recurring invoice gateway '{gateway}' is unsupported; only Stripe may collect saved cards",
                )
            try:
                invoice = Invoice.objects.select_related("customer", "currency").get(id=invoice_id)
            except Invoice.DoesNotExist:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Invoice {invoice_id} not found",
                )

            if invoice.status not in {"issued", "overdue"}:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Invoice status '{invoice.status}' is not eligible for payment",
                )

            resolved_currency = invoice.currency.code
            remaining_amount_cents = invoice.get_remaining_amount()

            saved_method = (
                CustomerPaymentMethod.objects.filter(
                    customer_id=invoice.customer_id,
                    method_type="stripe_card",
                    stripe_payment_method_id=payment_method_id,
                    is_active=True,
                )
                .defer("bank_details")
                .exclude(stripe_customer_id="")
                .first()
            )
            if saved_method is None:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Invoice customer has no matching active Stripe payment method",
                )

            collection_authorization = RecurringCollectionGate.authorize_invoice(invoice, saved_method)
            if collection_authorization.is_err():
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=collection_authorization.unwrap_err(),
                )

            existing_pending = _preferred_existing_payment(
                Payment.objects.filter(invoice=invoice, payment_method=gateway, status="pending")
            )
            payment: Payment | None = None
            idempotency_key = ""
            if existing_pending is not None:
                existing_currency = existing_pending.currency.code if existing_pending.currency else ""
                existing_idempotency_key = existing_pending.idempotency_key
                if (
                    existing_pending.amount_cents != remaining_amount_cents
                    or existing_currency.upper() != resolved_currency.upper()
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=existing_pending.gateway_txn_id or "",
                        client_secret=None,
                        error="Existing pending payment does not match the invoice balance or currency",
                    )
                if existing_pending.gateway_txn_id:
                    retry_binding_error = _bind_retry_result_before_gateway(existing_pending, retry_attempt_id)
                    if retry_binding_error is not None:
                        return PaymentIntentResult(
                            success=False,
                            payment_intent_id="",
                            client_secret=None,
                            error=retry_binding_error,
                        )
                    return PaymentIntentResult(
                        success=True,
                        payment_intent_id=existing_pending.gateway_txn_id,
                        client_secret=existing_pending.meta.get("client_secret"),
                        error=None,
                    )
                if (
                    existing_pending.meta.get("source") != "recurring_billing"
                    or existing_pending.meta.get("stripe_payment_method_id") != saved_method.stripe_payment_method_id
                    or not existing_idempotency_key
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Existing pending payment has no gateway transaction ID and is not a resumable attempt",
                    )
                payment = existing_pending
                idempotency_key = existing_idempotency_key
                reservation_is_resumed = True

            if remaining_amount_cents <= 0:
                existing_succeeded = (
                    Payment.objects.filter(
                        invoice=invoice,
                        payment_method=gateway,
                        status="succeeded",
                    )
                    .order_by("-created_at")
                    .first()
                )
                if existing_succeeded is not None:
                    return PaymentIntentResult(
                        success=True,
                        payment_intent_id=existing_succeeded.gateway_txn_id or "",
                        client_secret=existing_succeeded.meta.get("client_secret"),
                        error=None,
                    )
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Invoice has no outstanding balance",
                )

            gateway_metadata = {
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "customer_id": str(invoice.customer_id),
                "platform": "PRAHO",
                "source": "recurring_billing",
            }
            if payment is None:
                attempt_number = Payment.objects.filter(invoice=invoice, payment_method=gateway).count() + 1
                idempotency_key = f"invoice:{invoice.id}:{gateway}:{attempt_number}"
                if len(idempotency_key) > _PAYMENT_IDEMPOTENCY_KEY_MAX_LENGTH:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Generated invoice payment idempotency key is too long",
                    )
                with transaction.atomic():
                    payment, created = Payment.objects.get_or_create(
                        idempotency_key=idempotency_key,
                        defaults={
                            "invoice": invoice,
                            "customer": invoice.customer,
                            "payment_method": gateway,
                            "amount_cents": remaining_amount_cents,
                            "currency": invoice.currency,
                            "status": "pending",
                            "gateway_txn_id": None,
                            "meta": {
                                **gateway_metadata,
                                "client_secret": None,
                                "gateway": gateway,
                                "stripe_customer_id": saved_method.stripe_customer_id,
                                "stripe_payment_method_id": saved_method.stripe_payment_method_id,
                            },
                        },
                    )
                reservation_is_resumed = not created
                if not created and (
                    payment.invoice_id != invoice.id
                    or payment.proforma_id is not None
                    or payment.customer_id != invoice.customer_id
                    or payment.payment_method != gateway
                    or payment.amount_cents != remaining_amount_cents
                    or payment.currency_id != invoice.currency_id
                    or payment.status != "pending"
                    or payment.meta.get("source") != "recurring_billing"
                    or payment.meta.get("stripe_customer_id") != saved_method.stripe_customer_id
                    or payment.meta.get("stripe_payment_method_id") != saved_method.stripe_payment_method_id
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id or "",
                        client_secret=None,
                        error="Invoice payment idempotency key conflicts with another payment",
                    )
                if not created and payment.gateway_txn_id:
                    retry_binding_error = _bind_retry_result_before_gateway(payment, retry_attempt_id)
                    if retry_binding_error is not None:
                        return PaymentIntentResult(
                            success=False,
                            payment_intent_id="",
                            client_secret=None,
                            error=retry_binding_error,
                        )
                    return PaymentIntentResult(
                        success=True,
                        payment_intent_id=payment.gateway_txn_id,
                        client_secret=payment.meta.get("client_secret"),
                        error=None,
                    )
                if created:
                    log_security_event(
                        "invoice_payment_attempt_created",
                        {
                            "payment_id": str(payment.id),
                            "invoice_id": str(invoice.id),
                            "customer_id": str(invoice.customer_id),
                            "amount_cents": remaining_amount_cents,
                            "currency": resolved_currency,
                            "gateway": gateway,
                            "critical_financial_operation": True,
                        },
                    )

            retry_binding_error = _bind_retry_result_before_gateway(payment, retry_attempt_id)
            if retry_binding_error is not None:
                # Resumed reservations may already carry a live intent — never fail
                # them inline; a fresh one is provably pre-submit.
                if not reservation_is_resumed:
                    _abandon_unbound_payment_reservation(payment, retry_binding_error)
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=retry_binding_error,
                )

            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)
            payment_id = payment.id
            # Attempt-scoped: lets webhook recovery bind ONLY to this exact attempt.
            gateway_metadata["payment_attempt"] = str(payment_id)
            result, submitted = _submit_recurring_charge_under_revocation_lock(
                customer_id=invoice.customer_id,
                payment=payment,
                reservation_is_resumed=reservation_is_resumed,
                revalidate=lambda: _revalidate_invoice_payment_reservation(
                    invoice_id=invoice.id,
                    payment_id=payment_id,
                    expected_amount_cents=remaining_amount_cents,
                    expected_currency_id=invoice.currency_id,
                    expected_saved_method_id=saved_method.id,
                    abandon_on_failure=not reservation_is_resumed,
                ),
                submit=lambda: payment_gateway.create_off_session_payment_intent(
                    document_id=str(invoice.id),
                    document_type="invoice",
                    amount_cents=remaining_amount_cents,
                    currency=resolved_currency,
                    customer_id=saved_method.stripe_customer_id,
                    payment_method_id=saved_method.stripe_payment_method_id,
                    metadata=gateway_metadata,
                    idempotency_key=idempotency_key,
                ),
            )
            if not submitted:
                return result
            if not result.get("success", False):
                if not result.get("retryable", False):
                    _mark_invoice_payment_attempt_failed(
                        payment.id, result.get("error"), gateway_txn_id=result.get("payment_intent_id") or ""
                    )
                return result

            payment_intent_id = result.get("payment_intent_id", "")
            if not payment_intent_id:
                logger.error(
                    "❌ Gateway returned success without a payment intent ID for invoice %s",
                    invoice.id,
                )
                _mark_invoice_payment_attempt_failed(
                    payment.id,
                    "Payment gateway returned success without a payment intent ID",
                )
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Payment gateway returned success without a payment intent ID",
                )
            client_secret = result.get("client_secret")
            with transaction.atomic():
                payment = Payment.objects.select_for_update(of=("self",)).get(id=payment.id)
                if payment.gateway_txn_id and payment.gateway_txn_id != payment_intent_id:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id,
                        client_secret=payment.meta.get("client_secret"),
                        error="Gateway returned a different intent for the same payment attempt",
                    )
                if Payment.objects.filter(gateway_txn_id=payment_intent_id).exclude(id=payment.id).exists():
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Payment gateway transaction conflicts with an existing payment",
                    )
                payment.gateway_txn_id = payment_intent_id
                payment.meta = {
                    **payment.meta,
                    "client_secret": client_secret,
                }
                payment.save(update_fields=["gateway_txn_id", "meta", "updated_at"])

            canonical_result = PaymentIntentResult(
                success=True,
                payment_intent_id=payment.gateway_txn_id or "",
                client_secret=payment.meta.get("client_secret"),
                error=None,
            )
            return canonical_result
        except Exception as e:
            logger.error("🔥 Error creating payment intent for invoice %s: %s", invoice_id, e)
            return PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error=f"Invoice payment creation failed: {e}",
            )

    @staticmethod
    def create_payment_intent_for_proforma(  # noqa: C901, PLR0911, PLR0912, PLR0915
        proforma_id: int,
        payment_method_id: str,
        gateway: str = "stripe",
        retry_attempt_id: UUID | None = None,
    ) -> PaymentIntentResult:
        """Create an idempotent off-session payment for a recurring proforma."""
        from .proforma_models import ProformaInvoice  # noqa: PLC0415

        try:
            if gateway not in GATEWAY_PAYMENT_METHODS:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Recurring proforma gateway '{gateway}' is unsupported; only Stripe may collect saved cards",
                )
            try:
                proforma = ProformaInvoice.objects.select_related("customer", "currency").get(id=proforma_id)
            except ProformaInvoice.DoesNotExist:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Proforma {proforma_id} not found",
                )

            if proforma.status not in {"draft", "sent", "accepted"}:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Proforma status '{proforma.status}' is not eligible for payment",
                )
            if proforma.is_expired:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=f"Proforma {proforma.number} has expired",
                )

            saved_method = (
                CustomerPaymentMethod.objects.filter(
                    customer_id=proforma.customer_id,
                    method_type="stripe_card",
                    stripe_payment_method_id=payment_method_id,
                    is_active=True,
                )
                .defer("bank_details")
                .exclude(stripe_customer_id="")
                .first()
            )
            if saved_method is None:
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Proforma customer has no matching active Stripe payment method",
                )

            authorization = RecurringCollectionGate.authorize_proforma(proforma, saved_method)
            if authorization.is_err():
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=authorization.unwrap_err(),
                )

            existing = _preferred_existing_payment(
                Payment.objects.filter(
                    proforma=proforma,
                    payment_method=gateway,
                    status__in=["pending", "succeeded"],
                )
            )
            if existing is not None:
                if existing.amount_cents != proforma.total_cents or existing.currency_id != proforma.currency_id:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=existing.gateway_txn_id or "",
                        client_secret=None,
                        error="Existing proforma payment does not match the document total or currency",
                    )
                if existing.gateway_txn_id:
                    retry_binding_error = _bind_retry_result_before_gateway(existing, retry_attempt_id)
                    if retry_binding_error is not None:
                        return PaymentIntentResult(
                            success=False,
                            payment_intent_id="",
                            client_secret=None,
                            error=retry_binding_error,
                        )
                    return PaymentIntentResult(
                        success=True,
                        payment_intent_id=existing.gateway_txn_id,
                        client_secret=existing.meta.get("client_secret"),
                        error=None,
                    )
                if (
                    existing.meta.get("source") != "recurring_billing"
                    or existing.meta.get("stripe_payment_method_id") != saved_method.stripe_payment_method_id
                    or not existing.idempotency_key
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Existing pending proforma payment is not a resumable recurring attempt",
                    )
                payment = existing
                idempotency_key = existing.idempotency_key
                reservation_is_resumed = True
            else:
                attempt_number = Payment.objects.filter(proforma=proforma, payment_method=gateway).count() + 1
                idempotency_key = f"proforma:{proforma.id}:{gateway}:{attempt_number}"
                if len(idempotency_key) > _PAYMENT_IDEMPOTENCY_KEY_MAX_LENGTH:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Generated proforma payment idempotency key is too long",
                    )
                with transaction.atomic():
                    payment, created = Payment.objects.get_or_create(
                        idempotency_key=idempotency_key,
                        defaults={
                            "proforma": proforma,
                            "customer": proforma.customer,
                            "payment_method": gateway,
                            "amount_cents": proforma.total_cents,
                            "currency": proforma.currency,
                            "status": "pending",
                            "gateway_txn_id": None,
                            "meta": {
                                "proforma_id": str(proforma.id),
                                "proforma_number": proforma.number,
                                "customer_id": str(proforma.customer_id),
                                "platform": "PRAHO",
                                "source": "recurring_billing",
                                "gateway": gateway,
                                "client_secret": None,
                                "stripe_customer_id": saved_method.stripe_customer_id,
                                "stripe_payment_method_id": saved_method.stripe_payment_method_id,
                            },
                        },
                    )
                reservation_is_resumed = not created
                if not created and (
                    payment.proforma_id != proforma.id
                    or payment.invoice_id is not None
                    or payment.customer_id != proforma.customer_id
                    or payment.payment_method != gateway
                    or payment.amount_cents != proforma.total_cents
                    or payment.currency_id != proforma.currency_id
                    or payment.status != "pending"
                    or payment.meta.get("source") != "recurring_billing"
                    or payment.meta.get("stripe_customer_id") != saved_method.stripe_customer_id
                    or payment.meta.get("stripe_payment_method_id") != saved_method.stripe_payment_method_id
                ):
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id or "",
                        client_secret=None,
                        error="Proforma payment idempotency key conflicts with another payment",
                    )
                if not created and payment.gateway_txn_id:
                    retry_binding_error = _bind_retry_result_before_gateway(payment, retry_attempt_id)
                    if retry_binding_error is not None:
                        return PaymentIntentResult(
                            success=False,
                            payment_intent_id="",
                            client_secret=None,
                            error=retry_binding_error,
                        )
                    return PaymentIntentResult(
                        success=True,
                        payment_intent_id=payment.gateway_txn_id,
                        client_secret=payment.meta.get("client_secret"),
                        error=None,
                    )

            retry_binding_error = _bind_retry_result_before_gateway(payment, retry_attempt_id)
            if retry_binding_error is not None:
                # Resumed reservations may already carry a live intent — never fail
                # them inline; a fresh one is provably pre-submit.
                if not reservation_is_resumed:
                    _abandon_unbound_payment_reservation(payment, retry_binding_error)
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error=retry_binding_error,
                )

            gateway_metadata = {
                "proforma_id": str(proforma.id),
                "proforma_number": proforma.number,
                "customer_id": str(proforma.customer_id),
                "platform": "PRAHO",
                "source": "recurring_billing",
            }
            payment_gateway = PaymentGatewayFactory.create_gateway(gateway)
            payment_id = payment.id
            # Attempt-scoped: lets webhook recovery bind ONLY to this exact attempt.
            gateway_metadata["payment_attempt"] = str(payment_id)
            result, submitted = _submit_recurring_charge_under_revocation_lock(
                customer_id=proforma.customer_id,
                payment=payment,
                reservation_is_resumed=reservation_is_resumed,
                revalidate=lambda: _revalidate_proforma_payment_reservation(
                    proforma_id=proforma.id,
                    payment_id=payment_id,
                    expected_amount_cents=proforma.total_cents,
                    expected_currency_id=proforma.currency_id,
                    expected_saved_method_id=saved_method.id,
                    abandon_on_failure=not reservation_is_resumed,
                ),
                submit=lambda: payment_gateway.create_off_session_payment_intent(
                    document_id=str(proforma.id),
                    document_type="proforma",
                    amount_cents=proforma.total_cents,
                    currency=proforma.currency.code,
                    customer_id=saved_method.stripe_customer_id,
                    payment_method_id=saved_method.stripe_payment_method_id,
                    metadata=gateway_metadata,
                    idempotency_key=idempotency_key,
                ),
            )
            if not submitted:
                return result
            if not result.get("success", False):
                if not result.get("retryable", False):
                    _mark_invoice_payment_attempt_failed(
                        payment.id, result.get("error"), gateway_txn_id=result.get("payment_intent_id") or ""
                    )
                return result

            payment_intent_id = result.get("payment_intent_id", "")
            if not payment_intent_id:
                _mark_invoice_payment_attempt_failed(
                    payment.id,
                    "Payment gateway returned success without a payment intent ID",
                )
                return PaymentIntentResult(
                    success=False,
                    payment_intent_id="",
                    client_secret=None,
                    error="Payment gateway returned success without a payment intent ID",
                )

            with transaction.atomic():
                payment = Payment.objects.select_for_update(of=("self",)).get(id=payment.id)
                if payment.gateway_txn_id and payment.gateway_txn_id != payment_intent_id:
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id=payment.gateway_txn_id,
                        client_secret=payment.meta.get("client_secret"),
                        error="Gateway returned a different intent for the same proforma payment attempt",
                    )
                if Payment.objects.filter(gateway_txn_id=payment_intent_id).exclude(id=payment.id).exists():
                    return PaymentIntentResult(
                        success=False,
                        payment_intent_id="",
                        client_secret=None,
                        error="Payment gateway transaction conflicts with an existing payment",
                    )
                payment.gateway_txn_id = payment_intent_id
                payment.meta = {**payment.meta, "client_secret": result.get("client_secret")}
                payment.save(update_fields=["gateway_txn_id", "meta", "updated_at"])

            return PaymentIntentResult(
                success=True,
                payment_intent_id=payment.gateway_txn_id or "",
                client_secret=payment.meta.get("client_secret"),
                error=None,
            )
        except Exception as exc:
            logger.exception("Error creating payment intent for proforma %s", proforma_id)
            return PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error=f"Proforma payment creation failed: {exc}",
            )

    @staticmethod
    def confirm_payment(  # noqa: C901, PLR0911, PLR0912  # Explicit ownership, idempotency, and gateway guards
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

            if result.get("success", False) and result.get("status") == "succeeded":
                convergence = PaymentSuccessService.converge_gateway_success(payment_intent_id, result)
                if convergence.is_err():
                    error = convergence.unwrap_err()
                    if error.startswith("Payment state mismatch"):
                        failure_status = "fsm_conflict"
                    elif error.startswith("Payment not found"):
                        failure_status = "payment_not_found"
                    else:
                        failure_status = "gateway_fact_mismatch"
                    return PaymentConfirmResult(
                        success=False,
                        status=failure_status,
                        error=error,
                    )
                return result

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
                                if new_status == "failed":
                                    converge_recurring_payment_failure(payment)
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
