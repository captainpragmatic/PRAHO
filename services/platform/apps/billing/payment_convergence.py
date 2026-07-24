"""Atomic convergence of successful gateway payments into PRAHO billing state."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .metering_models import BillingCycle, UsageAggregation
from .payment_models import Payment, PaymentRetryAttempt, PaymentRetryPolicy
from .recurring_billing import fixed_renewal_schedule
from .subscription_models import Subscription
from .validators import log_security_event

logger = logging.getLogger(__name__)


def _stripe_reference(value: object) -> str | None:
    """Return a stable Stripe object ID from either an ID or expanded object."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        object_id = value.get("id")
        return object_id if isinstance(object_id, str) else None
    object_id = getattr(value, "id", None)
    return object_id if isinstance(object_id, str) else None


def _schedule_recurring_payment_retry(payment: Payment) -> bool:
    """Idempotently seed collection for one definitive recurring failure.

    Retry-result Payments are already owned by the collection worker, which
    schedules the next attempt against the original failed Payment. Seeding a
    second retry chain for those result Payments would double-charge customers.
    """
    if PaymentRetryAttempt.objects.filter(result_payment_id=payment.id).exists():
        return False

    policy = PaymentRetryPolicy.objects.filter(is_active=True, is_default=True).order_by("id").first()
    if policy is None:
        logger.critical("Recurring payment %s failed but no active default retry policy exists", payment.id)
        return False

    if payment.failed_at is None:
        logger.critical("Recurring payment %s has no definitive failure timestamp; refusing to schedule", payment.id)
        return False

    scheduled_at = policy.get_next_retry_date(payment.failed_at, 0)
    if scheduled_at is None:
        logger.critical("Recurring retry policy %s has no first retry interval", policy.id)
        return False

    _attempt, created = PaymentRetryAttempt.objects.get_or_create(
        payment=payment,
        attempt_number=1,
        defaults={
            "policy": policy,
            "scheduled_at": scheduled_at,
            "status": "pending",
        },
    )
    if created:
        logger.info("Scheduled recurring payment retry for failed payment %s at %s", payment.id, scheduled_at)
    return created


def converge_recurring_payment_failure(payment: Payment) -> int:
    """Move every cycle owned by one failed recurring attempt into dunning.

    The caller must invoke this in the same transaction that transitions the
    Payment. That keeps an asynchronous gateway decline from leaving a failed
    Payment attached to a still-processing renewal cycle.
    """
    cycle_filter = Q(pk__in=[])
    if payment.proforma_id is not None:
        cycle_filter |= Q(proforma_id=payment.proforma_id)
    if payment.invoice_id is not None:
        cycle_filter |= Q(invoice_id=payment.invoice_id) | Q(usage_invoice_id=payment.invoice_id)

    cycles = list(
        BillingCycle.objects.select_for_update(of=("self",)).filter(cycle_filter).order_by("subscription_id", "id")
    )
    if not cycles:
        return 0

    subscriptions = list(
        Subscription.objects.select_for_update(of=("self",))
        .filter(id__in={cycle.subscription_id for cycle in cycles})
        .order_by("id")
    )
    for subscription in subscriptions:
        if subscription.status in {"active", "trialing", "past_due", "paused"}:
            subscription.mark_payment_failed()
    for cycle in cycles:
        cycle.collection_status = "past_due"
        cycle.save(update_fields=["collection_status", "updated_at"])
    _schedule_recurring_payment_retry(payment)
    return len(cycles)


class PaymentSuccessService:
    """Validate gateway facts and advance all paid state exactly once."""

    @staticmethod
    def converge_gateway_success(  # noqa: PLR0911  # Each financial rejection remains explicit and auditable
        gateway_txn_id: str,
        gateway_facts: Mapping[str, Any],
    ) -> Result[Payment, str]:
        try:
            with transaction.atomic():
                try:
                    payment = (
                        Payment.objects.select_for_update(of=("self",))
                        .select_related("currency", "invoice", "proforma")
                        .get(gateway_txn_id=gateway_txn_id)
                    )
                except Payment.DoesNotExist:
                    recovery = PaymentSuccessService.recover_unlinked_recurring_attempt(
                        gateway_txn_id,
                        gateway_facts,
                    )
                    if recovery.is_err():
                        return Err(recovery.unwrap_err())
                    payment = recovery.unwrap()
                validation_error = PaymentSuccessService._validate_gateway_facts(payment, gateway_facts)
                if validation_error:
                    PaymentSuccessService._log_validation_failure(payment, validation_error, gateway_facts)
                    return Err(validation_error)

                if payment.status not in {"pending", "succeeded"}:
                    return Err(f"Payment state mismatch: cannot succeed a payment in '{payment.status}'")

                meta_update = {
                    "stripe_payment_intent": gateway_txn_id,
                    "stripe_payment_method": gateway_facts.get("payment_method_id"),
                    "stripe_amount_received": gateway_facts.get("amount_received"),
                    "stripe_currency": gateway_facts.get("currency"),
                    "stripe_customer": gateway_facts.get("customer_id"),
                }
                if payment.status == "pending":
                    if not payment.apply_gateway_event("succeeded", meta_update):
                        return Err("Payment state mismatch: success transition was not applied")
                    log_security_event(
                        "payment_status_changed",
                        {
                            "payment_id": str(payment.id),
                            "old_status": "pending",
                            "new_status": "succeeded",
                            "gateway_intent_id": gateway_txn_id,
                            "critical_financial_operation": True,
                        },
                    )
                else:
                    payment.meta = {**(payment.meta or {}), **meta_update}
                    payment.save(update_fields=["meta", "updated_at"])

                if payment.invoice_id is not None:
                    convergence_error = PaymentSuccessService._converge_paid_invoice(payment)
                    if convergence_error:
                        transaction.set_rollback(True)
                        return Err(convergence_error)

                return Ok(payment)
        except Payment.DoesNotExist:
            return Err(f"Payment not found for gateway transaction {gateway_txn_id}")
        except Exception as exc:
            logger.exception("Payment-success convergence failed for %s", gateway_txn_id)
            return Err(f"Payment-success convergence failed: {exc}")

    @staticmethod
    def recover_unlinked_recurring_attempt(  # noqa: PLR0911  # Preserve distinct fail-closed rejection reasons
        gateway_txn_id: str,
        gateway_facts: Mapping[str, Any],
    ) -> Result[Payment, str]:
        """Bind an early webhook to one exact pending recurring attempt.

        Stripe may deliver a success or failure webhook before the request
        thread persists the remote intent ID. Recovery is deliberately
        unavailable to non-recurring or ambiguous payments, and every gateway
        fact is validated before the local attempt is bound.
        """
        metadata = gateway_facts.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("source") != "recurring_billing":
            return Err(f"Payment not found for gateway transaction {gateway_txn_id}")

        invoice_id = metadata.get("invoice_id")
        proforma_id = metadata.get("proforma_id")
        if bool(invoice_id) == bool(proforma_id):
            return Err("Recurring gateway metadata must identify exactly one billing document")

        document_filter = Q(invoice_id=invoice_id) if invoice_id else Q(proforma_id=proforma_id)
        candidates = list(
            Payment.objects.select_for_update(of=("self",))
            .select_related("currency", "invoice", "proforma")
            .filter(
                document_filter,
                Q(gateway_txn_id__isnull=True) | Q(gateway_txn_id=""),
                status="pending",
                payment_method="stripe",
                meta__source="recurring_billing",
            )
            .order_by("id")[:2]
        )
        if not candidates:
            return Err(f"Payment not found for gateway transaction {gateway_txn_id}")
        if len(candidates) != 1:
            return Err("Ambiguous pending recurring payment for early gateway event")

        payment = candidates[0]
        # Attempt-level precision, not just document-level: a redelivered webhook from an
        # EARLIER attempt (whose intent ID capture regressed or predates it) must never bind
        # to a later attempt's pending payment — that records a real charge as failed.
        attempt_marker = metadata.get("payment_attempt")
        if attempt_marker is not None and str(payment.id) != str(attempt_marker):
            return Err(
                f"Gateway event belongs to payment attempt {attempt_marker}, not the pending attempt {payment.id}"
            )
        validation_error = PaymentSuccessService._validate_gateway_facts(payment, gateway_facts)
        if validation_error:
            PaymentSuccessService._log_validation_failure(payment, validation_error, gateway_facts)
            return Err(validation_error)

        payment.gateway_txn_id = gateway_txn_id
        payment.save(update_fields=["gateway_txn_id", "updated_at"])
        log_security_event(
            "payment_gateway_id_recovered",
            {
                "payment_id": str(payment.id),
                "gateway_intent_id": gateway_txn_id,
                "invoice_id": str(payment.invoice_id) if payment.invoice_id else None,
                "proforma_id": str(payment.proforma_id) if payment.proforma_id else None,
                "critical_financial_operation": True,
            },
        )
        return Ok(payment)

    @staticmethod
    def converge_local_paid_document(payment_id: int) -> Result[Payment, str]:
        """Advance invoice-linked state after a locally trusted proforma conversion."""
        try:
            with transaction.atomic():
                payment = Payment.objects.select_for_update(of=("self",)).select_related("invoice").get(id=payment_id)
                if payment.status != "succeeded":
                    return Err(f"Payment state mismatch: payment {payment.id} is '{payment.status}'")
                if payment.invoice_id is None:
                    return Err(f"Payment document mismatch: payment {payment.id} has no invoice")
                convergence_error = PaymentSuccessService._converge_paid_invoice(payment)
                if convergence_error:
                    transaction.set_rollback(True)
                    return Err(convergence_error)
                return Ok(payment)
        except Payment.DoesNotExist:
            return Err(f"Payment not found: {payment_id}")
        except Exception as exc:
            logger.exception("Local payment convergence failed for %s", payment_id)
            return Err(f"Local payment convergence failed: {exc}")

    @staticmethod
    def _validate_gateway_facts(  # noqa: PLR0911  # Fail closed with a precise mismatch reason per Stripe fact
        payment: Payment, gateway_facts: Mapping[str, Any]
    ) -> str | None:
        amount_received = gateway_facts.get("amount_received")
        if (
            isinstance(amount_received, bool)
            or not isinstance(amount_received, int)
            or amount_received != payment.amount_cents
        ):
            return f"Gateway amount mismatch: expected {payment.amount_cents}, received {amount_received!r}"

        received_currency = gateway_facts.get("currency")
        if not isinstance(received_currency, str) or received_currency.upper() != payment.currency.code.upper():
            return (
                f"Gateway currency mismatch: expected {payment.currency.code.upper()}, received {received_currency!r}"
            )

        payment_meta = payment.meta or {}
        if payment_meta.get("source") != "recurring_billing":
            return None

        received_customer = _stripe_reference(gateway_facts.get("customer_id"))
        expected_customer = payment_meta.get("stripe_customer_id")
        if not expected_customer or received_customer != expected_customer:
            return f"Gateway customer mismatch: expected {expected_customer!r}, received {received_customer!r}"

        received_method = _stripe_reference(gateway_facts.get("payment_method_id"))
        expected_method = payment_meta.get("stripe_payment_method_id")
        if not expected_method or received_method != expected_method:
            return f"Gateway payment method mismatch: expected {expected_method!r}, received {received_method!r}"

        received_metadata = gateway_facts.get("metadata")
        if not isinstance(received_metadata, Mapping):
            return "Gateway document metadata mismatch: metadata is missing"

        if payment.proforma_id is not None:
            expected_metadata = {
                "proforma_id": str(payment.proforma_id),
                "proforma_number": payment_meta.get("proforma_number"),
                "customer_id": str(payment.customer_id),
                "source": "recurring_billing",
            }
        else:
            expected_metadata = {
                "invoice_id": str(payment.invoice_id),
                "invoice_number": payment_meta.get("invoice_number"),
                "customer_id": str(payment.customer_id),
                "source": "recurring_billing",
            }
        for key, expected_value in expected_metadata.items():
            if not expected_value or str(received_metadata.get(key)) != expected_value:
                return (
                    f"Gateway document metadata mismatch for {key}: "
                    f"expected {expected_value!r}, received {received_metadata.get(key)!r}"
                )
        return None

    @staticmethod
    def _log_validation_failure(
        payment: Payment,
        error: str,
        gateway_facts: Mapping[str, Any],
    ) -> None:
        logger.critical("Gateway success rejected for payment %s: %s", payment.id, error)
        log_security_event(
            "payment_gateway_fact_mismatch",
            {
                "payment_id": str(payment.id),
                "invoice_id": str(payment.invoice_id) if payment.invoice_id else None,
                "gateway_intent_id": payment.gateway_txn_id,
                "reason": error,
                "received_amount_cents": gateway_facts.get("amount_received"),
                "received_currency": gateway_facts.get("currency"),
                "critical_financial_operation": True,
            },
        )

    @staticmethod
    def _converge_paid_invoice(  # noqa: C901, PLR0911, PLR0912  # Explicit financial lifecycle rejections
        payment: Payment,
    ) -> str | None:
        from .invoice_models import Invoice  # noqa: PLC0415

        if payment.invoice_id is None:
            return f"Payment document mismatch: payment {payment.id} has no invoice"
        invoice = Invoice.objects.select_for_update(of=("self",)).get(id=payment.invoice_id)
        invoice.update_status_from_payments()
        invoice.refresh_from_db()
        if invoice.get_remaining_amount() > 0:
            return None
        if invoice.status != "paid":
            return f"Invoice state mismatch: fully settled invoice {invoice.number} is '{invoice.status}'"

        cycles = list(
            BillingCycle.objects.select_for_update(of=("self",))
            .filter(invoice_id=invoice.id)
            .order_by("subscription_id", "period_start", "id")
        )
        usage_cycles = list(
            BillingCycle.objects.select_for_update(of=("self",))
            .filter(usage_invoice_id=invoice.id)
            .order_by("subscription_id", "period_start", "id")
        )
        if not cycles and not usage_cycles:
            return None

        subscription_ids = sorted({cycle.subscription_id for cycle in cycles}, key=str)
        subscriptions = {
            subscription.id: subscription
            for subscription in Subscription.objects.select_for_update(of=("self",))
            .select_related(
                "saved_payment_method",
                "payment_authorization__payment_method",
            )
            .defer(
                "saved_payment_method__bank_details",
                "payment_authorization__payment_method__bank_details",
            )
            .filter(id__in=subscription_ids)
            .order_by("id")
        }

        service_ids = sorted(
            {subscription.service_id for subscription in subscriptions.values() if subscription.service_id},
            key=str,
        )
        services: dict[object, Any] = {}
        if service_ids:
            from apps.provisioning.models import Service  # noqa: PLC0415

            services = {
                service.id: service
                for service in Service.objects.select_for_update(of=("self",)).filter(id__in=service_ids).order_by("id")
            }

        now = timezone.now()
        for cycle in cycles:
            subscription = subscriptions[cycle.subscription_id]
            if cycle.entitlement_applied_at is None:
                period_error = PaymentSuccessService._apply_cycle_entitlement(
                    cycle=cycle,
                    subscription=subscription,
                    service=services.get(subscription.service_id),
                    paid_at=now,
                )
                if period_error:
                    return period_error

            if cycle.status == "upcoming":
                cycle.activate()

            cycle.collection_status = "paid"
            cycle.paid_at = cycle.paid_at or now
            cycle.save(
                update_fields=[
                    "status",
                    "collection_status",
                    "paid_at",
                    "entitlement_applied_at",
                    "updated_at",
                ]
            )

        for cycle in usage_cycles:
            if cycle.status not in {"invoiced", "finalized"}:
                return f"Usage billing cycle state mismatch: cycle {cycle.id} is '{cycle.status}'"
            aggregations = list(
                UsageAggregation.objects.select_for_update(of=("self",)).filter(billing_cycle=cycle).order_by("id")
            )
            for aggregation in aggregations:
                if aggregation.status == "invoiced":
                    aggregation.finalize()
                    aggregation.save(update_fields=["status", "updated_at"])
            if cycle.status == "invoiced":
                cycle.finalize()
                cycle.save(update_fields=["status", "finalized_at", "updated_at"])
        return None

    @staticmethod
    def _apply_cycle_entitlement(
        *,
        cycle: BillingCycle,
        subscription: Subscription,
        service: Any,
        paid_at: Any,
    ) -> str | None:
        current_end = subscription.current_period_end
        if current_end < cycle.period_start:
            return (
                f"Subscription period gap for {subscription.subscription_number}: "
                f"paid through {current_end.isoformat()}, cycle starts {cycle.period_start.isoformat()}"
            )
        if cycle.period_start < current_end < cycle.period_end:
            return (
                f"Subscription period overlap for {subscription.subscription_number}: "
                f"paid through {current_end.isoformat()}, cycle ends {cycle.period_end.isoformat()}"
            )

        if current_end == cycle.period_start:
            subscription.current_period_start = cycle.period_start
            subscription.current_period_end = cycle.period_end
        elif current_end < cycle.period_end:
            return f"Subscription period mismatch for {subscription.subscription_number}"

        next_proforma_at, next_charge_at = fixed_renewal_schedule(cycle.period_end)
        subscription.next_proforma_at = next_proforma_at
        subscription.next_charge_at = next_charge_at
        subscription.next_billing_date = next_proforma_at
        subscription.last_payment_date = paid_at
        subscription.last_payment_amount_cents = cycle.total_cents
        subscription.failed_payment_count = 0
        subscription.grace_period_ends_at = None
        if subscription.status == "trialing":
            subscription.trial_converted = True
            subscription._convert_trial_now()
            subscription.started_at = subscription.started_at or paid_at
            log_security_event(
                event_type="subscription_trial_converted",
                details={
                    "subscription_id": str(subscription.id),
                    "subscription_number": subscription.subscription_number,
                    "invoice_id": str(cycle.invoice_id),
                },
            )
        elif subscription.status in {"past_due", "paused"}:
            prior_status = subscription.status
            subscription._resume_now()
            # Dunning recovery is a money-state transition and must be auditable like the
            # sibling trial-conversion branch: which subscription resumed, from which state,
            # on which invoice's successful collection.
            log_security_event(
                event_type="subscription_dunning_recovered",
                details={
                    "subscription_id": str(subscription.id),
                    "subscription_number": subscription.subscription_number,
                    "previous_status": prior_status,
                    "invoice_id": str(cycle.invoice_id),
                },
            )
        subscription.save()

        if service is not None:
            service_update_fields: set[str] = set()
            if service.status == "suspended" and service.suspension_reason == "payment_overdue":
                service.activate()
                service_update_fields.update({"status", "activated_at", "suspended_at", "suspension_reason"})
            if service.expires_at is None or service.expires_at < cycle.period_end:
                service.expires_at = cycle.period_end
                service_update_fields.add("expires_at")
            if service_update_fields:
                service_update_fields.add("updated_at")
                service.save(update_fields=sorted(service_update_fields))

        cycle.entitlement_applied_at = paid_at
        return None
