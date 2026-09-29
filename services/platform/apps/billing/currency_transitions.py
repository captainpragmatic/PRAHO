"""Commit notified renewal terms and activate them at their recorded period boundary."""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from .currency_policy import SellingCurrencyPolicy, get_selling_currency_policy
from .currency_transition_notice import notice_allows_preparation, render_notice, terms_fingerprint
from .cycle_terms import (
    CycleTerms,
    build_terms_snapshot,
    freeze_cycle_terms,
    get_cycle_terms,
    transition_price_blockers,
)
from .metering_models import BillingCycle
from .subscription_currency_models import SubscriptionCurrencyTransition
from .subscription_models import PriceGrandfathering, Subscription

RENEWING_STATUSES = ("active", "trialing", "past_due", "paused")
NOTICE_RETRY_INTERVAL = timedelta(hours=1)
logger = logging.getLogger(__name__)


def protected_terms_reason(subscription: Subscription, period_start: datetime, currency_code: str) -> str:
    """Evaluate promises at the service period, preserving known zero prices too."""
    if subscription.locked_price_cents is not None and (
        subscription.locked_price_expires_at is None or period_start < subscription.locked_price_expires_at
    ):
        return str(_("The subscription has a protected original price"))
    if PriceGrandfathering.objects.filter(
        Q(currency_id=currency_code) | Q(currency_id=None),
        Q(expires_at=None) | Q(expires_at__gt=period_start),
        customer=subscription.customer,
        product=subscription.product,
        is_active=True,
    ).exists():
        return str(_("An original or unresolved grandfathered price remains protected"))
    if subscription.items.filter(locked_price_cents__isnull=False).exists():
        return str(_("A subscription item has an indefinite original price guarantee"))
    if subscription.promotion_benefits.filter(
        Q(currency_id=currency_code) | Q(currency_id=None),
        Q(ended_at=None, remaining_cents__gt=0) | Q(uses__status="reserved"),
    ).exists():
        return str(_("An original-currency renewal benefit remains available or reserved"))
    return ""


def _baseline_terms(subscription: Subscription, period_start: datetime) -> dict[str, Any]:
    prepared = (
        subscription.billing_cycles.filter(
            terms_frozen_at__isnull=False,
            period_end__gte=subscription.current_period_end,
        )
        .exclude(collection_status="unbilled")
        .order_by("-period_start")
        .first()
    )
    if prepared:
        return get_cycle_terms(prepared).snapshot
    snapshot = build_terms_snapshot(subscription, effective_at=period_start)
    promise = PriceGrandfathering.objects.filter(
        Q(expires_at=None) | Q(expires_at__gt=period_start),
        customer=subscription.customer,
        product=subscription.product,
        is_active=True,
        currency_id=snapshot["currency"],
        currency_hold_reason="",
    ).first()
    if promise:
        snapshot["unit_price_cents"] = min(snapshot["unit_price_cents"], promise.locked_price_cents)
    return snapshot


def target_terms(subscription: Subscription, currency_code: str, period_start: datetime) -> dict[str, Any]:
    price = subscription.product.get_price_for_currency(currency_code)
    if price is None:
        raise ValidationError(
            _("No explicit %(currency)s renewal price for %(product)s")
            % {
                "currency": currency_code,
                "product": subscription.product.name,
            }
        )
    amount = price.get_price_cents_for_period(
        subscription.billing_cycle,
        custom_cycle_days=subscription.custom_cycle_days,
        include_promotions=False,
    )
    blockers = transition_price_blockers(subscription, currency_code)
    if blockers:
        raise ValidationError(blockers)
    return build_terms_snapshot(
        subscription, effective_at=period_start, currency_code=currency_code, unit_price_cents=amount
    )


def _prepare_locked_offer(
    subscription: Subscription,
    policy: SellingCurrencyPolicy,
    period_start: datetime,
) -> SubscriptionCurrencyTransition | None:
    existing = subscription.currency_transitions.select_for_update().filter(status__in=["pending", "notified"]).first()
    old = _baseline_terms(subscription, period_start)
    if (
        subscription.status not in RENEWING_STATUSES
        or subscription.cancel_at_period_end
        or old["currency"] == policy.currency_code
    ):
        if existing:
            existing.supersede()
            existing.save(update_fields=["status", "updated_at"])
        return None
    target = target_terms(subscription, policy.currency_code, period_start)
    fingerprint = terms_fingerprint(target)
    hold = protected_terms_reason(subscription, period_start, old["currency"])
    if existing and (
        existing.policy_revision != policy.revision
        or existing.target_fingerprint != fingerprint
        or existing.old_terms != old
        or existing.notice_recipient != subscription.customer.primary_email
    ):
        existing.supersede()
        existing.save(update_fields=["status", "updated_at"])
        existing = None
    if existing:
        if existing.hold_reason != hold:
            existing.hold_reason = hold
            existing.save(update_fields=["hold_reason", "updated_at"])
        return existing
    subject, body = render_notice(subscription.subscription_number, subscription.product.name, old, target)
    return SubscriptionCurrencyTransition.objects.create(
        subscription=subscription,
        policy_revision=policy.revision,
        old_terms=old,
        target_terms=target,
        target_fingerprint=fingerprint,
        notice_recipient=subscription.customer.primary_email or "",
        notice_subject=subject,
        notice_body=body,
        hold_reason=hold,
    )


@transaction.atomic
def prepare_currency_offer(subscription_id: UUID | str) -> SubscriptionCurrencyTransition | None:
    """Serialize an exact future offer with catalog changes and renewal preparation."""
    policy = get_selling_currency_policy(lock=True)
    subscription = (
        Subscription.objects.select_for_update(of=("self",))
        .select_related("customer", "product")
        .get(pk=subscription_id)
    )
    return _prepare_locked_offer(subscription, policy, subscription.current_period_end)


def terms_for_preparation(
    cycle: BillingCycle,
    policy: SellingCurrencyPolicy,
    *,
    prepared_at: datetime,
) -> tuple[CycleTerms, SubscriptionCurrencyTransition | None]:
    """Caller holds policy, subscription and cycle locks through document commit."""
    if cycle.terms_frozen_at:
        return get_cycle_terms(cycle), None
    subscription = cycle.subscription
    old = _baseline_terms(subscription, cycle.period_start)
    try:
        offer = _prepare_locked_offer(subscription, policy, cycle.period_start)
    except (ValidationError, ValueError) as exc:
        # A missing new tariff must not prevent renewal of the proven old contract.
        existing = (
            subscription.currency_transitions.select_for_update().filter(status__in=["pending", "notified"]).first()
        )
        if existing:
            existing.hold_reason = str(exc)[:255]
            existing.save(update_fields=["hold_reason", "updated_at"])
        logger.warning("⚠️ [Billing] Retaining original terms for subscription %s: %s", subscription.pk, exc)
        return freeze_cycle_terms(cycle, deepcopy(old)), None
    eligible = (
        offer is not None
        and offer.status == "notified"
        and not offer.hold_reason
        and notice_allows_preparation(offer.notice_accepted_at, prepared_at)
        and cycle.period_start >= prepared_at
    )
    snapshot = offer.target_terms if eligible and offer is not None else old
    return freeze_cycle_terms(cycle, deepcopy(snapshot)), offer if eligible else None


def commit_prepared_offer(offer: SubscriptionCurrencyTransition | None, cycle: BillingCycle) -> None:
    if offer is None:
        return
    if not cycle.proforma_id or get_cycle_terms(cycle).snapshot != offer.target_terms:
        raise ValidationError(_("A currency offer must match its prepared renewal document"))
    offer.committed_cycle = cycle
    offer.effective_period_start = cycle.period_start
    offer.commit()
    offer.save(update_fields=["committed_cycle", "effective_period_start", "status", "updated_at"])


def activate_locked_currency_terms(subscription: Subscription, *, as_of: datetime) -> bool:
    """Advance current terms without altering paid-through periods or reviving service."""
    if subscription.status not in RENEWING_STATUSES or subscription.cancel_at_period_end:
        return False
    offer = (
        subscription.currency_transitions.filter(
            status="committed",
            effective_period_start__lte=as_of,
        )
        .select_related("committed_cycle")
        .order_by("-effective_period_start")
        .first()
    )
    if offer is None:
        return False
    cycle = offer.committed_cycle
    if cycle is None or offer.effective_period_start != cycle.period_start:
        raise ValidationError(_("The committed currency offer has no matching period boundary"))
    if subscription.effective_terms_at is not None and subscription.effective_terms_at >= cycle.period_start:
        return False
    terms = get_cycle_terms(cycle)
    subscription.currency = terms.currency
    subscription.unit_price_cents = terms.unit_price_cents
    subscription.quantity = terms.quantity
    subscription.effective_terms_cycle = cycle
    subscription.effective_terms_at = cycle.period_start
    subscription.save(
        update_fields=[
            "currency",
            "unit_price_cents",
            "quantity",
            "effective_terms_cycle",
            "effective_terms_at",
            "updated_at",
        ]
    )
    if subscription.service_id:
        from apps.provisioning.models import Service  # noqa: PLC0415  # ADR-0007

        service = Service.objects.select_for_update().get(pk=subscription.service_id)
        if service.status in {"active", "suspended"}:
            service.currency = terms.currency
            service.price = Decimal(terms.subtotal_cents) / 100
            service.save(update_fields=["currency", "price", "updated_at"])
    return True


def activate_due_currency_terms(*, as_of: datetime | None = None) -> int:
    run_at = as_of or timezone.now()
    subscription_ids = (
        SubscriptionCurrencyTransition.objects.filter(
            status="committed",
            effective_period_start__lte=run_at,
        )
        .values_list("subscription_id", flat=True)
        .distinct()
    )
    activated = 0
    for subscription_id in subscription_ids.iterator():
        with transaction.atomic():
            subscription = Subscription.objects.select_for_update(of=("self",)).get(pk=subscription_id)
            activated += activate_locked_currency_terms(subscription, as_of=run_at)
    return activated


def _accept_logged_notice(offer: SubscriptionCurrencyTransition) -> bool:
    """Recover accepted delivery even if the process died before linking the log."""
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # ADR-0007

    log = offer.notice_email
    if log is None or log.status not in {"sent", "delivered"}:
        log = (
            EmailLog.objects.filter(
                template_key=f"subscription_currency_notice:{offer.pk}",
                status__in=["sent", "delivered"],
                customer_id=offer.subscription.customer_id,
                to_addr=offer.notice_recipient,
                subject=offer.notice_subject,
            )
            .order_by("sent_at")
            .first()
        )
    if log is None:
        return False
    offer.notice_email = log
    offer.accept_notice()
    offer.last_error = ""
    offer.save(
        update_fields=[
            "notice_email",
            "status",
            "notice_accepted_at",
            "preparation_not_before",
            "last_error",
            "updated_at",
        ]
    )
    return True


def send_currency_notice(offer_id: UUID | str, *, as_of: datetime | None = None) -> bool:
    """Only provider acceptance of this exact offer starts its thirty-day notice period."""
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # ADR-0007
    from apps.notifications.services import EmailService  # noqa: PLC0415  # ADR-0007

    now = as_of or timezone.now()
    subscription_id = SubscriptionCurrencyTransition.objects.values_list("subscription_id", flat=True).get(pk=offer_id)
    with transaction.atomic():
        offer = prepare_currency_offer(subscription_id)
        if offer is None or str(offer.pk) != str(offer_id) or offer.status != "pending" or offer.hold_reason:
            return False
        if _accept_logged_notice(offer):
            return True
        if offer.notice_attempted_at and offer.notice_attempted_at > now - NOTICE_RETRY_INTERVAL:
            return False
        offer.notice_attempted_at = now
        offer.save(update_fields=["notice_attempted_at", "updated_at"])
        if not offer.notice_recipient:
            offer.last_error = str(_("Customer has no billing email address"))
            offer.save(update_fields=["last_error", "updated_at"])
            return False

    # No database lock spans provider I/O. The stored claim limits concurrent retries.
    try:
        result = EmailService.send_email(
            to=offer.notice_recipient,
            subject=offer.notice_subject,
            body_text=offer.notice_body,
            customer=offer.subscription.customer,
            template_key=f"subscription_currency_notice:{offer.pk}",
            tags={"subscription_currency_transition_id": str(offer.pk)},
            async_send=False,
        )
    except Exception as exc:
        logger.exception("⚠️ [Billing] Currency notice failed for offer %s", offer.pk)
        SubscriptionCurrencyTransition.objects.filter(pk=offer.pk, status="pending").update(last_error=str(exc)[:255])
        return False

    accepted = False
    with transaction.atomic():
        # Match reconciliation's lock order, including deferred FK checks at commit.
        get_selling_currency_policy(lock=True)
        Subscription.objects.select_for_update(of=("self",)).get(pk=subscription_id)
        offer = SubscriptionCurrencyTransition.objects.select_for_update().get(pk=offer_id)
        if offer.status == "pending":
            if result.email_log_id:
                offer.notice_email = EmailLog.objects.get(pk=result.email_log_id)
            offer.last_error = (result.error or str(_("Provider has not accepted the notice")))[:255]
            offer.save(update_fields=["notice_email", "last_error", "updated_at"])
            accepted = _accept_logged_notice(offer)
    return accepted


def reconcile_currency_transitions(*, as_of: datetime | None = None) -> dict[str, Any]:
    """Repair durable offers and accepted notices; never prepare a charge here."""
    report: dict[str, Any] = {
        "checked": 0,
        "notices_sent": 0,
        "held": 0,
        "activated": activate_due_currency_terms(as_of=as_of),
        "errors": [],
    }
    subscription_ids = (
        Subscription.objects.filter(
            Q(status__in=RENEWING_STATUSES) | Q(currency_transitions__status__in=["pending", "notified"]),
        )
        .distinct()
        .values_list("pk", flat=True)
    )
    for subscription_id in subscription_ids.iterator():
        report["checked"] += 1
        try:
            offer = prepare_currency_offer(subscription_id)
            if offer is None:
                continue
            if offer.hold_reason:
                report["held"] += 1
            elif send_currency_notice(offer.pk, as_of=as_of):
                report["notices_sent"] += 1
        except Exception as exc:
            logger.exception("⚠️ [Billing] Currency offer reconciliation failed for subscription %s", subscription_id)
            report["errors"].append(f"{subscription_id}: {exc}")
    return report
