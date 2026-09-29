"""Original domain renewal terms and prospective, noticed currency offers.

Legacy evidence is resolved without rewriting historical rows. Preparation writers
acquire policy, domain, then transition locks in that order.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from dateutil.relativedelta import relativedelta
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.currency_transition_notice import terms_fingerprint

from .models import TLD, Domain, DomainCurrencyTransition, DomainOrderItem

if TYPE_CHECKING:
    from apps.billing.currency_policy import SellingCurrencyPolicy
    from apps.notifications.models import EmailLog

logger = logging.getLogger(__name__)
RENEWABLE_STATUSES = ("pending", "active", "expired", "suspended", "transfer_in")
FROZEN_ORDER_STATUSES = ("awaiting_payment", "paid", "in_review", "provisioning", "completed")


@dataclass(frozen=True)
class DomainRenewalQuote:
    currency_code: str
    unit_price_cents: int
    snapshot: dict[str, Any]
    transition_id: str | None = None


def _snapshot(  # noqa: PLR0913  # Each original purchase identity is recorded explicitly.
    name: str,
    tld_id: Any,
    customer_id: Any,
    currency: str,
    cents: int,
    privacy: bool,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "domain_name": name,
        "tld_id": str(tld_id),
        "customer_id": str(customer_id),
        "currency": currency,
        "unit_price_cents": cents,
        "whois_privacy": privacy,
    }


def _validate_snapshot(data: Any, *, name: str, tld_id: Any, customer_id: Any, privacy: bool) -> dict[str, Any]:
    if (
        not isinstance(data, dict)
        or type(data.get("schema")) is not int
        or data.get("schema") != 1
        or data.get("domain_name") != name
        or data.get("tld_id") != str(tld_id)
        or data.get("customer_id") != str(customer_id)
        or data.get("whois_privacy") is not privacy
        or data.get("currency") not in {"RON", "EUR", "USD"}
        or type(data.get("unit_price_cents")) is not int
        or data["unit_price_cents"] < 0
    ):
        raise ValueError("Cannot prove original renewal terms; review the domain's recorded purchase.")
    # Period reservations belong to the prepared item, while the price identity
    # remains comparable across notices and consecutive renewal periods.
    return _snapshot(name, tld_id, customer_id, data["currency"], data["unit_price_cents"], privacy)


def _domain_snapshot(domain: Domain, data: Any) -> dict[str, Any]:
    return _validate_snapshot(
        data, name=domain.name, tld_id=domain.tld_id, customer_id=domain.customer_id, privacy=domain.whois_privacy
    )


def purchase_renewal_terms(tld: TLD, name: str, customer_id: Any, currency_code: str, privacy: bool) -> dict[str, Any]:
    """Capture the explicitly priced annual renewal promise alongside a new sale."""
    price = tld.get_price_for_currency(currency_code)
    if price is None:
        raise ValueError(f"No renewal price for .{tld.extension} in {currency_code}")
    cents = price.renewal_price_cents
    if privacy and tld.whois_privacy_available:
        cents += price.whois_privacy_price_cents
    return _snapshot(name, tld.pk, customer_id, currency_code, cents, privacy)


def initialize_domain_terms(domain: Domain) -> None:
    """New direct registrations capture today's terms; existing rows never do."""
    policy = get_selling_currency_policy(lock=True)
    data = purchase_renewal_terms(
        domain.tld, domain.name, domain.customer_id, policy.currency_code, domain.whois_privacy
    )
    domain.billing_currency_id = data["currency"]
    domain.renewal_unit_price_cents = data["unit_price_cents"]
    domain.renewal_terms = data
    domain.renewal_terms_effective_at = timezone.now()


def domain_fields_from_order_item(
    item: DomainOrderItem,
    *,
    customer_id: Any = None,
    domain_name: str | None = None,
    tld_id: Any = None,
) -> dict[str, Any]:
    """Never substitute today's catalog after an original purchase is paid late."""
    if (
        (customer_id is not None and item.order.customer_id != customer_id)
        or (domain_name is not None and item.domain_name != domain_name)
        or (tld_id is not None and item.tld_id != tld_id)
    ):
        raise ValueError("The original domain purchase does not match this registration")
    try:
        data = _validate_snapshot(
            item.renewal_terms,
            name=item.domain_name,
            tld_id=item.tld_id,
            customer_id=item.order.customer_id,
            privacy=item.whois_privacy,
        )
        if data["currency"] != item.order.currency_id:
            raise ValueError("The domain promise and order currencies differ")
    except ValueError:
        return {
            "billing_currency_id": item.order.currency_id,
            "renewal_unit_price_cents": None,
            "renewal_terms": {},
            "currency_hold_reason": "Original purchase has no proven renewal price",
        }
    return {
        "billing_currency_id": data["currency"],
        "renewal_unit_price_cents": data["unit_price_cents"],
        "renewal_terms": data,
        "renewal_terms_effective_at": item.created_at,
    }


def original_domain_terms(domain: Domain) -> dict[str, Any]:
    if domain.renewal_terms:
        data = _domain_snapshot(domain, domain.renewal_terms)
        if (
            domain.billing_currency_id != data["currency"]
            or domain.renewal_unit_price_cents != data["unit_price_cents"]
        ):
            raise ValueError("Conflicting original renewal terms require review")
        return data
    if domain.billing_currency_id and domain.renewal_unit_price_cents is not None:
        return _domain_snapshot(
            domain,
            _snapshot(
                domain.name,
                domain.tld_id,
                domain.customer_id,
                domain.billing_currency_id,
                domain.renewal_unit_price_cents,
                domain.whois_privacy,
            ),
        )
    evidence: dict[str, dict[str, Any]] = {}
    for item in domain.order_items.select_related("order").filter(order__status__in=FROZEN_ORDER_STATUSES):
        if (
            item.order.customer_id != domain.customer_id
            or item.domain_name != domain.name
            or item.tld_id != domain.tld_id
            or item.whois_privacy != domain.whois_privacy
        ):
            continue
        if item.total_price_cents != item.unit_price_cents * item.years:
            raise ValueError("Conflicting original renewal terms require review")
        if item.renewal_terms:
            data = _domain_snapshot(domain, item.renewal_terms)
        elif item.action == "renew":
            data = _snapshot(
                domain.name,
                domain.tld_id,
                domain.customer_id,
                item.order.currency_id,
                item.unit_price_cents,
                item.whois_privacy,
            )
        else:
            continue
        if data["currency"] != item.order.currency_id or (
            item.action == "renew" and data["unit_price_cents"] != item.unit_price_cents
        ):
            raise ValueError("Conflicting original renewal terms require review")
        evidence[terms_fingerprint(data)] = data
    if len(evidence) != 1:
        raise ValueError("Cannot prove original renewal terms; review the domain's recorded purchase.")
    return next(iter(evidence.values()))


def committed_domain_terms(domain: Domain) -> dict[str, Any]:
    committed = domain.currency_transitions.filter(status="committed").order_by("-created_at", "-pk").first()
    return _domain_snapshot(domain, committed.target_terms) if committed else original_domain_terms(domain)


def _recorded_period_date(value: Any) -> datetime:
    try:
        result = parse_datetime(value) if isinstance(value, str) else None
    except ValueError:
        result = None
    if result is None or timezone.is_naive(result):
        raise ValueError("A prepared domain renewal period needs review")
    return result


def _legacy_renewal_completed(domain: Domain, item: DomainOrderItem) -> bool:
    from .operation_services import renewal_intent_key  # noqa: PLC0415

    operation = domain.operations.filter(
        operation_type="renew",
        state="completed",
        intent_key=renewal_intent_key(item.years, f"order_item:{item.pk}"),
    ).first()
    if operation is None or domain.expires_at is None or not isinstance(operation.result, dict):
        return False
    expiry = _recorded_period_date(operation.result.get("new_expires_at"))
    return expiry <= domain.expires_at


def next_domain_renewal_period_start(domain: Domain) -> datetime:
    """Find the first unprepared period without reallocating older promises."""
    if domain.expires_at is None:
        raise ValueError("The domain renewal period boundary is unknown")
    start = domain.expires_at
    for item in domain.order_items.filter(action="renew").select_related("order"):
        if item.order.status in {"cancelled", "refunded"}:
            continue
        if not isinstance(item.renewal_terms, dict):
            raise ValueError("A prepared domain renewal period needs review")
        if not item.renewal_terms.get("period_start"):
            if _legacy_renewal_completed(domain, item):
                continue
            raise ValueError("An earlier prepared domain renewal has no proven period; retain its original terms")
        data = _domain_snapshot(domain, item.renewal_terms)
        if (
            item.order.customer_id != domain.customer_id
            or item.domain_name != domain.name
            or item.tld_id != domain.tld_id
            or item.order.currency_id != data["currency"]
            or item.unit_price_cents != data["unit_price_cents"]
            or item.years < 1
            or item.total_price_cents != item.unit_price_cents * item.years
        ):
            raise ValueError("A prepared domain renewal does not match its original document")
        period_start = _recorded_period_date(item.renewal_terms.get("period_start"))
        period_end = _recorded_period_date(item.renewal_terms.get("period_end"))
        if period_end != period_start + relativedelta(years=item.years):
            raise ValueError("A prepared domain renewal period needs review")
        start = max(start, period_end)
    return start


def renewal_item_terms(domain: Domain, quote: DomainRenewalQuote, years: int) -> dict[str, Any]:
    """Freeze this document's period; unresolved old records keep their old price."""
    try:
        start = next_domain_renewal_period_start(domain)
    except ValueError:
        if quote.transition_id:
            raise
        return dict(quote.snapshot)
    return {
        **quote.snapshot,
        "period_start": start.isoformat(),
        "period_end": (start + relativedelta(years=years)).isoformat(),
    }


def domain_currency_switch_blockers(target_currency_code: str) -> list[str]:
    blockers = []
    for domain in Domain.objects.filter(status__in=RENEWABLE_STATUSES).select_related("tld"):
        try:
            committed_domain_terms(domain)
            purchase_renewal_terms(
                domain.tld, domain.name, domain.customer_id, target_currency_code, domain.whois_privacy
            )
        except ValueError as exc:
            blockers.append(f"{domain.name}: {exc}")
    return blockers


def domain_renewal_quote(domain: Domain, *, prepared_at: datetime | None = None) -> DomainRenewalQuote:
    """Read a promise without changing it; preparation must lock and commit it."""
    domain = Domain.objects.select_related("tld").get(pk=domain.pk)
    current = committed_domain_terms(domain)
    policy = get_selling_currency_policy()
    quote = DomainRenewalQuote(current["currency"], current["unit_price_cents"], current)
    if (
        domain.currency_hold_reason
        or domain.status not in RENEWABLE_STATUSES
        or current["currency"] == policy.currency_code
    ):
        return quote
    try:
        target = purchase_renewal_terms(
            domain.tld, domain.name, domain.customer_id, policy.currency_code, domain.whois_privacy
        )
        next_domain_renewal_period_start(domain)
    except ValueError:
        return quote
    offer = domain.currency_transitions.filter(
        status="notified",
        policy_revision=policy.revision,
        target_fingerprint=terms_fingerprint(target),
        old_terms=current,
        preparation_not_before__lte=prepared_at or timezone.now(),
    ).first()
    if offer is None:
        return quote
    return DomainRenewalQuote(target["currency"], target["unit_price_cents"], target, str(offer.pk))


def commit_domain_quote(domain: Domain, item: DomainOrderItem, quote: DomainRenewalQuote) -> None:
    """Called in the policy/domain locked document-creation transaction."""
    if quote.transition_id is None:
        return
    offer = DomainCurrencyTransition.objects.select_for_update().get(pk=quote.transition_id)
    if (
        offer.status != "notified"
        or offer.preparation_not_before is None
        or timezone.now() < offer.preparation_not_before
    ):
        raise ValueError("The domain currency offer is not ready for document preparation")
    if (
        item.order.currency_id != quote.currency_code
        or _domain_snapshot(domain, item.renewal_terms) != offer.target_terms
    ):
        raise ValueError("The prepared domain item does not match the accepted offer")
    offer.committed_item = item
    offer.effective_period_start = _recorded_period_date(item.renewal_terms.get("period_start"))
    offer.commit()
    offer.save()


def apply_effective_domain_terms(domain: Domain, *, effective_at: datetime | None = None) -> bool:
    """Activate scheduled pricing independently of early or late registrar responses."""
    if domain.status not in RENEWABLE_STATUSES or domain.currency_hold_reason:
        return False
    offer = (
        domain.currency_transitions.filter(
            status="committed",
            effective_period_start__lte=effective_at or timezone.now(),
        )
        .order_by("-effective_period_start", "-created_at")
        .first()
    )
    if offer is None or offer.effective_period_start is None:
        return False
    data = _domain_snapshot(domain, offer.target_terms)
    if domain.renewal_terms == data and domain.renewal_terms_effective_at == offer.effective_period_start:
        return False
    domain.billing_currency_id = data["currency"]
    domain.renewal_unit_price_cents = data["unit_price_cents"]
    domain.renewal_terms = data
    domain.renewal_terms_effective_at = offer.effective_period_start
    domain.save(
        update_fields=[
            "billing_currency",
            "renewal_unit_price_cents",
            "renewal_terms",
            "renewal_terms_effective_at",
            "updated_at",
        ]
    )
    return True


def _send_notice(offer: DomainCurrencyTransition) -> bool:
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # ADR-0007
    from apps.notifications.services import EmailService  # noqa: PLC0415

    try:
        result = EmailService.send_email(
            to=offer.notice_recipient,
            subject=offer.notice_subject,
            body_text=offer.notice_body,
            customer=offer.domain.customer,
            async_send=False,
            template_key=f"domain_currency_notice:{offer.pk}",
        )
        with transaction.atomic():
            get_selling_currency_policy(lock=True)
            Domain.objects.select_for_update().get(pk=offer.domain_id)
            current = DomainCurrencyTransition.objects.select_for_update().get(pk=offer.pk)
            if current.status != "pending" or current.notice_attempted_at != offer.notice_attempted_at:
                return False
            if not result.success or not result.email_log_id:
                current.last_error = (result.error or "No accepted email record")[:255]
            else:
                current.notice_email = EmailLog.objects.get(pk=result.email_log_id)
                current.accept_notice()
                current.last_error = ""
            current.save()
            return bool(current.status == "notified")
    except (ValidationError, ValueError, EmailLog.DoesNotExist) as exc:
        DomainCurrencyTransition.objects.filter(pk=offer.pk, status="pending").update(last_error=str(exc)[:255])
        return False


def _accepted_notice_email(offer: DomainCurrencyTransition) -> EmailLog | None:
    from apps.notifications.models import EmailLog  # noqa: PLC0415  # ADR-0007

    for email in EmailLog.objects.filter(
        template_key=f"domain_currency_notice:{offer.pk}",
        status__in=("sent", "delivered"),
        customer_id=offer.domain.customer_id,
        to_addr=offer.notice_recipient,
        subject=offer.notice_subject,
    ).order_by("sent_at"):
        if email.get_decrypted_body_text() == offer.notice_body:
            return email
    return None


def _prepare_notice(domain: Domain, policy: SellingCurrencyPolicy) -> DomainCurrencyTransition | None:
    current = committed_domain_terms(domain)
    target = purchase_renewal_terms(
        domain.tld, domain.name, domain.customer_id, policy.currency_code, domain.whois_privacy
    )
    offer = domain.currency_transitions.filter(status__in=("pending", "notified")).first()
    if offer and (
        offer.policy_revision != policy.revision
        or offer.target_terms != target
        or offer.old_terms != current
        or current["currency"] == policy.currency_code
        or domain.currency_hold_reason
    ):
        offer.supersede()
        offer.save()
        offer = None
    if current["currency"] == policy.currency_code or domain.currency_hold_reason or domain.expires_at is None:
        return None
    next_domain_renewal_period_start(domain)
    if offer is None:
        old_price = f"{Decimal(current['unit_price_cents']) / 100:.2f} {current['currency']}"
        new_price = f"{Decimal(target['unit_price_cents']) / 100:.2f} {target['currency']}"
        offer = DomainCurrencyTransition.objects.create(
            domain=domain,
            policy_revision=policy.revision,
            old_terms=current,
            target_terms=target,
            target_fingerprint=terms_fingerprint(target),
            notice_recipient=domain.customer.primary_email,
            notice_subject=f"Renewal currency change for {domain.name}",
            notice_body=(
                f"The annual renewal price for {domain.name} changes from {old_price} to {new_price}. "
                f"WHOIS privacy included: {'yes' if domain.whois_privacy else 'no'}. "
                "Existing purchases keep their recorded terms. We will prepare no renewal document "
                "at the new price until at least 30 days after this notice. "
                "The change applies from the next uncommitted renewal period."
            ),
        )
    if offer.status != "pending":
        return None
    accepted = _accepted_notice_email(offer)
    if accepted is not None:
        offer.notice_email = accepted
        offer.accept_notice()
        offer.last_error = ""
        offer.save()
        return offer
    if offer.notice_attempted_at and offer.notice_attempted_at > timezone.now() - timedelta(minutes=5):
        return None
    offer.notice_attempted_at = timezone.now()
    offer.save(update_fields=["notice_attempted_at", "updated_at"])
    return offer


def reconcile_domain_currency_notices() -> dict[str, int]:
    """Daily repair of notice delivery and independently scheduled future prices."""
    result = {"sent": 0, "held": 0, "activated": 0, "recovered": 0}
    for domain_id in Domain.objects.filter(status__in=RENEWABLE_STATUSES).values_list("pk", flat=True).iterator():
        try:
            with transaction.atomic():
                policy = get_selling_currency_policy(lock=True)
                domain = (
                    Domain.objects.select_for_update(of=("self",)).select_related("tld", "customer").get(pk=domain_id)
                )
                result["activated"] += int(apply_effective_domain_terms(domain))
                offer = _prepare_notice(domain, policy)
            if offer is not None:
                if offer.status == "notified":
                    result["recovered"] += 1
                else:
                    result["sent"] += int(_send_notice(offer))
        except (ValueError, ValidationError):
            result["held"] += 1
            logger.info("Original domain renewal terms require review: %s", domain_id)
        except Exception:
            result["held"] += 1
            logger.exception("Domain currency notice needs retry: %s", domain_id)
    return result
