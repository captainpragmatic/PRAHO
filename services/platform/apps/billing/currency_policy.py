"""The selling currency changes prospectively; stored money keeps its identity.

Settings writers and new-sale transactions lock the same setting row. Readers use
the database directly so a cached currency can never be paired with a newer revision.
RON remains the upgrade default because the old environment option was not wired.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from .currency_service import CurrencyNotIssuableError, assert_currency_issuable, normalize_currency_code

if TYPE_CHECKING:
    from apps.settings.models import SystemSetting

SELLING_CURRENCY_KEY = "billing.default_currency"
RENEWING_SUBSCRIPTION_STATUSES = ("pending", "trialing", "active", "past_due", "paused")


@dataclass(frozen=True)
class SellingCurrencyPolicy:
    currency_code: str
    revision: int

    def as_dict(self) -> dict[str, str | int]:
        return {"selling_currency": self.currency_code, "currency_revision": self.revision}


class SellingCurrencyChangedError(ValidationError):
    """The cart must be repriced and confirmed against the current selling policy."""


def get_selling_currency_policy(*, lock: bool = False) -> SellingCurrencyPolicy:
    from apps.settings.models import SystemSetting  # noqa: PLC0415  # ADR-0007

    rows = SystemSetting.objects.all()
    if lock:
        if not connection.in_atomic_block:
            raise RuntimeError("A selling-currency lock requires an enclosing transaction")
        rows.get_or_create(
            key=SELLING_CURRENCY_KEY,
            defaults={
                "value": "RON",
                "default_value": "RON",
                "name": "Selling currency",
                "description": "Currency used for new sales; existing financial records retain their currency.",
                "category": "billing",
                "data_type": "string",
            },
        )
        rows = rows.select_for_update(of=("self",))
    setting = rows.filter(key=SELLING_CURRENCY_KEY).first()
    if setting is None:
        return SellingCurrencyPolicy(currency_code="RON", revision=1)
    return SellingCurrencyPolicy(currency_code=normalize_currency_code(setting.value), revision=setting.revision)


def require_current_selling_policy(currency_code: str, revision: int | None) -> SellingCurrencyPolicy:
    """Hold the policy lock through creation of the immutable order snapshot."""
    policy = get_selling_currency_policy(lock=True)
    if currency_code != policy.currency_code or revision != policy.revision:
        raise SellingCurrencyChangedError(_("Prices have changed. Review the updated cart before placing the order."))
    return policy


def currency_switch_blockers(currency_code: str) -> list[str]:
    """Check live catalog and still-renewing products before admitting a switch."""
    from apps.products.models import Product  # noqa: PLC0415  # ADR-0007
    from apps.promotions.gift_purchase_policy import gift_purchase_currency_blockers  # noqa: PLC0415  # ADR-0007

    code = normalize_currency_code(currency_code)
    blockers: list[str] = []
    try:
        assert_currency_issuable(code, timezone.localdate())
    except CurrencyNotIssuableError as exc:
        blockers.append(str(exc))
    products = Product.objects.filter(
        Q(is_active=True, is_public=True) | Q(subscriptions__status__in=RENEWING_SUBSCRIPTION_STATUSES)
    ).distinct()
    blockers.extend(
        _("%(product)s needs an active %(currency)s price.") % {"product": product.name, "currency": code}
        for product in products
        if not product.prices.filter(currency_id=code, is_active=True).exists()
    )
    blockers.extend(_service_plan_price_blockers(code))
    blockers.extend(_domain_price_blockers(code))
    blockers.extend(_renewal_period_price_blockers(code))
    blockers.extend(gift_purchase_currency_blockers(code))
    blockers.extend(_offer_currency_blockers())
    return blockers


def _offer_currency_blockers() -> list[str]:
    from apps.promotions.models import Coupon, PromotionRule  # noqa: PLC0415  # ADR-0007
    from apps.promotions.offer_currency import has_monetary_terms  # noqa: PLC0415  # ADR-0007

    unresolved = Q(is_active=True, currency__isnull=True) & (
        Q(valid_until__isnull=True) | Q(valid_until__gte=timezone.now())
    )
    blockers: list[str] = []
    for offers in (
        Coupon.objects.filter(unresolved, status="active"),
        PromotionRule.objects.filter(unresolved),
    ):
        blockers.extend(
            _("%(offer)s has monetary limits without a recorded currency. Review its original currency.")
            % {"offer": offer.name}
            for offer in offers
            if has_monetary_terms(offer)
        )
    return blockers


def _renewal_period_price_blockers(code: str) -> list[str]:
    from .cycle_terms import transition_price_blockers  # noqa: PLC0415
    from .subscription_models import Subscription  # noqa: PLC0415  # Deferred: model import cycle

    blockers: list[str] = []
    subscriptions = Subscription.objects.filter(status__in=RENEWING_SUBSCRIPTION_STATUSES).select_related("product")
    for subscription in subscriptions:
        blockers.extend(transition_price_blockers(subscription, code))
        price = subscription.product.get_price_for_currency(code)
        if price is None:
            continue  # The product coverage check reports this with its catalog name.
        try:
            price.get_price_cents_for_period(
                subscription.billing_cycle, custom_cycle_days=subscription.custom_cycle_days, include_promotions=False
            )
        except ValueError as exc:
            blockers.append(f"{subscription.subscription_number}: {exc}")
    return blockers


def _service_plan_price_blockers(code: str) -> list[str]:
    from apps.provisioning.service_models import Service, ServicePlan  # noqa: PLC0415  # ADR-0007

    blockers: list[str] = []
    plans = ServicePlan.objects.filter(
        Q(is_active=True, is_public=True) | Q(service__status__in=("pending", "provisioning", "active", "suspended"))
    ).distinct()
    for plan in plans:
        price = plan.get_price_for_currency(code)
        if price is None:
            blockers.append(_("%(plan)s needs an active %(currency)s price.") % {"plan": plan.name, "currency": code})
            continue
        periods = {"monthly"}
        if plan.price_quarterly is not None:
            periods.add("quarterly")
        if plan.price_annual is not None:
            periods.add("annual")
        periods.update(
            Service.objects.filter(service_plan=plan)
            .exclude(status__in=("terminated", "expired"))
            .values_list("billing_cycle", flat=True)
        )
        for period in sorted(periods):
            try:
                price.price_for_period(period)
            except ValueError as exc:
                blockers.append(str(exc))
    return blockers


def _domain_price_blockers(code: str) -> list[str]:
    from apps.domains.currency_terms import domain_currency_switch_blockers  # noqa: PLC0415  # ADR-0007
    from apps.domains.models import TLD  # noqa: PLC0415  # ADR-0007

    return [
        _(".%(tld)s needs an active %(currency)s retail price.") % {"tld": tld.extension, "currency": code}
        for tld in TLD.objects.filter(
            Q(is_active=True) | Q(domains__status__in=("pending", "active", "expired", "suspended", "transfer_in"))
        ).distinct()
        if tld.get_price_for_currency(code) is None
    ] + domain_currency_switch_blockers(code)


def validate_currency_switch(currency_code: str) -> None:
    policy = get_selling_currency_policy(lock=True)
    code = normalize_currency_code(currency_code)
    if code == policy.currency_code:
        return
    blockers = currency_switch_blockers(code)
    if blockers:
        raise ValidationError({"value": blockers})


def prepare_currency_setting_save(setting: SystemSetting) -> None:
    """Guard direct model/admin/setup writes as well as SettingsService writes.

    The caller holds an atomic block through save. The migration supplies the row;
    creating the historical RON baseline also supports an empty development database.
    """
    from apps.settings.models import SystemSetting  # noqa: PLC0415  # ADR-0007

    try:
        code = normalize_currency_code(setting.value)
    except (ValueError, AttributeError) as exc:
        raise ValidationError({"value": str(exc)}) from exc
    previous = SystemSetting.objects.select_for_update(of=("self",)).filter(key=SELLING_CURRENCY_KEY).first()
    old_code = previous.value if previous is not None else "RON"
    revision = previous.revision if previous is not None else 1
    if code != old_code:
        blockers = currency_switch_blockers(code)
        if blockers:
            raise ValidationError({"value": blockers})
        revision += 1
        transaction.on_commit(_queue_currency_notice_reconciliation, robust=True)
    setting.value = code
    setting.revision = revision


def _queue_currency_notice_reconciliation() -> None:
    """The daily repair also covers a process exit or unavailable queue after commit."""
    from django_q.tasks import async_task  # noqa: PLC0415  # Only queue after the settings transaction commits.

    async_task("apps.billing.tasks.reconcile_currency_transition_notices")
