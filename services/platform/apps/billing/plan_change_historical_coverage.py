"""Validate an accepted grant's original financial evidence across later legitimate terms."""

from copy import copy
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils.translation import gettext as _

from .metering_models import BillingCycle
from .plan_change_coverage import _apply_supplement_coverage, _fixed_evidence
from .plan_change_models import PlanChange
from .subscription_models import Subscription


def original_plan_coverage(change: PlanChange) -> dict[str, dict[str, Any]]:
    """No catalog reads or locks; later unrelated renewals never redefine an old grant."""
    original = change.quote_snapshot.get("coverage")
    if not isinstance(original, dict) or not original:
        raise ValidationError(_("Original plan coverage is unavailable and requires review."))
    try:
        identifiers = {UUID(value) for value in original}
    except (ValueError, TypeError, AttributeError) as error:
        raise ValidationError(_("Original plan coverage identities require review.")) from error
    subscription = Subscription.objects.get(pk=change.subscription_id)
    if (
        subscription.customer_id != change.customer_id
        or subscription.service_id != change.service_id
        or subscription.quantity != change.quote_snapshot.get("quantity")
    ):
        raise ValidationError(_("Original plan coverage no longer belongs to this quantity-one service."))
    # An actual, separately notified currency transition does not rewrite the
    # original invoices. Pin only the read view; never save these historical terms.
    frozen = copy(subscription)
    frozen.currency_id = change.currency_id
    cycles = list(
        BillingCycle.objects.filter(pk__in=identifiers, subscription_id=subscription.pk)
        .select_related("invoice", "proforma")
        .order_by("period_start", "pk")
    )
    if {cycle.pk for cycle in cycles} != identifiers:
        raise ValidationError(_("An original plan coverage interval is missing or belongs to another subscription."))
    current = [cycle for cycle in cycles if cycle.period_start <= change.quoted_at < cycle.period_end]
    if len(current) != 1:
        raise ValidationError(_("Original current-period paid coverage requires review."))
    values = {str(cycle.pk): _fixed_evidence(cycle, frozen) for cycle in cycles}
    key = str(current[0].pk)
    if not values[key][1]:
        raise ValidationError(_("The original current interval no longer has paid coverage."))
    selected = Q(committed_at__lte=change.quoted_at)
    if change.committed_at is not None:
        selected |= Q(pk=change.pk)
    changes = (
        PlanChange.objects.filter(selected, subscription_id=subscription.pk, committed_at__isnull=False)
        .select_related("invoice")
        .prefetch_related("intervals")
        .order_by("committed_at", "pk")
    )
    supplements, _price = _apply_supplement_coverage(
        frozen, values, key, values[key][0], change.quoted_at, changes=changes
    )
    result: dict[str, dict[str, Any]] = {}
    for identifier, (_base, _paid, evidence) in values.items():
        result[identifier] = {**evidence, "prior_supplement_cents": supplements.get(identifier, 0)}
    return result
