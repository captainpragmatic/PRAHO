"""Billing staff share the customer-owned commercial checkout without accepting it."""

from typing import cast
from urllib.parse import urlencode

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from apps.billing.plan_change_catalog import eligible_plan_targets
from apps.billing.plan_change_quote_service import _tax_quote
from apps.common.decorators import billing_staff_required
from apps.settings.services import SettingsService
from apps.users.services import portal_link

from .service_models import Service


def _customer_checkout(path: str) -> str:
    # The existing login endpoint validates next and retains it for a signed-in
    # customer too. The URL carries no customer credential or staff authority.
    return portal_link("/login/?" + urlencode({"next": path}))


@never_cache
@billing_staff_required
@require_GET
def service_plan_change_proposal(request: HttpRequest, pk: int) -> HttpResponse:
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415  # ADR-0007: runtime model.
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415  # ADR-0007: runtime model.
    from apps.users.models import User  # noqa: PLC0415  # ADR-0007: runtime model.

    service = get_object_or_404(Service.objects.select_related("customer", "currency", "hosting_limits"), pk=pk)
    actor = cast(User, request.user)
    customer = service.customer
    if not actor.can_access_customer(customer):
        return HttpResponseBadRequest(_("This customer is outside your billing access."))
    if (
        service.status != "active"
        or customer.status != "active"
        or customer.deleted_at is not None
        or customer.anonymized_at is not None
    ):
        return HttpResponseBadRequest(_("This service cannot currently accept a plan proposal."))
    current = PlanChange.objects.filter(service=service, customer=customer, status__in=PlanChange.ACTIVE_STATES).first()
    options = []
    if current is None and SettingsService.get_setting("billing.hosting_plan_changes_enabled", default=False) is True:
        subscription = Subscription.objects.filter(service=service, customer=customer, status="active").first()
        for target in eligible_plan_targets(subscription) if subscription is not None else []:
            try:
                amounts = _tax_quote(customer, [target.period_price_cents])
            except ValidationError:
                return HttpResponseBadRequest(
                    _("Refresh this customer's billing details before preparing a plan link.")
                )
            options.append(
                {
                    "product_id": str(target.product_id),
                    "name": target.name,
                    "net_cents": amounts["net_cents"],
                    "tax_cents": amounts["tax_cents"],
                    "total_cents": amounts["total_cents"],
                    "limits": target.limits,
                    "proposal_url": _customer_checkout(
                        f"/services/{service.pk}/change-plan/?target={target.product_id}#plan-{target.product_id}"
                    ),
                }
            )
    return render(
        request,
        "provisioning/plan_change_proposal.html",
        {
            "service": service,
            "options": options,
            "current_change": current,
            "current_checkout_url": _customer_checkout(f"/services/{service.pk}/change-plan/{current.pk}/")
            if current
            else None,
        },
    )
