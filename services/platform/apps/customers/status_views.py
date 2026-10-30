"""Staff move a customer through its lifecycle statuses (ADR-0066)."""

from __future__ import annotations

import logging

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.audit.actor_context import acting_as
from apps.common.decorators import staff_required

from .customer_models import Customer
from .lifecycle import STATUS_ACTIONS, role_status_actions

logger = logging.getLogger(__name__)

# Each action name maps to its transition once, here, from the fixed list: the request only picks a key.
_TRANSITIONS = {name: getattr(Customer, name) for name in STATUS_ACTIONS}


@staff_required
@require_POST
def customer_status_change(request: HttpRequest, customer_id: int, action: str) -> HttpResponse:
    transition = _TRANSITIONS.get(action)
    if transition is None:
        raise Http404
    if action not in role_status_actions(request.user):
        raise PermissionDenied
    get_object_or_404(Customer, pk=customer_id)
    try:
        with transaction.atomic(), acting_as(request.user):
            customer = Customer.objects.select_for_update(of=("self",)).get(pk=customer_id)
            old_status = customer.status
            transition(customer)
            customer.save(update_fields=["status", "updated_at"])
    except TransitionNotAllowed:
        messages.error(request, _("This customer cannot be moved that way from its current status."))
    except ConcurrentTransition:
        messages.error(request, _("This customer was changed at the same time. Reload the page and try again."))
    else:
        logger.info(f"🔄 [Customer] {request.user} moved customer {customer_id}: {old_status} → {customer.status}")
        messages.success(
            request, _("The customer's status is now {status}.").format(status=customer.get_status_display())
        )
    return redirect("customers:detail", customer_id=customer_id)
