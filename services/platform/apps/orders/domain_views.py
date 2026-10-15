"""Staff record registrar answers on the order the customer paid for."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeGuard
from uuid import UUID

from django.contrib import messages
from django.db import IntegrityError
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.dateparse import parse_date
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from apps.common.decorators import staff_required_strict
from apps.domains.staff_fulfilment import record_paid_domain, refuse_paid_domain

from .models import Order, OrderItem
from .views import _REVIEW_APPROVE_ROLES

if TYPE_CHECKING:
    from apps.users.models import User


def _can_record(user: object) -> TypeGuard[User]:
    from apps.users.models import User  # noqa: PLC0415  # Cross-app models are deferred (ADR-0007).

    return isinstance(user, User) and (user.is_superuser or user.staff_role in _REVIEW_APPROVE_ROLES)


def _domain_redirect(request: HttpRequest, order_id: UUID) -> HttpResponse:
    destination = reverse("orders:order_detail", kwargs={"pk": order_id})
    if request.headers.get("HX-Request") == "true":
        return HttpResponse(headers={"HX-Redirect": destination})
    return redirect(destination)


@staff_required_strict
@require_POST
def domain_record(request: HttpRequest, pk: UUID, item_pk: UUID) -> HttpResponse:
    if not _can_record(request.user):
        return HttpResponseForbidden(_("Only admin or billing staff can record registrar answers."))
    try:
        try:
            expires_on = parse_date(request.POST.get("expires_on", ""))
        except ValueError:
            expires_on = None
        if expires_on is None:
            raise ValueError(_("Enter a future expiry date and the registrar domain ID."))
        count = record_paid_domain(
            pk,
            item_pk,
            expires_on=expires_on,
            registrar_domain_id=request.POST.get("registrar_domain_id", ""),
            actor=request.user,
        )
    except (Order.DoesNotExist, OrderItem.DoesNotExist):
        raise Http404 from None
    except (ValueError, IntegrityError) as error:
        message = (
            str(error)
            if isinstance(error, ValueError)
            else _("A domain with this name already exists; review its ownership first.")
        )
        return HttpResponseBadRequest(message)
    messages.success(request, _("Recorded %(count)s domain order line(s).") % {"count": count})
    return _domain_redirect(request, pk)


@staff_required_strict
@require_POST
def domain_refuse(request: HttpRequest, pk: UUID, item_pk: UUID) -> HttpResponse:
    if not _can_record(request.user):
        return HttpResponseForbidden(_("Only admin or billing staff can record registrar answers."))
    try:
        refuse_paid_domain(pk, item_pk, actor=request.user)
    except (Order.DoesNotExist, OrderItem.DoesNotExist):
        raise Http404 from None
    except ValueError as error:
        return HttpResponseBadRequest(str(error))
    messages.success(request, _("Registrar refusal recorded."))
    return _domain_redirect(request, pk)
