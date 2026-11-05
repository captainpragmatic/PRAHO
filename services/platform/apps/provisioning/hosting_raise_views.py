"""Explicit staff request and expiry consent for temporary disk relief."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.common.decorators import staff_required_strict

from .hosting_limit_override_service import can_override_hosting_resources
from .hosting_raise_models import ServiceHostingRaise
from .hosting_raise_policy import DEFAULT_RAISE_DURATION, MAX_RAISE_DURATION, maximum_raise_mib
from .hosting_raise_service import grant_hosting_raise
from .hosting_safety_observation import request_safety_refresh
from .service_models import Service

if TYPE_CHECKING:
    from apps.tickets.models import Ticket
    from apps.users.models import User


class HostingRaiseForm(forms.Form):
    extra_mib = forms.IntegerField(min_value=1, label=_("Extra disk capacity (MiB)"))
    ticket: forms.ModelChoiceField[Ticket] = forms.ModelChoiceField(queryset=None, label=_("Customer support ticket"))
    reason = forms.CharField(
        min_length=10, max_length=2000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Reason")
    )
    expires_at = forms.DateTimeField(
        label=_("Expiry"), widget=forms.DateTimeInput(format="%Y-%m-%dT%H:%M", attrs={"type": "datetime-local"})
    )
    expected_base_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    expected_overlay_revision = forms.IntegerField(min_value=0, widget=forms.HiddenInput)
    submission_id = forms.UUIDField(widget=forms.HiddenInput)
    acknowledge_expiry = forms.BooleanField(
        label=_(
            "I authorize automatic removal of this temporary capacity at expiry, including if usage is still above the plan allowance."
        )
    )

    def __init__(self, *args: Any, service: Service, maximum: int, **kwargs: Any) -> None:
        from apps.tickets.models import Ticket  # noqa: PLC0415 -- Cross-app form choices.

        super().__init__(*args, **kwargs)
        cast("forms.ModelChoiceField[Ticket]", self.fields["ticket"]).queryset = Ticket.objects.filter(
            customer_id=service.customer_id
        ).order_by("-created_at")
        self.fields["extra_mib"].help_text = _(
            "Up to %(maximum)d MiB. An existing raise can only extend its expiry."
        ) % {"maximum": maximum}
        self.fields["expires_at"].label = _("Expiry (%(timezone)s)") % {
            "timezone": timezone.get_current_timezone_name()
        }
        for field in self.fields.values():
            if not isinstance(field.widget, forms.HiddenInput):
                field.widget.attrs["class"] = "rounded border-slate-600 bg-slate-700 text-white px-3 py-2"


@staff_required_strict
@require_http_methods(["GET", "POST"])
def service_hosting_raise(request: HttpRequest, pk: int) -> HttpResponse:
    user = cast("User", request.user)
    if not can_override_hosting_resources(user):
        raise PermissionDenied(_("Administrator or manager authority is required for temporary resource relief."))
    service = get_object_or_404(Service.objects.select_related("customer", "hosting_limits"), pk=pk)
    if not user.can_access_customer(service.customer):
        raise PermissionDenied
    limits = getattr(service, "hosting_limits", None)
    row = ServiceHostingRaise.objects.filter(service=service, owner_id=service.customer_id).first()
    maximum = maximum_raise_mib(limits.disk_allowance_mib if limits else None)
    now = timezone.now()
    active = row is not None and row.status == "active" and row.expires_at > now
    expiry = (
        min(row.expires_at + timedelta(days=1), row.first_granted_at + MAX_RAISE_DURATION)
        if row and active
        else now + DEFAULT_RAISE_DURATION
    )
    expiry = expiry.replace(second=0, microsecond=0)
    can_request = not active or (row is not None and expiry > row.expires_at)
    form = HostingRaiseForm(
        request.POST if request.method == "POST" else None,
        service=service,
        maximum=maximum,
        initial={
            "extra_mib": row.extra_mib if row and row.status == "active" else maximum,
            "expires_at": expiry,
            "expected_base_revision": limits.revision if limits else None,
            "expected_overlay_revision": row.revision if row else 0,
            "submission_id": uuid4(),
        },
    )
    if request.method == "POST":
        try:
            if request.POST.get("action") == "refresh-usage":
                request_safety_refresh(service.pk, service.customer_id, user.pk)
                messages.success(request, _("Usage check queued. Reload this page after it finishes."))
                return redirect("provisioning:service_hosting_raise", pk=service.pk)
            if not can_request:
                form.add_error(None, _("This raise has reached its original seven-day limit."))
            elif form.is_valid():
                values = form.cleaned_data
                grant_hosting_raise(
                    user=user,
                    service=service,
                    extra_mib=values["extra_mib"],
                    ticket_id=values["ticket"].pk,
                    reason=values["reason"],
                    expected_base_revision=values["expected_base_revision"],
                    expected_overlay_revision=values["expected_overlay_revision"],
                    submission_id=values["submission_id"],
                    expires_at=values["expires_at"],
                )
                messages.success(request, _("Temporary relief requested. Capacity remains pending until verified."))
                return redirect("provisioning:service_detail", pk=service.pk)
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "provisioning/service_hosting_raise.html",
        {"service": service, "form": form, "raise": row, "can_request": can_request},
        status=400 if request.method == "POST" else 200,
    )
