"""Separate named staff workflow for exceptional resources, with unchanged billing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from apps.common.decorators import staff_required_strict

from .hosting_limit_override_service import can_override_hosting_resources, grant_resource_override
from .hosting_limit_selectors import hosting_limits_summary
from .service_models import Service, ServicePlan

if TYPE_CHECKING:
    from apps.tickets.models import Ticket
    from apps.users.models import User


class ResourceOverrideForm(forms.Form):
    target_plan = forms.ModelChoiceField(queryset=ServicePlan.objects.none(), label=_("Resource plan"))
    ticket: forms.ModelChoiceField[Ticket] = forms.ModelChoiceField(queryset=None, label=_("Customer support ticket"))
    reason = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={"rows": 3}), label=_("Reason"))
    expected_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    submission_id = forms.UUIDField(widget=forms.HiddenInput)
    billing_unchanged = forms.BooleanField(
        label=_("I acknowledge that billing, recurring prices and frozen tariffs stay unchanged."),
    )
    adopt_existing_native_limits = forms.BooleanField(
        required=False,
        label=_(
            "I explicitly authorize adopting native quota enforcement for this existing account after fresh verification."
        ),
        help_text=_(
            "Leave unchecked to keep an imported account observational. Adoption requires a qualified node, current ownership and fresh usage that fits; it may impose a hard disk cap."
        ),
    )

    def __init__(self, *args: Any, service: Service, **kwargs: Any) -> None:
        from apps.tickets.models import Ticket  # noqa: PLC0415

        super().__init__(*args, **kwargs)
        cast("forms.ModelChoiceField[ServicePlan]", self.fields["target_plan"]).queryset = ServicePlan.objects.filter(
            plan_type=service.service_plan.plan_type
        ).order_by("name")
        cast("forms.ModelChoiceField[Ticket]", self.fields["ticket"]).queryset = Ticket.objects.filter(
            customer_id=service.customer_id
        ).order_by("-created_at")
        for field in self.fields.values():
            if not isinstance(field.widget, forms.HiddenInput):
                field.widget.attrs["class"] = (
                    "rounded border-slate-600 bg-slate-700 text-white focus:ring-2 focus:ring-blue-500"
                    if isinstance(field.widget, forms.CheckboxInput)
                    else "block w-full rounded-md border border-slate-600 bg-slate-700 text-white px-3 py-2 focus:ring-2 focus:ring-blue-500"
                )


@staff_required_strict
def service_resource_override(request: HttpRequest, pk: int) -> HttpResponse:
    user = cast("User", request.user)
    if not can_override_hosting_resources(user):
        raise PermissionDenied(_("Administrator or manager authority is required for a resource-only exception."))
    service = get_object_or_404(Service.objects.select_related("customer", "service_plan", "hosting_limits"), pk=pk)
    if not user.can_access_customer(service.customer):
        raise PermissionDenied
    limits = getattr(service, "hosting_limits", None)
    form = ResourceOverrideForm(
        request.POST if request.method == "POST" else None,
        service=service,
        initial={"expected_revision": limits.revision if limits else None, "submission_id": uuid4()},
    )
    status = 200
    if request.method == "POST":
        status = 400
        if form.is_valid():
            try:
                grant_resource_override(
                    user=user,
                    service=service,
                    target_plan_id=form.cleaned_data["target_plan"].pk,
                    ticket_id=form.cleaned_data["ticket"].pk,
                    reason=form.cleaned_data["reason"],
                    expected_revision=form.cleaned_data["expected_revision"],
                    submission_id=form.cleaned_data["submission_id"],
                    billing_unchanged=form.cleaned_data["billing_unchanged"],
                    adopt_existing_native_limits=form.cleaned_data["adopt_existing_native_limits"],
                )
            except ValidationError as error:
                form.add_error(None, error)
                status = 409
            else:
                messages.success(
                    request,
                    _(
                        "Resource-only exception accepted. Billing is unchanged; native limits are pending verification."
                    ),
                )
                return redirect("provisioning:service_detail", pk=service.pk)
    return render(
        request,
        "provisioning/service_resource_override.html",
        {
            "service": service,
            "form": form,
            "hosting_limits": hosting_limits_summary(service),
        },
        status=status,
    )
