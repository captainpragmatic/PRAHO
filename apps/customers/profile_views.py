"""
Customer profile views for PRAHO Platform.
Tax profile and billing profile management views.
"""

from __future__ import annotations

import logging
from typing import cast

from django.contrib import messages
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from apps.common.decorators import staff_required
from apps.users.models import User

from .customer_models import Customer
from .forms import CustomerBillingProfileForm, CustomerTaxProfileForm
from .profile_models import CustomerBillingProfile, CustomerTaxProfile

logger = logging.getLogger(__name__)


@staff_required
def customer_tax_profile(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🧾 Edit customer tax profile (CUI, VAT, compliance)
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_customers = user.get_accessible_customers()
    accessible_qs = (
        accessible_customers
        if isinstance(accessible_customers, QuerySet)
        else Customer.objects.filter(id__in=[c.id for c in accessible_customers])
        if accessible_customers
        else Customer.objects.none()
    )
    customer = get_object_or_404(accessible_qs, id=customer_id)

    # Get or create tax profile
    tax_profile, created = CustomerTaxProfile.objects.get_or_create(customer=customer)

    if request.method == "POST":
        form = CustomerTaxProfileForm(request.POST, instance=tax_profile)
        if form.is_valid():
            form.save()
            messages.success(request, _("✅ Tax profile updated successfully"))
            return redirect("customers:detail", customer_id=customer.id)
        else:
            messages.error(request, _("❌ Please correct the errors below"))
    else:
        form = CustomerTaxProfileForm(instance=tax_profile)

    context = {
        "form": form,
        "customer": customer,
        "tax_profile": tax_profile,
        "action": _("Tax Profile"),
    }

    return render(request, "customers/tax_profile_form.html", context)


@staff_required
def customer_billing_profile(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    💰 Edit customer billing profile (payment terms, credit)
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_customers = user.get_accessible_customers()
    accessible_qs = (
        accessible_customers
        if isinstance(accessible_customers, QuerySet)
        else Customer.objects.filter(id__in=[c.id for c in accessible_customers])
        if accessible_customers
        else Customer.objects.none()
    )
    customer = get_object_or_404(accessible_qs, id=customer_id)

    # Get or create billing profile
    billing_profile, created = CustomerBillingProfile.objects.get_or_create(customer=customer)

    if request.method == "POST":
        form = CustomerBillingProfileForm(request.POST, instance=billing_profile)
        if form.is_valid():
            form.save()
            messages.success(request, _("✅ Billing profile updated successfully"))
            return redirect("customers:detail", customer_id=customer.id)
        else:
            messages.error(request, _("❌ Please correct the errors below"))
    else:
        form = CustomerBillingProfileForm(instance=billing_profile)

    context = {
        "form": form,
        "customer": customer,
        "billing_profile": billing_profile,
        "action": _("Billing Profile"),
    }

    return render(request, "customers/billing_profile_form.html", context)
