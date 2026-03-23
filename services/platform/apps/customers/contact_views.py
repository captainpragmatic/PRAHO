"""
Customer contact views for PRAHO Platform.
Address, notes, and contact information management views.
"""

from __future__ import annotations

import logging
from typing import cast

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from apps.common.decorators import staff_required
from apps.users.models import User

from .customer_service import CustomerService
from .forms import CustomerAddressForm, CustomerNoteForm

logger = logging.getLogger(__name__)


@staff_required
def customer_address_add(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🏠 Add new address for customer
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_qs = CustomerService.get_accessible_customers(user)
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        form = CustomerAddressForm(request.POST)
        if form.is_valid():
            address = form.save(commit=False)
            address.customer = customer

            # The model's save() enforces is_primary / is_billing exclusivity automatically
            address.save()
            messages.success(request, _("✅ Address added"))
            return redirect("customers:detail", customer_id=customer.id)
        else:
            messages.error(request, _("❌ Please correct the errors below"))
    else:
        form = CustomerAddressForm()

    context = {
        "form": form,
        "customer": customer,
        "action": _("Add Address"),
    }

    return render(request, "customers/address_form.html", context)


@staff_required
def customer_note_add(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    📝 Add customer interaction note
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_qs = CustomerService.get_accessible_customers(user)
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        form = CustomerNoteForm(request.POST)
        if form.is_valid():
            note = form.save(commit=False)
            note.customer = customer
            user = cast(User, request.user)  # Safe due to @staff_required
            note.created_by = user
            note.save()
            messages.success(request, _("✅ Note added successfully"))
            return redirect("customers:detail", customer_id=customer.id)
        else:
            messages.error(request, _("❌ Please correct the errors below"))
    else:
        form = CustomerNoteForm()

    context = {
        "form": form,
        "customer": customer,
        "action": _("Add Note"),
    }

    return render(request, "customers/note_form.html", context)
