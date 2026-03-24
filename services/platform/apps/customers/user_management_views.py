"""
User management views for customers - PRAHO Platform.
Handles user assignment, role changes, and access management.
"""

from typing import cast

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods, require_POST

from apps.common.decorators import staff_required
from apps.customers.customer_service import CustomerService
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from apps.users.services import SecureCustomerUserService


def _get_accessible_customer(request: HttpRequest, customer_id: int) -> Customer:
    """Get customer with access control check."""
    user = cast(User, request.user)
    accessible_qs = CustomerService.get_accessible_customers(user)
    return get_object_or_404(accessible_qs, id=customer_id)


@staff_required
@require_http_methods(["GET", "POST"])
def customer_add_user(request: HttpRequest, customer_id: int) -> HttpResponse:
    """Add existing user to customer."""
    customer = _get_accessible_customer(request, customer_id)

    if request.method == "POST":
        user_email = request.POST.get("user_email", "").strip()
        role = request.POST.get("role", "viewer")

        # Validate role against allowed choices
        valid_roles = [choice[0] for choice in CustomerMembership.CUSTOMER_ROLE_CHOICES]
        if role not in valid_roles:
            messages.error(request, _("Invalid role selected."))
            return redirect("customers:detail", customer_id=customer.id)

        if not user_email:
            messages.error(request, _("Email address is required."))
            return redirect("customers:detail", customer_id=customer.id)

        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            messages.error(request, _("User with email '{}' not found.").format(user_email))
            return redirect("customers:detail", customer_id=customer.id)

        # Check if user is already assigned
        if CustomerMembership.objects.filter(customer=customer, user=user).exists():
            messages.error(request, _("User is already assigned to this customer."))
            return redirect("customers:detail", customer_id=customer.id)

        # Create membership
        CustomerMembership.objects.create(customer=customer, user=user, role=role)

        messages.success(request, _("User '{}' added to customer with {} role.").format(user.email, role))
        return redirect("customers:detail", customer_id=customer.id)

    # GET request - show form
    available_users = (
        User.objects.filter(is_active=True).exclude(customer_memberships__customer=customer).order_by("email")
    )

    context = {
        "customer": customer,
        "available_users": available_users,
        "role_choices": CustomerMembership.CUSTOMER_ROLE_CHOICES,
        "breadcrumb_items": [
            {"text": _("Dashboard"), "url": reverse("dashboard")},
            {"text": _("Customers"), "url": reverse("customers:list")},
            {
                "text": customer.get_display_name(),
                "url": reverse("customers:detail", kwargs={"customer_id": customer.pk}),
            },
            {"text": _("Add User")},
        ],
    }
    return render(request, "customers/add_user.html", context)


@staff_required
@require_http_methods(["GET", "POST"])
def customer_create_user(request: HttpRequest, customer_id: int) -> HttpResponse:
    """Create new user and assign to customer."""
    customer = _get_accessible_customer(request, customer_id)

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        role = request.POST.get("role", "viewer")

        if not email:
            messages.error(request, _("Email address is required."))
            return redirect("customers:detail", customer_id=customer.id)

        # Validate role against allowed choices
        valid_roles = [choice[0] for choice in CustomerMembership.CUSTOMER_ROLE_CHOICES]
        if role not in valid_roles:
            messages.error(request, _("Invalid role selected."))
            return redirect("customers:detail", customer_id=customer.id)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, _("User with email '{}' already exists.").format(email))
            return redirect("customers:detail", customer_id=customer.id)

        # Create new user with proper password hashing
        user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name)

        # Create membership
        CustomerMembership.objects.create(customer=customer, user=user, role=role)

        # Send invite email with password reset link
        email_sent = SecureCustomerUserService._send_welcome_email_secure(user, customer)
        if not email_sent:
            messages.warning(request, _("User created but invite email could not be sent."))

        messages.success(request, _("New user '{}' created and assigned to customer.").format(user.email))
        return redirect("customers:detail", customer_id=customer.id)

    # GET request - show form
    context = {
        "customer": customer,
        "role_choices": CustomerMembership.CUSTOMER_ROLE_CHOICES,
        "breadcrumb_items": [
            {"text": _("Dashboard"), "url": reverse("dashboard")},
            {"text": _("Customers"), "url": reverse("customers:list")},
            {
                "text": customer.get_display_name(),
                "url": reverse("customers:detail", kwargs={"customer_id": customer.pk}),
            },
            {"text": _("Create User")},
        ],
    }
    return render(request, "customers/create_user.html", context)


@staff_required
@require_POST
def change_user_role(request: HttpRequest, customer_id: int, membership_id: int) -> HttpResponse:
    """Change user's role within customer organization."""
    customer = _get_accessible_customer(request, customer_id)
    membership = get_object_or_404(CustomerMembership, id=membership_id, customer=customer)

    new_role = request.POST.get("role")
    valid_roles = [choice[0] for choice in CustomerMembership.CUSTOMER_ROLE_CHOICES]

    if new_role not in valid_roles:
        messages.error(request, _("Invalid role selected."))
        return redirect("customers:detail", customer_id=customer.id)

    if membership.role == new_role:
        messages.info(request, _("User already has the {} role.").format(new_role))
        return redirect("customers:detail", customer_id=customer.id)

    # SAFEGUARD: Prevent demoting the last owner
    if membership.role == "owner" and new_role != "owner":
        owner_count = CustomerMembership.objects.filter(customer=customer, role="owner").count()

        if owner_count <= 1:
            messages.error(
                request,
                _("Cannot change role: {} is the only owner. Promote another user to owner first.").format(
                    membership.user.email
                ),
            )
            return redirect("customers:detail", customer_id=customer.id)

    old_role = membership.get_role_display()
    membership.role = new_role
    membership.save()

    messages.success(
        request,
        _("Changed {}'s role from {} to {}.").format(membership.user.email, old_role, membership.get_role_display()),
    )

    return redirect("customers:detail", customer_id=customer.id)


@staff_required
@require_POST
def toggle_user_status(request: HttpRequest, customer_id: int, user_id: int) -> HttpResponse:
    """Toggle user's active status. NOTE: This sets User.is_active globally — affects all customer memberships."""
    customer = _get_accessible_customer(request, customer_id)
    user = get_object_or_404(User, id=user_id)

    # Verify user is associated with this customer
    if not CustomerMembership.objects.filter(customer=customer, user=user).exists():
        messages.error(request, _("User is not associated with this customer."))
        return redirect("customers:detail", customer_id=customer.id)

    is_active = request.POST.get("is_active") == "true"
    user.is_active = is_active
    user.save()

    action = _("activated") if is_active else _("suspended")
    messages.success(request, _("User '{}' has been {}.").format(user.email, action))
    if not is_active:
        messages.warning(
            request,
            _("Note: This affects the user's access to ALL customer accounts, not just this one."),
        )

    return redirect("customers:detail", customer_id=customer.id)


@staff_required
@require_POST
def remove_user(request: HttpRequest, customer_id: int, membership_id: int) -> HttpResponse:
    """Remove user from customer organization."""
    customer = _get_accessible_customer(request, customer_id)
    membership = get_object_or_404(CustomerMembership, id=membership_id, customer=customer)

    # SAFEGUARD 1: Prevent removing the last user from customer
    total_users = CustomerMembership.objects.filter(customer=customer).count()
    if total_users <= 1:
        messages.error(
            request,
            _(
                "Cannot remove user: {} is the only user assigned to this customer. "
                "A customer must have at least one user."
            ).format(membership.user.email),
        )
        return redirect("customers:detail", customer_id=customer.id)

    # SAFEGUARD 2: Prevent removing the last owner
    if membership.role == "owner":
        owner_count = CustomerMembership.objects.filter(customer=customer, role="owner").count()

        if owner_count <= 1:
            messages.error(
                request,
                _("Cannot remove user: {} is the only owner. Promote another user to owner first.").format(
                    membership.user.email
                ),
            )
            return redirect("customers:detail", customer_id=customer.id)

    user_email = membership.user.email
    membership.delete()

    messages.success(request, _("User '{}' removed from customer.").format(user_email))
    return redirect("customers:detail", customer_id=customer.id)
