"""
Customer core views for PRAHO Platform.
Customer CRUD operations and basic management views.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any, cast
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.messages.api import MessageFailure
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Count, Prefetch, Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from apps.billing.models import Invoice
from apps.common.constants import SEARCH_QUERY_MIN_LENGTH
from apps.common.decorators import staff_required
from apps.common.rate_limiting import rate_limit
from apps.common.types import Err
from apps.customers.contact_models import CustomerAddress
from apps.provisioning.models import Service
from apps.tickets.models import Ticket
from apps.users.models import User
from apps.users.services import CustomerUserService, UserCreationRequest, UserLinkingRequest

from .customer_models import Customer
from .customer_service import CustomerService
from .forms import CustomerCreationForm, CustomerEditForm, CustomerUserAssignmentForm

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("security")


def _handle_secure_error(request: HttpRequest, error: Exception, operation: str, user_id: int | None = None) -> None:
    """🔒 Handle errors securely without leaking sensitive information"""
    # Use logger from re-export module so patches work correctly
    from . import views as views_module  # noqa: PLC0415  # Deferred: avoids circular import

    logger = views_module.security_logger

    def _safe_add_message(request: HttpRequest, message: str) -> None:
        """Safely add a message, handling cases where MessageMiddleware is not installed"""
        with suppress(MessageFailure):
            messages.error(request, message)

    if isinstance(error, ValidationError):
        _safe_add_message(request, str(_("❌ Please check your input: Invalid data provided")))
        logger.warning(
            f"⚡ [CustomerSecurity] Validation error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "validation"},
        )
    elif isinstance(error, IntegrityError):
        _safe_add_message(request, str(_("❌ This operation conflicts with existing data")))
        logger.error(
            f"⚡ [CustomerSecurity] Integrity error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "integrity"},
        )
    elif isinstance(error, PermissionDenied):
        _safe_add_message(request, str(_("❌ You don't have permission to perform this action")))
        logger.warning(
            f"⚡ [CustomerSecurity] Permission denied during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "permission"},
        )
    else:
        # Unexpected errors - completely generic message
        _safe_add_message(request, str(_("❌ Operation failed. Please contact support if this continues")))
        logger.exception(
            f"⚡ [CustomerSecurity] Unexpected error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "unexpected"},
        )


def _build_customer_queryset(
    user: User,
    search_query: str = "",
    status_filter: str = "",
    type_filter: str = "",
) -> tuple[Any, str, str, str]:
    """Build annotated, filtered customer queryset for list and HTMX views."""
    customers = CustomerService.get_accessible_customers(user)

    # Search filter — uses canonical `q` param
    if search_query and len(search_query) >= SEARCH_QUERY_MIN_LENGTH:
        customers = CustomerService.search_customers(search_query, user)

    # Status filter
    if status_filter:
        customers = customers.filter(status=status_filter)

    # Type filter
    if type_filter:
        customers = customers.filter(customer_type=type_filter)

    # Annotations for service/ticket counts
    customers = customers.annotate(
        active_services_count=Count("services", filter=Q(services__status="active")),
        open_tickets_count=Count("tickets", filter=Q(tickets__status__in=["open", "in_progress"])),
    )

    # Efficient prefetch: tax profile, billing profile, primary address only
    customers = (
        customers.select_related("tax_profile", "billing_profile")
        .prefetch_related(
            Prefetch(
                "addresses",
                queryset=CustomerAddress.objects.filter(address_type="primary", is_current=True),
                to_attr="primary_addresses",
            )
        )
        .order_by("-created_at")
    )

    return customers, search_query, status_filter, type_filter


@login_required
def customer_list(request: HttpRequest) -> HttpResponse:
    """👥 Display list of customers with search, filtering, and HTMX support."""
    user = cast(User, request.user)

    search_query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "").strip()
    type_filter = request.GET.get("type", "").strip()

    customers, search_query, status_filter, type_filter = _build_customer_queryset(
        user, search_query, status_filter, type_filter
    )

    # Compute stats before pagination (from unfiltered base)
    all_customers = CustomerService.get_accessible_customers(user)
    total_count = all_customers.count()
    active_count = all_customers.filter(status="active").count()

    # Pagination
    paginator = Paginator(customers, 25)
    page_number = request.GET.get("page")
    customers_page = paginator.get_page(page_number)

    # Build URL-safe extra params for pagination links
    params: dict[str, str] = {}
    if search_query:
        params["q"] = search_query
    if status_filter:
        params["status"] = status_filter
    if type_filter:
        params["type"] = type_filter
    extra_params = urlencode(params) if params else ""

    # Status tabs for filter UI
    status_tabs = [
        {"value": "", "label": str(_("All")), "border_class": "border-blue-500", "text_class": "text-blue-400"},
        {
            "value": "active",
            "label": str(_("Active")),
            "border_class": "border-green-500",
            "text_class": "text-green-400",
        },
        {
            "value": "prospect",
            "label": str(_("Prospect")),
            "border_class": "border-cyan-500",
            "text_class": "text-cyan-400",
        },
        {
            "value": "inactive",
            "label": str(_("Inactive")),
            "border_class": "border-slate-500",
            "text_class": "text-slate-400",
        },
        {
            "value": "suspended",
            "label": str(_("Suspended")),
            "border_class": "border-amber-500",
            "text_class": "text-amber-400",
        },
    ]

    # Breadcrumbs
    breadcrumb_items = [
        {"text": _("Dashboard"), "url": reverse("dashboard")},
        {"text": _("Customers")},
    ]

    context = {
        "customers": customers_page,
        "search_query": search_query,
        "status_filter": status_filter,
        "type_filter": type_filter,
        "total_customers": paginator.count,
        "total_count": total_count,
        "active_count": active_count,
        "extra_params": extra_params,
        "breadcrumb_items": breadcrumb_items,
        "status_tabs": status_tabs,
        "filter_active_tab": status_filter,
        "search_htmx_url": reverse("customers:search_htmx"),
    }

    return render(request, "customers/list.html", context)


@login_required
@rate_limit(key="user", rate="45/m", method="GET")
def customer_search_htmx(request: HttpRequest) -> HttpResponse:
    """🔄 HTMX endpoint for live customer filtering."""
    user = cast(User, request.user)

    search_query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "").strip()
    type_filter = request.GET.get("type", "").strip()

    customers, search_query, status_filter, type_filter = _build_customer_queryset(
        user, search_query, status_filter, type_filter
    )

    # HTMX: first page only for real-time filtering
    customers_page = customers[:25]

    context = {
        "customers": customers_page,
        "search_query": search_query,
        "status_filter": status_filter,
        "type_filter": type_filter,
    }

    return render(request, "customers/partials/customer_table.html", context)


@login_required
def customer_detail(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🔍 Customer detail view with all related information
    Shows normalized data from separate profile models
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @login_required
    accessible_qs = CustomerService.get_accessible_customers(user)

    # Expected queries: 4 (customer + tax + billing + addresses)
    customer = get_object_or_404(
        accessible_qs.select_related("tax_profile", "billing_profile").prefetch_related(
            "addresses", "notes", "memberships__user"
        ),
        id=customer_id,
    )

    # Get recent notes
    recent_notes = customer.notes.order_by("-created_at")[:5]

    # Build base querysets once; each is evaluated exactly twice below (aggregate + slice).
    services_qs = Service.objects.filter(customer=customer)
    invoices_qs = Invoice.objects.filter(customer=customer)
    tickets_qs = Ticket.objects.filter(customer=customer)

    # Get services for this customer (single aggregate query instead of 4 separate counts)
    services_summary = services_qs.aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(status="active")),
        suspended=Count("id", filter=Q(status="suspended")),
        pending=Count("id", filter=Q(status="pending")),
    )
    services = list(services_qs.select_related("service_plan").order_by("-created_at")[:5])

    # Get recent invoices (single aggregate query instead of 4 separate counts)
    invoices_summary = invoices_qs.aggregate(
        total=Count("id"),
        paid=Count("id", filter=Q(status="paid")),
        unpaid=Count("id", filter=Q(status__in=["issued", "overdue"])),
        draft=Count("id", filter=Q(status="draft")),
    )
    invoices = list(invoices_qs.order_by("-created_at")[:5])

    # Get recent tickets (single aggregate query instead of 4 separate counts)
    tickets_summary = tickets_qs.aggregate(
        total=Count("id"),
        open=Count("id", filter=Q(status__in=["open", "in_progress"])),
        closed=Count("id", filter=Q(status="closed")),
        pending=Count("id", filter=Q(status="waiting_on_customer")),
    )
    tickets = list(tickets_qs.order_by("-created_at")[:5])

    # User management context — single aggregate instead of two separate .count() queries
    membership_stats = customer.memberships.aggregate(
        total=Count("id"),
        owners=Count("id", filter=Q(role="owner")),
    )
    total_users = membership_stats["total"]
    owner_count = membership_stats["owners"]

    # Breadcrumb navigation
    breadcrumb_items = [
        {"text": _("Dashboard"), "url": reverse("dashboard")},
        {"text": _("Customers"), "url": reverse("customers:list")},
        {"text": customer.get_display_name()},
    ]

    context = {
        "customer": customer,
        "tax_profile": customer.get_tax_profile(),
        "billing_profile": customer.get_billing_profile(),
        "primary_address": customer.get_primary_address(),
        "billing_address": customer.get_billing_address(),
        "recent_notes": recent_notes,
        # New data for cards
        "services": services,
        "services_summary": services_summary,
        "invoices": invoices,
        "invoices_summary": invoices_summary,
        "tickets": tickets,
        "tickets_summary": tickets_summary,
        # User management context
        "total_users": total_users,
        "owner_count": owner_count,
        "is_last_user": total_users <= 1,
        "is_last_owner": owner_count <= 1,
        # Navigation and access
        "breadcrumb_items": breadcrumb_items,
        "is_staff_user": user.is_staff or bool(user.staff_role),
    }

    return render(request, "customers/detail.html", context)


# --- Customer-creation workflow handlers ---
# These three helpers (_handle_user_creation_for_customer, _handle_user_linking_for_customer,
# _handle_skip_user_for_customer) are intentionally separate from the user-assignment workflow
# handlers below (_handle_user_creation_action, _handle_user_linking_action, _handle_user_skip_action).
#
# Key differences that make unification awkward:
#   - send_welcome source: result dict (bool, already coerced) vs. POST data (raw string, needs coercion)
#   - is_primary flag: True for new customers (first owner), False for existing customers
#   - Success messages: creation says "created and linked", assignment is role-aware
#   - Skip messages: creation says "no user assigned", assignment says "skipped"
# Merging would require a parameter-heavy _handle_user_workflow() that is harder to follow than
# two focused sets of handlers.


def _handle_user_creation_for_customer(
    request: HttpRequest, customer: Customer, form_data: dict[str, str], result: dict[str, str]
) -> None:
    """Handle user creation for a new customer."""
    created_by_user = cast(User, request.user)  # Safe in authenticated contexts
    user_creation_request = UserCreationRequest(
        customer=customer,
        first_name=form_data.get("first_name", ""),
        last_name=form_data.get("last_name", ""),
        send_welcome=bool(result["send_welcome_email"]),
        created_by=created_by_user,
    )
    user_result = CustomerUserService.create_user_for_customer(user_creation_request)

    if user_result.is_ok():
        user, email_sent = user_result.unwrap()
        _show_user_creation_success_message(request, customer, user, email_sent)
    else:
        messages.success(
            request, _('✅ Customer "{customer_name}" created successfully').format(customer_name=customer.name)
        )
        messages.error(request, _("❌ Failed to create user account: {error}").format(error=user_result.unwrap_err()))


def _handle_user_linking_for_customer(request: HttpRequest, customer: Customer, result: dict[str, Any]) -> None:
    """Handle linking existing user to a new customer."""
    existing_user = result["existing_user"]
    if not existing_user:
        return

    created_by_user = cast(User, request.user)  # Safe in authenticated contexts
    user_linking_request = UserLinkingRequest(
        user=existing_user, customer=customer, role="owner", is_primary=True, created_by=created_by_user
    )
    link_result = CustomerUserService.link_existing_user(user_linking_request)

    if link_result.is_ok():
        messages.success(
            request,
            _('✅ Customer "{customer_name}" created and linked to user {email}').format(
                customer_name=customer.name, email=existing_user.email
            ),
        )
    else:
        messages.success(
            request, _('✅ Customer "{customer_name}" created successfully').format(customer_name=customer.name)
        )
        messages.error(request, _("❌ Failed to link user: {error}").format(error=link_result.unwrap_err()))


def _handle_skip_user_for_customer(request: HttpRequest, customer: Customer) -> None:
    """Handle skipping user assignment for a new customer."""
    messages.success(
        request,
        _('✅ Customer "{customer_name}" created successfully. No user assigned.').format(customer_name=customer.name),
    )
    messages.info(request, _("💡 You can assign users later from the customer detail page."))


def _handle_customer_create_post(request: HttpRequest) -> HttpResponse:
    """Handle POST request for customer creation with secure error handling."""
    form = CustomerCreationForm(request.POST)
    if not form.is_valid():
        messages.error(request, _("❌ Please correct the errors below"))
        return _render_customer_form(request, form)

    try:
        # Save customer and get result data
        user = cast(User, request.user)  # Safe in authenticated contexts
        result = form.save(user=user)
        customer = result["customer"]
        user_action = result["user_action"]

        # Handle user assignment based on action
        if user_action == "create":
            _handle_user_creation_for_customer(request, customer, form.cleaned_data, result)
        elif user_action == "link":
            _handle_user_linking_for_customer(request, customer, result)
        else:  # user_action == 'skip'
            _handle_skip_user_for_customer(request, customer)

        return redirect("customers:detail", customer_id=customer.pk)

    except Exception as e:
        _handle_secure_error(request, e, "customer_create", request.user.id)

    return _render_customer_form(request, form)


def _render_customer_form(request: HttpRequest, form: CustomerCreationForm | None = None) -> HttpResponse:
    """Render the customer creation form."""
    if form is None:
        form = CustomerCreationForm()

    context = {
        "form": form,
        "action": _("Create"),
    }
    return render(request, "customers/form.html", context)


@staff_required
def customer_create(request: HttpRequest) -> HttpResponse:
    """
    + Create new customer with all profiles and optional user assignment
    Uses composite form to handle normalized structure and user creation/linking
    """
    if request.method == "POST":
        return _handle_customer_create_post(request)

    return _render_customer_form(request)


@staff_required
def customer_edit(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    ✏️ Comprehensive customer edit with all profiles
    Edits core customer, tax profile, billing profile, and primary address
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_qs = CustomerService.get_accessible_customers(user)
    # Prefetch related profiles for efficiency
    customer = get_object_or_404(
        accessible_qs.select_related("tax_profile", "billing_profile").prefetch_related("addresses"), id=customer_id
    )

    if request.method == "POST":
        try:
            form = CustomerEditForm(customer, request.POST)
            if form.is_valid():
                updated_customer = form.save(user=user)
                messages.success(
                    request,
                    _('✅ Customer "{customer_name}" updated successfully').format(
                        customer_name=updated_customer.get_display_name()
                    ),
                )
                return redirect("customers:detail", customer_id=updated_customer.id)
            else:
                messages.error(request, _("❌ Please correct the errors below"))
        except Exception as e:
            _handle_secure_error(request, e, "customer_edit", user.id)
            # Form will be re-rendered with error messages
    else:
        form = CustomerEditForm(customer)

    context = {
        "form": form,
        "customer": customer,
        "title": _("Edit Customer"),
        "submit_text": _("Update Customer"),
        "breadcrumb_items": [
            {"text": _("Dashboard"), "url": reverse("dashboard")},
            {"text": _("Customers"), "url": reverse("customers:list")},
            {
                "text": customer.get_display_name(),
                "url": reverse("customers:detail", kwargs={"customer_id": customer.pk}),
            },
            {"text": _("Edit")},
        ],
    }

    return render(request, "customers/edit.html", context)


@staff_required
def customer_delete(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🗑️ Soft delete customer (preserves audit trail)
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_qs = CustomerService.get_accessible_customers(user)
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        # Server-side confirmation: confirm_name must match customer name
        confirm_name = request.POST.get("confirm_name", "").strip()
        if confirm_name != customer.name:
            messages.error(
                request, _("❌ Customer name does not match. Please type the exact name to confirm deletion.")
            )
            return render(request, "customers/delete_confirm.html", {"customer": customer})

        # Soft delete preserves all related data
        user = cast(User, request.user)  # Safe due to @staff_required
        customer.soft_delete(user=user)
        messages.success(
            request,
            _('🗑️ Customer "{customer_name}" deleted successfully').format(customer_name=customer.get_display_name()),
        )
        return redirect("customers:list")

    context = {
        "customer": customer,
    }

    return render(request, "customers/delete_confirm.html", context)


@login_required
@rate_limit(key="user", rate="45/m", method="GET")
def customer_search_api(request: HttpRequest) -> JsonResponse:
    """
    🔍 AJAX customer search for dropdowns with rate limiting
    """
    # Check if rate limited
    if getattr(request, "limited", False):
        logger.warning(f"🚨 [Security] Rate limit exceeded for customer search by user {request.user.id}")
        return JsonResponse({"error": "Too many requests. Please slow down."}, status=429)

    query = request.GET.get("q", "")
    if len(query) < SEARCH_QUERY_MIN_LENGTH:
        return JsonResponse({"results": []})

    user = cast(User, request.user)  # Safe due to @login_required
    customers = CustomerService.search_customers(query, user)[:10]

    results = [
        {
            "id": customer.id,
            "text": customer.get_display_name(),
            "email": customer.primary_email,
        }
        for customer in customers
    ]

    return JsonResponse({"results": results})


def _validate_customer_assign_access(request: HttpRequest, user: User, customer: Customer) -> HttpResponse | None:
    """Validate user access to assign users to customer."""
    if not user.can_access_customer(customer):
        messages.error(request, _("Access denied to this customer"))
        return redirect("customers:list")
    return None


# --- User-assignment workflow handlers (post-creation) ---
# See the comment above the customer-creation handlers for why these are kept separate.


def _handle_user_creation_action(request: HttpRequest, customer: Customer, assignment_data: dict[str, str]) -> None:
    """Handle the 'create' action for user assignment."""
    send_welcome = bool(assignment_data.get("send_welcome_email", True))
    created_by_user = cast(User, request.user)  # Safe in authenticated contexts
    user_creation_request = UserCreationRequest(
        customer=customer,
        first_name=assignment_data["first_name"],
        last_name=assignment_data["last_name"],
        send_welcome=send_welcome,
        created_by=created_by_user,
    )
    user_result = CustomerUserService.create_user_for_customer(user_creation_request)

    if user_result.is_ok():
        user, email_sent = user_result.unwrap()
        _show_user_creation_success_message(request, customer, user, email_sent)
    else:
        error_result = cast(Err[str], user_result)
        messages.error(request, _("❌ Failed to create user account: {error}").format(error=error_result.error))


def _show_user_creation_success_message(request: HttpRequest, customer: Customer, user: User, email_sent: bool) -> None:
    """Show appropriate success message for user creation."""
    if email_sent:
        messages.success(
            request,
            _("✅ User account created for {customer_name}. Welcome email sent to {email}").format(
                customer_name=customer.name, email=user.email
            ),
        )
    else:
        messages.success(
            request,
            _("✅ User account created for {customer_name}: {email}").format(
                customer_name=customer.name, email=user.email
            ),
        )
        messages.warning(request, _("⚠️ Welcome email could not be sent. Please inform the user manually."))


def _handle_user_linking_action(request: HttpRequest, customer: Customer, assignment_data: dict[str, str]) -> None:
    """Handle the 'link' action for user assignment."""
    existing_user = assignment_data["existing_user"]
    role = assignment_data["role"]

    if not existing_user:
        messages.error(request, _("❌ No user selected for linking"))
        return

    if not isinstance(existing_user, User):
        messages.error(request, _("❌ Invalid user selected"))
        return

    created_by_user = cast(User, request.user)  # Safe in authenticated contexts
    user_linking_request = UserLinkingRequest(
        user=existing_user,
        customer=customer,
        role=role,
        is_primary=False,  # Existing customers might already have primary users
        created_by=created_by_user,
    )
    link_result = CustomerUserService.link_existing_user(user_linking_request)

    if link_result.is_ok():
        messages.success(
            request,
            _('✅ User {email} linked to customer "{customer_name}" with {role} role').format(
                email=existing_user.email, customer_name=customer.name, role=role
            ),
        )
    else:
        error_result = cast(Err[str], link_result)
        messages.error(request, _("❌ Failed to link user: {error}").format(error=error_result.error))


def _handle_user_skip_action(request: HttpRequest, customer: Customer) -> None:
    """Handle the 'skip' action for user assignment."""
    messages.info(
        request, _('💡 User assignment skipped for customer "{customer_name}"').format(customer_name=customer.name)
    )


def _handle_user_assignment_post(request: HttpRequest, customer: Customer) -> HttpResponse:
    """Handle POST request for user assignment with secure error handling."""
    form = CustomerUserAssignmentForm(data=request.POST, customer=customer)
    if not form.is_valid():
        messages.error(request, _("❌ Please correct the errors below"))
        return _render_assignment_form(request, form, customer)

    try:
        created_by_user = cast(User, request.user)  # Safe in authenticated contexts
        assignment_data = form.save(customer=customer, created_by=created_by_user)
        action = assignment_data["action"]

        if action == "create":
            _handle_user_creation_action(request, customer, assignment_data)
        elif action == "link":
            _handle_user_linking_action(request, customer, assignment_data)
        else:  # action == 'skip'
            _handle_user_skip_action(request, customer)

        return redirect("customers:detail", customer_id=customer.pk)

    except Exception as e:
        _handle_secure_error(request, e, "user_assignment", request.user.id)

    return _render_assignment_form(request, form, customer)


def _render_assignment_form(
    request: HttpRequest, form: CustomerUserAssignmentForm | None, customer: Customer
) -> HttpResponse:
    """Render the user assignment form."""
    if form is None:
        form = CustomerUserAssignmentForm(customer=customer)

    context = {
        "form": form,
        "customer": customer,
        "action": _("Assign User"),
        "breadcrumb_items": [
            {"text": _("Dashboard"), "url": reverse("dashboard")},
            {"text": _("Customers"), "url": reverse("customers:list")},
            {
                "text": customer.get_display_name(),
                "url": reverse("customers:detail", kwargs={"customer_id": customer.pk}),
            },
            {"text": _("Assign User")},
        ],
    }
    return render(request, "customers/assign_user.html", context)


@staff_required
def customer_assign_user(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🔗 Assign user to existing customer (for orphaned customers)
    Provides same three-option workflow as customer creation
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_qs = CustomerService.get_accessible_customers(user)
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        return _handle_user_assignment_post(request, customer)

    return _render_assignment_form(request, None, customer)


@login_required
@rate_limit(key="user", rate="90/m", method="GET")
def customer_services_api(request: HttpRequest, customer_id: int) -> JsonResponse:
    """
    🔗 API endpoint for customer services (for ticket form) with rate limiting
    Returns real Service objects filtered by customer access.
    """
    # Check if rate limited
    if getattr(request, "limited", False):
        logger.warning(f"🚨 [Security] Rate limit exceeded for services API by user {request.user.id}")
        return JsonResponse({"error": "Too many requests. Please slow down."}, status=429)

    # Verify user has access to this customer
    user = cast(User, request.user)
    customers_qs = CustomerService.get_accessible_customers(user)

    if not customers_qs.filter(id=customer_id).exists():
        return JsonResponse({"error": "Access denied"}, status=403)

    # Response contract: {"results": [{"id": ..., "service_name": ..., "status": ..., "service_plan__name": ...}, ...]}
    # Consumers (e.g. ticket form dropdown JS) must use the "results" key — not a bare array.
    services = list(
        Service.objects.filter(customer_id=customer_id)
        .values("id", "service_name", "status", "service_plan__name")
        .order_by("service_name")
    )
    return JsonResponse({"results": services})
