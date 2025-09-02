"""
Customer core views for PRAHO Platform.
Customer CRUD operations and basic management views.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.messages.api import MessageFailure
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django_ratelimit.decorators import ratelimit  # type: ignore[import-untyped]

from apps.common.constants import SEARCH_QUERY_MIN_LENGTH
from apps.common.decorators import staff_required
from apps.common.types import Err
from apps.users.models import User
from apps.users.services import CustomerUserService, UserCreationRequest, UserLinkingRequest

from .customer_models import Customer
from .forms import CustomerCreationForm, CustomerForm, CustomerUserAssignmentForm

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("security")


def _handle_secure_error(request: HttpRequest, error: Exception, operation: str, user_id: int | None = None) -> None:
    """🔒 Handle errors securely without leaking sensitive information"""
    # Use logger from re-export module so patches work correctly
    from . import views as views_module  # noqa: PLC0415
    logger = views_module.security_logger
    
    def _safe_add_message(request: HttpRequest, message: str) -> None:
        """Safely add a message, handling cases where MessageMiddleware is not installed"""
        with suppress(MessageFailure):
            messages.error(request, message)
    
    if isinstance(error, ValidationError):
        _safe_add_message(request, _("❌ Please check your input: Invalid data provided"))
        logger.warning(
            f"⚡ [CustomerSecurity] Validation error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "validation"},
        )
    elif isinstance(error, IntegrityError):
        _safe_add_message(request, _("❌ This operation conflicts with existing data"))
        logger.error(
            f"⚡ [CustomerSecurity] Integrity error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "integrity"},
        )
    elif isinstance(error, PermissionDenied):
        _safe_add_message(request, _("❌ You don't have permission to perform this action"))
        logger.warning(
            f"⚡ [CustomerSecurity] Permission denied during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "permission"},
        )
    else:
        # Unexpected errors - completely generic message
        _safe_add_message(request, _("❌ Operation failed. Please contact support if this continues"))
        logger.exception(
            f"⚡ [CustomerSecurity] Unexpected error during {operation}",
            extra={"user_id": user_id, "operation": operation, "error_type": "unexpected"},
        )


@login_required
def customer_list(request: HttpRequest) -> HttpResponse:
    """
    👥 Display list of customers with search functionality
    Uses simplified Customer model with related data loaded efficiently
    """
    # Get user's accessible customers (multi-tenant)
    user = cast(User, request.user)  # Safe due to @login_required
    accessible_customers_list = user.get_accessible_customers()

    # Convert to QuerySet for database operations
    if isinstance(accessible_customers_list, QuerySet):
        customers = accessible_customers_list
    elif accessible_customers_list:
        customer_ids = [c.id for c in accessible_customers_list]
        customers = Customer.objects.filter(id__in=customer_ids)
    else:
        customers = Customer.objects.none()

    # Search functionality - updated for new model structure
    search_query = request.GET.get("search", "")
    if search_query:
        customers = customers.filter(
            Q(company_name__icontains=search_query)
            | Q(name__icontains=search_query)
            | Q(primary_email__icontains=search_query)
            | Q(tax_profile__cui__icontains=search_query)  # Search in related tax profile
        ).distinct()

    # Expected queries: 3 (customers + tax profiles + addresses for display)
    customers = (
        customers.select_related("tax_profile", "billing_profile").prefetch_related("addresses").order_by("-created_at")
    )

    # Pagination
    paginator = Paginator(customers, 25)
    page_number = request.GET.get("page")
    customers_page = paginator.get_page(page_number)

    context = {
        "customers": customers_page,
        "search_query": search_query,
        "total_customers": customers.count(),
    }

    return render(request, "customers/list.html", context)


@login_required
def customer_detail(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🔍 Customer detail view with all related information
    Shows normalized data from separate profile models
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @login_required
    accessible_customers = user.get_accessible_customers()
    if isinstance(accessible_customers, QuerySet):
        accessible_qs: QuerySet[Customer] = accessible_customers
    elif accessible_customers:
        accessible_qs = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        accessible_qs = Customer.objects.none()
    
    # Expected queries: 4 (customer + tax + billing + addresses)
    customer = get_object_or_404(
        accessible_qs.select_related("tax_profile", "billing_profile")
        .prefetch_related("addresses", "notes"), 
        id=customer_id
    )

    # Get recent notes
    recent_notes = customer.notes.order_by("-created_at")[:5]

    context = {
        "customer": customer,
        "tax_profile": customer.get_tax_profile(),
        "billing_profile": customer.get_billing_profile(),
        "primary_address": customer.get_primary_address(),
        "billing_address": customer.get_billing_address(),
        "recent_notes": recent_notes,
    }

    return render(request, "customers/detail.html", context)


def _handle_user_creation_for_customer(request: HttpRequest, customer: Customer, form_data: dict, result: dict) -> None:
    """Handle user creation for a new customer."""
    created_by_user = cast(User, request.user)  # Safe in authenticated contexts
    user_creation_request = UserCreationRequest(
        customer=customer,
        first_name=form_data.get("first_name", ""),
        last_name=form_data.get("last_name", ""),
        send_welcome=result["send_welcome_email"],
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


def _handle_user_linking_for_customer(request: HttpRequest, customer: Customer, result: dict) -> None:
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

    except ValidationError as e:
        # Known validation issues - safe to show some details
        messages.error(request, _("❌ Please check your input: Invalid data provided"))
        logger.warning(f"Customer creation validation error for user {request.user.id}: {e}")

    except IntegrityError as e:
        # Database constraint violations - generic message
        messages.error(request, _("❌ This customer information conflicts with existing data"))
        logger.error(f"Customer creation integrity error for user {request.user.id}: {e}")

    except PermissionDenied as e:
        # Authorization issues
        messages.error(request, _("❌ You don't have permission to create customers"))
        logger.warning(f"Unauthorized customer creation attempt by user {request.user.id}: {e}")

    except Exception as e:
        # Unexpected errors - completely generic message
        messages.error(request, _("❌ Unable to create customer. Please contact support if this continues"))
        logger.exception(f"Unexpected error creating customer for user {request.user.id}: {e}")

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
    ✏️ Edit customer core information
    Separate views for tax/billing/address profiles
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_customers = user.get_accessible_customers()
    accessible_qs = (
        accessible_customers if isinstance(accessible_customers, QuerySet)
        else Customer.objects.filter(id__in=[c.id for c in accessible_customers]) if accessible_customers else Customer.objects.none()
    )
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        form = CustomerForm(request.POST, instance=customer)
        if form.is_valid():
            form.save()
            messages.success(
                request, _('✅ Customer "{customer_name}" updated').format(customer_name=customer.get_display_name())
            )
            return redirect("customers:detail", customer_id=customer.id)
        else:
            messages.error(request, _("❌ Please correct the errors below"))
    else:
        form = CustomerForm(instance=customer)

    context = {
        "form": form,
        "customer": customer,
        "action": _("Edit"),
    }

    return render(request, "customers/form.html", context)


@staff_required
def customer_delete(request: HttpRequest, customer_id: int) -> HttpResponse:
    """
    🗑️ Soft delete customer (preserves audit trail)
    """
    # 🔒 Security: Check access permissions BEFORE object retrieval to prevent enumeration
    user = cast(User, request.user)  # Safe due to @staff_required
    accessible_customers = user.get_accessible_customers()
    accessible_qs = (
        accessible_customers if isinstance(accessible_customers, QuerySet)
        else Customer.objects.filter(id__in=[c.id for c in accessible_customers]) if accessible_customers else Customer.objects.none()
    )
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
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
@ratelimit(key="user", rate="30/m", method="GET", block=False)  # type: ignore[misc]
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
    customers = user.get_accessible_customers()

    # Filter based on search query
    if hasattr(customers, "filter"):  # QuerySet
        customers = customers.filter(
            Q(name__icontains=query) | Q(company_name__icontains=query) | Q(primary_email__icontains=query)
        )[:10]
    else:  # List
        customers = [
            c
            for c in customers
            if query.lower() in c.name.lower()
            or query.lower() in c.company_name.lower()
            or query.lower() in c.primary_email.lower()
        ][:10]

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


def _handle_user_creation_action(request: HttpRequest, customer: Customer, assignment_data: dict) -> None:
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
        error_result = cast(Err, user_result)
        messages.error(request, _("❌ Failed to create user account: {error}").format(error=error_result.error))


def _show_user_creation_success_message(
    request: HttpRequest, customer: Customer, user: User, email_sent: bool
) -> None:
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


def _handle_user_linking_action(request: HttpRequest, customer: Customer, assignment_data: dict) -> None:
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
        error_result = cast(Err, link_result)
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

    except ValidationError as e:
        # Known validation issues - safe to show some details
        messages.error(request, _("❌ Please check your input: Invalid user assignment data"))
        logger.warning(f"User assignment validation error for customer {customer.id} by user {request.user.id}: {e}")

    except IntegrityError as e:
        # Database constraint violations - generic message
        messages.error(request, _("❌ This user assignment conflicts with existing data"))
        logger.error(f"User assignment integrity error for customer {customer.id} by user {request.user.id}: {e}")

    except PermissionDenied as e:
        # Authorization issues
        messages.error(request, _("❌ You don't have permission to assign users to this customer"))
        logger.warning(
            f"Unauthorized user assignment attempt for customer {customer.id} by user {request.user.id}: {e}"
        )

    except Exception as e:
        # Unexpected errors - completely generic message
        messages.error(request, _("❌ Unable to assign user. Please contact support if this continues"))
        logger.exception(f"Unexpected error assigning user to customer {customer.id} by user {request.user.id}: {e}")

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
    accessible_customers = user.get_accessible_customers()
    accessible_qs = (
        accessible_customers if isinstance(accessible_customers, QuerySet)
        else Customer.objects.filter(id__in=[c.id for c in accessible_customers]) if accessible_customers else Customer.objects.none()
    )
    customer = get_object_or_404(accessible_qs, id=customer_id)

    if request.method == "POST":
        return _handle_user_assignment_post(request, customer)

    return _render_assignment_form(request, None, customer)


@login_required
@ratelimit(key="user", rate="60/m", method="GET", block=False)  # type: ignore[misc]
def customer_services_api(request: HttpRequest, customer_id: int) -> JsonResponse:
    """
    🔗 API endpoint for customer services (for ticket form) with rate limiting
    Returns empty list for now - placeholder for future service management
    """
    # Check if rate limited
    if getattr(request, "limited", False):
        logger.warning(f"🚨 [Security] Rate limit exceeded for services API by user {request.user.id}")
        return JsonResponse({"error": "Too many requests. Please slow down."}, status=429)

    # Verify user has access to this customer
    user = cast(User, request.user)
    accessible_customers_list = user.get_accessible_customers()
    if isinstance(accessible_customers_list, QuerySet):
        customers_qs = accessible_customers_list
    elif accessible_customers_list:
        customer_ids = [c.id for c in accessible_customers_list]
        customers_qs = Customer.objects.filter(id__in=customer_ids)
    else:
        customers_qs = Customer.objects.none()

    if not customers_qs.filter(id=customer_id).exists():
        return JsonResponse({"error": "Access denied"}, status=403)

    # For now, return empty services list
    # TODO: Implement actual service management
    return JsonResponse([], safe=False)
