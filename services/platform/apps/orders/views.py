# ===============================================================================
# ORDERS VIEWS - ORDER MANAGEMENT & LIFECYCLE
# ===============================================================================

from __future__ import annotations

import json
import logging
import re
import uuid
from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, QuerySet
from django.forms import ModelForm, modelform_factory
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from apps.billing.models import Currency

# TODO: RefundService implementation pending
from apps.common.decorators import staff_required_strict
from apps.common.mixins import get_search_context
from apps.common.utils import json_error, json_success
from apps.customers.models import Customer
from apps.products.models import Product
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import User

from .models import Order, OrderItem
from .preflight import OrderPreflightValidationService
from .services import (
    OrderService,
    StatusChangeData,
)

logger = logging.getLogger(__name__)

# Constants for validation and limits
MAX_SEARCH_QUERY_LENGTH = 100
MAX_PRICE_OVERRIDE_CENTS = 100_000_000  # 1 million EUR in cents
MAX_PRICE_OVERRIDE_MULTIPLIER = 10

# ===============================================================================
# SECURITY VALIDATION FUNCTIONS
# ===============================================================================


def _sanitize_search_query(query: str) -> str:
    """🔒 Sanitize search query to prevent injection attacks"""
    if not query:
        return ""

    original_query = query
    original_length = len(query)

    # Check for dangerous patterns first
    dangerous_patterns = [
        r"[';\"\\]",  # Quotes and backslashes
        r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\b",  # SQL injection
        r"\{\$\w+:",  # NoSQL injection patterns like {$where:
        r"[{}$]",  # MongoDB-style injection chars
        r"<script",  # XSS patterns
        r"javascript:",  # Javascript injection
        r"alert\(",  # Alert calls
    ]

    # Check if query contains any dangerous patterns
    has_dangerous_pattern = False
    for pattern in dangerous_patterns:
        if re.search(pattern, query, flags=re.IGNORECASE):
            has_dangerous_pattern = True
            break

    if has_dangerous_pattern:
        logger.warning(
            f"🚨 [Orders] Search Security: Blocked search with suspicious characters: {original_query[:50]}..."
        )
        return ""

    # Remove dangerous patterns (defensive measure)
    query = re.sub(r"[';\"\\]", "", query)  # Remove quotes and backslashes
    query = re.sub(r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\b", "", query, flags=re.IGNORECASE)
    query = re.sub(r"\{\$\w+:", "", query)  # Remove NoSQL injection patterns like {$where:
    query = re.sub(r"[{}$]", "", query)  # Remove MongoDB-style injection chars

    # Limit length
    if len(query) > MAX_SEARCH_QUERY_LENGTH:
        logger.warning(
            f"⚠️ [Orders] Truncated overly long search query from {original_length} to {MAX_SEARCH_QUERY_LENGTH} characters"
        )
        query = query[:MAX_SEARCH_QUERY_LENGTH]

    return query.strip()


def _validate_manual_price_override(
    manual_price_cents: int, product_price_cents: int, user: User, context: str = ""
) -> tuple[bool, str]:
    """🔒 Validate manual price override for security"""
    if not hasattr(user, "is_staff") or not user.is_staff:
        logger.warning(
            f"⛔ [Orders] Price Security: Unauthorized price override attempt by user {getattr(user, 'id', 'Unknown')} ({getattr(user, 'email', 'Unknown')}) in context: {context}"
        )
        return False, "Insufficient permissions for price override"

    # Check for specific financial permissions (staff role required)
    if not (user.is_superuser or (hasattr(user, "staff_role") and user.staff_role in ["admin", "billing"])):
        logger.warning(
            f"⛔ [Orders] Price Security: Staff user {getattr(user, 'id', 'Unknown')} ({getattr(user, 'email', 'Unknown')}) lacks financial permissions for price override in context: {context}"
        )
        return False, "Insufficient permissions for price override"

    # Check minimum price
    if manual_price_cents < 1:
        logger.warning(
            f"⚠️ [Orders] Invalid price override attempt (too low): {manual_price_cents} by {user.email} in context: {context}"
        )
        return False, "Price must be at least 1 cents"

    # Check absolute maximum price limit
    if manual_price_cents > MAX_PRICE_OVERRIDE_CENTS:
        logger.warning(
            f"⚠️ [Orders] Blocked extremely high price override: {manual_price_cents} by {user.email} in context: {context}"
        )
        return False, f"Price cannot exceed {MAX_PRICE_OVERRIDE_CENTS} cents"

    # Check if override is within reasonable bounds (10x original)
    if manual_price_cents > product_price_cents * MAX_PRICE_OVERRIDE_MULTIPLIER:
        logger.warning(
            f"🚨 [Orders] Price Security: Excessive price override {manual_price_cents} (max {product_price_cents * 10}) by user {user.id} ({user.email}) in context: {context}"
        )
        return False, "Price override cannot exceed 10x original price"

    # Log successful validation
    logger.info(
        f"✅ [Orders] Price Override: {manual_price_cents} cents (original: {product_price_cents} cents) by user {user.id} ({user.email}) in context: {context}"
    )
    return True, ""


# ===============================================================================
# HELPER FUNCTIONS FOR ORDER ITEMS
# ===============================================================================


def _get_vat_rate_for_customer(customer: Customer) -> Decimal:
    """
    Calculate VAT rate for customer using centralized TaxService.
    DEPRECATED: Use OrderVATCalculator.calculate_vat() instead for full compliance.
    """
    try:
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        tax_profile = customer.get_tax_profile()

        # Determine customer country
        country_code = "RO"  # Default to Romania
        if tax_profile and tax_profile.cui and tax_profile.cui.startswith("RO"):
            country_code = "RO"

        # Get VAT rate as decimal (0.21 for 21%)
        vat_rate = TaxService.get_vat_rate(country_code, as_decimal=True)

        logger.info(f"💰 [Orders] VAT rate for customer {customer.id}: {vat_rate} ({country_code})")
        return vat_rate

    except Exception as e:
        logger.warning(f"⚠️ [Orders] Could not determine VAT rate for customer {customer.id}: {e}")
        # Fall back to centralized Romanian VAT rate
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        return TaxService.get_vat_rate("RO", as_decimal=True)


def _get_accessible_customer_ids(user: User) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()

    if isinstance(accessible_customers, QuerySet):
        return list(accessible_customers.values_list("id", flat=True))
    else:
        return [c.id for c in accessible_customers] if accessible_customers else []


def _validate_order_access(request: HttpRequest, order: Order) -> HttpResponse | None:
    """
    Validate user access to order.
    Returns redirect response if access denied, None if access granted.
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        messages.error(request, _("❌ You do not have permission to access this order."))
        return redirect("orders:order_list")
    return None


@login_required
def order_list(request: HttpRequest) -> HttpResponse:
    """
    🛒 Display paginated list of orders with filtering and search
    Multi-tenant: Users only see orders for their accessible customers
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    # Get accessible customers
    customer_ids = _get_accessible_customer_ids(request.user)

    # Get search context for template and sanitize query
    search_context = get_search_context(request, "search")
    search_query = _sanitize_search_query(search_context["search_query"]) if search_context.get("search_query") else ""
    # Keep sanitized value in context for template rendering
    search_context["search_query"] = search_query

    # Build base queryset
    queryset = Order.objects.filter(customer_id__in=customer_ids).select_related("customer").prefetch_related("items")

    # Apply filters
    status_filter = request.GET.get("status", "")
    if status_filter:
        queryset = queryset.filter(status=status_filter)

    # Apply search
    if search_query:
        queryset = queryset.filter(
            Q(order_number__icontains=search_query)
            | Q(customer_company__icontains=search_query)
            | Q(customer__company_name__icontains=search_query)
        )

    # Order by newest first
    queryset = queryset.order_by("-created_at")

    # Pagination (15 orders per page)
    paginator = Paginator(queryset, 15)
    page_number = request.GET.get("page")
    orders = paginator.get_page(page_number)

    # Get status counts for filter badges
    status_counts = {
        "total": Order.objects.filter(customer_id__in=customer_ids).count(),
        "draft": Order.objects.filter(customer_id__in=customer_ids, status="draft").count(),
        "pending": Order.objects.filter(customer_id__in=customer_ids, status="pending").count(),
        "processing": Order.objects.filter(customer_id__in=customer_ids, status="processing").count(),
        "completed": Order.objects.filter(customer_id__in=customer_ids, status="completed").count(),
    }

    context = {
        "orders": orders,
        "status_counts": status_counts,
        "current_status": status_filter,
        # Only superusers or users with a staff_role are considered staff for UI permissions
        "is_staff": getattr(request.user, "is_superuser", False) or bool(getattr(request.user, "staff_role", "")),
        **search_context,
    }

    return render(request, "orders/order_list.html", context)


@login_required
def order_list_htmx(request: HttpRequest) -> HttpResponse:
    """
    🚀 HTMX endpoint for orders list with dynamic loading
    Returns only the results partial for smooth pagination and filtering
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    # Get accessible customers
    customer_ids = _get_accessible_customer_ids(request.user)

    # Get search context and sanitize query
    search_context = get_search_context(request, "search")
    search_query = _sanitize_search_query(search_context["search_query"]) if search_context.get("search_query") else ""
    search_context["search_query"] = search_query

    # Build base queryset
    queryset = Order.objects.filter(customer_id__in=customer_ids).select_related("customer").prefetch_related("items")

    # Apply filters
    status_filter = request.GET.get("status", "")
    if status_filter:
        queryset = queryset.filter(status=status_filter)

    # Apply search
    if search_query:
        queryset = queryset.filter(
            Q(order_number__icontains=search_query)
            | Q(customer_company__icontains=search_query)
            | Q(customer__company_name__icontains=search_query)
        )

    # Order by newest first
    queryset = queryset.order_by("-created_at")

    # Pagination (15 orders per page)
    paginator = Paginator(queryset, 15)
    page_number = request.GET.get("page")
    orders = paginator.get_page(page_number)

    # Build extra_params for pagination
    extra_params_dict = {k: v for k, v in request.GET.items() if k != "page"}
    extra_params = "&".join([f"{k}={v}" for k, v in extra_params_dict.items()])
    if extra_params:
        extra_params = "&" + extra_params

    context = {
        "orders": orders,
        "page_obj": orders,
        "extra_params": extra_params,
        "current_status": status_filter,
        "is_staff": getattr(request.user, "is_superuser", False) or bool(getattr(request.user, "staff_role", "")),
    }

    return render(request, "orders/partials/order_list.html", context)


@login_required
def order_detail(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    🔍 Display detailed order view with items and status history
    Multi-tenant: Only accessible if user has access to the order's customer
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    order = get_object_or_404(
        Order.objects.select_related("customer").prefetch_related(
            "items__product", "items__service", "status_history__changed_by"
        ),
        id=pk,
    )

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Basic staff access for viewing and general management (UI-level)
    is_staff = getattr(request.user, "is_superuser", False) or bool(getattr(request.user, "staff_role", ""))
    editable_fields = order.get_editable_fields()

    # Determine if order can be edited based on status and user permissions
    can_edit = (
        is_staff
        and len(editable_fields) > 0
        and order.status not in ["completed", "cancelled", "refunded"]  # Terminal states
    )

    # Preflight validation (only for draft orders)
    preflight_errors: list[str] = []
    preflight_warnings: list[str] = []
    preflight_ok = True
    if order.status == "draft":
        try:
            preflight_errors, preflight_warnings = OrderPreflightValidationService.validate(order)
            preflight_ok = len(preflight_errors) == 0
        except Exception as e:
            logger.warning(f"⚠️ [Orders] Preflight computation failed for {order.order_number}: {e}")
            preflight_ok = False

    context = {
        "order": order,
        "is_staff": is_staff,
        "can_edit": can_edit,
        "editable_fields": editable_fields,
        "can_edit_all": editable_fields == ["*"],
        # Preflight
        "preflight_ok": preflight_ok,
        "preflight_errors": preflight_errors,
        "preflight_warnings": preflight_warnings,
    }

    return render(request, "orders/order_detail.html", context)


@staff_required_strict
def order_validate(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    🧪 Run preflight validation for an order (HTMX/partial)
    Returns a partial with errors/warnings and a JS hint to enable UI.
    """
    order = get_object_or_404(Order, id=pk)

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    errors: list[str] = []
    warnings: list[str] = []
    ok = False
    try:
        errors, warnings = OrderPreflightValidationService.validate(order)
        ok = len(errors) == 0
    except Exception as e:
        logger.error(f"🔥 [Orders] Preflight validation error for {order.order_number}: {e}")
        errors = ["Validation failed to run"]
        ok = False

    context = {
        "order": order,
        "preflight_ok": ok,
        "preflight_errors": errors,
        "preflight_warnings": warnings,
    }

    return render(request, "orders/partials/preflight_results.html", context)


@staff_required_strict
def order_create(request: HttpRequest) -> HttpResponse:
    """
    ✨ Create new order (staff only) with Romanian business compliance
    """
    # Dynamic form creation for Order
    order_form = modelform_factory(Order, fields=["customer", "currency", "payment_method", "notes", "customer_notes"])

    if request.method == "POST":
        form = order_form(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Create order from form data
                    order = form.save(commit=False)

                    # Set customer information snapshot
                    customer = order.customer
                    tax_profile = customer.get_tax_profile()
                    billing_address = customer.get_billing_address()

                    order.customer_email = customer.primary_email
                    order.customer_name = customer.get_display_name()
                    order.customer_company = customer.company_name
                    order.customer_vat_id = tax_profile.cui if tax_profile else ""

                    # Set billing address snapshot from customer
                    if billing_address:
                        order.billing_address = {
                            "company_name": customer.company_name,
                            "line1": billing_address.address_line1,
                            "line2": billing_address.address_line2,
                            "city": billing_address.city,
                            "county": billing_address.county,
                            "postal_code": billing_address.postal_code,
                            "country": billing_address.country,
                            "vat_id": tax_profile.cui if tax_profile else "",
                            "contact_person": customer.get_display_name(),
                            "contact_email": customer.primary_email,
                            "contact_phone": customer.primary_phone,
                        }
                    else:
                        # Fallback when no billing address exists
                        order.billing_address = {
                            "company_name": customer.company_name,
                            "line1": "",
                            "line2": "",
                            "city": "",
                            "county": "",
                            "postal_code": "",
                            "country": "România",  # Default to Romania
                            "vat_id": tax_profile.cui if tax_profile else "",
                            "contact_person": customer.get_display_name(),
                            "contact_email": customer.primary_email,
                            "contact_phone": customer.primary_phone,
                        }

                    # Initial totals (will be calculated when items are added)
                    order.subtotal_cents = 0
                    order.tax_cents = 0
                    order.total_cents = 0

                    order.save()

                    logger.info(f"✅ [Orders] Created order: {order.order_number} for customer {customer.company_name}")
                    messages.success(
                        request, _(f"✅ Order '{order.order_number}' created successfully. You can now add products.")
                    )
                    return redirect("orders:order_detail", pk=order.id)

            except Exception as e:
                logger.error(f"🔥 [Orders] Error creating order: {e}")
                messages.error(request, _("❌ Error creating order. Please try again."))
        else:
            # Form validation failed - add error message but preserve form data
            messages.error(request, _("❌ Please correct the errors below. All required fields must be filled in."))
    else:
        form = order_form()

    # Get customers and products for selection
    customers = Customer.objects.filter(status="active").order_by("company_name")
    currencies = Currency.objects.all().order_by("code")
    products = Product.objects.filter(is_active=True).order_by("name")

    # Convert to component format for dropdowns
    customer_options = []
    for customer in customers:
        tax_profile = customer.get_tax_profile()
        vat_display = tax_profile.cui if tax_profile else "No CUI"
        customer_options.append({"value": customer.id, "label": f"{customer.get_display_name()} ({vat_display})"})

    currency_options = [
        {"value": currency.code, "label": f"{currency.code} - {currency.symbol}"} for currency in currencies
    ]

    payment_method_choices = Order._meta.get_field("payment_method").choices
    payment_method_options = [
        {"value": choice[0], "label": str(choice[1])} for choice in (payment_method_choices or [])
    ]

    context = {
        "form": form,
        "action": "create",
        "customers": customers,
        "currencies": currencies,
        "products": products,
        "customer_options": customer_options,
        "currency_options": currency_options,
        "payment_method_options": payment_method_options,
        "is_staff_user": True,
    }

    return render(request, "orders/order_form.html", context)


@staff_required_strict
@require_POST
def order_create_preview(request: HttpRequest) -> HttpResponse:
    """
    🧮 HTMX endpoint: Preview first item + VAT totals during order creation (staff UI)
    No persistence. Uses OrderVATCalculator for authoritative VAT rules.
    """
    try:
        customer_id = request.POST.get("customer")
        currency_code = request.POST.get("currency", "RON")
        product_id = request.POST.get("first_product")
        billing_period = request.POST.get("first_billing_period", "monthly")
        quantity = int(request.POST.get("first_quantity", 1) or 1)
        (request.POST.get("first_domain_name") or "").strip()

        if not (customer_id and product_id):
            return render(
                request,
                "orders/partials/create_preview_totals.html",
                {
                    "error": True,
                    "message": "Select a customer and product to preview totals",
                },
            )

        customer = get_object_or_404(Customer, id=customer_id)
        product = get_object_or_404(Product, id=product_id)

        # Resolve price for selected period + currency
        price = product.get_price_for_period(currency_code, billing_period)
        if price is None:
            return render(
                request,
                "orders/partials/create_preview_totals.html",
                {
                    "error": True,
                    "message": f"No price for {currency_code} / {billing_period}",
                },
            )

        unit_cents = int(price.effective_price_cents)
        setup_cents = int(price.setup_cents)
        subtotal_cents = (unit_cents * quantity) + setup_cents

        # VAT calc per rules
        from .vat_rules import CustomerVATInfo, OrderVATCalculator  # noqa: PLC0415

        billing = customer.get_billing_address()
        tax_profile = customer.get_tax_profile()
        country = (billing.country if billing and billing.country else "RO").upper()
        vat_number = getattr(tax_profile, "vat_number", None) or getattr(tax_profile, "cui", None)
        is_business = bool(getattr(customer, "company_name", ""))

        customer_vat_info: CustomerVATInfo = {
            "country": country,
            "is_business": is_business,
            "vat_number": vat_number,
            "customer_id": str(customer.id),
            "order_id": None,
        }
        vat_result = OrderVATCalculator.calculate_vat(subtotal_cents=subtotal_cents, customer_info=customer_vat_info)

        context = {
            "error": False,
            "currency": currency_code,
            "quantity": quantity,
            "product": product,
            "billing_period": billing_period,
            "unit_cents": unit_cents,
            "setup_cents": setup_cents,
            "subtotal_cents": subtotal_cents,
            "vat_cents": int(vat_result.vat_cents),
            "total_cents": int(vat_result.total_cents),
            "vat_reasoning": vat_result.reasoning,
        }
        return render(request, "orders/partials/create_preview_totals.html", context)

    except Exception as e:
        logger.error(f"🔥 [Orders] Preview error: {e}")
        return render(
            request,
            "orders/partials/create_preview_totals.html",
            {
                "error": True,
                "message": "Failed to calculate preview",
            },
        )


@staff_required_strict
@require_POST
def order_create_with_item(request: HttpRequest) -> HttpResponse:
    """
    ✨ Create order and first item in one transaction (staff UI).
    Uses server-side price resolution and VAT rules.
    """
    # Base order form
    order_form = modelform_factory(Order, fields=["customer", "currency", "payment_method", "notes", "customer_notes"])
    form = order_form(request.POST)
    if not form.is_valid():
        messages.error(request, _("❌ Please correct the errors below."))
        return redirect("orders:order_create")

    try:
        with transaction.atomic():
            # Create order (reuse logic from order_create)
            order = form.save(commit=False)
            customer = order.customer
            tax_profile = customer.get_tax_profile()
            billing_address = customer.get_billing_address()

            order.customer_email = customer.primary_email
            order.customer_name = customer.get_display_name()
            order.customer_company = customer.company_name
            order.customer_vat_id = tax_profile.cui if tax_profile else ""

            if billing_address:
                order.billing_address = {
                    "company_name": customer.company_name,
                    "line1": billing_address.address_line1,
                    "line2": billing_address.address_line2,
                    "city": billing_address.city,
                    "county": billing_address.county,
                    "postal_code": billing_address.postal_code,
                    "country": billing_address.country,
                    "vat_id": tax_profile.cui if tax_profile else "",
                    "contact_person": customer.get_display_name(),
                    "contact_email": customer.primary_email,
                    "contact_phone": customer.primary_phone,
                }
            else:
                order.billing_address = {
                    "company_name": customer.company_name,
                    "line1": "",
                    "line2": "",
                    "city": "",
                    "county": "",
                    "postal_code": "",
                    "country": "România",
                    "vat_id": tax_profile.cui if tax_profile else "",
                    "contact_person": customer.get_display_name(),
                    "contact_email": customer.primary_email,
                    "contact_phone": customer.primary_phone,
                }

            order.subtotal_cents = 0
            order.tax_cents = 0
            order.total_cents = 0
            order.save()

            # First item fields
            product_id = request.POST.get("first_product")
            billing_period = request.POST.get("first_billing_period", "monthly")
            quantity = int(request.POST.get("first_quantity", 1) or 1)
            domain_name = (request.POST.get("first_domain_name") or "").strip()

            if product_id:
                product = get_object_or_404(Product, id=product_id)
                price = product.get_price_for_period(order.currency.code, billing_period)
                if not price:
                    raise ValueError(f"No price for {order.currency.code} / {billing_period}")

                # Build item
                from .models import OrderItem  # noqa: PLC0415

                item = OrderItem(
                    order=order,
                    product=product,
                    product_name=product.name,
                    product_type=product.product_type,
                    billing_period=billing_period,
                    quantity=quantity,
                    unit_price_cents=int(price.effective_price_cents),
                    setup_cents=int(price.setup_cents),
                    config={"product_price_id": str(price.id)},
                    domain_name=domain_name,
                )
                # Save triggers total calc in model; but recalc order totals afterward too
                item.save()
                order.calculate_totals()

            messages.success(
                request,
                _(f"✅ Order '{order.order_number}' created successfully. You can now add products."),
            )
            return redirect("orders:order_detail", pk=order.id)

    except Exception as e:
        logger.error(f"🔥 [Orders] Error creating order with item: {e}")
        messages.error(request, _("❌ Error creating order with first item. Please try again."))
        return redirect("orders:order_create")


@staff_required_strict
def order_edit(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    ✏️ Edit existing order (staff only, limited to draft/pending orders)
    """
    order = get_object_or_404(Order, id=pk)

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Check if order has any editable fields
    editable_fields = order.get_editable_fields()
    if not editable_fields:
        messages.error(request, _("❌ This order cannot be edited in its current status."))
        return redirect("orders:order_detail", pk=pk)

    if request.method == "POST":
        # TODO: Implement order editing form processing
        messages.info(request, _("Order editing form processing will be implemented next."))
        return redirect("orders:order_detail", pk=pk)

    context = {
        "order": order,
        "editable_fields": editable_fields,
        "can_edit_all": editable_fields == ["*"],
    }

    return render(request, "orders/order_form.html", context)


@staff_required_strict
@require_POST
def order_change_status(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """
    🔄 Change order status (AJAX endpoint)
    """
    order = get_object_or_404(Order, id=pk)

    # Validate access
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        return json_error("Access denied")

    new_status = request.POST.get("status", "")
    notes = request.POST.get("notes", "")

    if not new_status:
        return json_error("Status is required")

    # Use service to change status
    status_data = StatusChangeData(new_status=new_status, notes=notes, changed_by=request.user)

    result = OrderService.update_order_status(order, status_data)

    if result.is_ok():
        return JsonResponse(
            {
                "success": True,
                "message": f"Order status changed to {new_status}",
                "new_status": new_status,
                "status_display": order.get_status_display(),
            }
        )
    # Handle error case - use hasattr to check for error attribute
    elif hasattr(result, "error"):
        return json_error(result.error)
    else:
        return json_error("Unknown error occurred")


@staff_required_strict
@require_POST
def order_cancel(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    ❌ Cancel an order
    """
    order = get_object_or_404(Order, id=pk)

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Check if order can be cancelled
    if order.status in ["completed", "cancelled"]:
        messages.error(request, _("❌ This order cannot be cancelled."))
        return redirect("orders:order_detail", pk=pk)

    notes = request.POST.get("cancellation_reason", "Order cancelled by staff")

    # Type guard: request.user is always User due to @staff_required_strict decorator
    user = request.user if request.user.is_authenticated else None

    status_data = StatusChangeData(new_status="cancelled", notes=notes, changed_by=user)

    result = OrderService.update_order_status(order, status_data)

    if result.is_ok():
        messages.success(request, _("✅ Order has been cancelled."))
    # Handle error case - use hasattr to check for error attribute
    elif hasattr(result, "error"):
        messages.error(request, f"❌ Failed to cancel order: {result.error}")
    else:
        messages.error(request, "❌ Unknown error occurred while cancelling order")

    return redirect("orders:order_detail", pk=pk)


# TODO: RefundService implementation pending - temporarily comment out refund functionality
@staff_required_strict
@require_POST
def order_refund(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """
    💰 Refund an order (bidirectional with invoice refunds) - TEMPORARILY DISABLED
    """
    return json_error("Refund functionality temporarily disabled - RefundService implementation pending")


@login_required
@require_POST
def order_refund_request(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """
    🎫 Create a refund request ticket for an order (customer-facing)
    """

    order = get_object_or_404(Order, id=pk)

    # Validate access - user must be able to access this order's customer
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        return json_error("You do not have permission to request refunds for this order")

    # Only allow refund requests for completed or partially refunded orders
    if order.status not in ["completed", "partially_refunded"]:
        return json_error("Refund requests are only allowed for completed orders")

    try:
        refund_reason = request.POST.get("refund_reason", "").strip()
        refund_notes = request.POST.get("refund_notes", "").strip()

        if not refund_reason or not refund_notes:
            return json_error("All fields are required")

        # Map refund reason to user-friendly title
        reason_titles = {
            "customer_request": "General Customer Request",
            "service_failure": "Service Not Working",
            "quality_issue": "Quality Not As Expected",
            "technical_issue": "Technical Problems",
            "cancellation_request": "Want to Cancel Service",
            "duplicate_order": "Duplicate Order",
            "billing_error": "Billing Error",
            "policy_violation": "Service Policy Issue",
            "unsatisfied_service": "Not Satisfied with Service",
            "other": "Other Reason",
        }

        reason_title = reason_titles.get(refund_reason, "Refund Request")

        # Get or create billing category
        billing_category, _ = SupportCategory.objects.get_or_create(
            name="Billing",
            defaults={
                "name_en": "Billing",
                "description": "Billing and refund related issues",
                "icon": "credit-card",
                "color": "#10B981",
                "sla_response_hours": 24,
                "sla_resolution_hours": 48,
            },
        )

        # Create ticket
        ticket = Ticket.objects.create(
            title=f"Refund Request for Order {order.order_number}",
            description=f"""
REFUND REQUEST DETAILS
======================

Order Number: {order.order_number}
Order Total: {order.total_cents / 100:.2f} {order.currency}
Order Status: {order.get_status_display()}
Created Date: {order.created_at.strftime("%Y-%m-%d %H:%M")}

Refund Reason: {reason_title}

Customer Details:
{refund_notes}

---
This ticket was automatically created from a customer refund request.
            """.strip(),
            customer=order.customer,
            contact_person=request.user.get_full_name() or request.user.email,
            contact_email=request.user.email,
            contact_phone=getattr(request.user, "phone", ""),
            category=billing_category,
            priority="normal",
            status="new",
            source="web",
            created_by=request.user,
            # Link to order
            content_type=ContentType.objects.get_for_model(Order),
            object_id=str(order.id),
        )

        logger.info(
            f"🎫 Refund request ticket #{ticket.ticket_number} created for order {order.order_number} by user {request.user.email}"
        )

        return json_success(
            {
                "message": "Refund request submitted successfully",
                "ticket_number": ticket.ticket_number,
                "order_number": order.order_number,
            }
        )

    except Exception as e:
        logger.exception(f"Failed to create refund request ticket: {e}")
        return json_error("An unexpected error occurred while submitting your refund request")


# ===============================================================================
# PLACEHOLDER VIEWS - TO BE IMPLEMENTED
# ===============================================================================


@staff_required_strict
def order_pdf(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📄 Generate order PDF (to be implemented)"""
    messages.info(request, _("PDF generation will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required_strict
def order_send(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📧 Send order by email (to be implemented)"""
    messages.info(request, _("Email sending will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required_strict
def order_provision(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """⚙️ Provision order services (to be implemented)"""
    messages.info(request, _("Service provisioning will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required_strict
def order_items_list(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    📋 HTMX-powered order items list with real-time updates
    Returns order items partial for dynamic loading and manipulation
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    order = get_object_or_404(
        Order.objects.select_related("customer", "currency").prefetch_related("items__product", "items__service"), id=pk
    )

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Get order items with related data
    items = order.items.select_related("product").order_by("created_at")

    # Calculate totals for display
    order.calculate_totals()

    # Basic staff access for viewing and general management
    is_staff = request.user.is_staff or bool(getattr(request.user, "staff_role", ""))
    editable_fields = order.get_editable_fields()

    # Use consistent can_edit logic with order_detail view
    can_edit = (
        is_staff
        and len(editable_fields) > 0
        and order.status not in ["completed", "cancelled", "refunded"]  # Terminal states
    )

    context = {
        "order": order,
        "items": items,
        "can_edit": can_edit,
        "is_staff": is_staff,
    }

    # Return partial template for HTMX requests
    template = "orders/partials/order_items_list.html"
    return render(request, template, context)


def _process_order_item_creation(
    form: ModelForm[Any], order: Order, pk: uuid.UUID, request: HttpRequest
) -> HttpResponse:
    """Process the creation of a new order item with proper price override logic"""
    try:
        with transaction.atomic():
            # Create order item
            item = form.save(commit=False)
            item.order = order

            # Get product and pricing information
            product = item.product

            # INDUSTRY STANDARD PRICING LOGIC:
            # 1. Use manual override prices if provided
            # 2. Fall back to product default prices
            # 3. Error only if both are missing

            # Check if user provided manual pricing (form data takes precedence)
            manual_unit_price = item.unit_price_cents
            manual_setup_price = item.setup_cents

            # Get product default pricing for this billing period
            product_price = product.get_price_for_period(order.currency.code, item.billing_period)

            # Apply pricing hierarchy: Manual Override > Product Default > Error
            if manual_unit_price and manual_unit_price > 0:
                # User provided manual unit price - use it (OVERRIDE)
                item.unit_price_cents = manual_unit_price
                logger.info(f"💰 [Orders] Using manual override unit price: {manual_unit_price} cents")
            elif product_price:
                # No manual price - use product default
                item.unit_price_cents = product_price.amount_cents
                logger.info(f"💰 [Orders] Using product default unit price: {product_price.amount_cents} cents")
            else:
                # Neither manual nor product price available
                return json_error(
                    f"No pricing available for {product.name} in {order.currency.code}. Please enter a manual price."
                )

            # Same logic for setup fee
            if manual_setup_price is not None and manual_setup_price >= 0:
                # User provided manual setup fee (including 0) - use it
                item.setup_cents = manual_setup_price
                logger.info(f"🛠️ [Orders] Using manual override setup fee: {manual_setup_price} cents")
            elif product_price:
                # No manual setup fee - use product default
                item.setup_cents = product_price.setup_cents
                logger.info(f"🛠️ [Orders] Using product default setup fee: {product_price.setup_cents} cents")
            else:
                # No product price, default setup to 0
                item.setup_cents = 0

            # Calculate VAT for Romanian customers
            tax_rate = _get_vat_rate_for_customer(order.customer)
            item.tax_rate = tax_rate

            # Save the item (totals will be calculated in save method)
            item.save()

            # Recalculate order totals
            order.calculate_totals()

            logger.info(
                f"✅ [Orders] Added item {product.name} to order {order.order_number} with final pricing: {item.unit_price_cents}¢ + {item.setup_cents}¢ setup"
            )

            # Return updated items list for HTMX, redirect otherwise
            if request.headers.get("HX-Request"):
                return order_items_list(request, pk)
            return redirect("orders:order_detail", pk=order.id)

    except Exception as e:
        logger.error(f"🔥 [Orders] Error adding item to order {order.order_number}: {e}")
        return json_error("Failed to add item to order")


@staff_required_strict
def order_item_create(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    ✨ Add new order item with VAT calculation and Romanian compliance
    HTMX endpoint for dynamic item addition
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    order = get_object_or_404(Order, id=pk)

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Check if order can be edited
    if not (order.is_draft or order.status == "pending"):
        return json_error("Order cannot be modified in current status")

    # Dynamic form creation for OrderItem
    order_item_form = modelform_factory(
        OrderItem,
        fields=["product", "quantity", "unit_price_cents", "setup_cents", "config", "domain_name"],
    )

    if request.method == "POST":
        form = order_item_form(request.POST)
        if form.is_valid():
            return _process_order_item_creation(form, order, pk, request)

        # Form validation failed
        errors: list[str] = []
        for field, field_errors in form.errors.items():
            errors.extend(f"{field}: {error}" for error in field_errors)
        return json_error("Validation failed: " + "; ".join(errors))

    # GET request - show form
    return _render_order_item_form(request, order_item_form(), order, action="create")


def _render_order_item_form(
    request: HttpRequest, form: ModelForm[Any], order: Order, item: OrderItem | None = None, action: str = "create"
) -> HttpResponse:
    """Render the order item form with all necessary context"""
    # Get available products
    products = Product.objects.filter(is_active=True).order_by("name")

    # Convert billing period choices to component format
    billing_period_choices = [
        ("once", _("One Time")),
        ("monthly", _("Monthly")),
        ("quarterly", _("Quarterly")),
        ("semiannual", _("Semi-Annual")),
        ("annual", _("Annual")),
        ("biennial", _("Biennial")),
        ("triennial", _("Triennial")),
    ]

    billing_period_options = [{"value": choice[0], "label": str(choice[1])} for choice in billing_period_choices]

    # Create product options with pricing data for auto-population
    product_options = []
    for product in products:
        # Get all available prices for this product in the order's currency
        prices_data = {}
        for price in product.get_active_prices().filter(currency=order.currency):
            prices_data[price.billing_period] = {
                "unit_cents": price.amount_cents,
                "setup_cents": price.setup_cents,
                "amount_display": f"{order.currency.code} {price.amount}",
                "setup_display": f"{order.currency.code} {price.setup_fee}",
            }

        product_options.append(
            {
                "value": product.id,
                "label": f"{product.name} ({product.get_product_type_display()})",
                "data": {
                    "product_type": product.product_type,
                    "requires_domain": product.requires_domain,
                    "prices": json.dumps(prices_data),  # JSON-encoded pricing data for auto-population
                },
            }
        )

    context = {
        "form": form,
        "order": order,
        "item": item,
        "products": products,
        "product_options": product_options,
        "billing_period_options": billing_period_options,
        "action": action,
    }

    # Check if this is a request from expandable row (check for inline parameter or HX-Request header)
    is_inline_request = (
        request.headers.get("HX-Request")
        or request.GET.get("inline") == "true"
        or "expandable" in request.headers.get("HX-Trigger", "")
    )

    # Use inline template for expandable rows, full modal template otherwise
    template = "orders/partials/order_item_inline_form.html" if is_inline_request else "orders/order_item_form.html"

    return render(request, template, context)


def _handle_unit_price_update(
    updated_item: Any, form: ModelForm[Any], product_price: Any, product_changed: bool, billing_period_changed: bool
) -> HttpResponse | None:
    """Handle unit price update logic with validation"""
    manual_unit_price_changed = "unit_price_cents" in form.changed_data

    if manual_unit_price_changed:
        # Security check: Validate price override limits
        if product_price and updated_item.unit_price_cents > 0:
            base_price = product_price.monthly_price_cents
            if base_price > 0:  # Avoid division by zero
                price_ratio = updated_item.unit_price_cents / base_price
                if price_ratio > MAX_PRICE_OVERRIDE_MULTIPLIER:  # More than 10x the base price
                    return json_error(
                        f"Price override cannot exceed {MAX_PRICE_OVERRIDE_MULTIPLIER}x the base product price"
                    )

        # User explicitly changed unit price - use their value (MANUAL OVERRIDE)
        logger.info(f"💰 [Orders] Using manual override unit price: {updated_item.unit_price_cents} cents")
    elif product_changed or billing_period_changed:
        # Product or billing period changed - auto-update from product if available
        if product_price:
            updated_item.unit_price_cents = product_price.amount_cents
            logger.info(f"💰 [Orders] Auto-updated unit price from product: {product_price.amount_cents} cents")
        else:
            # No product pricing - keep existing price but warn
            logger.warning(
                f"⚠️ [Orders] No product pricing available for {updated_item.product.name}, keeping existing price: {updated_item.unit_price_cents} cents"
            )
    return None


def _handle_setup_fee_update(
    updated_item: Any, form: ModelForm[Any], product_price: Any, product_changed: bool, billing_period_changed: bool
) -> None:
    """Handle setup fee update logic"""
    manual_setup_changed = "setup_cents" in form.changed_data

    if manual_setup_changed:
        # User explicitly changed setup fee - use their value
        logger.info(f"🛠️ [Orders] Using manual override setup fee: {updated_item.setup_cents} cents")
    elif product_changed or billing_period_changed:
        # Product or billing period changed - auto-update from product if available
        if product_price:
            updated_item.setup_cents = product_price.setup_cents
            logger.info(f"🛠️ [Orders] Auto-updated setup fee from product: {product_price.setup_cents} cents")
        else:
            # No product pricing - keep existing setup fee
            logger.warning(
                f"⚠️ [Orders] No product pricing available for setup fee, keeping existing: {updated_item.setup_cents} cents"
            )


def _process_order_item_update(form: ModelForm[Any], order: Order, pk: uuid.UUID, request: HttpRequest) -> HttpResponse:
    """Process the update of an existing order item with proper price override logic"""
    try:
        with transaction.atomic():
            # Update order item
            updated_item = form.save(commit=False)

            # Get product and pricing information
            product = updated_item.product

            # Check what fields were changed
            product_changed = "product" in form.changed_data
            billing_period_changed = "billing_period" in form.changed_data

            # INDUSTRY STANDARD PRICING LOGIC FOR UPDATES:
            # 1. If user manually changed prices - use those (OVERRIDE)
            # 2. If product/billing period changed but prices not manually changed - auto-update from product
            # 3. If only other fields changed - keep existing prices
            # 4. Always respect manual price edits

            # Get product default pricing for reference
            product_price = product.get_price_for_period(order.currency.code, updated_item.billing_period)

            # Handle unit price logic using helper function
            price_error = _handle_unit_price_update(
                updated_item, form, product_price, product_changed, billing_period_changed
            )
            if price_error:
                return price_error

            # Handle setup fee logic using helper function
            _handle_setup_fee_update(updated_item, form, product_price, product_changed, billing_period_changed)

            # Recalculate VAT if customer-related or product changed
            if product_changed or billing_period_changed:
                tax_rate = _get_vat_rate_for_customer(order.customer)
                updated_item.tax_rate = tax_rate

            # Save the updated item (totals will be calculated in save method)
            updated_item.save()

            # Recalculate order totals
            order.calculate_totals()

            logger.info(
                f"✅ [Orders] Updated item {product.name} in order {order.order_number} with final pricing: {updated_item.unit_price_cents}¢ + {updated_item.setup_cents}¢ setup"
            )

            # Return updated items list for HTMX
            return order_items_list(request, pk)

    except Exception as e:
        logger.error(f"🔥 [Orders] Error updating item in order {order.order_number}: {e}")
        return json_error("Failed to update order item")


@staff_required_strict
def order_item_edit(request: HttpRequest, pk: uuid.UUID, item_pk: uuid.UUID) -> HttpResponse:
    """
    ✏️ Edit existing order item with inline editing capabilities
    HTMX endpoint for dynamic item updates
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    order = get_object_or_404(Order, id=pk)

    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied

    # Check if order can be edited
    if not (order.is_draft or order.status == "pending"):
        return json_error("Order cannot be modified in current status")

    item = get_object_or_404(OrderItem, id=item_pk, order=order)

    # Dynamic form creation for OrderItem
    order_item_form = modelform_factory(
        OrderItem,
        fields=["product", "quantity", "unit_price_cents", "setup_cents", "config", "domain_name"],
    )

    if request.method == "POST":
        form = order_item_form(request.POST, instance=item)
        if form.is_valid():
            return _process_order_item_update(form, order, pk, request)

        # Form validation failed
        errors: list[str] = []
        for field, field_errors in form.errors.items():
            errors.extend(f"{field}: {error}" for error in field_errors)
        return json_error("Validation failed: " + "; ".join(errors))

    # GET request - show form
    form = order_item_form(instance=item)
    return _render_order_item_form(request, form, order, item=item, action="edit")


@staff_required_strict
@require_POST
def order_item_delete(request: HttpRequest, pk: uuid.UUID, item_pk: uuid.UUID) -> JsonResponse:
    """
    🗑️ Delete order item with AJAX confirmation
    Returns success response for HTMX handling
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return json_error("Authentication required")

    order = get_object_or_404(Order, id=pk)

    # Validate access
    if not request.user.can_access_customer(order.customer):
        return json_error("Access denied")

    # Check if order can be edited
    if not (order.is_draft or order.status == "pending"):
        return json_error("Order cannot be modified in current status")

    try:
        item = get_object_or_404(OrderItem, id=item_pk, order=order)
        product_name = item.product_name

        with transaction.atomic():
            # Delete the item
            item.delete()

            # Recalculate order totals
            order.calculate_totals()

            logger.info(f"✅ [Orders] Deleted item {product_name} from order {order.order_number}")

            return json_success(
                {
                    "message": f"Item {product_name} removed from order",
                    "order_total": str(order.total),
                    "order_total_cents": order.total_cents,
                    "item_count": order.items.count(),
                }
            )

    except Exception as e:
        logger.error(f"🔥 [Orders] Error deleting item from order {order.order_number}: {e}")
        return json_error("Failed to delete order item")


@staff_required_strict
def order_duplicate(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📋 Duplicate order (to be implemented)"""
    messages.info(request, _("Order duplication will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required_strict
def order_to_invoice(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """🧾 Convert order to invoice (to be implemented)"""
    messages.info(request, _("Order to invoice conversion will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required_strict
def order_reports(request: HttpRequest) -> HttpResponse:
    """📊 Order reports and analytics (to be implemented)"""
    messages.info(request, _("Order reports will be implemented next."))
    return redirect("orders:order_list")


@staff_required_strict
def order_export(request: HttpRequest) -> HttpResponse:
    """📤 Export orders (to be implemented)"""
    messages.info(request, _("Order export will be implemented next."))
    return redirect("orders:order_list")


# ===============================================================================
# CART OPERATIONS - CUSTOMER SHOPPING CART 🛒
# ===============================================================================


@login_required
def cart_view(request: HttpRequest) -> HttpResponse:
    """
    🛒 Display customer shopping cart with items and totals
    Multi-tenant: Users only see their own cart items
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect("users:login")

    # Get or create current customer context
    try:
        customer = request.user.get_primary_customer()
        if not customer:
            messages.error(request, _("❌ No customer profile found. Please contact support."))
            return redirect("dashboard")
    except Exception as e:
        logger.error(f"🔥 [Cart] Error getting customer for user {request.user.id}: {e}")
        messages.error(request, _("❌ Error accessing cart. Please try again."))
        return redirect("dashboard")

    # Get current cart order (draft)
    cart_order = Order.objects.filter(customer=customer, status=Order.Status.DRAFT).first()

    context = {
        "cart_order": cart_order,
        "cart_items": cart_order.items.select_related("product") if cart_order else [],
        "customer": customer,
    }

    return render(request, "orders/cart/cart_view.html", context)


@login_required
def cart_calculate(request: HttpRequest) -> HttpResponse:
    """
    🧮 Calculate cart totals via HTMX
    Returns order summary HTML partial
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return HttpResponse("Authentication required", status=401)

    try:
        customer = request.user.get_primary_customer()
        if not customer:
            return HttpResponse("No customer profile", status=400)

        # Get current cart order
        cart_order = Order.objects.filter(customer=customer, status=Order.Status.DRAFT).first()

        if not cart_order:
            return HttpResponse("Empty cart", status=400)

        # Recalculate totals
        cart_order.calculate_totals()
        cart_order.save()

        # Return order summary partial
        context = {
            "cart_order": cart_order,
            "customer": customer,
        }

        return render(request, "orders/cart/cart_summary_partial.html", context)

    except Exception as e:
        logger.error(f"🔥 [Cart] Error calculating cart totals: {e}")
        return HttpResponse("Calculation error", status=500)


@login_required
def cart_update(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911
    """
    📝 Update cart item quantity via HTMX
    """
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=405)

    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return HttpResponse("Authentication required", status=401)

    try:
        customer = request.user.get_primary_customer()
        if not customer:
            return HttpResponse("No customer profile", status=400)

        item_id = request.POST.get("item_id")
        quantity = int(request.POST.get("quantity", 1))

        if not item_id or quantity < 1:
            return HttpResponse("Invalid parameters", status=400)

        # Get cart order and item
        cart_order = Order.objects.filter(customer=customer, status=Order.Status.DRAFT).first()

        if not cart_order:
            return HttpResponse("Cart not found", status=404)

        cart_item = get_object_or_404(OrderItem, id=item_id, order=cart_order)

        # Update quantity
        cart_item.quantity = quantity
        cart_item.save()

        # Recalculate totals
        cart_order.calculate_totals()
        cart_order.save()

        # Return updated cart partial
        context = {
            "cart_order": cart_order,
            "customer": customer,
        }
        return render(request, "orders/cart/cart_items_partial.html", context)

    except Exception as e:
        logger.error(f"🔥 [Cart] Error updating cart item: {e}")
        return HttpResponse("Update error", status=500)


@login_required
def cart_remove(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911
    """
    🗑️ Remove item from cart via HTMX
    """
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=405)

    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return HttpResponse("Authentication required", status=401)

    try:
        customer = request.user.get_primary_customer()
        if not customer:
            return HttpResponse("No customer profile", status=400)

        item_id = request.POST.get("item_id")
        if not item_id:
            return HttpResponse("Invalid parameters", status=400)

        # Get cart order and item
        cart_order = Order.objects.filter(customer=customer, status=Order.Status.DRAFT).first()

        if not cart_order:
            return HttpResponse("Cart not found", status=404)

        cart_item = get_object_or_404(OrderItem, id=item_id, order=cart_order)

        # Remove item
        cart_item.delete()

        # Recalculate totals
        cart_order.calculate_totals()
        cart_order.save()

        # Return updated cart partial
        context = {
            "cart_order": cart_order,
            "customer": customer,
        }
        return render(request, "orders/cart/cart_items_partial.html", context)

    except Exception as e:
        logger.error(f"🔥 [Cart] Error removing cart item: {e}")
        return HttpResponse("Remove error", status=500)
