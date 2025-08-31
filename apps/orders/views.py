# ===============================================================================
# ORDERS VIEWS - ORDER MANAGEMENT & LIFECYCLE
# ===============================================================================

from __future__ import annotations

import json
import logging
import uuid
from decimal import Decimal
from typing import TYPE_CHECKING

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
from apps.billing.services import RefundData, RefundReason, RefundService, RefundType
from apps.common.decorators import staff_required
from apps.common.mixins import get_search_context
from apps.common.utils import json_error, json_success
from apps.customers.models import Customer
from apps.products.models import Product
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import User

from .models import Order, OrderItem
from .services import (
    OrderService,
    StatusChangeData,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# HELPER FUNCTIONS FOR ORDER ITEMS
# ===============================================================================


def _get_vat_rate_for_customer(customer: Customer) -> Decimal:
    """
    Calculate VAT rate for customer based on Romanian tax rules.
    Romanian customers: 19% VAT
    EU customers with valid VAT ID: 0% (reverse charge)
    EU customers without VAT ID: 19%
    Non-EU customers: 0%
    """
    try:
        tax_profile = customer.get_tax_profile()

        # Romanian customers always pay 19% VAT
        if tax_profile and tax_profile.cui and tax_profile.cui.startswith("RO"):
            return Decimal("0.19")  # 19%

        # For now, default to 19% VAT for all customers with tax profile
        # TODO: Implement EU/non-EU logic based on customer address or VAT ID format
        if tax_profile and tax_profile.is_vat_payer:
            return Decimal("0.19")  # 19%

        # No tax profile or not VAT payer: 0%
        return Decimal("0.00")  # 0%

    except Exception as e:
        logger.warning(f"⚠️ [Orders] Could not determine VAT rate for customer {customer.id}: {e}")
        return Decimal("0.19")  # Default to 19% for safety


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

    # Get search context for template
    search_context = get_search_context(request, "search")
    search_query = search_context["search_query"]

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
        "is_staff": request.user.is_staff or bool(getattr(request.user, "staff_role", "")),
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

    # Get search context
    search_context = get_search_context(request, "search")
    search_query = search_context["search_query"]

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
        "is_staff": request.user.is_staff or bool(getattr(request.user, "staff_role", "")),
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

    is_staff = request.user.is_staff or bool(getattr(request.user, "staff_role", ""))
    editable_fields = order.get_editable_fields()

    # Determine if order can be edited based on status and user permissions
    can_edit = (
        is_staff
        and len(editable_fields) > 0
        and order.status not in ["completed", "cancelled", "refunded"]  # Terminal states
    )

    context = {
        "order": order,
        "is_staff": is_staff,
        "can_edit": can_edit,
        "editable_fields": editable_fields,
        "can_edit_all": editable_fields == ["*"],
    }

    return render(request, "orders/order_detail.html", context)


@staff_required
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


@staff_required
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


@staff_required
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


@staff_required
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

    # Type guard: request.user is always User due to @staff_required decorator
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


@staff_required
@require_POST
def order_refund(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:  # noqa: PLR0911
    """
    💰 Refund an order (bidirectional with invoice refunds)
    """

    order = get_object_or_404(Order, id=pk)

    # Validate access
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        return json_error("You do not have permission to refund this order")

    # Parse form data
    try:
        refund_type_str = request.POST.get("refund_type", "").strip()
        refund_reason_str = request.POST.get("refund_reason", "").strip()
        refund_notes = request.POST.get("refund_notes", "").strip()
        refund_amount_str = request.POST.get("refund_amount", "0").strip()
        process_payment = request.POST.get("process_payment_refund") == "true"

        if not refund_type_str or not refund_reason_str or not refund_notes:
            return json_error("All fields are required")

        # Parse refund type
        refund_type = RefundType.FULL if refund_type_str == "full" else RefundType.PARTIAL

        # Parse refund reason
        try:
            refund_reason = RefundReason(refund_reason_str)
        except ValueError:
            return json_error("Invalid refund reason")

        # Parse refund amount for partial refunds
        amount_cents = 0
        if refund_type == RefundType.PARTIAL:
            try:
                refund_amount = Decimal(refund_amount_str)
                if refund_amount <= 0:
                    return json_error("Refund amount must be greater than 0")
                amount_cents = int(refund_amount * 100)
            except (ValueError, TypeError):
                return json_error("Invalid refund amount")

        # Create refund data
        refund_data: RefundData = {
            "refund_type": refund_type,
            "amount_cents": amount_cents,
            "reason": refund_reason,
            "notes": refund_notes,
            "initiated_by": request.user,
            "external_refund_id": None,
            "process_payment_refund": process_payment,
        }

        # Process refund using RefundService
        result = RefundService.refund_order(order.id, refund_data)

        if result.is_ok():
            refund_result = result.unwrap()
            return json_success(
                {
                    "message": "Order refund processed successfully",
                    "refund_id": str(refund_result["refund_id"]) if refund_result.get("refund_id") else None,
                    "new_status": order.status,  # Will be updated by the service
                }
            )
        # Handle error case - use hasattr to check for error attribute
        elif hasattr(result, "error"):
            return json_error(result.error)
        else:
            return json_error("Unknown error occurred")

    except Exception as e:
        logger.exception(f"Failed to process order refund: {e}")
        return json_error("An unexpected error occurred while processing the refund")


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


@staff_required
def order_pdf(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📄 Generate order PDF (to be implemented)"""
    messages.info(request, _("PDF generation will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required
def order_send(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📧 Send order by email (to be implemented)"""
    messages.info(request, _("Email sending will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required
def order_provision(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """⚙️ Provision order services (to be implemented)"""
    messages.info(request, _("Service provisioning will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required
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


def _process_order_item_creation(form: ModelForm, order: Order, pk: uuid.UUID, request: HttpRequest) -> HttpResponse:
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

            # Return updated items list for HTMX
            return order_items_list(request, pk)

    except Exception as e:
        logger.error(f"🔥 [Orders] Error adding item to order {order.order_number}: {e}")
        return json_error("Failed to add item to order")


@staff_required
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
        fields=["product", "quantity", "unit_price_cents", "setup_cents", "billing_period", "config", "domain_name"],
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
    request: HttpRequest, form: ModelForm, order: Order, item: OrderItem = None, action: str = "create"
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


def _process_order_item_update(form: ModelForm, order: Order, pk: uuid.UUID, request: HttpRequest) -> HttpResponse:
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
            manual_unit_price_changed = "unit_price_cents" in form.changed_data
            manual_setup_changed = "setup_cents" in form.changed_data

            # INDUSTRY STANDARD PRICING LOGIC FOR UPDATES:
            # 1. If user manually changed prices - use those (OVERRIDE)
            # 2. If product/billing period changed but prices not manually changed - auto-update from product
            # 3. If only other fields changed - keep existing prices
            # 4. Always respect manual price edits

            # Get product default pricing for reference
            product_price = product.get_price_for_period(order.currency.code, updated_item.billing_period)

            # Handle unit price logic
            if manual_unit_price_changed:
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
                        f"⚠️ [Orders] No product pricing available for {product.name}, keeping existing price: {updated_item.unit_price_cents} cents"
                    )
            # If neither pricing fields nor product/billing changed, keep existing prices

            # Handle setup fee logic
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


@staff_required
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
        fields=["product", "quantity", "unit_price_cents", "setup_cents", "billing_period", "config", "domain_name"],
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


@staff_required
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


@staff_required
def order_duplicate(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📋 Duplicate order (to be implemented)"""
    messages.info(request, _("Order duplication will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required
def order_to_invoice(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """🧾 Convert order to invoice (to be implemented)"""
    messages.info(request, _("Order to invoice conversion will be implemented next."))
    return redirect("orders:order_detail", pk=pk)


@staff_required
def order_reports(request: HttpRequest) -> HttpResponse:
    """📊 Order reports and analytics (to be implemented)"""
    messages.info(request, _("Order reports will be implemented next."))
    return redirect("orders:order_list")


@staff_required
def order_export(request: HttpRequest) -> HttpResponse:
    """📤 Export orders (to be implemented)"""
    messages.info(request, _("Order export will be implemented next."))
    return redirect("orders:order_list")
