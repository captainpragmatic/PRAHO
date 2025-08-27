
# ===============================================================================
# ORDERS VIEWS - ORDER MANAGEMENT & LIFECYCLE
# ===============================================================================

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from apps.common.decorators import staff_required
from apps.common.mixins import get_search_context
from apps.common.utils import json_error, json_success
from apps.customers.models import Customer
from apps.users.models import User

from .models import Order

logger = logging.getLogger(__name__)
from .services import (
    OrderService,
    StatusChangeData,
)


def _get_accessible_customer_ids(user: User) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()
    
    if isinstance(accessible_customers, QuerySet):
        return list(accessible_customers.values_list('id', flat=True))
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
        return redirect('orders:order_list')
    return None


@login_required
def order_list(request: HttpRequest) -> HttpResponse:
    """
    🛒 Display paginated list of orders with filtering and search
    Multi-tenant: Users only see orders for their accessible customers
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
    
    # Get accessible customers
    customer_ids = _get_accessible_customer_ids(request.user)
    
    # Get search context for template
    search_context = get_search_context(request, 'search')
    search_query = search_context['search_query']
    
    # Build base queryset
    queryset = (
        Order.objects
        .filter(customer_id__in=customer_ids)
        .select_related('customer')
        .prefetch_related('items')
    )
    
    # Apply filters
    status_filter = request.GET.get('status', '')
    if status_filter:
        queryset = queryset.filter(status=status_filter)
    
    # Apply search
    if search_query:
        queryset = queryset.filter(
            Q(order_number__icontains=search_query) |
            Q(billing_company_name__icontains=search_query) |
            Q(customer__company_name__icontains=search_query)
        )
    
    # Order by newest first
    queryset = queryset.order_by('-created_at')
    
    # Pagination (15 orders per page)
    paginator = Paginator(queryset, 15)
    page_number = request.GET.get('page')
    orders = paginator.get_page(page_number)
    
    # Get status counts for filter badges
    status_counts = {
        'total': Order.objects.filter(customer_id__in=customer_ids).count(),
        'draft': Order.objects.filter(customer_id__in=customer_ids, status='draft').count(),
        'pending': Order.objects.filter(customer_id__in=customer_ids, status='pending').count(),
        'processing': Order.objects.filter(customer_id__in=customer_ids, status='processing').count(),
        'completed': Order.objects.filter(customer_id__in=customer_ids, status='completed').count(),
    }
    
    context = {
        'orders': orders,
        'status_counts': status_counts,
        'current_status': status_filter,
        'is_staff': request.user.is_staff or bool(getattr(request.user, 'staff_role', '')),
        **search_context,
    }
    
    return render(request, 'orders/order_list.html', context)


@login_required
def order_detail(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """
    🔍 Display detailed order view with items and status history
    Multi-tenant: Only accessible if user has access to the order's customer
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
    
    order = get_object_or_404(
        Order.objects
        .select_related('customer')
        .prefetch_related(
            'items__product',
            'items__service',
            'status_history__changed_by'
        ),
        id=pk
    )
    
    # Validate access
    if access_denied := _validate_order_access(request, order):
        return access_denied
    
    context = {
        'order': order,
        'is_staff': request.user.is_staff or bool(getattr(request.user, 'staff_role', '')),
        'can_edit': (
            request.user.is_staff or bool(getattr(request.user, 'staff_role', ''))
        ) and len(order.get_editable_fields()) > 0,
        'editable_fields': order.get_editable_fields(),
        'can_edit_all': order.get_editable_fields() == ['*'],
    }
    
    return render(request, 'orders/order_detail.html', context)


@staff_required
def order_create(request: HttpRequest) -> HttpResponse:
    """
    ➕ Create new order (staff only)
    """
    if request.method == 'POST':
        # TODO: Implement order creation form processing
        messages.info(request, _("Order creation form processing will be implemented next."))
        return redirect('orders:order_list')
    
    # Get customers for selection
    customers = Customer.objects.filter(status='active').order_by('company_name')
    
    context = {
        'customers': customers,
    }
    
    return render(request, 'orders/order_form.html', context)


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
        return redirect('orders:order_detail', pk=pk)
    
    if request.method == 'POST':
        # TODO: Implement order editing form processing
        messages.info(request, _("Order editing form processing will be implemented next."))
        return redirect('orders:order_detail', pk=pk)
    
    context = {
        'order': order,
        'editable_fields': editable_fields,
        'can_edit_all': editable_fields == ['*'],
    }
    
    return render(request, 'orders/order_form.html', context)


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
    
    new_status = request.POST.get('status', '')
    notes = request.POST.get('notes', '')
    
    if not new_status:
        return json_error("Status is required")
    
    # Use service to change status
    status_data = StatusChangeData(
        new_status=new_status,
        notes=notes,
        changed_by=request.user
    )
    
    result = OrderService.update_order_status(order, status_data)
    
    if result.is_ok():
        return json_success({
            'message': f'Order status changed to {new_status}',
            'new_status': new_status,
            'status_display': order.get_status_display()
        })
    else:
        # Handle error case - use hasattr to check for error attribute
        if hasattr(result, 'error'):
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
    if order.status in ['completed', 'cancelled']:
        messages.error(request, _("❌ This order cannot be cancelled."))
        return redirect('orders:order_detail', pk=pk)
    
    notes = request.POST.get('cancellation_reason', 'Order cancelled by staff')
    
    # Type guard: request.user is always User due to @staff_required decorator
    user = request.user if request.user.is_authenticated else None
    
    status_data = StatusChangeData(
        new_status='cancelled',
        notes=notes,
        changed_by=user
    )
    
    result = OrderService.update_order_status(order, status_data)
    
    if result.is_ok():
        messages.success(request, _("✅ Order has been cancelled."))
    else:
        # Handle error case - use hasattr to check for error attribute
        if hasattr(result, 'error'):
            messages.error(request, f"❌ Failed to cancel order: {result.error}")
        else:
            messages.error(request, "❌ Unknown error occurred while cancelling order")
    
    return redirect('orders:order_detail', pk=pk)


@staff_required
@require_POST
def order_refund(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """
    💰 Refund an order (bidirectional with invoice refunds)
    """
    from apps.billing.services import RefundService, RefundData, RefundType, RefundReason
    from decimal import Decimal
    
    order = get_object_or_404(Order, id=pk)
    
    # Validate access
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        return json_error("You do not have permission to refund this order")
    
    # Parse form data
    try:
        refund_type_str = request.POST.get('refund_type', '').strip()
        refund_reason_str = request.POST.get('refund_reason', '').strip()
        refund_notes = request.POST.get('refund_notes', '').strip()
        refund_amount_str = request.POST.get('refund_amount', '0').strip()
        process_payment = request.POST.get('process_payment_refund') == 'true'
        
        if not refund_type_str or not refund_reason_str or not refund_notes:
            return json_error("All fields are required")
            
        # Parse refund type
        refund_type = RefundType.FULL if refund_type_str == 'full' else RefundType.PARTIAL
        
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
            'refund_type': refund_type,
            'amount_cents': amount_cents,
            'reason': refund_reason,
            'notes': refund_notes,
            'initiated_by': request.user,
            'external_refund_id': None,
            'process_payment_refund': process_payment
        }
        
        # Process refund using RefundService
        result = RefundService.refund_order(order.id, refund_data)
        
        if result.is_ok():
            refund_result = result.unwrap()
            return json_success({
                'message': f'Order refund processed successfully',
                'refund_id': str(refund_result['refund_id']) if refund_result.get('refund_id') else None,
                'new_status': order.status  # Will be updated by the service
            })
        else:
            # Handle error case - use hasattr to check for error attribute
            if hasattr(result, 'error'):
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
    from apps.tickets.models import SupportTicket, SupportCategory
    from apps.common.utils import json_success, json_error
    
    order = get_object_or_404(Order, id=pk)
    
    # Validate access - user must be able to access this order's customer
    if not isinstance(request.user, User) or not request.user.can_access_customer(order.customer):
        return json_error("You do not have permission to request refunds for this order")
    
    # Only allow refund requests for completed or partially refunded orders
    if order.status not in ['completed', 'partially_refunded']:
        return json_error("Refund requests are only allowed for completed orders")
    
    try:
        refund_reason = request.POST.get('refund_reason', '').strip()
        refund_notes = request.POST.get('refund_notes', '').strip()
        
        if not refund_reason or not refund_notes:
            return json_error("All fields are required")
        
        # Map refund reason to user-friendly title
        reason_titles = {
            'customer_request': 'General Customer Request',
            'service_failure': 'Service Not Working',
            'quality_issue': 'Quality Not As Expected', 
            'technical_issue': 'Technical Problems',
            'cancellation_request': 'Want to Cancel Service',
            'duplicate_order': 'Duplicate Order',
            'billing_error': 'Billing Error',
            'policy_violation': 'Service Policy Issue',
            'unsatisfied_service': 'Not Satisfied with Service',
            'other': 'Other Reason'
        }
        
        reason_title = reason_titles.get(refund_reason, 'Refund Request')
        
        # Get or create billing category
        billing_category, _ = SupportCategory.objects.get_or_create(
            name='Billing',
            defaults={
                'name_en': 'Billing',
                'description': 'Billing and refund related issues',
                'icon': 'credit-card',
                'color': '#10B981',
                'sla_response_hours': 24,
                'sla_resolution_hours': 48
            }
        )
        
        # Create ticket
        ticket = SupportTicket.objects.create(
            title=f"Refund Request for Order {order.order_number}",
            description=f"""
REFUND REQUEST DETAILS
======================

Order Number: {order.order_number}
Order Total: {order.total_cents / 100:.2f} {order.currency}
Order Status: {order.get_status_display()}
Created Date: {order.created_at.strftime('%Y-%m-%d %H:%M')}

Refund Reason: {reason_title}

Customer Details:
{refund_notes}

---
This ticket was automatically created from a customer refund request.
            """.strip(),
            customer=order.customer,
            contact_person=request.user.get_full_name() or request.user.email,
            contact_email=request.user.email,
            contact_phone=getattr(request.user, 'phone', ''),
            category=billing_category,
            priority='normal',
            status='new',
            source='web',
            created_by=request.user,
            # Link to order
            content_type=ContentType.objects.get_for_model(Order),
            object_id=order.id
        )
        
        logger.info(f"🎫 Refund request ticket #{ticket.ticket_number} created for order {order.order_number} by user {request.user.email}")
        
        return json_success({
            'message': f'Refund request submitted successfully',
            'ticket_number': ticket.ticket_number,
            'order_number': order.order_number
        })
        
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
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_send(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📧 Send order by email (to be implemented)"""
    messages.info(request, _("Email sending will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_provision(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """⚙️ Provision order services (to be implemented)"""
    messages.info(request, _("Service provisioning will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_items_list(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📋 HTMX: Order items list (to be implemented)"""
    messages.info(request, _("Order items management will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_item_create(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """➕ HTMX: Add order item (to be implemented)"""
    messages.info(request, _("Order item creation will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_item_edit(request: HttpRequest, pk: uuid.UUID, item_pk: uuid.UUID) -> HttpResponse:
    """✏️ HTMX: Edit order item (to be implemented)"""
    messages.info(request, _("Order item editing will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
@require_POST
def order_item_delete(request: HttpRequest, pk: uuid.UUID, item_pk: uuid.UUID) -> JsonResponse:
    """🗑️ HTMX: Delete order item (to be implemented)"""
    return json_success({'message': 'Order item deletion will be implemented next'})


@staff_required
def order_duplicate(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """📋 Duplicate order (to be implemented)"""
    messages.info(request, _("Order duplication will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_to_invoice(request: HttpRequest, pk: uuid.UUID) -> HttpResponse:
    """🧾 Convert order to invoice (to be implemented)"""
    messages.info(request, _("Order to invoice conversion will be implemented next."))
    return redirect('orders:order_detail', pk=pk)


@staff_required
def order_reports(request: HttpRequest) -> HttpResponse:
    """📊 Order reports and analytics (to be implemented)"""
    messages.info(request, _("Order reports will be implemented next."))
    return redirect('orders:order_list')


@staff_required
def order_export(request: HttpRequest) -> HttpResponse:
    """📤 Export orders (to be implemented)"""
    messages.info(request, _("Order export will be implemented next."))
    return redirect('orders:order_list')
