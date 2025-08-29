# ===============================================================================
# BILLING VIEWS - INVOICE & PAYMENT PROCESSING
# ===============================================================================

from __future__ import annotations

import decimal
import logging
import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q, QuerySet, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from apps.billing.pdf_generators import RomanianInvoicePDFGenerator, RomanianProformaPDFGenerator
from apps.common.decorators import billing_staff_required, can_edit_proforma, staff_required
from apps.common.mixins import get_search_context
from apps.common.utils import json_error, json_success
from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket
from apps.ui.table_helpers import prepare_billing_table_data
from apps.users.models import User

from .models import (
    Currency,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    Payment,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
)
from .services import RefundData, RefundReason, RefundService, RefundType


def _get_accessible_customer_ids(user: User) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()

    if isinstance(accessible_customers, QuerySet):
        return list(accessible_customers.values_list('id', flat=True))
    else:
        return [c.id for c in accessible_customers] if accessible_customers else []


def _validate_pdf_access(request: HttpRequest, document: Invoice | ProformaInvoice) -> HttpResponse | None:
    """
    Validate user access to PDF document.
    Returns redirect response if access denied, None if access granted.
    """
    # Handle None request objects (for testing)
    if request is None:
        return redirect('billing:invoice_list')
    
    # Handle None document objects (for testing)
    if document is None:
        return redirect('billing:invoice_list')
    
    # Type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(document.customer):
        messages.error(request, _("❌ You do not have permission to access this document."))
        return redirect('billing:invoice_list')
    return None


@login_required
def billing_list(request: HttpRequest) -> HttpResponse:
    """
    🧾 Display combined list of proformas and invoices (Romanian business practice)
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
    
    try:
        # Get accessible customers
        customer_ids = _get_accessible_customer_ids(request.user)

        # Filter by type
        doc_type = request.GET.get('type', 'all')  # all, proforma, invoice

        # ✅ Get search context for template
        search_context = get_search_context(request, 'search')
        search_query = search_context['search_query']

        # Get both proformas and invoices with search applied
        proformas_qs = ProformaInvoice.objects.filter(customer_id__in=customer_ids).select_related('customer')
        invoices_qs = Invoice.objects.filter(customer_id__in=customer_ids).select_related('customer')

        # Apply search filter
        if search_query:
            proformas_qs = proformas_qs.filter(
                Q(number__icontains=search_query) |
                Q(customer__company_name__icontains=search_query) |
                Q(customer__name__icontains=search_query)
            )
            invoices_qs = invoices_qs.filter(
                Q(number__icontains=search_query) |
                Q(customer__company_name__icontains=search_query) |
                Q(customer__name__icontains=search_query)
            )

        # 🎯 For pagination, we need to create a unified dataset
        # Since Django doesn't support heterogeneous pagination well, we'll use a simpler approach
        
        # Build combined list for pagination (performance optimized for Romanian business scale)
        combined_documents = []

        if doc_type in ['all', 'proforma']:
            # ⚡ PERFORMANCE: Use list extend for better performance than multiple appends
            proforma_data = [
                {
                    'type': 'proforma',
                    'obj': proforma,
                    'id': proforma.pk,
                    'number': proforma.number,
                    'customer': proforma.customer,
                    'total': proforma.total,
                    'currency': proforma.currency,
                    'created_at': proforma.created_at,
                    'status': 'valid' if not proforma.is_expired else 'expired',
                    'can_edit': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
                    'can_convert': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
                }
                for proforma in proformas_qs
            ]
            combined_documents.extend(proforma_data)

        if doc_type in ['all', 'invoice']:
            invoice_data = [
                {
                    'type': 'invoice',
                    'obj': invoice,
                    'id': invoice.pk,
                    'number': invoice.number,
                    'customer': invoice.customer,
                    'total': invoice.total,
                    'currency': invoice.currency,
                    'created_at': invoice.created_at,
                    'status': invoice.status,
                    'can_edit': False,  # Invoices are immutable
                    'can_convert': False,
                }
                for invoice in invoices_qs
            ]
            combined_documents.extend(invoice_data)

        # Sort by creation date (newest first)
        combined_documents.sort(key=lambda x: x['created_at'] if isinstance(x['created_at'], datetime) else datetime.min, reverse=True)

        # ✅ Apply pagination using reusable utility (20 items per page for Romanian business)
        # Convert list to mock queryset-like object for pagination
        paginator = Paginator(combined_documents, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        pagination_context = {
            'page_obj': page_obj,
            'is_paginated': page_obj.has_other_pages(),
            'extra_params': {k: v for k, v in request.GET.items() if k != 'page'}
        }

        # Statistics (calculate from original querysets for accuracy)
        proforma_total = proformas_qs.aggregate(total=Sum('total_cents'))['total'] or 0
        invoice_total = invoices_qs.aggregate(total=Sum('total_cents'))['total'] or 0

        # Check if user is staff for different context
        is_staff_user = request.user.is_staff or getattr(request.user, 'staff_role', None)

        context = {
            'documents': pagination_context['page_obj'],  # ✅ Use paginated documents
            'doc_type': doc_type,
            'proforma_count': proformas_qs.count(),
            'invoice_count': invoices_qs.count(),
            'proforma_total': Decimal(proforma_total) / 100,
            'invoice_total': Decimal(invoice_total) / 100,
            'total_amount': Decimal(proforma_total + invoice_total) / 100,
            'is_staff_user': is_staff_user,
            **pagination_context,  # ✅ Add pagination context (page_obj, is_paginated, extra_params)
            **search_context,      # ✅ Add search context (search_query, has_search)
        }

        return render(request, 'billing/billing_list.html', context)
        
    except Exception as e:
        # Handle database errors gracefully
        logger = logging.getLogger(__name__)
        logger.error(f"Database error in billing_list: {e}")
        
        # Add error message for user display
        messages.error(request, _("Unable to load billing data. Please try again later."))
        
        # Return empty context with error handling
        context = {
            'documents': [],
            'doc_type': 'all',
            'proforma_count': 0,
            'invoice_count': 0,
            'proforma_total': Decimal('0.00'),
            'invoice_total': Decimal('0.00'),
            'total_amount': Decimal('0.00'),
            'is_staff_user': False,
            'page_obj': None,
            'is_paginated': False,
            'extra_params': {},
            'search_query': '',
            'has_search': False,
            'error_message': 'Unable to load billing data. Please try again later.',
        }
        return render(request, 'billing/billing_list.html', context)


@login_required
def proforma_list(request: HttpRequest) -> HttpResponse:
    """
    🧾 Display list of proformas only (Romanian business practice)
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
    
    try:
        # Get accessible customers
        customer_ids = _get_accessible_customer_ids(request.user)

        # ✅ Get search context for template
        search_context = get_search_context(request, 'search')
        search_query = search_context['search_query']

        # Get proformas with search applied
        proformas_qs = ProformaInvoice.objects.filter(customer_id__in=customer_ids).select_related('customer')

        # Apply search filter
        if search_query:
            proformas_qs = proformas_qs.filter(
                Q(number__icontains=search_query) |
                Q(customer__company_name__icontains=search_query) |
                Q(customer__name__icontains=search_query)
            )

        # Build proforma data for rendering
        proforma_documents = [
            {
                'type': 'proforma',
                'obj': proforma,
                'id': proforma.pk,
                'number': proforma.number,
                'customer': proforma.customer,
                'total': proforma.total,
                'currency': proforma.currency,
                'created_at': proforma.created_at,
                'status': 'valid' if not proforma.is_expired else 'expired',
                'can_edit': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
                'can_convert': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
            }
            for proforma in proformas_qs
        ]

        # Sort by creation date (newest first)
        proforma_documents.sort(key=lambda x: x['created_at'], reverse=True)  # type: ignore[arg-type,return-value]

        # ⚡ PERFORMANCE: Implement pagination for 25 items per page (Romanian business scale)
        paginator = Paginator(proforma_documents, 25)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Build pagination context
        pagination_context = {
            'page_obj': page_obj,
            'is_paginated': page_obj.has_other_pages(),
            'extra_params': {k: v for k, v in request.GET.items() if k != 'page'}
        }

        # Statistics 
        proforma_total = proformas_qs.aggregate(total=Sum('total_cents'))['total'] or 0

        # Check if user is staff for different context
        is_staff_user = request.user.is_staff or getattr(request.user, 'staff_role', None)

        context = {
            'documents': pagination_context['page_obj'],
            'doc_type': 'proforma',  # Always proforma for this view
            'proforma_count': proformas_qs.count(),
            'invoice_count': 0,  # No invoices in this view
            'proforma_total': Decimal(proforma_total) / 100,
            'invoice_total': Decimal('0.00'),
            'total_amount': Decimal(proforma_total) / 100,
            'is_staff_user': is_staff_user,
            **pagination_context,
            **search_context,
        }

        return render(request, 'billing/billing_list.html', context)
        
    except Exception as e:
        # Handle database errors gracefully
        logger = logging.getLogger(__name__)
        logger.error(f"Database error in proforma_list: {e}")
        
        # Return empty context with error handling
        context = {
            'documents': [],
            'doc_type': 'proforma',
            'proforma_count': 0,
            'invoice_count': 0,
            'proforma_total': Decimal('0.00'),
            'invoice_total': Decimal('0.00'),
            'total_amount': Decimal('0.00'),
            'is_staff_user': False,
            'page_obj': None,
            'is_paginated': False,
            'extra_params': {},
            'search_query': '',
            'has_search': False,
            'error_message': 'Unable to load proforma data. Please try again later.',
        }

        return render(request, 'billing/billing_list.html', context)


@login_required  
def billing_list_htmx(request: HttpRequest) -> HttpResponse:
    """
    🚀 HTMX endpoint for billing documents list with dynamic loading
    Returns only the results partial for smooth pagination and filtering
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
    
    try:
        # Get accessible customers
        customer_ids = _get_accessible_customer_ids(request.user)

        # Filter by type
        doc_type = request.GET.get('type', 'all')  # all, proforma, invoice

        # ✅ Get search context for template
        search_context = get_search_context(request, 'search')
        search_query = search_context['search_query']

        # Get both proformas and invoices with search applied
        proformas_qs = ProformaInvoice.objects.filter(customer_id__in=customer_ids).select_related('customer')
        invoices_qs = Invoice.objects.filter(customer_id__in=customer_ids).select_related('customer')

        # Apply search filter
        if search_query:
            proformas_qs = proformas_qs.filter(
                Q(number__icontains=search_query) |
                Q(customer__company_name__icontains=search_query) |
                Q(customer__name__icontains=search_query)
            )
            invoices_qs = invoices_qs.filter(
                Q(number__icontains=search_query) |
                Q(customer__company_name__icontains=search_query) |
                Q(customer__name__icontains=search_query)
            )

        # Build combined list for pagination
        combined_documents = []

        if doc_type in ['all', 'proforma']:
            proforma_data = [
                {
                    'type': 'proforma',
                    'obj': proforma,
                    'id': proforma.pk,
                    'number': proforma.number,
                    'customer': proforma.customer,
                    'total': proforma.total,
                    'currency': proforma.currency,
                    'created_at': proforma.created_at,
                    'status': 'valid' if not proforma.is_expired else 'expired',
                    'can_edit': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
                    'can_convert': (request.user.is_staff or getattr(request.user, 'staff_role', None)) and not proforma.is_expired,
                }
                for proforma in proformas_qs
            ]
            combined_documents.extend(proforma_data)

        if doc_type in ['all', 'invoice']:
            invoice_data = [
                {
                    'type': 'invoice',
                    'obj': invoice,
                    'id': invoice.pk,
                    'number': invoice.number,
                    'customer': invoice.customer,
                    'total': invoice.total,
                    'currency': invoice.currency,
                    'created_at': invoice.created_at,
                    'status': invoice.status,
                    'can_edit': False,  # Invoices are immutable
                    'can_convert': False,
                }
                for invoice in invoices_qs
            ]
            combined_documents.extend(invoice_data)

        # Sort by creation date (newest first)
        combined_documents.sort(key=lambda x: x['created_at'] if isinstance(x['created_at'], datetime) else datetime.min, reverse=True)

        # Apply pagination
        paginator = Paginator(combined_documents, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Build extra_params for pagination
        extra_params_dict = {k: v for k, v in request.GET.items() if k != 'page'}
        extra_params = '&'.join([f"{k}={v}" for k, v in extra_params_dict.items()])
        if extra_params:
            extra_params = '&' + extra_params

        # Prepare data for standardized table component
        table_data = prepare_billing_table_data(list(page_obj), request.user)

        context = {
            'documents': page_obj,
            'page_obj': page_obj,
            'extra_params': extra_params,
            'table_data': table_data,  # Add table component data
        }

        return render(request, 'billing/partials/billing_list.html', context)
        
    except Exception as e:
        # Handle errors gracefully for HTMX
        logger = logging.getLogger(__name__)
        logger.error(f"HTMX billing list error: {e}")
        
        # Return empty partial with error state
        context = {
            'documents': [],
            'page_obj': None,  # type: ignore[dict-item]
            'extra_params': '',
            'error_message': 'Unable to load billing data.',
        }
        return render(request, 'billing/partials/billing_list.html', context)


@login_required
def invoice_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📋 Display detailed invoice information
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        messages.error(request, _("❌ You do not have permission to access this invoice."))
        return redirect('billing:invoice_list')

    # Get invoice items and payments
    items = invoice.lines.all()
    payments = invoice.payments.order_by('-created_at')

    context = {
        'invoice': invoice,
        'items': items,
        'payments': payments,
        'can_edit': invoice.status == 'draft',
    }

    return render(request, 'billing/invoice_detail.html', context)


def _create_proforma_with_sequence(customer: Customer, valid_until: datetime) -> ProformaInvoice:
    """Create a new proforma with proper sequence number."""
    with transaction.atomic():
        sequence, created = ProformaSequence.objects.get_or_create(scope='default')
        proforma_number = sequence.get_next_number('PRO')
        
        # Create proforma
        ron_currency = Currency.objects.get(code='RON')
        
        return ProformaInvoice.objects.create(
            customer=customer,
            number=proforma_number,
            currency=ron_currency,
            valid_until=valid_until,
            # Copy customer billing info
            bill_to_name=customer.company_name or customer.name,
            bill_to_email=customer.primary_email,
            bill_to_tax_id=(getattr(customer, 'tax_profile', None) and customer.tax_profile.vat_number) or '',
        )


def _handle_proforma_create_post(request: HttpRequest) -> HttpResponse:
    """Handle POST request for proforma creation."""
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    # Validate customer assignment
    customer_id = request.POST.get('customer')
    customer, error_response = _validate_customer_assignment(request.user, customer_id, None)
    if error_response:
        return error_response

    # Process valid_until date
    valid_until, validation_errors = _process_valid_until_date(request.POST)

    try:
        # Create proforma - customer is guaranteed to be not None here due to validation above
        if customer is None:
            messages.error(request, _("❌ Customer is required to create proforma."))
            return redirect('billing:proforma_list')
        proforma = _create_proforma_with_sequence(customer, valid_until)
    except Exception as e:
        messages.error(request, _("❌ Error creating proforma: {error}").format(error=str(e)))
        return redirect('billing:proforma_list')

    # Process line items
    line_errors = _process_proforma_line_items(proforma, request.POST)
    validation_errors.extend(line_errors)
    
    # Save proforma with totals
    proforma.save()

    # Show validation errors if any
    for error in validation_errors:
        messages.warning(request, _("⚠️ {error}").format(error=error))

    messages.success(request, _("✅ Proforma #{number} has been created!").format(number=proforma.number))
    return redirect('billing:proforma_detail', pk=proforma.pk)


@billing_staff_required
def proforma_create(request: HttpRequest) -> HttpResponse:
    """
    + Create new proforma invoice (Romanian business practice - only proformas can be created manually)
    """
    if request.method == 'POST':
        return _handle_proforma_create_post(request)

    # GET request - render form
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    customers = _get_customers_for_edit_form(request.user)
    context = {
        'customers': customers,
        'vat_rate': Decimal('19.00'),  # Romanian standard VAT
        'document_type': 'proforma',
    }
    return render(request, 'billing/proforma_form.html', context)


@login_required
def proforma_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📋 Display detailed proforma information
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to access this proforma."))
        return redirect('billing:invoice_list')

    # Get proforma lines
    lines = proforma.lines.all()
    
    context = {
        'proforma': proforma,
        'lines': lines,
        'can_edit': can_edit_proforma(request.user, proforma),
        'can_convert': can_edit_proforma(request.user, proforma),  # Only staff can convert
        'is_staff_user': request.user.is_staff,
        'document_type': 'proforma',
    }

    return render(request, 'billing/proforma_detail.html', context)


@billing_staff_required
def proforma_to_invoice(request: HttpRequest, pk: int) -> HttpResponse:
    """
    🔄 Convert proforma to actual invoice (Romanian business practice)
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to convert this proforma."))
        return redirect('billing:invoice_list')

    # Business rules
    if proforma.is_expired:
        messages.error(request, _("❌ Cannot convert expired proforma to invoice."))
        return redirect('billing:proforma_detail', pk=pk)

    # Check if already converted
    existing_invoice = Invoice.objects.filter(meta__proforma_id=proforma.id).first()
    if existing_invoice:
        messages.warning(request, _("⚠️ This proforma has already been converted to invoice #{number}").format(number=existing_invoice.number))
        return redirect('billing:invoice_detail', pk=existing_invoice.pk)

    if request.method == 'POST':
        # Get next invoice number
        sequence, created = InvoiceSequence.objects.get_or_create(scope='default')
        invoice_number = sequence.get_next_number('INV')

        # Create invoice from proforma
        invoice = Invoice.objects.create(
            customer=proforma.customer,
            number=invoice_number,
            status='issued',  # Invoices start as issued, not draft
            currency=proforma.currency,
            subtotal_cents=proforma.subtotal_cents,
            tax_cents=proforma.tax_cents,
            total_cents=proforma.total_cents,
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            locked_at=timezone.now(),  # Invoices are immutable
            # Copy billing address from proforma
            bill_to_name=proforma.bill_to_name,
            bill_to_tax_id=proforma.bill_to_tax_id,
            bill_to_email=proforma.bill_to_email,
            bill_to_address1=proforma.bill_to_address1,
            bill_to_address2=proforma.bill_to_address2,
            bill_to_city=proforma.bill_to_city,
            bill_to_region=proforma.bill_to_region,
            bill_to_postal=proforma.bill_to_postal,
            bill_to_country=proforma.bill_to_country,
            # Link back to proforma
            meta={'proforma_id': proforma.id, 'proforma_number': proforma.number}
        )

        # Copy line items
        for proforma_line in proforma.lines.all():
            InvoiceLine.objects.create(
                invoice=invoice,
                kind=proforma_line.kind,
                service=proforma_line.service,
                description=proforma_line.description,
                quantity=proforma_line.quantity,
                unit_price_cents=proforma_line.unit_price_cents,
                tax_rate=proforma_line.tax_rate,
                line_total_cents=proforma_line.line_total_cents,
            )

        messages.success(request, _("✅ Proforma #{proforma_number} converted to Invoice #{invoice_number}!").format(
            proforma_number=proforma.number,
            invoice_number=invoice.number
        ))
        return redirect('billing:invoice_detail', pk=invoice.pk)

    context = {
        'proforma': proforma,
        'lines': proforma.lines.all(),
    }

    return render(request, 'billing/proforma_convert.html', context)


@billing_staff_required
def process_proforma_payment(request: HttpRequest, pk: int) -> HttpResponse:
    """
    💳 Process payment for proforma (automatically converts to invoice)
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(proforma.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # Convert proforma to invoice first using the billing service
        # Instead of calling the view directly (which causes messages issues),
        # we'll duplicate the conversion logic here
        
        # Check if already converted
        existing_invoice = Invoice.objects.filter(meta__proforma_id=proforma.id).first()
        if existing_invoice:
            # Already converted, process payment on existing invoice
            invoice = existing_invoice
        else:
            # Convert proforma to invoice
            sequence, created = InvoiceSequence.objects.get_or_create(scope='default')
            invoice_number = sequence.get_next_number('INV')

            # Create invoice from proforma
            invoice = Invoice.objects.create(
                customer=proforma.customer,
                number=invoice_number,
                status='draft',
                currency=proforma.currency,
                total_cents=proforma.total_cents,
                tax_cents=proforma.tax_cents,
                subtotal_cents=proforma.subtotal_cents,
                due_at=proforma.valid_until if proforma.valid_until else timezone.now() + timezone.timedelta(days=30),
                issued_at=timezone.now(),
                meta={'proforma_id': proforma.id},
                converted_from_proforma=proforma,
            )

            # Copy all line items
            from apps.billing.models import InvoiceLine  # noqa: PLC0415
            for proforma_line in proforma.lines.all():
                InvoiceLine.objects.create(
                    invoice=invoice,
                    kind=proforma_line.kind,
                    service=proforma_line.service,
                    description=proforma_line.description,
                    quantity=proforma_line.quantity,
                    unit_price_cents=proforma_line.unit_price_cents,
                    tax_rate=proforma_line.tax_rate,
                    line_total_cents=proforma_line.line_total_cents,
                )

        # Process payment on the invoice
        if invoice:
            # Process payment on the invoice
            amount = Decimal(request.POST.get('amount', str(invoice.total)))
            payment_method = request.POST.get('payment_method', 'bank_transfer')

            Payment.objects.create(
                customer=invoice.customer,
                invoice=invoice,
                amount_cents=int(amount * 100),
                currency=invoice.currency,
                payment_method=payment_method if payment_method in ['stripe', 'bank', 'paypal', 'cash', 'other'] else 'other',
                status='succeeded',
                created_by=request.user,
            )

            # Mark invoice as paid
            invoice.status = 'paid'
            invoice.paid_at = timezone.now()
            invoice.save()

            messages.success(request, _("✅ Payment processed and invoice #{number} marked as paid!").format(number=invoice.number))
            return json_success({'invoice_id': invoice.id}, "Payment processed successfully")
        else:
            return json_error('Failed to convert proforma', status=400)

    return json_error('Invalid method', status=405)


def _validate_proforma_edit_access(user: User, proforma: ProformaInvoice, request: HttpRequest) -> HttpResponse | None:
    """Validate user access to edit proforma. Returns error response or None if valid."""
    if not user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to edit this proforma."))
        return redirect('billing:invoice_list')
    
    if proforma.is_expired:
        messages.error(request, _("❌ Cannot edit expired proforma."))
        return redirect('billing:proforma_detail', pk=proforma.pk)
    
    return None


def _validate_customer_assignment(user: User, customer_id: str | None, proforma_pk: int | None) -> tuple[Customer | None, HttpResponse | None]:
    """Validate customer assignment. Returns (customer, error_response) tuple."""
    if not customer_id:
        return None, redirect('billing:invoice_list')
        
    try:
        customer = Customer.objects.get(pk=customer_id)
    except (ValueError, Customer.DoesNotExist):
        if proforma_pk:
            return None, redirect('billing:proforma_detail', pk=proforma_pk)
        else:
            return None, redirect('billing:invoice_list')
    
    accessible_customer_ids = _get_accessible_customer_ids(user)
    if int(customer_id) not in accessible_customer_ids:
        if proforma_pk:
            return None, redirect('billing:proforma_detail', pk=proforma_pk)
        else:
            return None, redirect('billing:invoice_list')
    
    return customer, None


def _update_proforma_basic_info(proforma: ProformaInvoice, request_data: dict[str, Any]) -> None:
    """Update proforma basic information from form data."""
    bill_to_name = (request_data.get('bill_to_name') or '').strip()
    if bill_to_name:
        proforma.bill_to_name = bill_to_name

    bill_to_email = (request_data.get('bill_to_email') or '').strip()
    if bill_to_email:
        proforma.bill_to_email = bill_to_email

    bill_to_tax_id = (request_data.get('bill_to_tax_id') or '').strip()
    if bill_to_tax_id:
        proforma.bill_to_tax_id = bill_to_tax_id


def _process_valid_until_date(request_data: dict[str, Any] | None) -> tuple[datetime, list[str]]:
    """Process and validate the valid_until date from form data."""
    validation_errors: list[str] = []
    
    # Handle None case properly
    if request_data is None:
        valid_until = timezone.now() + timezone.timedelta(days=30)
        return valid_until, validation_errors
    
    valid_until_str = (request_data.get('valid_until') or '').strip()

    if valid_until_str:
        try:
            # Parse date from form (YYYY-MM-DD format)
            valid_until_date = datetime.strptime(valid_until_str, '%Y-%m-%d').date()
            valid_until = timezone.make_aware(datetime.combine(valid_until_date, datetime.min.time()))
        except ValueError:
            # Invalid date format, use default
            valid_until = timezone.now() + timezone.timedelta(days=30)
            validation_errors.append(f"Invalid date format '{valid_until_str}', using 30 days from now")
    else:
        # No date provided, use default
        valid_until = timezone.now() + timezone.timedelta(days=30)

    return valid_until, validation_errors


def _process_proforma_line_items(proforma: ProformaInvoice, request_data: dict[str, Any]) -> list[str]:
    """Process line items from form data and create ProformaLine objects."""
    # Clear existing line items first
    proforma.lines.all().delete()
    
    line_counter = 0
    total_subtotal = Decimal('0')
    total_tax = Decimal('0')
    validation_errors = []

    while f'line_{line_counter}_description' in request_data:
        description = (request_data.get(f'line_{line_counter}_description') or '').strip()
        quantity, price_errors = _parse_line_quantity(request_data, line_counter)
        unit_price, price_errors_2 = _parse_line_unit_price(request_data, line_counter)
        vat_rate, vat_errors = _parse_line_vat_rate(request_data, line_counter)
        
        validation_errors.extend(price_errors + price_errors_2 + vat_errors)

        if description and quantity > 0 and unit_price > 0:
            line_subtotal = quantity * unit_price
            line_tax = line_subtotal * (vat_rate / 100)
            line_total = line_subtotal + line_tax

            ProformaLine.objects.create(
                proforma=proforma,
                kind='service',
                description=description,
                quantity=quantity,
                unit_price_cents=int(unit_price * 100),
                tax_rate=vat_rate / 100,
                line_total_cents=int(line_total * 100),
            )

            total_subtotal += line_subtotal
            total_tax += line_tax

        line_counter += 1

    # Update proforma totals
    proforma.subtotal_cents = int(total_subtotal * 100)
    proforma.tax_cents = int(total_tax * 100)
    proforma.total_cents = int((total_subtotal + total_tax) * 100)
    
    return validation_errors


def _parse_line_quantity(request_data: dict[str, Any], line_counter: int) -> tuple[Decimal, list[str]]:
    """Parse and validate line item quantity."""
    errors = []
    try:
        quantity_raw = request_data.get(f'line_{line_counter}_quantity', '0')
        quantity_str = (quantity_raw or '0').strip()
        quantity = Decimal(quantity_str) if quantity_str else Decimal('0')
    except (ValueError, TypeError, decimal.InvalidOperation):
        quantity = Decimal('0')
        errors.append(f"Line {line_counter + 1}: Invalid quantity '{quantity_str}', using 0")
    return quantity, errors


def _parse_line_unit_price(request_data: dict[str, Any], line_counter: int) -> tuple[Decimal, list[str]]:
    """Parse and validate line item unit price."""
    errors = []
    try:
        unit_price_str = (request_data.get(f'line_{line_counter}_unit_price') or '0').strip()
        unit_price = Decimal(unit_price_str) if unit_price_str else Decimal('0')
    except (ValueError, TypeError, decimal.InvalidOperation):
        unit_price = Decimal('0')
        errors.append(f"Line {line_counter + 1}: Invalid unit price '{unit_price_str}', using 0")
    return unit_price, errors


def _parse_line_vat_rate(request_data: dict[str, Any], line_counter: int) -> tuple[Decimal, list[str]]:
    """Parse and validate line item VAT rate."""
    errors = []
    try:
        vat_rate_str = (request_data.get(f'line_{line_counter}_vat_rate') or '19').strip()
        vat_rate = Decimal(vat_rate_str) if vat_rate_str else Decimal('19')
    except (ValueError, TypeError, decimal.InvalidOperation):
        vat_rate = Decimal('19')
        errors.append(f"Line {line_counter + 1}: Invalid VAT rate '{vat_rate_str}', using 19%")
    return vat_rate, errors


def _handle_proforma_edit_post(request: HttpRequest, proforma: ProformaInvoice) -> HttpResponse:
    """Handle POST request for proforma editing."""
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    # Validate customer assignment
    customer_id = request.POST.get('customer')
    customer, error_response = _validate_customer_assignment(request.user, customer_id, proforma.pk)
    if error_response:
        return error_response

    # Update proforma data - customer is guaranteed to be not None here
    if customer:
        proforma.customer = customer
    _update_proforma_basic_info(proforma, request.POST)
    
    # Process valid_until date
    valid_until, validation_errors = _process_valid_until_date(request.POST)
    proforma.valid_until = valid_until
    
    # Process line items
    line_errors = _process_proforma_line_items(proforma, request.POST)
    validation_errors.extend(line_errors)
    
    # Save proforma
    proforma.save()

    # Show validation errors if any
    for error in validation_errors:
        messages.warning(request, _("⚠️ {error}").format(error=error))

    messages.success(request, _("✅ Proforma #{proforma_number} has been updated!").format(proforma_number=proforma.number))
    return redirect('billing:proforma_detail', pk=proforma.pk)


def _get_customers_for_edit_form(user: User) -> QuerySet[Customer, Customer]:
    """Get accessible customers for the edit form dropdown."""
    accessible_customers = user.get_accessible_customers()
    if isinstance(accessible_customers, QuerySet):
        return accessible_customers.select_related('tax_profile', 'billing_profile')
    elif isinstance(accessible_customers, list | tuple):
        return Customer.objects.filter(
            id__in=[c.id for c in accessible_customers]
        ).select_related('tax_profile', 'billing_profile')
    else:
        # Fallback - assume it's already a QuerySet
        return accessible_customers.select_related('tax_profile', 'billing_profile')


@billing_staff_required
def proforma_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """
    ✏️ Edit proforma invoice
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Guard clauses with early returns
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    error_response = _validate_proforma_edit_access(request.user, proforma, request)
    if error_response:
        return error_response

    if request.method == 'POST':
        return _handle_proforma_edit_post(request, proforma)

    # GET request - render form
    customers = _get_customers_for_edit_form(request.user)
    context = {
        'proforma': proforma,
        'lines': proforma.lines.all(),
        'customers': customers,
        'document_type': 'proforma',
    }
    return render(request, 'billing/proforma_form.html', context)


@login_required
def proforma_pdf(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📄 Generate PDF proforma (Romanian format) using ReportLab
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)
    
    # Security check
    access_denied_response = _validate_pdf_access(request, proforma)
    if access_denied_response:
        return access_denied_response
    
    # Generate PDF using Romanian proforma generator
    pdf_generator = RomanianProformaPDFGenerator(proforma)
    return pdf_generator.generate_response()


@billing_staff_required
def proforma_send(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📧 Send proforma via email to customer
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(proforma.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # TODO: Implement email sending with Romanian template
        messages.success(request, _("✅ Proforma #{proforma_number} has been sent successfully!").format(proforma_number=proforma.number))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@billing_staff_required
def invoice_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """
    ✏️ Edit draft invoice
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security and business rule checks - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        messages.error(request, _("❌ You do not have permission to edit this invoice."))
        return redirect('billing:invoice_list')

    if invoice.status != 'draft':
        messages.error(request, _("❌ Only draft invoices can be edited."))
        return redirect('billing:invoice_detail', pk=pk)

    if request.method == 'POST':
        # Update invoice logic here
        messages.success(request, _("✅ Invoice #{invoice_number} has been updated!").format(invoice_number=invoice.number))
        return redirect('billing:invoice_detail', pk=pk)

    context = {
        'invoice': invoice,
        'items': invoice.lines.all(),
    }

    return render(request, 'billing/invoice_form.html', context)


@login_required
def invoice_pdf(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📄 Generate PDF invoice (Romanian format) using ReportLab
    """
    invoice = get_object_or_404(Invoice, pk=pk)
    
    # Security check
    access_denied_response = _validate_pdf_access(request, invoice)
    if access_denied_response:
        return access_denied_response
    
    # Generate PDF using Romanian invoice generator
    pdf_generator = RomanianInvoicePDFGenerator(invoice)
    return pdf_generator.generate_response()


@billing_staff_required
def invoice_send(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📧 Send invoice via email to customer
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # TODO: Implement email sending with Romanian template
        # Keep invoice as issued (don't need to change status just for sending)
        invoice.sent_at = timezone.now()
        invoice.save()

        messages.success(request, _("✅ Invoice #{invoice_number} has been sent successfully!").format(invoice_number=invoice.number))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@billing_staff_required
def generate_e_factura(request: HttpRequest, pk: int) -> HttpResponse:
    """
    🇷🇴 Generate e-Factura XML for Romanian tax authorities
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        messages.error(request, _("❌ You do not have permission to generate e-Invoice for this invoice."))
        return redirect('billing:invoice_detail', pk=pk)

    # TODO: Implement e-Factura XML generation according to Romanian standards
    # This is a critical feature for Romanian businesses

    response = HttpResponse(content_type='application/xml')
    response['Content-Disposition'] = f'attachment; filename="e_factura_{invoice.number}.xml"'

    # Placeholder XML
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
    <ID>{invoice.number}</ID>
    <IssueDate>{invoice.created_at.date()}</IssueDate>
    <DocumentCurrencyCode>RON</DocumentCurrencyCode>
    <!-- Full e-Factura implementation needed -->
</Invoice>"""

    response.write(xml_content.encode('utf-8'))
    return response


@login_required
def payment_list(request: HttpRequest) -> HttpResponse:
    """
    💰 Display list of payments
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    customer_ids = _get_accessible_customer_ids(request.user)
    payments = Payment.objects.filter(
        invoice__customer_id__in=customer_ids
    ).select_related('invoice', 'invoice__customer').order_by('-created_at')

    # Pagination
    paginator = Paginator(payments, 25)
    page_number = request.GET.get('page')
    payments_page = paginator.get_page(page_number)

    context = {
        'payments': payments_page,
        'total_amount': payments.aggregate(total=Sum('amount_cents'))['total'] or Decimal('0'),
    }

    return render(request, 'billing/payment_list.html', context)


@billing_staff_required
def process_payment(request: HttpRequest, pk: int) -> HttpResponse:
    """
    💳 Process payment for invoice
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check - type guard for authenticated user
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        amount = Decimal(request.POST.get('amount', '0'))
        payment_method = request.POST.get('payment_method', 'bank_transfer')

        # Create payment record
        Payment.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            amount_cents=int(amount * 100),
            currency=invoice.currency,
            payment_method=payment_method if payment_method in ['stripe', 'bank', 'paypal', 'cash', 'other'] else 'other',
            status='succeeded',  # Changed from 'completed' to match model choices
            created_by=request.user,
        )

        # Update invoice status if fully paid
        if invoice.get_remaining_amount() <= 0:
            invoice.status = 'paid'
            invoice.paid_at = timezone.now()
            invoice.save()

        messages.success(request, _("✅ Payment of {amount} RON has been registered!").format(amount=amount))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@billing_staff_required
def billing_reports(request: HttpRequest) -> HttpResponse:
    """
    📊 Billing reports and analytics
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    customer_ids = _get_accessible_customer_ids(request.user)

    # Monthly revenue
    monthly_stats = Invoice.objects.filter(
        customer_id__in=customer_ids,
        status='paid'
    ).extra(
        select={'month': 'EXTRACT(month FROM created_at)'}
    ).values('month').annotate(
        revenue=Sum('total_cents'),
        count=Count('id')
    )

    context = {
        'monthly_stats': monthly_stats,
        'total_revenue': Invoice.objects.filter(
            customer_id__in=customer_ids,
            status='paid'
        ).aggregate(total=Sum('total_cents'))['total'] or Decimal('0'),
    }

    return render(request, 'billing/reports.html', context)


@billing_staff_required
def vat_report(request: HttpRequest) -> HttpResponse:
    """
    🇷🇴 VAT report for Romanian tax compliance
    """
    # Type guard for authenticated user
    if not isinstance(request.user, User):
        return redirect('users:login')
        
    customer_ids = _get_accessible_customer_ids(request.user)

    # VAT calculations for the selected period
    start_date = request.GET.get('start_date', timezone.now().replace(day=1).date())
    end_date = request.GET.get('end_date', timezone.now().date())

    invoices = Invoice.objects.filter(
        customer_id__in=customer_ids,
        created_at__date__range=[start_date, end_date],
        status__in=['issued', 'paid']
    )

    total_vat = invoices.aggregate(total_vat=Sum('tax_cents'))['total_vat'] or Decimal('0')
    total_net = invoices.aggregate(total_net=Sum('subtotal_cents'))['total_net'] or Decimal('0')

    context = {
        'invoices': invoices,
        'total_vat': total_vat,
        'total_net': total_net,
        'start_date': start_date,
        'end_date': end_date,
    }

    return render(request, 'billing/vat_report.html', context)


@staff_required
@require_POST
def invoice_refund(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:  # noqa: PLR0911
    """
    💰 Refund an invoice (bidirectional with order refunds)
    """
    logger = logging.getLogger(__name__)
    
    invoice = get_object_or_404(Invoice, id=pk)
    
    # Validate access
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        return json_error("You do not have permission to refund this invoice")
    
    # Parse form data
    try:
        refund_type_str = (request.POST.get('refund_type') or '').strip()
        refund_reason_str = (request.POST.get('refund_reason') or '').strip()
        refund_notes = (request.POST.get('refund_notes') or '').strip()
        refund_amount_str = (request.POST.get('refund_amount') or '0').strip()
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
        result = RefundService.refund_invoice(invoice.id, refund_data)
        
        if result.is_ok():
            refund_result = result.unwrap()
            return json_success({
                'message': 'Invoice refund processed successfully',
                'refund_id': str(refund_result['refund_id']) if refund_result.get('refund_id') else None,
                'new_status': invoice.status  # Will be updated by the service
            })
        # Handle error case - use hasattr to check for error attribute
        elif hasattr(result, 'error'):
            return json_error(result.error)
        else:
            return json_error("Unknown error occurred")
            
    except Exception as e:
        logger.exception(f"Failed to process invoice refund: {e}")
        return json_error("An unexpected error occurred while processing the refund")


@login_required
@require_POST
def invoice_refund_request(request: HttpRequest, pk: uuid.UUID) -> JsonResponse:
    """
    🎫 Create a refund request ticket for an invoice (customer-facing)
    """
    logger = logging.getLogger(__name__)
    
    invoice = get_object_or_404(Invoice, id=pk)
    
    # Validate access - user must be able to access this invoice's customer
    if not isinstance(request.user, User) or not request.user.can_access_customer(invoice.customer):
        return json_error("You do not have permission to request refunds for this invoice")
    
    # Only allow refund requests for paid invoices
    if invoice.status != 'paid':
        return json_error("Refund requests are only allowed for paid invoices")
    
    try:
        refund_reason = (request.POST.get('refund_reason') or '').strip()
        refund_notes = (request.POST.get('refund_notes') or '').strip()
        
        if not refund_reason or not refund_notes:
            return json_error("All fields are required")
        
        # Map refund reason to user-friendly title
        reason_titles = {
            'customer_request': 'General Customer Request',
            'service_failure': 'Service Not Working',
            'quality_issue': 'Quality Not As Expected', 
            'technical_issue': 'Technical Problems',
            'cancellation_request': 'Want to Cancel Service',
            'duplicate_invoice': 'Duplicate Invoice',
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
        ticket = Ticket.objects.create(
            title=f"Refund Request for Invoice {invoice.number}",
            description=f"""
REFUND REQUEST DETAILS
======================

Invoice Number: {invoice.number}
Invoice Total: {invoice.total_cents / 100:.2f} {invoice.currency}
Invoice Status: {invoice.get_status_display()}
Issue Date: {invoice.issued_at.strftime('%Y-%m-%d') if invoice.issued_at else 'Draft'}

Refund Reason: {reason_title}

Customer Details:
{refund_notes}

---
This ticket was automatically created from a customer refund request.
            """.strip(),
            customer=invoice.customer,
            contact_person=request.user.get_full_name() or request.user.email,
            contact_email=request.user.email,
            contact_phone=getattr(request.user, 'phone', ''),
            category=billing_category,
            priority='normal',
            status='new',
            source='web',
            created_by=request.user,
            # Link to invoice
            content_type=ContentType.objects.get_for_model(Invoice),
            object_id=invoice.id
        )
        
        logger.info(f"🎫 Refund request ticket #{ticket.ticket_number} created for invoice {invoice.number} by user {request.user.email}")
        
        return json_success({
            'message': 'Refund request submitted successfully',
            'ticket_number': ticket.ticket_number,
            'invoice_number': invoice.number
        })
        
    except Exception as e:
        logger.exception(f"Failed to create invoice refund request ticket: {e}")
        return json_error("An unexpected error occurred while submitting your refund request")
