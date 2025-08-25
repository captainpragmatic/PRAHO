# ===============================================================================
# BILLING VIEWS - INVOICE & PAYMENT PROCESSING
# ===============================================================================

from __future__ import annotations

import decimal
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.utils import json_error, json_success
from apps.customers.models import Customer

from .models import (
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    Payment,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
)


def _get_accessible_customer_ids(user: Any) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()

    from django.db.models import QuerySet
    if isinstance(accessible_customers, QuerySet):
        return accessible_customers.values_list('id', flat=True)
    else:
        return [c.id for c in accessible_customers] if accessible_customers else []


@login_required
def billing_list(request: HttpRequest) -> HttpResponse:
    """
    🧾 Display combined list of proformas and invoices (Romanian business practice)
    """
    # Get accessible customers
    customer_ids = _get_accessible_customer_ids(request.user)

    # Get both proformas and invoices
    proformas = ProformaInvoice.objects.filter(customer_id__in=customer_ids).select_related('customer')
    invoices = Invoice.objects.filter(customer_id__in=customer_ids).select_related('customer')

    # Filter by type
    doc_type = request.GET.get('type', 'all')  # all, proforma, invoice

    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        proformas = proformas.filter(
            Q(number__icontains=search_query) |
            Q(customer__company_name__icontains=search_query)
        )
        invoices = invoices.filter(
            Q(number__icontains=search_query) |
            Q(customer__company_name__icontains=search_query)
        )

    # Combine and annotate with type
    # ⚡ PERFORMANCE: Use list extend for better performance than multiple appends
    combined_documents = []

    if doc_type in ['all', 'proforma']:
        combined_documents.extend([
            {
                'type': 'proforma',
                'obj': proforma,
                'id': proforma.id,
                'number': proforma.number,
                'customer': proforma.customer,
                'total': proforma.total,
                'currency': proforma.currency,
                'created_at': proforma.created_at,
                'status': 'valid' if not proforma.is_expired else 'expired',
                'can_edit': True,
                'can_convert': not proforma.is_expired,
            }
            for proforma in proformas
        ])

    if doc_type in ['all', 'invoice']:
        combined_documents.extend([
            {
                'type': 'invoice',
                'obj': invoice,
                'id': invoice.id,
                'number': invoice.number,
                'customer': invoice.customer,
                'total': invoice.total,
                'currency': invoice.currency,
                'created_at': invoice.created_at,
                'status': invoice.status,
                'can_edit': False,  # Invoices are immutable
                'can_convert': False,
            }
            for invoice in invoices
        ])

    # Sort by creation date (newest first)
    combined_documents.sort(key=lambda x: x['created_at'], reverse=True)

    # Pagination
    paginator = Paginator(combined_documents, 25)
    page_number = request.GET.get('page')
    documents_page = paginator.get_page(page_number)

    # Statistics
    proforma_total = proformas.aggregate(total=Sum('total_cents'))['total'] or 0
    invoice_total = invoices.aggregate(total=Sum('total_cents'))['total'] or 0

    context = {
        'documents': documents_page,
        'search_query': search_query,
        'doc_type': doc_type,
        'proforma_count': proformas.count(),
        'invoice_count': invoices.count(),
        'proforma_total': Decimal(proforma_total) / 100,
        'invoice_total': Decimal(invoice_total) / 100,
        'total_amount': Decimal(proforma_total + invoice_total) / 100,
    }

    return render(request, 'billing/billing_list.html', context)


@login_required
def invoice_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📋 Display detailed invoice information
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(invoice.customer):
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


@login_required
def proforma_create(request: HttpRequest) -> HttpResponse:
    """
    ➕ Create new proforma invoice (Romanian business practice - only proformas can be created manually)
    """
    if request.method == 'POST':
        # Create proforma from form data
        customer_id = request.POST.get('customer')
        customer = get_object_or_404(Customer, pk=customer_id)

        # Security check
        accessible_customer_ids = _get_accessible_customer_ids(request.user)
        if int(customer_id) not in accessible_customer_ids:
            messages.error(request, _("❌ You do not have permission to create proformas for this customer."))
            return redirect('billing:invoice_list')

        # Get next proforma number with proper error handling
        from django.db import transaction

        # Get valid until date from form
        valid_until_str = request.POST.get('valid_until', '').strip()
        validation_errors = []

        if valid_until_str:
            try:
                from datetime import datetime
                valid_until_date = datetime.strptime(valid_until_str, '%Y-%m-%d').date()
                valid_until = timezone.make_aware(datetime.combine(valid_until_date, datetime.min.time()))
            except ValueError:
                # If date parsing fails, default to 30 days
                valid_until = timezone.now() + timezone.timedelta(days=30)
                validation_errors.append("Invalid 'Valid Until' date format, using 30 days from now")
        else:
            # If no date provided, default to 30 days
            valid_until = timezone.now() + timezone.timedelta(days=30)

        try:
            with transaction.atomic():
                sequence, created = ProformaSequence.objects.get_or_create(scope='default')
                proforma_number = sequence.get_next_number('PRO')

                # Create proforma
                from apps.billing.models import Currency
                ron_currency = Currency.objects.get(code='RON')

                proforma = ProformaInvoice.objects.create(
                    customer=customer,
                    number=proforma_number,
                    currency=ron_currency,
                    valid_until=valid_until,
                    # Copy customer billing info
                    bill_to_name=customer.company_name or customer.name,
                    bill_to_email=customer.primary_email,
                    bill_to_tax_id=(getattr(customer, 'tax_profile', None) and customer.tax_profile.vat_number) or '',
                )
        except Exception as e:
            messages.error(request, _("❌ Error creating proforma: {error}").format(error=str(e)))
            return redirect('billing:proforma_list')

        # Process line items from form
        line_counter = 0
        total_subtotal = 0
        total_tax = 0

        while f'line_{line_counter}_description' in request.POST:
            description = request.POST.get(f'line_{line_counter}_description', '').strip()

            # Safe decimal conversion with validation
            try:
                quantity_str = request.POST.get(f'line_{line_counter}_quantity', '0').strip()
                quantity = Decimal(quantity_str) if quantity_str else Decimal('0')
            except (ValueError, TypeError, decimal.InvalidOperation):
                quantity = Decimal('0')
                validation_errors.append(f"Line {line_counter + 1}: Invalid quantity '{quantity_str}', using 0")

            try:
                unit_price_str = request.POST.get(f'line_{line_counter}_unit_price', '0').strip()
                unit_price = Decimal(unit_price_str) if unit_price_str else Decimal('0')
            except (ValueError, TypeError, decimal.InvalidOperation):
                unit_price = Decimal('0')
                validation_errors.append(f"Line {line_counter + 1}: Invalid unit price '{unit_price_str}', using 0")

            try:
                vat_rate_str = request.POST.get(f'line_{line_counter}_vat_rate', '19').strip()
                vat_rate = Decimal(vat_rate_str) if vat_rate_str else Decimal('19')
            except (ValueError, TypeError, decimal.InvalidOperation):
                vat_rate = Decimal('19')
                validation_errors.append(f"Line {line_counter + 1}: Invalid VAT rate '{vat_rate_str}', using 19%")

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
        proforma.save()

        # Show validation errors if any
        if validation_errors:
            for error in validation_errors:
                messages.warning(request, _("⚠️ {error}").format(error=error))

        messages.success(request, _("✅ Proforma #{number} has been created!").format(number=proforma.number))
        return redirect('billing:proforma_detail', pk=proforma.pk)

    # Get user's customers for dropdown with related data
    accessible_customers = request.user.get_accessible_customers()
    if hasattr(accessible_customers, 'all'):
        customers = accessible_customers.select_related('tax_profile', 'billing_profile').all()
    # Customer is already imported at module level
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(
            id__in=[c.id for c in accessible_customers]
        ).select_related('tax_profile', 'billing_profile')
    else:
        customers = accessible_customers.select_related('tax_profile', 'billing_profile')

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

    # Security check
    if not request.user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to access this proforma."))
        return redirect('billing:invoice_list')

    # Get proforma lines
    lines = proforma.lines.all()

    context = {
        'proforma': proforma,
        'lines': lines,
        'can_edit': not proforma.is_expired,
        'can_convert': not proforma.is_expired,
        'document_type': 'proforma',
    }

    return render(request, 'billing/proforma_detail.html', context)


@login_required
def proforma_to_invoice(request: HttpRequest, pk: int) -> HttpResponse:
    """
    🔄 Convert proforma to actual invoice (Romanian business practice)
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(proforma.customer):
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


@login_required
def process_proforma_payment(request: HttpRequest, pk: int) -> HttpResponse:
    """
    💳 Process payment for proforma (automatically converts to invoice)
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(proforma.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # Convert proforma to invoice first
        from django.test import RequestFactory
        factory = RequestFactory()
        convert_request = factory.post('')
        convert_request.user = request.user

        # Call conversion view
        proforma_to_invoice(convert_request, pk)

        # If conversion successful, process payment on the new invoice
        invoice = Invoice.objects.filter(meta__proforma_id=proforma.id).first()
        if invoice:
            # Process payment on the invoice
            amount = Decimal(request.POST.get('amount', str(invoice.total)))
            payment_method = request.POST.get('payment_method', 'bank_transfer')

            Payment.objects.create(
                invoice=invoice,
                amount=amount,
                payment_method=payment_method,
                status='completed',
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


@login_required
def proforma_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """
    ✏️ Edit proforma invoice
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to edit this proforma."))
        return redirect('billing:invoice_list')

    # Business rule check
    if proforma.is_expired:
        messages.error(request, _("❌ Cannot edit expired proforma."))
        return redirect('billing:proforma_detail', pk=pk)

    if request.method == 'POST':
        # Update proforma from form data
        customer_id = request.POST.get('customer')
        customer = get_object_or_404(Customer, pk=customer_id)

        # Security check
        accessible_customer_ids = _get_accessible_customer_ids(request.user)
        if int(customer_id) not in accessible_customer_ids:
            messages.error(request, _("❌ You do not have permission to assign this customer."))
            return redirect('billing:proforma_detail', pk=pk)

        # Update proforma basic info
        proforma.customer = customer

        # Update billing address if provided
        bill_to_name = request.POST.get('bill_to_name', '').strip()
        if bill_to_name:
            proforma.bill_to_name = bill_to_name

        bill_to_email = request.POST.get('bill_to_email', '').strip()
        if bill_to_email:
            proforma.bill_to_email = bill_to_email

        bill_to_tax_id = request.POST.get('bill_to_tax_id', '').strip()
        if bill_to_tax_id:
            proforma.bill_to_tax_id = bill_to_tax_id

        # ===============================================================================
        # 📅 PROCESS VALID_UNTIL DATE FROM FORM
        # ===============================================================================
        validation_errors = []

        # Process valid_until date from form with proper validation
        valid_until_str = request.POST.get('valid_until', '').strip()

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

        # Update proforma valid_until
        proforma.valid_until = valid_until

        # Clear existing line items
        proforma.lines.all().delete()

        # Process line items from form
        line_counter = 0
        total_subtotal = 0
        total_tax = 0
        validation_errors = []

        while f'line_{line_counter}_description' in request.POST:
            description = request.POST.get(f'line_{line_counter}_description', '').strip()

            # Safe decimal conversion with validation
            try:
                quantity_str = request.POST.get(f'line_{line_counter}_quantity', '0').strip()
                quantity = Decimal(quantity_str) if quantity_str else Decimal('0')
            except (ValueError, TypeError, decimal.InvalidOperation):
                quantity = Decimal('0')
                validation_errors.append(f"Line {line_counter + 1}: Invalid quantity '{quantity_str}', using 0")

            try:
                unit_price_str = request.POST.get(f'line_{line_counter}_unit_price', '0').strip()
                unit_price = Decimal(unit_price_str) if unit_price_str else Decimal('0')
            except (ValueError, TypeError, decimal.InvalidOperation):
                unit_price = Decimal('0')
                validation_errors.append(f"Line {line_counter + 1}: Invalid unit price '{unit_price_str}', using 0")

            try:
                vat_rate_str = request.POST.get(f'line_{line_counter}_vat_rate', '19').strip()
                vat_rate = Decimal(vat_rate_str) if vat_rate_str else Decimal('19')
            except (ValueError, TypeError, decimal.InvalidOperation):
                vat_rate = Decimal('19')
                validation_errors.append(f"Line {line_counter + 1}: Invalid VAT rate '{vat_rate_str}', using 19%")

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
        proforma.save()

        # Show validation errors if any
        if validation_errors:
            for error in validation_errors:
                messages.warning(request, _("⚠️ {error}").format(error=error))

        messages.success(request, _("✅ Proforma #{proforma_number} has been updated!").format(proforma_number=proforma.number))
        return redirect('billing:proforma_detail', pk=pk)

    # Get user's customers for dropdown
    accessible_customers = request.user.get_accessible_customers()
    if hasattr(accessible_customers, 'all'):
        customers = accessible_customers.select_related('tax_profile', 'billing_profile').all()
    # Customer is already imported at module level
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(
            id__in=[c.id for c in accessible_customers]
        ).select_related('tax_profile', 'billing_profile')
    else:
        customers = accessible_customers.select_related('tax_profile', 'billing_profile')

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
    from io import BytesIO

    from django.conf import settings
    from django.utils.translation import (
        gettext as _t,  # Use gettext for immediate evaluation
    )
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas

    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(proforma.customer):
        messages.error(request, _("❌ You do not have permission to access this proforma."))
        return redirect('billing:invoice_list')

    # Create PDF buffer
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # ===============================================================================
    # COMPANY INFO FROM SETTINGS 🏢
    # ===============================================================================

    # Get company info from settings (with fallbacks)
    company_name = getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')
    company_address = getattr(settings, 'COMPANY_ADDRESS', 'Str. Exemplu Nr. 1')
    company_city = getattr(settings, 'COMPANY_CITY', 'București')
    company_country = getattr(settings, 'COMPANY_COUNTRY', 'România')
    company_cui = getattr(settings, 'COMPANY_CUI', 'RO12345678')
    company_email = getattr(settings, 'COMPANY_EMAIL', 'contact@praho.ro')

    # ===============================================================================
    # PDF CONTENT GENERATION 📄
    # ===============================================================================

    # Header with company branding
    p.setFont("Helvetica-Bold", 24)
    p.drawString(2*cm, height - 3*cm, f"🇷🇴 {company_name}")

    p.setFont("Helvetica-Bold", 16)
    p.drawString(2*cm, height - 4*cm, str(_t("FACTURĂ PROFORMA")))

    p.setFont("Helvetica", 12)
    p.drawString(2*cm, height - 5*cm, str(_t("Number: {number}")).format(number=proforma.number))
    p.drawString(2*cm, height - 5.5*cm, str(_t("Date: {date}")).format(date=proforma.created_at.strftime('%d.%m.%Y')))
    p.drawString(2*cm, height - 6*cm, str(_t("Valid until: {date}")).format(date=proforma.valid_until.strftime('%d.%m.%Y')))

    # Company info section
    y_pos = height - 8*cm
    p.setFont("Helvetica-Bold", 14)
    p.drawString(2*cm, y_pos, str(_t("Supplier:")))

    p.setFont("Helvetica", 10)
    p.drawString(2*cm, y_pos - 0.5*cm, company_name)
    p.drawString(2*cm, y_pos - 1*cm, f"{company_address}, {company_city}, {company_country}")
    p.drawString(2*cm, y_pos - 1.5*cm, str(_t("Tax ID: {cui}")).format(cui=company_cui))
    p.drawString(2*cm, y_pos - 2*cm, str(_t("Email: {email}")).format(email=company_email))

    # Client info section
    p.setFont("Helvetica-Bold", 14)
    p.drawString(11*cm, y_pos, str(_t("Client:")))

    p.setFont("Helvetica", 10)
    p.drawString(11*cm, y_pos - 0.5*cm, proforma.bill_to_name or "")
    if proforma.bill_to_address1:
        p.drawString(11*cm, y_pos - 1*cm, proforma.bill_to_address1)
    if proforma.bill_to_tax_id:
        p.drawString(11*cm, y_pos - 1.5*cm, str(_t("Tax ID: {tax_id}")).format(tax_id=proforma.bill_to_tax_id))
    if proforma.bill_to_email:
        p.drawString(11*cm, y_pos - 2*cm, str(_t("Email: {email}")).format(email=proforma.bill_to_email))

    # Items table headers
    table_y = height - 13*cm
    p.setFont("Helvetica-Bold", 10)
    p.drawString(2*cm, table_y, str(_t("Description")))
    p.drawString(10*cm, table_y, str(_t("Quantity")))
    p.drawString(12*cm, table_y, str(_t("Unit Price")))
    p.drawString(15*cm, table_y, str(_t("Total")))

    # Draw line under headers
    p.line(2*cm, table_y - 0.3*cm, 18*cm, table_y - 0.3*cm)

    # Items data
    p.setFont("Helvetica", 9)
    current_y = table_y - 0.8*cm

    lines = proforma.lines.all()
    for line in lines:
        p.drawString(2*cm, current_y, str(line.description)[:40])  # Truncate long descriptions
        p.drawString(10*cm, current_y, f"{line.quantity:.2f}")
        p.drawString(12*cm, current_y, f"{line.unit_price:.2f} RON")
        p.drawString(15*cm, current_y, f"{line.line_total:.2f} RON")
        current_y -= 0.5*cm

    # Totals section
    totals_y = current_y - 1*cm
    p.setFont("Helvetica-Bold", 12)
    p.drawString(12*cm, totals_y, str(_t("Subtotal: {amount} RON")).format(amount=f"{proforma.subtotal:.2f}"))
    p.drawString(12*cm, totals_y - 0.5*cm, str(_t("VAT (19%): {amount} RON")).format(amount=f"{proforma.tax_amount:.2f}"))
    p.drawString(12*cm, totals_y - 1*cm, str(_t("TOTAL: {amount} RON")).format(amount=f"{proforma.total:.2f}"))

    # Footer with legal disclaimers
    p.setFont("Helvetica", 8)
    p.drawString(2*cm, 2*cm, str(_t("This proforma is not a fiscal invoice.")))
    p.drawString(2*cm, 1.5*cm, str(_t("Generated automatically by {platform}")).format(platform=company_name))

    # Finalize PDF
    p.showPage()
    p.save()

    # Return response
    buffer.seek(0)
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="proforma_{proforma.number}.pdf"'

    return response


@login_required
def proforma_send(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📧 Send proforma via email to customer
    """
    proforma = get_object_or_404(ProformaInvoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(proforma.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # TODO: Implement email sending with Romanian template
        messages.success(request, _("✅ Proforma #{proforma_number} has been sent successfully!").format(proforma_number=proforma.number))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@login_required
def invoice_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """
    ✏️ Edit draft invoice
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security and business rule checks
    if not request.user.can_access_customer(invoice.customer):
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
        'items': invoice.items.all(),
    }

    return render(request, 'billing/invoice_form.html', context)


@login_required
def invoice_pdf(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📄 Generate PDF invoice (Romanian format) using ReportLab
    """
    from io import BytesIO

    from django.conf import settings
    from django.utils.translation import (
        gettext as _t,  # Use gettext for immediate evaluation
    )
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas

    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(invoice.customer):
        messages.error(request, _("❌ You do not have permission to access this invoice."))
        return redirect('billing:invoice_list')

    # Create PDF buffer
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # ===============================================================================
    # COMPANY INFO FROM SETTINGS 🏢
    # ===============================================================================

    # Get company info from settings (with fallbacks)
    company_name = getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')
    company_address = getattr(settings, 'COMPANY_ADDRESS', 'Str. Exemplu Nr. 1')
    company_city = getattr(settings, 'COMPANY_CITY', 'București')
    company_country = getattr(settings, 'COMPANY_COUNTRY', 'România')
    company_cui = getattr(settings, 'COMPANY_CUI', 'RO12345678')
    company_email = getattr(settings, 'COMPANY_EMAIL', 'contact@praho.ro')

    # ===============================================================================
    # PDF CONTENT GENERATION 📄
    # ===============================================================================

    # Header with company branding
    p.setFont("Helvetica-Bold", 24)
    p.drawString(2*cm, height - 3*cm, f"🇷🇴 {company_name}")

    p.setFont("Helvetica-Bold", 16)
    p.drawString(2*cm, height - 4*cm, str(_t("FISCAL INVOICE")))

    p.setFont("Helvetica", 12)
    p.drawString(2*cm, height - 5*cm, str(_t("Number: {number}")).format(number=invoice.number))
    if invoice.issued_at:
        p.drawString(2*cm, height - 5.5*cm, str(_t("Issue date: {date}")).format(date=invoice.issued_at.strftime('%d.%m.%Y')))
    if invoice.due_at:
        p.drawString(2*cm, height - 6*cm, str(_t("Due date: {date}")).format(date=invoice.due_at.strftime('%d.%m.%Y')))

    # Status indicator
    p.setFont("Helvetica-Bold", 10)
    p.drawString(14*cm, height - 5*cm, str(_t("Status: {status}")).format(status=invoice.status.upper()))

    # Company info section
    y_pos = height - 8*cm
    p.setFont("Helvetica-Bold", 14)
    p.drawString(2*cm, y_pos, str(_t("Supplier:")))

    p.setFont("Helvetica", 10)
    p.drawString(2*cm, y_pos - 0.5*cm, company_name)
    p.drawString(2*cm, y_pos - 1*cm, f"{company_address}, {company_city}, {company_country}")
    p.drawString(2*cm, y_pos - 1.5*cm, str(_t("Tax ID: {cui}")).format(cui=company_cui))
    p.drawString(2*cm, y_pos - 2*cm, str(_t("Email: {email}")).format(email=company_email))

    # Client info section
    p.setFont("Helvetica-Bold", 14)
    p.drawString(11*cm, y_pos, str(_t("Client:")))

    p.setFont("Helvetica", 10)
    p.drawString(11*cm, y_pos - 0.5*cm, invoice.bill_to_name or "")
    if invoice.bill_to_address1:
        p.drawString(11*cm, y_pos - 1*cm, invoice.bill_to_address1)
    if invoice.bill_to_tax_id:
        p.drawString(11*cm, y_pos - 1.5*cm, str(_t("Tax ID: {tax_id}")).format(tax_id=invoice.bill_to_tax_id))
    if invoice.bill_to_email:
        p.drawString(11*cm, y_pos - 2*cm, str(_t("Email: {email}")).format(email=invoice.bill_to_email))

    # Items table headers
    table_y = height - 13*cm
    p.setFont("Helvetica-Bold", 10)
    p.drawString(2*cm, table_y, str(_t("Description")))
    p.drawString(10*cm, table_y, str(_t("Quantity")))
    p.drawString(12*cm, table_y, str(_t("Unit Price")))
    p.drawString(15*cm, table_y, str(_t("Total")))

    # Draw line under headers
    p.line(2*cm, table_y - 0.3*cm, 18*cm, table_y - 0.3*cm)

    # Items data
    p.setFont("Helvetica", 9)
    current_y = table_y - 0.8*cm

    lines = invoice.lines.all()
    for line in lines:
        p.drawString(2*cm, current_y, str(line.description)[:40])  # Truncate long descriptions
        p.drawString(10*cm, current_y, f"{line.quantity:.2f}")
        p.drawString(12*cm, current_y, f"{line.unit_price:.2f} RON")
        p.drawString(15*cm, current_y, f"{line.line_total:.2f} RON")
        current_y -= 0.5*cm

    # Totals section
    totals_y = current_y - 1*cm
    p.setFont("Helvetica-Bold", 12)
    p.drawString(12*cm, totals_y, str(_t("Subtotal: {amount} RON")).format(amount=f"{invoice.subtotal:.2f}"))
    p.drawString(12*cm, totals_y - 0.5*cm, str(_t("VAT (19%): {amount} RON")).format(amount=f"{invoice.tax_amount:.2f}"))
    p.drawString(12*cm, totals_y - 1*cm, str(_t("TOTAL TO PAY: {amount} RON")).format(amount=f"{invoice.total:.2f}"))

    # Payment status info
    if invoice.status != 'paid':
        p.setFont("Helvetica-Bold", 10)
        due_date_str = invoice.due_at.strftime('%d.%m.%Y') if invoice.due_at else str(_t("undefined"))
        p.drawString(2*cm, totals_y - 2*cm, str(_t("⚠️  Unpaid invoice - Due: {date}")).format(date=due_date_str))
    elif invoice.status == 'paid' and hasattr(invoice, 'paid_at') and invoice.paid_at:
        p.setFont("Helvetica-Bold", 10)
        p.drawString(2*cm, totals_y - 2*cm, str(_t("✅ Invoice paid on: {date}")).format(date=invoice.paid_at.strftime('%d.%m.%Y')))

    # Footer with legal disclaimers
    p.setFont("Helvetica", 8)
    p.drawString(2*cm, 2*cm, str(_t("Fiscal invoice issued according to Romanian legislation.")))
    p.drawString(2*cm, 1.5*cm, str(_t("Generated automatically by {platform}")).format(platform=company_name))

    # Finalize PDF
    p.showPage()
    p.save()

    # Return response
    buffer.seek(0)
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="factura_{invoice.number}.pdf"'

    return response


@login_required
def invoice_send(request: HttpRequest, pk: int) -> HttpResponse:
    """
    📧 Send invoice via email to customer
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(invoice.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        # TODO: Implement email sending with Romanian template
        # Update invoice status to sent
        invoice.status = 'sent'
        invoice.sent_at = timezone.now()
        invoice.save()

        messages.success(request, _("✅ Invoice #{invoice_number} has been sent successfully!").format(invoice_number=invoice.number))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@login_required
def generate_e_factura(request: HttpRequest, pk: int) -> HttpResponse:
    """
    🇷🇴 Generate e-Factura XML for Romanian tax authorities
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(invoice.customer):
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
        'total_amount': payments.aggregate(total=Sum('amount'))['total'] or Decimal('0'),
    }

    return render(request, 'billing/payment_list.html', context)


@login_required
def process_payment(request: HttpRequest, pk: int) -> HttpResponse:
    """
    💳 Process payment for invoice
    """
    invoice = get_object_or_404(Invoice, pk=pk)

    # Security check
    if not request.user.can_access_customer(invoice.customer):
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    if request.method == 'POST':
        amount = Decimal(request.POST.get('amount', '0'))
        payment_method = request.POST.get('payment_method', 'bank_transfer')

        # Create payment record
        Payment.objects.create(
            invoice=invoice,
            amount=amount,
            payment_method=payment_method,
            status='completed',  # Simplified - would integrate with payment gateway
        )

        # Update invoice status if fully paid
        if invoice.get_remaining_amount() <= 0:
            invoice.status = 'paid'
            invoice.paid_at = timezone.now()
            invoice.save()

        messages.success(request, _("✅ Payment of {amount} RON has been registered!").format(amount=amount))
        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Invalid method'}, status=405)


@login_required
def billing_reports(request: HttpRequest) -> HttpResponse:
    """
    📊 Billing reports and analytics
    """
    customer_ids = _get_accessible_customer_ids(request.user)

    # Monthly revenue
    from django.db.models import Count
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


@login_required
def vat_report(request: HttpRequest) -> HttpResponse:
    """
    🇷🇴 VAT report for Romanian tax compliance
    """
    customer_ids = _get_accessible_customer_ids(request.user)

    # VAT calculations for the selected period
    start_date = request.GET.get('start_date', timezone.now().replace(day=1).date())
    end_date = request.GET.get('end_date', timezone.now().date())

    invoices = Invoice.objects.filter(
        customer_id__in=customer_ids,
        created_at__date__range=[start_date, end_date],
        status__in=['sent', 'paid']
    )

    total_vat = invoices.aggregate(total_vat=Sum('vat_amount'))['total_vat'] or Decimal('0')
    total_net = invoices.aggregate(total_net=Sum('subtotal_cents'))['total_net'] or Decimal('0')

    context = {
        'invoices': invoices,
        'total_vat': total_vat,
        'total_net': total_net,
        'start_date': start_date,
        'end_date': end_date,
    }

    return render(request, 'billing/vat_report.html', context)
