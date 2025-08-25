"""
Django admin configuration for billing models.
Romanian hosting provider billing management with VAT compliance.
"""

from decimal import Decimal

from django.contrib import admin
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _

from .models import (
    CreditLedger,
    Currency,
    FXRate,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    Payment,
    PaymentCollectionRun,
    PaymentRetryAttempt,
    PaymentRetryPolicy,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
    TaxRule,
    VATValidation,
)

# ===============================================================================
# CURRENCY & FX ADMIN
# ===============================================================================

@admin.register(Currency)
class CurrencyAdmin(admin.ModelAdmin):
    """Currency management"""

    list_display = ['code', 'symbol', 'decimals']
    search_fields = ['code', 'symbol']
    ordering = ['code']


@admin.register(FXRate)
class FXRateAdmin(admin.ModelAdmin):
    """Foreign exchange rates"""

    list_display = ['base_code', 'quote_code', 'rate', 'as_of']
    list_filter = ['base_code', 'quote_code', 'as_of']
    ordering = ['-as_of', 'base_code', 'quote_code']
    date_hierarchy = 'as_of'


# ===============================================================================
# SEQUENCING ADMIN
# ===============================================================================

@admin.register(InvoiceSequence)
class InvoiceSequenceAdmin(admin.ModelAdmin):
    """Invoice numbering sequences"""

    list_display = ['scope', 'last_value', 'next_number_preview']
    search_fields = ['scope']

    def next_number_preview(self, obj: InvoiceSequence) -> str:
        """Preview next number without incrementing"""
        return f"INV-{obj.last_value + 1:06d}"
    next_number_preview.short_description = _('Next Number')


@admin.register(ProformaSequence)
class ProformaSequenceAdmin(admin.ModelAdmin):
    """Proforma invoice numbering sequences"""

    list_display = ['scope', 'last_value', 'next_number_preview']
    search_fields = ['scope']

    def next_number_preview(self, obj: ProformaSequence) -> str:
        """Preview next number without incrementing"""
        return f"PRO-{obj.last_value + 1:06d}"
    next_number_preview.short_description = _('Next Number')


# ===============================================================================
# PROFORMA INVOICE ADMIN
# ===============================================================================

class ProformaLineInline(admin.TabularInline):
    """Proforma invoice line items"""
    model = ProformaLine
    extra = 0
    readonly_fields = ['line_total_display']

    def line_total_display(self, obj: ProformaLine) -> str:
        if obj.pk:
            return f"€{obj.line_total:.2f}"
        return "-"
    line_total_display.short_description = _('Line Total')


@admin.register(ProformaInvoice)
class ProformaInvoiceAdmin(admin.ModelAdmin):
    """Proforma invoice management"""

    list_display = [
        'number',
        'customer',
        'total_display',
        'currency',
        'valid_until',
        'is_expired_display',
        'created_at',
    ]
    list_filter = [
        'currency',
        'created_at',
        'valid_until',
    ]
    search_fields = [
        'number',
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'bill_to_name',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = [
        'number',
        'subtotal_display',
        'tax_display',
        'total_display',
        'created_at',
    ]
    inlines = [ProformaLineInline]

    fieldsets = (
        (_('Proforma Information'), {
            'fields': (
                'number',
                'customer',
                'currency',
                'valid_until',
                'created_at',
            )
        }),
        (_('Amounts'), {
            'fields': (
                'subtotal_display',
                'tax_display',
                'total_display',
            )
        }),
        (_('Billing Address'), {
            'fields': (
                'bill_to_name',
                'bill_to_tax_id',
                'bill_to_email',
                'bill_to_address1',
                'bill_to_address2',
                'bill_to_city',
                'bill_to_region',
                'bill_to_postal',
                'bill_to_country',
            ),
            'classes': ('collapse',),
        }),
        (_('Files & Metadata'), {
            'fields': (
                'pdf_file',
                'meta',
            ),
            'classes': ('collapse',),
        }),
    )

    def total_display(self, obj: ProformaInvoice) -> str:
        return f"{obj.currency.symbol}{obj.total:.2f}"
    total_display.short_description = _('Total')

    def subtotal_display(self, obj: ProformaInvoice) -> str:
        return f"{obj.currency.symbol}{obj.subtotal:.2f}"
    subtotal_display.short_description = _('Subtotal')

    def tax_display(self, obj: ProformaInvoice) -> str:
        return f"{obj.currency.symbol}{obj.tax_amount:.2f}"
    tax_display.short_description = _('Tax')

    def is_expired_display(self, obj: ProformaInvoice) -> SafeString:
        if obj.is_expired:
            return format_html('<span style="color: red;">❌ Expired</span>')
        return format_html('<span style="color: green;">✅ Valid</span>')
    is_expired_display.short_description = _('Status')


# ===============================================================================
# INVOICE ADMIN
# ===============================================================================

class InvoiceLineInline(admin.TabularInline):
    """Invoice line items"""
    model = InvoiceLine
    extra = 0
    readonly_fields = ['line_total_display']

    def line_total_display(self, obj) -> str:
        if obj.pk:
            return f"€{obj.line_total:.2f}"
        return "-"
    line_total_display.short_description = _('Line Total')


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    """Romanian compliant invoice management"""

    list_display = [
        'number',
        'customer',
        'status_display',
        'total_display',
        'currency',
        'issued_at',
        'due_at',
        'efactura_status',
    ]
    list_filter = [
        'status',
        'currency',
        'issued_at',
        'due_at',
        'efactura_sent',
        'created_at',
    ]
    search_fields = [
        'number',
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'bill_to_name',
        'efactura_id',
    ]
    date_hierarchy = 'issued_at'
    readonly_fields = [
        'number',
        'subtotal_display',
        'tax_display',
        'total_display',
        'created_at',
        'updated_at',
        'locked_at',
        'remaining_amount_display',
    ]
    inlines = [InvoiceLineInline]

    fieldsets = (
        (_('Invoice Information'), {
            'fields': (
                'number',
                'customer',
                'status',
                'currency',
                'exchange_to_ron',
                'created_by',
                'converted_from_proforma',
            )
        }),
        (_('Dates'), {
            'fields': (
                'created_at',
                'updated_at',
                'issued_at',
                'due_at',
                'sent_at',
                'paid_at',
                'locked_at',
            )
        }),
        (_('Amounts'), {
            'fields': (
                'subtotal_display',
                'tax_display',
                'total_display',
                'remaining_amount_display',
            )
        }),
        (_('e-Factura (Romanian)'), {
            'fields': (
                'efactura_id',
                'efactura_sent',
                'efactura_sent_date',
                'efactura_response',
            ),
            'classes': ('collapse',),
        }),
        (_('Billing Address'), {
            'fields': (
                'bill_to_name',
                'bill_to_tax_id',
                'bill_to_email',
                'bill_to_address1',
                'bill_to_address2',
                'bill_to_city',
                'bill_to_region',
                'bill_to_postal',
                'bill_to_country',
            ),
            'classes': ('collapse',),
        }),
        (_('Files & Metadata'), {
            'fields': (
                'pdf_file',
                'xml_file',
                'meta',
            ),
            'classes': ('collapse',),
        }),
    )

    def status_display(self, obj):
        """Display status with colors"""
        colors = {
            'draft': 'orange',
            'issued': 'blue',
            'paid': 'green',
            'overdue': 'red',
            'void': 'gray',
            'refunded': 'purple',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def total_display(self, obj) -> str:
        return f"{obj.currency.symbol}{obj.total:.2f}"
    total_display.short_description = _('Total')

    def subtotal_display(self, obj) -> str:
        return f"{obj.currency.symbol}{obj.subtotal:.2f}"
    subtotal_display.short_description = _('Subtotal')

    def tax_display(self, obj) -> str:
        return f"{obj.currency.symbol}{obj.tax_amount:.2f}"
    tax_display.short_description = _('Tax')

    def remaining_amount_display(self, obj):
        remaining_cents = obj.get_remaining_amount()
        remaining = Decimal(remaining_cents) / 100
        if remaining > 0:
            return format_html(
                '<span style="color: red;">{}{:.2f}</span>',
                obj.currency.symbol,
                remaining
            )
        return format_html('<span style="color: green;">Paid</span>')
    remaining_amount_display.short_description = _('Remaining')

    def efactura_status(self, obj):
        """e-Factura submission status"""
        if obj.efactura_sent:
            return format_html(
                '<span style="color: green;">✅ Sent</span><br/>'
                '<small>{}</small>',
                obj.efactura_id or 'No ID'
            )
        return format_html('<span style="color: orange;">⏳ Pending</span>')
    efactura_status.short_description = _('e-Factura')

    actions = ['mark_as_paid', 'send_efactura']

    def mark_as_paid(self, request, queryset) -> None:
        """Mark selected invoices as paid"""
        updated = 0
        for invoice in queryset:
            if invoice.status in ['issued', 'overdue']:
                invoice.mark_as_paid()
                updated += 1

        self.message_user(
            request,
            f'Successfully marked {updated} invoices as paid.'
        )
    mark_as_paid.short_description = _('Mark as paid')


# ===============================================================================
# PAYMENT ADMIN
# ===============================================================================

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    """Payment tracking administration"""

    list_display = [
        'received_at',
        'customer',
        'invoice',
        'amount_display',
        'currency',
        'method',
        'status_display',
        'reference_number',
    ]
    list_filter = [
        'status',
        'method',
        'currency',
        'received_at',
        'created_at',
    ]
    search_fields = [
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'invoice__number',
        'gateway_txn_id',
        'reference_number',
    ]
    date_hierarchy = 'received_at'
    readonly_fields = [
        'amount_display',
        'created_at',
    ]

    fieldsets = (
        (_('Payment Information'), {
            'fields': (
                'customer',
                'invoice',
                'status',
                'method',
                'amount_display',
                'currency',
                'received_at',
                'created_at',
                'created_by',
            )
        }),
        (_('Gateway Information'), {
            'fields': (
                'gateway_txn_id',
                'reference_number',
                'meta',
                'notes',
            ),
            'classes': ('collapse',),
        }),
    )

    def amount_display(self, obj) -> str:
        return f"{obj.currency.symbol}{obj.amount:.2f}"
    amount_display.short_description = _('Amount')

    def status_display(self, obj):
        """Display status with colors"""
        colors = {
            'pending': 'orange',
            'succeeded': 'green',
            'failed': 'red',
            'refunded': 'purple',
            'partially_refunded': 'blue',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')


# ===============================================================================
# CREDIT LEDGER ADMIN
# ===============================================================================

@admin.register(CreditLedger)
class CreditLedgerAdmin(admin.ModelAdmin):
    """Customer credit/balance tracking"""

    list_display = [
        'created_at',
        'customer',
        'delta_display',
        'reason',
        'invoice',
        'payment',
        'created_by',
    ]
    list_filter = [
        'created_at',
    ]
    search_fields = [
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'reason',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = ['created_at', 'delta_display']

    fieldsets = (
        (_('Credit Entry'), {
            'fields': (
                'customer',
                'delta_display',
                'reason',
                'created_at',
                'created_by',
            )
        }),
        (_('Related Objects'), {
            'fields': (
                'invoice',
                'payment',
            )
        }),
    )

    def delta_display(self, obj):
        """Display credit change with color"""
        if obj.delta >= 0:
            return format_html(
                '<span style="color: green;">+€{:.2f}</span>',
                obj.delta
            )
        else:
            return format_html(
                '<span style="color: red;">€{:.2f}</span>',
                obj.delta
            )
    delta_display.short_description = _('Credit Change')

    def get_queryset(self, request):
        """Order by most recent first"""
        return super().get_queryset(request).order_by('-created_at')


# ===============================================================================
# TAX & VAT COMPLIANCE ADMIN
# ===============================================================================

@admin.register(TaxRule)
class TaxRuleAdmin(admin.ModelAdmin):
    """Tax rule management for EU VAT compliance"""

    list_display = [
        'country_code', 'tax_type', 'rate_display', 'valid_from',
        'valid_to', 'is_eu_member', 'reverse_charge_eligible', 'is_active_now'
    ]
    list_filter = [
        'tax_type', 'is_eu_member', 'reverse_charge_eligible',
        'applies_to_b2b', 'applies_to_b2c', 'vies_required'
    ]
    search_fields = ['country_code', 'region']
    date_hierarchy = 'valid_from'

    fieldsets = (
        ('Geographic Scope', {
            'fields': ('country_code', 'region')
        }),
        ('Tax Configuration', {
            'fields': ('tax_type', 'rate', 'reduced_rate')
        }),
        ('Validity Period', {
            'fields': ('valid_from', 'valid_to')
        }),
        ('Business Rules', {
            'fields': ('applies_to_b2b', 'applies_to_b2c', 'reverse_charge_eligible')
        }),
        ('EU Compliance', {
            'fields': ('is_eu_member', 'vies_required'),
            'classes': ('collapse',)
        }),
        ('Additional Configuration', {
            'fields': ('meta',),
            'classes': ('collapse',)
        })
    )

    readonly_fields = ('created_at', 'updated_at')

    def rate_display(self, obj) -> str:
        """Display rate as percentage"""
        return f"{obj.rate * 100:.2f}%"
    rate_display.short_description = _('Rate')

    def is_active_now(self, obj):
        """Show if rule is currently active"""
        return obj.is_active()
    is_active_now.boolean = True
    is_active_now.short_description = _('Active Now')

    def get_queryset(self, request):
        """Order by country and validity"""
        return super().get_queryset(request).select_related().order_by(
            'country_code', 'tax_type', '-valid_from'
        )


@admin.register(VATValidation)
class VATValidationAdmin(admin.ModelAdmin):
    """VAT number validation results"""

    list_display = [
        'full_vat_number', 'company_name', 'is_valid', 'is_active',
        'validation_date', 'validation_source', 'is_expired_now'
    ]
    list_filter = [
        'is_valid', 'is_active', 'validation_source', 'country_code'
    ]
    search_fields = ['full_vat_number', 'vat_number', 'company_name']
    readonly_fields = ('validation_date',)
    date_hierarchy = 'validation_date'

    fieldsets = (
        ('VAT Number', {
            'fields': ('country_code', 'vat_number', 'full_vat_number')
        }),
        ('Validation Results', {
            'fields': ('is_valid', 'is_active', 'company_name', 'company_address')
        }),
        ('Validation Metadata', {
            'fields': ('validation_date', 'validation_source', 'expires_at')
        }),
        ('Raw Response Data', {
            'fields': ('response_data',),
            'classes': ('collapse',)
        })
    )

    def is_expired_now(self, obj):
        """Show if validation has expired"""
        return obj.is_expired()
    is_expired_now.boolean = True
    is_expired_now.short_description = _('Expired')

    def get_queryset(self, request):
        """Order by most recent validations"""
        return super().get_queryset(request).order_by('-validation_date')


# ===============================================================================
# PAYMENT COLLECTION & DUNNING ADMIN
# ===============================================================================

@admin.register(PaymentRetryPolicy)
class PaymentRetryPolicyAdmin(admin.ModelAdmin):
    """Payment retry policy management"""

    list_display = [
        'name', 'max_attempts', 'retry_schedule_display',
        'suspend_after_days', 'is_default', 'is_active'
    ]
    list_filter = ['is_default', 'is_active', 'send_dunning_emails']
    search_fields = ['name', 'description']

    fieldsets = (
        ('Policy Information', {
            'fields': ('name', 'description', 'is_default', 'is_active')
        }),
        ('Retry Configuration', {
            'fields': ('retry_intervals_days', 'max_attempts')
        }),
        ('Service Actions', {
            'fields': ('suspend_service_after_days', 'terminate_service_after_days')
        }),
        ('Communication Settings', {
            'fields': ('send_dunning_emails', 'email_template_prefix')
        }),
        ('Additional Configuration', {
            'fields': ('meta',),
            'classes': ('collapse',)
        })
    )

    readonly_fields = ('created_at', 'updated_at')

    def retry_schedule_display(self, obj):
        """Display retry schedule in readable format"""
        if not obj.retry_intervals_days:
            return "No retries"
        intervals = obj.retry_intervals_days[:5]  # Show first 5
        schedule = ", ".join(f"Day {day}" for day in intervals)
        if len(obj.retry_intervals_days) > 5:
            schedule += "..."
        return schedule
    retry_schedule_display.short_description = _('Retry Schedule')

    def suspend_after_days(self, obj) -> str:
        """Display suspension period"""
        return f"{obj.suspend_service_after_days} days" if obj.suspend_service_after_days else "Never"
    suspend_after_days.short_description = _('Suspend After')


@admin.register(PaymentRetryAttempt)
class PaymentRetryAttemptAdmin(admin.ModelAdmin):
    """Payment retry attempt tracking"""

    list_display = [
        'payment_link', 'attempt_number', 'status', 'scheduled_at',
        'executed_at', 'dunning_email_sent', 'policy'
    ]
    list_filter = [
        'status', 'policy', 'dunning_email_sent', 'scheduled_at'
    ]
    search_fields = ['payment__id', 'failure_reason']
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'scheduled_at'

    fieldsets = (
        ('Retry Information', {
            'fields': ('payment', 'policy', 'attempt_number')
        }),
        ('Scheduling', {
            'fields': ('scheduled_at', 'executed_at', 'status')
        }),
        ('Results', {
            'fields': ('failure_reason', 'gateway_response')
        }),
        ('Communication', {
            'fields': ('dunning_email_sent', 'dunning_email_sent_at')
        })
    )

    def payment_link(self, obj):
        """Link to payment admin"""
        url = reverse('admin:billing_payment_change', args=[obj.payment.id])
        return format_html('<a href="{}">{}</a>', url, str(obj.payment.id)[:8])
    payment_link.short_description = _('Payment')

    def get_queryset(self, request):
        """Optimize queries"""
        return super().get_queryset(request).select_related(
            'payment', 'policy'
        ).order_by('-scheduled_at')


@admin.register(PaymentCollectionRun)
class PaymentCollectionRunAdmin(admin.ModelAdmin):
    """Payment collection run monitoring"""

    list_display = [
        'started_at', 'run_type', 'status', 'duration_display',
        'success_rate_display', 'amount_recovered_display', 'triggered_by'
    ]
    list_filter = ['run_type', 'status', 'started_at']
    readonly_fields = (
        'started_at', 'completed_at', 'total_scheduled', 'total_processed',
        'total_successful', 'total_failed', 'amount_recovered_cents',
        'fees_charged_cents'
    )
    date_hierarchy = 'started_at'

    fieldsets = (
        ('Run Information', {
            'fields': ('run_type', 'triggered_by', 'status')
        }),
        ('Execution Timeline', {
            'fields': ('started_at', 'completed_at')
        }),
        ('Processing Results', {
            'fields': (
                'total_scheduled', 'total_processed', 'total_successful', 'total_failed'
            )
        }),
        ('Financial Impact', {
            'fields': ('amount_recovered_cents', 'fees_charged_cents')
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('Configuration Snapshot', {
            'fields': ('config_snapshot',),
            'classes': ('collapse',)
        })
    )

    def duration_display(self, obj) -> str:
        """Display run duration"""
        if not obj.completed_at:
            if obj.status == 'running':
                duration = timezone.now() - obj.started_at
                return f"Running ({duration.total_seconds():.0f}s)"
            return "N/A"

        duration = obj.completed_at - obj.started_at
        return f"{duration.total_seconds():.0f}s"
    duration_display.short_description = _('Duration')

    def success_rate_display(self, obj):
        """Display success rate percentage"""
        if obj.total_processed == 0:
            return "N/A"

        rate = (obj.total_successful / obj.total_processed) * 100
        color = "green" if rate >= 50 else "orange" if rate >= 25 else "red"
        return format_html(
            '<span style="color: {};">{:.1f}%</span>',
            color, rate
        )
    success_rate_display.short_description = _('Success Rate')

    def amount_recovered_display(self, obj):
        """Display recovered amount with currency"""
        if obj.amount_recovered_cents == 0:
            return "€0.00"

        amount = obj.amount_recovered
        return format_html(
            '<span style="color: green; font-weight: bold;">€{:.2f}</span>',
            amount
        )
    amount_recovered_display.short_description = _('Recovered Amount')

    def get_queryset(self, request):
        """Order by most recent runs"""
        return super().get_queryset(request).select_related('triggered_by').order_by('-started_at')
