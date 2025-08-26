"""
Django admin configuration for orders app.
Romanian hosting provider order management interface.
"""


from typing import ClassVar

from django.contrib import admin

from .models import Order, OrderItem, OrderStatusHistory


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """Admin interface for orders."""

    list_display: ClassVar[list[str]] = (
        'order_number', 'customer', 'status', 'total_cents',
        'currency', 'created_at'
    )
    list_filter: ClassVar[list[str]] = (
        'status', 'currency', 'created_at', 'updated_at'
    )
    search_fields: ClassVar[list[str]] = (
        'order_number', 'customer__company_name', 'customer_email',
        'billing_company_name'
    )
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at', 'order_number')

    fieldsets: ClassVar[tuple] = (
        ('Order Information', {
            'fields': ('order_number', 'customer', 'status')
        }),
        ('Financial Details', {
            'fields': ('currency', 'subtotal_cents', 'tax_cents', 'total_cents')
        }),
        ('Billing Address', {
            'fields': (
                'billing_company_name', 'billing_contact_name', 'billing_email',
                'billing_phone', 'billing_address_line1', 'billing_address_line2',
                'billing_city', 'billing_county', 'billing_postal_code', 'billing_country'
            ),
            'classes': ('collapse',)
        }),
        ('Romanian Compliance', {
            'fields': ('billing_fiscal_code', 'billing_registration_number', 'billing_vat_number'),
            'classes': ('collapse',)
        }),
        ('Additional Information', {
            'fields': ('notes', 'meta'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )


class OrderItemInline(admin.TabularInline):
    """Inline admin for order items."""
    model = OrderItem
    extra = 0
    readonly_fields: ClassVar[list[str]] = ('created_at',)
    fields: ClassVar[list[str]] = (
        'product', 'service', 'quantity', 'unit_price_cents',
        'line_total_cents', 'provisioning_status', 'created_at'
    )


# Add the inline to OrderAdmin
OrderAdmin.inlines = [OrderItemInline]


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    """Admin interface for order items."""

    list_display: ClassVar[list[str]] = (
        'order', 'product', 'quantity', 'unit_price_cents',
        'line_total_cents', 'provisioning_status', 'created_at'
    )
    list_filter: ClassVar[list[str]] = ('provisioning_status', 'created_at')
    search_fields: ClassVar[list[str]] = (
        'order__order_number', 'product__name', 'description'
    )
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')

    fieldsets: ClassVar[tuple] = (
        ('Order & Product', {
            'fields': ('order', 'product', 'service')
        }),
        ('Pricing', {
            'fields': ('quantity', 'unit_price_cents', 'line_total_cents')
        }),
        ('Details', {
            'fields': ('description', 'provisioning_status')
        }),
        ('Additional Data', {
            'fields': ('meta',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )


@admin.register(OrderStatusHistory)
class OrderStatusHistoryAdmin(admin.ModelAdmin):
    """Admin interface for order status history."""

    list_display: ClassVar[list[str]] = (
        'order', 'old_status', 'new_status', 'changed_by', 'created_at'
    )
    list_filter: ClassVar[list[str]] = ('old_status', 'new_status', 'created_at')
    search_fields: ClassVar[list[str]] = ('order__order_number', 'notes')
    readonly_fields: ClassVar[list[str]] = ('created_at',)

    fieldsets: ClassVar[tuple] = (
        ('Status Change', {
            'fields': ('order', 'old_status', 'new_status', 'changed_by')
        }),
        ('Details', {
            'fields': ('notes',)
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        })
    )
