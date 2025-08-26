"""
Django admin configuration for Customers app
"""


from typing import ClassVar

from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import Customer, CustomerAddress, CustomerBillingProfile


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """Customer admin with Romanian business support"""

    list_display: ClassVar[list[str]] = (
        'name', 'customer_type', 'primary_email', 'status',
        'company_name', 'created_at'
    )

    list_filter: ClassVar[list[str]] = (
        'customer_type', 'status', 'created_at', 'updated_at'
    )

    search_fields: ClassVar[list[str]] = (
        'name', 'company_name', 'primary_email', 'primary_phone'
    )

    fieldsets: ClassVar[tuple] = (
        (_('Basic Information'), {
            'fields': ('name', 'customer_type', 'company_name', 'status')
        }),
        (_('Contact Information'), {
            'fields': ('primary_email', 'primary_phone', 'website', 'industry')
        }),
        (_('GDPR Compliance'), {
            'fields': (
                'data_processing_consent', 'marketing_consent',
                'gdpr_consent_date'
            )
        }),
        (_('Account Management'), {
            'fields': ('assigned_account_manager',)
        }),
        (_('Audit Information'), {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')


@admin.register(CustomerAddress)
class CustomerAddressAdmin(admin.ModelAdmin):
    """Customer address admin"""

    list_display: ClassVar[list[str]] = (
        'customer', 'address_type', 'county', 'city', 'is_current'
    )

    list_filter: ClassVar[list[str]] = ('address_type', 'county', 'is_current')

    search_fields: ClassVar[list[str]] = (
        'customer__name', 'address_line1', 'city', 'county'
    )

    fieldsets: ClassVar[tuple] = (
        (_('Customer'), {
            'fields': ('customer', 'address_type', 'is_current')
        }),
        (_('Address Details'), {
            'fields': (
                'address_line1', 'address_line2', 'city', 'county',
                'postal_code', 'country'
            )
        }),
        (_('Validation'), {
            'fields': ('is_validated', 'validated_at')
        })
    )


@admin.register(CustomerBillingProfile)
class CustomerBillingProfileAdmin(admin.ModelAdmin):
    """Customer billing profile admin"""

    list_display: ClassVar[list[str]] = (
        'customer', 'payment_terms', 'preferred_currency', 'auto_payment_enabled'
    )

    list_filter: ClassVar[list[str]] = ('payment_terms', 'preferred_currency', 'auto_payment_enabled')

    search_fields: ClassVar[tuple[str, ...]] = ('customer__name',)

    fieldsets: ClassVar[tuple] = (
        (_('Customer'), {
            'fields': ('customer',)
        }),
        (_('Payment Terms'), {
            'fields': (
                'payment_terms', 'credit_limit', 'preferred_currency'
            )
        }),
        (_('Billing Preferences'), {
            'fields': ('invoice_delivery_method', 'auto_payment_enabled')
        })
    )
