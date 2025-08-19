"""
Django admin configuration for Customers app
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import Customer, CustomerAddress, CustomerBillingProfile


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """Customer admin with Romanian business support"""
    
    list_display = [
        'name', 'customer_type', 'primary_email', 'status',
        'company_name', 'created_at'
    ]
    
    list_filter = [
        'customer_type', 'status', 'created_at', 'updated_at'
    ]
    
    search_fields = [
        'name', 'company_name', 'primary_email', 'primary_phone'
    ]
    
    fieldsets = (
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
    
    readonly_fields = ['created_at', 'updated_at']


@admin.register(CustomerAddress)
class CustomerAddressAdmin(admin.ModelAdmin):
    """Customer address admin"""
    
    list_display = [
        'customer', 'address_type', 'county', 'city', 'is_current'
    ]
    
    list_filter = ['address_type', 'county', 'is_current']
    
    search_fields = [
        'customer__name', 'address_line1', 'city', 'county'
    ]
    
    fieldsets = (
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
    
    list_display = [
        'customer', 'payment_terms', 'preferred_currency', 'auto_payment_enabled'
    ]
    
    list_filter = ['payment_terms', 'preferred_currency', 'auto_payment_enabled']
    
    search_fields = ['customer__name']
    
    fieldsets = (
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
