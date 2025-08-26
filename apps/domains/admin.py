"""
Django admin configuration for Domains app
"""


from typing import ClassVar

from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _

from apps.common.constants import (
    DAYS_CRITICAL_EXPIRY,
    DAYS_WARNING_EXPIRY,
    SUCCESS_RATE_EXCELLENT_THRESHOLD,
    SUCCESS_RATE_WARNING_THRESHOLD,
)

from .models import TLD, Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment


@admin.register(TLD)
class TLDAdmin(admin.ModelAdmin):
    """TLD management with pricing and configuration"""

    list_display: ClassVar[list[str]] = (
        'extension_display', 'description', 'registration_price_display',
        'renewal_price_display', 'profit_margin_display', 'is_active', 'is_featured'
    )
    
    list_filter: ClassVar[list[str]] = (
        'is_active', 'is_featured', 'requires_local_presence',
        'whois_privacy_available'
    )
    
    search_fields: ClassVar[list[str]] = ('extension', 'description')
    
    fieldsets: ClassVar[tuple] = (
        (_('Basic Information'), {
            'fields': ('extension', 'description', 'is_active', 'is_featured')
        }),
        (_('Pricing (in cents)'), {
            'fields': (
                'registration_price_cents', 'renewal_price_cents', 
                'transfer_price_cents', 'registrar_cost_cents',
                'redemption_fee_cents'
            )
        }),
        (_('Registration Periods'), {
            'fields': ('min_registration_period', 'max_registration_period')
        }),
        (_('Features'), {
            'fields': (
                'whois_privacy_available', 'grace_period_days',
                'requires_local_presence', 'special_requirements'
            )
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')

    def extension_display(self, obj: TLD) -> str:
        """Display TLD extension with dot prefix"""
        return f".{obj.extension}"
    extension_display.short_description = _('Extension')

    def registration_price_display(self, obj: TLD) -> str:
        """Display registration price in RON"""
        return f"{obj.registration_price:.2f} RON"
    registration_price_display.short_description = _('Registration Price')

    def renewal_price_display(self, obj: TLD) -> str:
        """Display renewal price in RON"""
        return f"{obj.renewal_price:.2f} RON"
    renewal_price_display.short_description = _('Renewal Price')

    def profit_margin_display(self, obj: TLD) -> SafeString:
        """Display profit margin with color coding"""
        margin_pct = obj.profit_margin_percentage
        
        if margin_pct >= SUCCESS_RATE_EXCELLENT_THRESHOLD:
            color = 'green'
            emoji = '💰'
        elif margin_pct >= SUCCESS_RATE_WARNING_THRESHOLD:
            color = 'orange'
            emoji = '💸'
        else:
            color = 'red'
            emoji = '📉'
        
        return format_html(
            '<span style="color: {};">{} {:.1f}%</span>',
            color, emoji, margin_pct
        )
    profit_margin_display.short_description = _('Profit Margin')


@admin.register(Registrar)
class RegistrarAdmin(admin.ModelAdmin):
    """Registrar management with API configuration"""

    list_display: ClassVar[list[str]] = (
        'display_name', 'status_display', 'total_domains',
        'supported_tlds_count', 'last_sync_at'
    )
    
    list_filter: ClassVar[list[str]] = ('status', 'currency', 'last_sync_at')
    
    search_fields: ClassVar[list[str]] = ('name', 'display_name', 'website_url')
    
    fieldsets: ClassVar[tuple] = (
        (_('Basic Information'), {
            'fields': ('name', 'display_name', 'website_url', 'status')
        }),
        (_('API Configuration'), {
            'fields': (
                'api_endpoint', 'api_username', 'api_key', 'api_secret'
            ),
            'classes': ('collapse',)
        }),
        (_('Webhooks'), {
            'fields': ('webhook_endpoint', 'webhook_secret'),
            'classes': ('collapse',)
        }),
        (_('Settings'), {
            'fields': (
                'default_nameservers', 'currency', 'monthly_fee_cents'
            )
        }),
        (_('Statistics'), {
            'fields': (
                'total_domains', 'last_sync_at', 'last_error'
            )
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at', 'total_domains', 'last_sync_at')

    def status_display(self, obj: Registrar) -> SafeString:
        """Display registrar status with colors"""
        status_colors = {
            'active': 'green',
            'suspended': 'orange',
            'disabled': 'red'
        }
        
        status_emojis = {
            'active': '🟢',
            'suspended': '🟡',
            'disabled': '🔴'
        }
        
        color = status_colors.get(obj.status, 'gray')
        emoji = status_emojis.get(obj.status, '❓')
        
        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, emoji, obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def supported_tlds_count(self, obj: Registrar) -> int:
        """Count of supported TLDs"""
        return obj.get_supported_tlds().count()
    supported_tlds_count.short_description = _('Supported TLDs')


@admin.register(TLDRegistrarAssignment)
class TLDRegistrarAssignmentAdmin(admin.ModelAdmin):
    """TLD-Registrar assignment management"""

    list_display: ClassVar[list[str]] = (
        'tld', 'registrar', 'is_primary_display', 'priority',
        'cost_override_display', 'is_active'
    )
    
    list_filter: ClassVar[list[str]] = ('is_primary', 'is_active', 'tld', 'registrar')
    
    search_fields: ClassVar[list[str]] = ('tld__extension', 'registrar__name')
    
    fieldsets: ClassVar[tuple] = (
        (_('Assignment'), {
            'fields': ('tld', 'registrar', 'is_primary', 'priority', 'is_active')
        }),
        (_('Cost Override'), {
            'fields': ('cost_override_cents',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')

    def is_primary_display(self, obj: TLDRegistrarAssignment) -> SafeString:
        """Display primary status with styling"""
        if obj.is_primary:
            return format_html('<span style="color: green; font-weight: bold;">⭐ Primary</span>')
        return format_html('<span style="color: gray;">Backup</span>')
    is_primary_display.short_description = _('Role')

    def cost_override_display(self, obj: TLDRegistrarAssignment) -> str:
        """Display cost override if set"""
        if obj.cost_override_cents:
            return f"{obj.cost_override_cents / 100:.2f} RON"
        return "-"
    cost_override_display.short_description = _('Cost Override')


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Domain management with lifecycle tracking"""

    list_display: ClassVar[list[str]] = (
        'name', 'customer', 'status_display', 'tld', 'registrar',
        'expires_at', 'days_until_expiry_display', 'auto_renew_display'
    )
    
    list_filter: ClassVar[list[str]] = (
        'status', 'tld', 'registrar', 'auto_renew', 'whois_privacy',
        'locked', 'expires_at'
    )
    
    search_fields: ClassVar[list[str]] = (
        'name', 'customer__name', 'customer__company_name',
        'registrar_domain_id', 'epp_code'
    )
    
    date_hierarchy = 'expires_at'
    
    readonly_fields: ClassVar[list[str]] = ('id', 'created_at', 'updated_at')
    
    fieldsets: ClassVar[tuple] = (
        (_('Domain Information'), {
            'fields': ('id', 'name', 'tld', 'status')
        }),
        (_('Ownership'), {
            'fields': ('customer', 'registrar')
        }),
        (_('Lifecycle'), {
            'fields': (
                'registered_at', 'expires_at', 'auto_renew'
            )
        }),
        (_('Registrar Data'), {
            'fields': ('registrar_domain_id', 'epp_code'),
            'classes': ('collapse',)
        }),
        (_('Settings'), {
            'fields': ('whois_privacy', 'locked', 'nameservers')
        }),
        (_('Billing'), {
            'fields': ('last_paid_amount_cents',)
        }),
        (_('Notifications'), {
            'fields': (
                'renewal_notices_sent', 'last_renewal_notice'
            ),
            'classes': ('collapse',)
        }),
        (_('Notes'), {
            'fields': ('notes',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    def status_display(self, obj: Domain) -> SafeString:
        """Display domain status with colors"""
        status_colors = {
            'pending': 'orange',
            'active': 'green',
            'expired': 'red',
            'suspended': 'orange',
            'transfer_in': 'blue',
            'transfer_out': 'blue',
            'cancelled': 'gray'
        }
        
        status_emojis = {
            'pending': '⏳',
            'active': '🟢',
            'expired': '🔴',
            'suspended': '🟡',
            'transfer_in': '📥',
            'transfer_out': '📤',
            'cancelled': '❌'
        }
        
        color = status_colors.get(obj.status, 'gray')
        emoji = status_emojis.get(obj.status, '❓')
        
        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, emoji, obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def days_until_expiry_display(self, obj: Domain) -> SafeString:
        """Display days until expiry with color coding"""
        days = obj.days_until_expiry
        
        if days is None:
            return format_html('<span style="color: gray;">-</span>')
        
        if days < 0:
            return format_html(
                '<span style="color: red; font-weight: bold;">❌ Expired {}</span>',
                abs(days)
            )
        elif days <= DAYS_CRITICAL_EXPIRY:
            return format_html(
                '<span style="color: red; font-weight: bold;">🚨 {} days</span>',
                days
            )
        elif days <= DAYS_WARNING_EXPIRY:
            return format_html(
                '<span style="color: orange;">⚠️ {} days</span>',
                days
            )
        else:
            return format_html(
                '<span style="color: green;">✅ {} days</span>',
                days
            )
    days_until_expiry_display.short_description = _('Expires In')

    def auto_renew_display(self, obj: Domain) -> SafeString:
        """Display auto-renew status"""
        if obj.auto_renew:
            return format_html('<span style="color: green;">🔄 Enabled</span>')
        return format_html('<span style="color: orange;">⏸️ Disabled</span>')
    auto_renew_display.short_description = _('Auto Renew')


@admin.register(DomainOrderItem)
class DomainOrderItemAdmin(admin.ModelAdmin):
    """Domain order items management"""

    list_display: ClassVar[list[str]] = (
        'domain_name', 'action_display', 'order', 'years',
        'total_price_display', 'domain_link'
    )
    
    list_filter: ClassVar[list[str]] = ('action', 'years', 'whois_privacy', 'auto_renew')
    
    search_fields: ClassVar[list[str]] = ('domain_name', 'order__order_number')
    
    fieldsets: ClassVar[tuple] = (
        (_('Order Information'), {
            'fields': ('order', 'domain_name', 'tld', 'action', 'years')
        }),
        (_('Pricing'), {
            'fields': ('unit_price_cents', 'total_price_cents')
        }),
        (_('Options'), {
            'fields': ('whois_privacy', 'auto_renew')
        }),
        (_('Transfer'), {
            'fields': ('epp_code',),
            'classes': ('collapse',)
        }),
        (_('Result'), {
            'fields': ('domain',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')

    def action_display(self, obj: DomainOrderItem) -> SafeString:
        """Display action with icons"""
        action_emojis = {
            'register': '🆕',
            'renew': '🔄',
            'transfer': '📥'
        }
        
        emoji = action_emojis.get(obj.action, '❓')
        return format_html(
            '{} {}',
            emoji, obj.get_action_display()
        )
    action_display.short_description = _('Action')

    def total_price_display(self, obj: DomainOrderItem) -> str:
        """Display total price in RON"""
        return f"{obj.total_price:.2f} RON"
    total_price_display.short_description = _('Total Price')

    def domain_link(self, obj: DomainOrderItem) -> SafeString:
        """Link to created domain if available"""
        if obj.domain:
            return format_html(
                '<a href="/admin/domains/domain/{}/change/">🌍 {}</a>',
                obj.domain.id, obj.domain.name
            )
        return format_html('<span style="color: gray;">Not created</span>')
    domain_link.short_description = _('Created Domain')
