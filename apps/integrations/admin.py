from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import WebhookDelivery, WebhookEvent

# ===============================================================================
# WEBHOOK EVENT ADMINISTRATION
# ===============================================================================

@admin.register(WebhookEvent)
class WebhookEventAdmin(admin.ModelAdmin):
    """🔄 Webhook event administration with deduplication tracking"""

    list_display = [
        'received_at',
        'source_display',
        'event_type_short',
        'status_display',
        'retry_count',
        'processing_time',
        'payload_size',
    ]
    list_filter = [
        'source',
        'status',
        'event_type',
        'received_at',
        'retry_count',
    ]
    search_fields = [
        'event_id',
        'event_type',
        'error_message',
        'ip_address',
    ]
    readonly_fields = [
        'id',
        'payload_hash',
        'processing_duration',
        'created_at',
        'updated_at',
    ]
    date_hierarchy = 'received_at'

    fieldsets = (
        (_('🔍 Event Information'), {
            'fields': (
                'id',
                'source',
                'event_id',
                'event_type',
                'status',
                'received_at',
                'processed_at',
            )
        }),
        (_('📋 Processing Details'), {
            'fields': (
                'retry_count',
                'next_retry_at',
                'error_message',
                'processing_duration',
            ),
            'classes': ('collapse',),
        }),
        (_('🌐 Request Information'), {
            'fields': (
                'ip_address',
                'user_agent',
                'signature',
                'headers',
            ),
            'classes': ('collapse',),
        }),
        (_('📦 Payload Data'), {
            'fields': (
                'payload',
                'payload_hash',
            ),
            'classes': ('collapse',),
        }),
        (_('📅 Timestamps'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def source_display(self, obj):
        """🔌 Display source with icon"""
        source_icons = {
            'stripe': '💳',
            'paypal': '🟡',
            'virtualmin': '🖥️',
            'cpanel': '🌐',
            'registrar_namecheap': '🏷️',
            'registrar_godaddy': '🏷️',
            'bank_bt': '🏦',
            'bank_bcr': '🏦',
            'efactura': '🇷🇴',
            'other': '🔌',
        }
        icon = source_icons.get(obj.source, '🔌')
        return f"{icon} {obj.get_source_display()}"
    source_display.short_description = _('Source')

    def event_type_short(self, obj):
        """📝 Shortened event type for display"""
        if len(obj.event_type) > 30:
            return f"{obj.event_type[:27]}..."
        return obj.event_type
    event_type_short.short_description = _('Event Type')

    def status_display(self, obj):
        """📊 Status with color indicators"""
        status_colors = {
            'pending': '#fbbf24',      # Yellow
            'processed': '#10b981',    # Green
            'failed': '#ef4444',       # Red
            'skipped': '#6b7280',      # Gray
        }
        color = status_colors.get(obj.status, '#6b7280')

        status_icons = {
            'pending': '⏳',
            'processed': '✅',
            'failed': '❌',
            'skipped': '⏭️',
        }
        icon = status_icons.get(obj.status, '❓')

        return format_html(
            '<span style="color: {};">{} {}</span>',
            color,
            icon,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def processing_time(self, obj):
        """⏱️ Processing duration"""
        if obj.processing_duration:
            seconds = obj.processing_duration.total_seconds()
            if seconds < 1:
                return f"{int(seconds * 1000)}ms"
            else:
                return f"{seconds:.1f}s"
        return "-"
    processing_time.short_description = _('Duration')

    def payload_size(self, obj):
        """📦 Payload size in KB"""
        import json
        payload_str = json.dumps(obj.payload)
        size_bytes = len(payload_str.encode('utf-8'))
        size_kb = size_bytes / 1024

        if size_kb < 1:
            return f"{size_bytes}B"
        else:
            return f"{size_kb:.1f}KB"
    payload_size.short_description = _('Size')

    def get_queryset(self, request):
        """🚀 Optimize admin queries"""
        return super().get_queryset(request).order_by('-received_at')


# ===============================================================================
# WEBHOOK DELIVERY ADMINISTRATION
# ===============================================================================

@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    """📤 Outgoing webhook delivery administration"""

    list_display = [
        'scheduled_at',
        'customer_link',
        'event_type',
        'status_display',
        'http_status',
        'retry_count',
        'delivery_time',
    ]
    list_filter = [
        'status',
        'event_type',
        'http_status',
        'scheduled_at',
        'retry_count',
    ]
    search_fields = [
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'endpoint_url',
        'event_type',
    ]
    readonly_fields = [
        'id',
        'created_at',
        'updated_at',
    ]
    date_hierarchy = 'scheduled_at'

    fieldsets = (
        (_('📤 Delivery Information'), {
            'fields': (
                'id',
                'customer',
                'endpoint_url',
                'event_type',
                'status',
            )
        }),
        (_('📋 Delivery Results'), {
            'fields': (
                'http_status',
                'response_body',
                'scheduled_at',
                'delivered_at',
            )
        }),
        (_('🔄 Retry Logic'), {
            'fields': (
                'retry_count',
                'next_retry_at',
            ),
            'classes': ('collapse',),
        }),
        (_('📦 Payload'), {
            'fields': (
                'payload',
            ),
            'classes': ('collapse',),
        }),
        (_('📅 Timestamps'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def customer_link(self, obj):
        """🔗 Link to customer admin"""
        url = reverse('admin:customers_customer_change', args=[obj.customer.id])
        return format_html('<a href="{}">{}</a>', url, str(obj.customer))
    customer_link.short_description = _('Customer')

    def status_display(self, obj):
        """📊 Status with color indicators"""
        status_colors = {
            'pending': '#fbbf24',      # Yellow
            'delivered': '#10b981',    # Green
            'failed': '#ef4444',       # Red
            'disabled': '#6b7280',     # Gray
        }
        color = status_colors.get(obj.status, '#6b7280')

        status_icons = {
            'pending': '⏳',
            'delivered': '✅',
            'failed': '❌',
            'disabled': '🚫',
        }
        icon = status_icons.get(obj.status, '❓')

        return format_html(
            '<span style="color: {};">{} {}</span>',
            color,
            icon,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def delivery_time(self, obj):
        """⏱️ Delivery duration"""
        if obj.delivered_at and obj.scheduled_at:
            duration = obj.delivered_at - obj.scheduled_at
            seconds = duration.total_seconds()
            if seconds < 1:
                return f"{int(seconds * 1000)}ms"
            else:
                return f"{seconds:.1f}s"
        return "-"
    delivery_time.short_description = _('Duration')

    def get_queryset(self, request):
        """🚀 Optimize admin queries"""
        return super().get_queryset(request).select_related(
            'customer'
        ).order_by('-scheduled_at')
