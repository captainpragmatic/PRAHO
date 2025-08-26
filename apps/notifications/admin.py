"""
Django admin for notifications app.
Email templates and communication logging for Romanian hosting provider.
"""

from __future__ import annotations

from typing import ClassVar

from django import forms
from django.contrib import admin
from django.http import HttpRequest
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _

from apps.common.constants import EXCELLENT_SUCCESS_RATE, GOOD_SUCCESS_RATE

from .models import EmailCampaign, EmailLog, EmailTemplate

# ===============================================================================
# EMAIL TEMPLATE ADMIN
# ===============================================================================

@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    """Admin interface for email templates"""

    list_display: ClassVar[list[str]] = (
        'key', 'locale', 'get_subject_display', 'category',
        'is_active', 'version', 'created_at'
    )
    list_filter: ClassVar[list[str]] = (
        'category', 'locale', 'is_active', 'created_at'
    )
    search_fields: ClassVar[list[str]] = ('key', 'subject', 'description')
    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')

    fieldsets: ClassVar[tuple] = (
        (_('Template Identification'), {
            'fields': ('key', 'locale', 'category', 'description')
        }),
        (_('Content'), {
            'fields': ('subject', 'body_html', 'body_text'),
            'classes': ('wide',)
        }),
        (_('Configuration'), {
            'fields': ('variables', 'is_active', 'version')
        }),
        (_('Audit'), {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_subject_display(self, obj: EmailTemplate) -> str:
        """Display truncated subject"""
        return obj.get_subject_display()
    get_subject_display.short_description = _('Subject')

    def save_model(self, request: HttpRequest, obj: EmailTemplate, form: forms.ModelForm, change: bool) -> None:
        """Set created_by on new templates"""
        if not change and not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


# ===============================================================================
# EMAIL LOG ADMIN
# ===============================================================================

@admin.register(EmailLog)
class EmailLogAdmin(admin.ModelAdmin):
    """Admin interface for email delivery logs"""

    list_display: ClassVar[list[str]] = (
        'subject', 'to_addr', 'get_status_display_colored',
        'provider', 'template_key', 'sent_at'
    )
    list_filter: ClassVar[list[str]] = (
        'status', 'provider', 'priority', 'sent_at'
    )
    search_fields: ClassVar[list[str]] = ('to_addr', 'subject', 'template_key')
    readonly_fields: ClassVar[list[str]] = (
        'sent_at', 'delivered_at', 'opened_at', 'clicked_at',
        'provider_response', 'meta'
    )
    date_hierarchy = 'sent_at'

    fieldsets: ClassVar[tuple] = (
        (_('Email Details'), {
            'fields': ('to_addr', 'from_addr', 'reply_to', 'subject')
        }),
        (_('Template & Content'), {
            'fields': ('template_key', 'body_text', 'body_html'),
            'classes': ('collapse',)
        }),
        (_('Delivery Status'), {
            'fields': ('status', 'provider', 'provider_id', 'priority')
        }),
        (_('Timing'), {
            'fields': ('sent_at', 'delivered_at', 'opened_at', 'clicked_at')
        }),
        (_('Context'), {
            'fields': ('customer', 'sent_by')
        }),
        (_('Technical Details'), {
            'fields': ('provider_response', 'meta'),
            'classes': ('collapse',)
        }),
    )

    def get_status_display_colored(self, obj: EmailLog) -> SafeString:
        """Display status with color coding"""
        color = obj.get_status_display_color()
        status_text = obj.get_status_display()

        # Add emoji indicators
        status_emoji = {
            'queued': '⏳',
            'sending': '📤',
            'sent': '✅',
            'delivered': '📬',
            'bounced': '❌',
            'soft_bounced': '⚠️',
            'complained': '🚨',
            'failed': '💥',
            'rejected': '🚫',
        }
        emoji = status_emoji.get(obj.status, '❓')

        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, emoji, status_text
        )
    get_status_display_colored.short_description = _('Status')
    get_status_display_colored.admin_order_field = 'status'

    def has_add_permission(self, request: HttpRequest) -> bool:
        """Email logs are created by system, not manually"""
        return False

    def has_change_permission(self, request: HttpRequest, obj: EmailLog | None = None) -> bool:
        """Email logs are immutable for audit purposes"""
        return False


# ===============================================================================
# EMAIL CAMPAIGN ADMIN
# ===============================================================================

@admin.register(EmailCampaign)
class EmailCampaignAdmin(admin.ModelAdmin):
    """Admin interface for email campaigns"""

    list_display: ClassVar[list[str]] = (
        'name', 'get_status_display_colored', 'audience',
        'get_progress_display', 'get_success_rate_display',
        'scheduled_at', 'created_at'
    )
    list_filter: ClassVar[list[str]] = (
        'status', 'audience', 'is_transactional', 'requires_consent',
        'created_at', 'scheduled_at'
    )
    search_fields: ClassVar[list[str]] = ('name', 'description')
    readonly_fields: ClassVar[list[str]] = (
        'total_recipients', 'emails_sent', 'emails_failed',
        'started_at', 'completed_at', 'created_at', 'updated_at'
    )
    date_hierarchy = 'created_at'

    fieldsets: ClassVar[tuple] = (
        (_('Campaign Details'), {
            'fields': ('name', 'description', 'template')
        }),
        (_('Targeting'), {
            'fields': ('audience', 'audience_filter')
        }),
        (_('Scheduling & Status'), {
            'fields': ('status', 'scheduled_at')
        }),
        (_('Compliance'), {
            'fields': ('is_transactional', 'requires_consent')
        }),
        (_('Results'), {
            'fields': (
                'total_recipients', 'emails_sent', 'emails_failed',
                'started_at', 'completed_at'
            ),
            'classes': ('collapse',)
        }),
        (_('Audit'), {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_status_display_colored(self, obj: EmailCampaign) -> SafeString:
        """Display campaign status with color coding"""
        status_colors = {
            'draft': '#6B7280',       # Gray
            'scheduled': '#3B82F6',   # Blue
            'sending': '#F59E0B',     # Amber
            'sent': '#10B981',        # Green
            'paused': '#F59E0B',      # Amber
            'cancelled': '#6B7280',   # Gray
            'failed': '#EF4444',      # Red
        }

        status_emoji = {
            'draft': '📝',
            'scheduled': '⏰',
            'sending': '📤',
            'sent': '✅',
            'paused': '⏸️',
            'cancelled': '❌',
            'failed': '💥',
        }

        color = status_colors.get(obj.status, '#6B7280')
        emoji = status_emoji.get(obj.status, '❓')
        status_text = obj.get_status_display()

        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, emoji, status_text
        )
    get_status_display_colored.short_description = _('Status')
    get_status_display_colored.admin_order_field = 'status'

    def get_progress_display(self, obj: EmailCampaign) -> SafeString:
        """Display campaign progress"""
        if obj.total_recipients == 0:
            return _('No recipients')

        progress = (obj.emails_sent + obj.emails_failed) / obj.total_recipients * 100
        return format_html(
            '{}/{} ({}%)',
            obj.emails_sent + obj.emails_failed,
            obj.total_recipients,
            round(progress, 1)
        )
    get_progress_display.short_description = _('Progress')

    def get_success_rate_display(self, obj: EmailCampaign) -> SafeString:
        """Display success rate with color coding"""
        rate = obj.get_success_rate()

        if rate >= EXCELLENT_SUCCESS_RATE:
            color = '#10B981'  # Green
            emoji = '🎯'
        elif rate >= GOOD_SUCCESS_RATE:
            color = '#F59E0B'  # Amber
            emoji = '⚠️'
        else:
            color = '#EF4444'  # Red
            emoji = '❌'

        return format_html(
            '<span style="color: {};">{} {}%</span>',
            color, emoji, rate
        )
    get_success_rate_display.short_description = _('Success Rate')

    def save_model(self, request: HttpRequest, obj: EmailCampaign, form: forms.ModelForm, change: bool) -> None:
        """Set created_by on new campaigns"""
        if not change and not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
