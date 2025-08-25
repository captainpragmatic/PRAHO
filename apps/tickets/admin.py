"""
Django admin configuration for support ticket models.
Romanian hosting provider customer support system administration.
"""


from typing import Any, Optional

from django.contrib import admin
from django.db import models
from django.db.models import Sum
from django.db.models.query import QuerySet
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _

from .models import (
    SupportCategory,
    Ticket,
    TicketAttachment,
    TicketComment,
    TicketWorklog,
)

# ===============================================================================
# SUPPORT CATEGORY ADMIN
# ===============================================================================

@admin.register(SupportCategory)
class SupportCategoryAdmin(admin.ModelAdmin):
    """Support ticket categories management"""

    list_display = [
        'name',
        'name_en',
        'icon_display',
        'sla_response_hours',
        'sla_resolution_hours',
        'auto_assign_to',
        'is_active',
        'sort_order',
    ]
    list_filter = [
        'is_active',
        'auto_assign_to',
    ]
    search_fields = ['name', 'name_en', 'description']
    ordering = ['sort_order', 'name']

    fieldsets = (
        (_('Category Information'), {
            'fields': (
                'name',
                'name_en',
                'description',
                'icon',
                'color',
                'sort_order',
                'is_active',
            )
        }),
        (_('Service Level Agreement'), {
            'fields': (
                'sla_response_hours',
                'sla_resolution_hours',
                'auto_assign_to',
            )
        }),
        (_('Timestamps'), {
            'fields': (
                'created_at',
            ),
            'classes': ('collapse',),
        }),
    )
    readonly_fields = ['created_at']

    def icon_display(self, obj: SupportCategory) -> SafeString:
        """Display category icon with color"""
        return format_html(
            '<span style="color: {}; font-size: 16px;">{}</span>',
            obj.color,
            obj.icon
        )
    icon_display.short_description = _('Icon')


# ===============================================================================
# TICKET COMMENT INLINE
# ===============================================================================

class TicketCommentInline(admin.TabularInline):
    """Inline ticket comments"""
    model = TicketComment
    extra = 0
    fields = ['comment_type', 'content', 'is_public', 'time_spent', 'created_at']
    readonly_fields = ['created_at']
    ordering = ['created_at']


class TicketAttachmentInline(admin.TabularInline):
    """Inline ticket attachments"""
    model = TicketAttachment
    extra = 0
    fields = ['filename', 'file_size_display', 'content_type', 'is_safe', 'uploaded_at']
    readonly_fields = ['file_size_display', 'uploaded_at']

    def file_size_display(self, obj: TicketAttachment) -> str:
        """Display file size in human readable format"""
        if obj.pk:
            return obj.get_file_size_display()
        return '-'
    file_size_display.short_description = _('Size')


class TicketWorklogInline(admin.TabularInline):
    """Inline ticket work logs"""
    model = TicketWorklog
    extra = 0
    fields = ['user', 'work_date', 'time_spent', 'is_billable', 'hourly_rate', 'description']
    ordering = ['-work_date']


# ===============================================================================
# TICKET ADMIN
# ===============================================================================

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    """Support ticket management"""

    list_display = [
        'ticket_number',
        'title_truncated',
        'customer',
        'status_display',
        'priority_display',
        'assigned_to',
        'category',
        'sla_status',
        'created_at',
        'satisfaction_display',
    ]
    list_filter = [
        'status',
        'priority',
        'category',
        'source',
        'assigned_to',
        'is_escalated',
        'requires_customer_response',
        'created_at',
    ]
    search_fields = [
        'ticket_number',
        'title',
        'description',
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
        'contact_email',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = [
        'ticket_number',
        'created_at',
        'updated_at',
        'sla_response_due',
        'sla_resolution_due',
        'first_response_at',
        'resolved_at',
        'actual_hours',
    ]
    inlines = [TicketCommentInline, TicketAttachmentInline, TicketWorklogInline]
    ordering = ['-created_at']

    fieldsets = (
        (_('Ticket Information'), {
            'fields': (
                'ticket_number',
                'title',
                'description',
                'category',
                'priority',
                'status',
                'source',
            )
        }),
        (_('Customer & Contact'), {
            'fields': (
                'customer',
                'contact_person',
                'contact_email',
                'contact_phone',
                'related_service',
            )
        }),
        (_('Assignment'), {
            'fields': (
                'assigned_to',
                'assigned_at',
                'created_by',
            )
        }),
        (_('SLA Tracking'), {
            'fields': (
                'sla_response_due',
                'sla_resolution_due',
                'first_response_at',
                'resolved_at',
            ),
            'classes': ('collapse',),
        }),
        (_('Time Tracking'), {
            'fields': (
                'estimated_hours',
                'actual_hours',
            )
        }),
        (_('Customer Satisfaction'), {
            'fields': (
                'satisfaction_rating',
                'satisfaction_comment',
            ),
            'classes': ('collapse',),
        }),
        (_('Flags & Options'), {
            'fields': (
                'is_escalated',
                'is_public',
                'requires_customer_response',
            )
        }),
        (_('Timestamps'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def title_truncated(self, obj: Ticket) -> str:
        """Display truncated title"""
        if len(obj.title) > 50:
            return f"{obj.title[:47]}..."
        return obj.title
    title_truncated.short_description = _('Title')

    def status_display(self, obj: Ticket) -> SafeString:
        """Display status with colors"""
        color = obj.get_status_color()
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def priority_display(self, obj: Ticket) -> SafeString:
        """Display priority with colors"""
        color = obj.get_priority_color()
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_priority_display()
        )
    priority_display.short_description = _('Priority')

    def sla_status(self, obj: Ticket) -> SafeString:
        """Display SLA status with warnings"""
        now = timezone.now()

        # Response SLA
        if not obj.first_response_at and obj.sla_response_due:
            if now > obj.sla_response_due:
                response_status = format_html('<span style="color: red;">❌ Response Overdue</span>')
            elif (obj.sla_response_due - now).total_seconds() < 3600:  # Less than 1 hour
                response_status = format_html('<span style="color: orange;">⚠️ Response Due Soon</span>')
            else:
                response_status = format_html('<span style="color: green;">✅ Response On Time</span>')
        else:
            response_status = format_html('<span style="color: green;">✅ Response Complete</span>')

        # Resolution SLA
        if not obj.resolved_at and obj.sla_resolution_due:
            if now > obj.sla_resolution_due:
                resolution_status = format_html('<span style="color: red;">❌ Resolution Overdue</span>')
            elif (obj.sla_resolution_due - now).total_seconds() < 7200:  # Less than 2 hours
                resolution_status = format_html('<span style="color: orange;">⚠️ Resolution Due Soon</span>')
            else:
                resolution_status = format_html('<span style="color: green;">✅ Resolution On Time</span>')
        else:
            resolution_status = format_html('<span style="color: green;">✅ Resolution Complete</span>')

        return format_html(
            '{}<br/>{}',
            response_status,
            resolution_status
        )
    sla_status.short_description = _('SLA Status')

    def satisfaction_display(self, obj: Ticket) -> SafeString:
        """Display customer satisfaction rating"""
        if obj.satisfaction_rating:
            stars = '⭐' * obj.satisfaction_rating
            empty_stars = '☆' * (5 - obj.satisfaction_rating)
            return format_html(
                '<span title="{}/5 stars">{}{}</span>',
                obj.satisfaction_rating,
                stars,
                empty_stars
            )
        return '-'
    satisfaction_display.short_description = _('Satisfaction')

    actions = [
        'assign_to_me',
        'mark_resolved',
        'escalate_tickets',
        'require_customer_response',
    ]

    def assign_to_me(self, request: HttpRequest, queryset: QuerySet[Ticket]) -> None:
        """Assign selected tickets to current user"""
        updated = queryset.filter(status__in=['new', 'open']).update(
            assigned_to=request.user,
            assigned_at=timezone.now()
        )
        self.message_user(request, f'Successfully assigned {updated} tickets to you.')
    assign_to_me.short_description = _('Assign to me')

    def mark_resolved(self, request: HttpRequest, queryset: QuerySet[Ticket]) -> None:
        """Mark selected tickets as resolved"""
        now = timezone.now()
        updated = 0
        for ticket in queryset:
            if ticket.status not in ['resolved', 'closed']:
                ticket.status = 'resolved'
                ticket.resolved_at = now
                ticket.save()
                updated += 1
        self.message_user(request, f'Successfully resolved {updated} tickets.')
    mark_resolved.short_description = _('Mark as resolved')

    def escalate_tickets(self, request: HttpRequest, queryset: QuerySet[Ticket]) -> None:
        """Escalate selected tickets"""
        updated = queryset.update(is_escalated=True, priority='urgent')
        self.message_user(request, f'Successfully escalated {updated} tickets.')
    escalate_tickets.short_description = _('Escalate tickets')

    def require_customer_response(self, request: HttpRequest, queryset: QuerySet[Ticket]) -> None:
        """Mark tickets as requiring customer response"""
        updated = queryset.update(
            requires_customer_response=True,
            status='pending'
        )
        self.message_user(request, f'Successfully marked {updated} tickets as requiring customer response.')
    require_customer_response.short_description = _('Require customer response')


# ===============================================================================
# TICKET COMMENT ADMIN
# ===============================================================================

@admin.register(TicketComment)
class TicketCommentAdmin(admin.ModelAdmin):
    """Ticket comment management"""

    list_display = [
        'created_at',
        'ticket',
        'comment_type',
        'author_display',
        'content_preview',
        'is_public',
        'is_solution',
        'time_spent',
    ]
    list_filter = [
        'comment_type',
        'is_public',
        'is_solution',
        'created_at',
    ]
    search_fields = [
        'ticket__ticket_number',
        'ticket__title',
        'content',
        'author__first_name',
        'author__last_name',
        'author_name',
        'author_email',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']

    fieldsets = (
        (_('Comment Information'), {
            'fields': (
                'ticket',
                'comment_type',
                'content',
                'is_public',
                'is_solution',
            )
        }),
        (_('Author'), {
            'fields': (
                'author',
                'author_name',
                'author_email',
            )
        }),
        (_('Time Tracking'), {
            'fields': (
                'time_spent',
            )
        }),
        (_('Timestamps'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def author_display(self, obj: TicketComment) -> SafeString:
        """Display comment author"""
        if obj.author:
            return format_html(
                '👤 {} ({})',
                obj.author.get_full_name(),
                obj.author.email
            )
        elif obj.author_name:
            return format_html(
                '👥 {} ({})',
                obj.author_name,
                obj.author_email or 'No email'
            )
        return 'Anonymous'
    author_display.short_description = _('Author')

    def content_preview(self, obj: TicketComment) -> str:
        """Display content preview"""
        if len(obj.content) > 100:
            return f"{obj.content[:97]}..."
        return obj.content
    content_preview.short_description = _('Content Preview')


# ===============================================================================
# TICKET WORKLOG ADMIN
# ===============================================================================

@admin.register(TicketWorklog)
class TicketWorklogAdmin(admin.ModelAdmin):
    """Ticket work time tracking"""

    list_display = [
        'work_date',
        'ticket',
        'user',
        'time_spent',
        'is_billable',
        'hourly_rate',
        'total_cost_display',
        'description_preview',
    ]
    list_filter = [
        'is_billable',
        'work_date',
        'user',
        'created_at',
    ]
    search_fields = [
        'ticket__ticket_number',
        'ticket__title',
        'user__first_name',
        'user__last_name',
        'description',
    ]
    date_hierarchy = 'work_date'
    readonly_fields = ['created_at', 'total_cost_display']
    ordering = ['-work_date']

    fieldsets = (
        (_('Work Information'), {
            'fields': (
                'ticket',
                'user',
                'work_date',
                'time_spent',
                'description',
            )
        }),
        (_('Billing'), {
            'fields': (
                'is_billable',
                'hourly_rate',
                'total_cost_display',
            )
        }),
        (_('Timestamps'), {
            'fields': (
                'created_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def total_cost_display(self, obj: TicketWorklog) -> str:
        """Display total cost if billable"""
        if obj.is_billable and obj.hourly_rate:
            total = obj.total_cost
            return f"{total:.2f} RON"
        return '-'
    total_cost_display.short_description = _('Total Cost')

    def description_preview(self, obj: TicketWorklog) -> str:
        """Display description preview"""
        if len(obj.description) > 80:
            return f"{obj.description[:77]}..."
        return obj.description
    description_preview.short_description = _('Description')

    def changelist_view(self, request: HttpRequest, extra_context: Optional[dict[str, Any]] = None) -> HttpResponse:
        """Add summary statistics to changelist"""
        response = super().changelist_view(request, extra_context=extra_context)

        if hasattr(response, 'context_data'):
            queryset = response.context_data['cl'].queryset

            # Calculate summary statistics
            summary = queryset.aggregate(
                total_hours=Sum('time_spent'),
                billable_hours=Sum('time_spent', filter=models.Q(is_billable=True)),
                total_cost=Sum(
                    models.F('time_spent') * models.F('hourly_rate'),
                    filter=models.Q(is_billable=True)
                )
            )

            response.context_data['summary'] = {
                'total_hours': summary['total_hours'] or 0,
                'billable_hours': summary['billable_hours'] or 0,
                'total_cost': summary['total_cost'] or 0,
            }

        return response


# ===============================================================================
# TICKET ATTACHMENT ADMIN
# ===============================================================================

@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    """Ticket file attachment management"""

    list_display = [
        'uploaded_at',
        'ticket',
        'filename',
        'file_size_display',
        'content_type',
        'is_safe_display',
        'uploaded_by',
    ]
    list_filter = [
        'content_type',
        'is_safe',
        'uploaded_at',
    ]
    search_fields = [
        'ticket__ticket_number',
        'ticket__title',
        'filename',
        'uploaded_by__first_name',
        'uploaded_by__last_name',
    ]
    date_hierarchy = 'uploaded_at'
    readonly_fields = ['uploaded_at', 'file_size_display']
    ordering = ['-uploaded_at']

    fieldsets = (
        (_('Attachment Information'), {
            'fields': (
                'ticket',
                'comment',
                'file',
                'filename',
                'file_size_display',
                'content_type',
            )
        }),
        (_('Security'), {
            'fields': (
                'is_safe',
                'virus_scan_result',
            )
        }),
        (_('Upload Info'), {
            'fields': (
                'uploaded_by',
                'uploaded_at',
            ),
            'classes': ('collapse',),
        }),
    )

    def file_size_display(self, obj: TicketAttachment) -> str:
        """Display file size in human readable format"""
        if obj.pk:
            return obj.get_file_size_display()
        return '-'
    file_size_display.short_description = _('File Size')

    def is_safe_display(self, obj: TicketAttachment) -> SafeString:
        """Display safety status with colors"""
        if obj.is_safe:
            return format_html('<span style="color: green;">✅ Safe</span>')
        else:
            return format_html('<span style="color: red;">❌ Unsafe</span>')
    is_safe_display.short_description = _('Safety Status')
