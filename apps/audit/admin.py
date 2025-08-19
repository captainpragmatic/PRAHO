"""
Django admin configuration for audit models.
Romanian PRAHO Platform audit trail management with security focus.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import AuditEvent, DataExport, ComplianceLog


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    """Audit event admin interface"""
    
    list_display = [
        'timestamp',
        'action',
        'user_display',
        'content_type',
        'object_id',
        'ip_address',
        'actor_type',
    ]
    list_filter = [
        'action',
        'actor_type',
        'timestamp',
        'content_type',
    ]
    search_fields = [
        'user__email',
        'user__first_name',
        'user__last_name',
        'description',
        'ip_address',
    ]
    date_hierarchy = 'timestamp'
    readonly_fields = [
        'id',
        'timestamp',
        'ip_address',
        'user_agent',
        'user',
        'actor_type',
        'action',
        'content_type',
        'object_id',
        'content_object',
        'old_values',
        'new_values',
        'description',
        'request_id',
        'session_key',
        'metadata',
    ]
    
    fieldsets = (
        (_('Event Information'), {
            'fields': (
                'id',
                'timestamp',
                'action',
                'description',
            )
        }),
        (_('User & Session'), {
            'fields': (
                'user',
                'actor_type',
                'ip_address',
                'user_agent',
                'session_key',
                'request_id',
            )
        }),
        (_('Target Object'), {
            'fields': (
                'content_type',
                'object_id',
                'content_object',
            )
        }),
        (_('Changes'), {
            'fields': (
                'old_values',
                'new_values',
                'metadata',
            ),
            'classes': ('collapse',),
        }),
    )
    
    def user_display(self, obj):
        """Display user with icon"""
        if obj.user:
            return format_html(
                '👤 {} ({})',
                obj.user.get_full_name(),
                obj.user.email
            )
        return format_html('🤖 System')
    user_display.short_description = _('User')
    
    def has_add_permission(self, request):
        """Audit events cannot be manually created"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Audit events are immutable"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Audit events cannot be deleted"""
        return False


@admin.register(DataExport)
class DataExportAdmin(admin.ModelAdmin):
    """Data export admin interface for GDPR compliance"""
    
    list_display = [
        'requested_at',
        'export_type',
        'requested_by',
        'status',
        'file_size_display',
        'record_count',
        'expires_at',
        'download_count',
    ]
    list_filter = [
        'export_type',
        'status',
        'requested_at',
        'expires_at',
    ]
    search_fields = [
        'requested_by__email',
        'requested_by__first_name',
        'requested_by__last_name',
        'export_type',
    ]
    date_hierarchy = 'requested_at'
    readonly_fields = [
        'id',
        'requested_at',
        'started_at',
        'completed_at',
        'file_path',
        'file_size',
        'record_count',
        'download_count',
    ]
    
    fieldsets = (
        (_('Export Request'), {
            'fields': (
                'id',
                'export_type',
                'requested_by',
                'requested_at',
                'scope',
            )
        }),
        (_('Processing'), {
            'fields': (
                'status',
                'started_at',
                'completed_at',
                'error_message',
            )
        }),
        (_('Results'), {
            'fields': (
                'file_path',
                'file_size',
                'record_count',
                'download_count',
            )
        }),
        (_('Security'), {
            'fields': (
                'expires_at',
            )
        }),
    )
    
    def file_size_display(self, obj):
        """Display file size in human readable format"""
        if not obj.file_size:
            return '-'
        
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    file_size_display.short_description = _('File Size')
    
    def get_queryset(self, request):
        """Filter exports by user permissions"""
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            # Non-superusers can only see their own exports
            qs = qs.filter(requested_by=request.user)
        return qs


@admin.register(ComplianceLog)
class ComplianceLogAdmin(admin.ModelAdmin):
    """Romanian compliance logging admin"""
    
    list_display = [
        'timestamp',
        'compliance_type_display',
        'reference_id',
        'status_display',
        'user_display',
    ]
    list_filter = [
        'compliance_type',
        'status',
        'timestamp',
    ]
    search_fields = [
        'reference_id',
        'description',
        'user__email',
        'user__first_name',
        'user__last_name',
    ]
    date_hierarchy = 'timestamp'
    readonly_fields = [
        'id',
        'timestamp',
        'compliance_type',
        'reference_id',
        'user',
        'description',
        'status',
        'evidence',
        'metadata',
    ]
    
    fieldsets = (
        (_('Compliance Event'), {
            'fields': (
                'id',
                'compliance_type',
                'reference_id',
                'timestamp',
                'user',
            )
        }),
        (_('Details'), {
            'fields': (
                'description',
                'status',
            )
        }),
        (_('Evidence & Metadata'), {
            'fields': (
                'evidence',
                'metadata',
            ),
            'classes': ('collapse',),
        }),
    )
    
    def compliance_type_display(self, obj):
        """Display compliance type with icon"""
        icons = {
            'gdpr_consent': '🛡️',
            'gdpr_deletion': '🗑️',
            'vat_validation': '🧾',
            'efactura_submission': '📋',
            'data_retention': '📅',
            'security_incident': '🚨',
        }
        icon = icons.get(obj.compliance_type, '📄')
        return format_html(
            '{} {}',
            icon,
            obj.get_compliance_type_display()
        )
    compliance_type_display.short_description = _('Type')
    
    def status_display(self, obj):
        """Display status with color"""
        if obj.status == 'success':
            return format_html(
                '<span style="color: green;">✅ {}</span>',
                obj.status.title()
            )
        elif obj.status == 'failed':
            return format_html(
                '<span style="color: red;">❌ {}</span>',
                obj.status.title()
            )
        else:
            return format_html(
                '<span style="color: orange;">⏳ {}</span>',
                obj.status.title()
            )
    status_display.short_description = _('Status')
    
    def user_display(self, obj):
        """Display user with icon"""
        if obj.user:
            return format_html(
                '👤 {}',
                obj.user.get_full_name()
            )
        return format_html('🤖 System')
    user_display.short_description = _('User')
    
    def has_add_permission(self, request):
        """Compliance logs cannot be manually created"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Compliance logs are immutable"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Compliance logs cannot be deleted for audit trail"""
        return False