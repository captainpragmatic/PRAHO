"""
Django admin configuration for provisioning models.
Romanian hosting provider service provisioning and server management.
"""



from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _

from .models import ProvisioningTask, Server, Service, ServicePlan

# ===============================================================================
# SERVICE PLAN ADMIN
# ===============================================================================

@admin.register(ServicePlan)
class ServicePlanAdmin(admin.ModelAdmin):
    """Hosting service plans management"""

    list_display = [
        'name',
        'plan_type',
        'price_monthly_display',
        'setup_fee_display',
        'is_active',
        'is_public',
        'auto_provision',
        'sort_order',
    ]
    list_filter = [
        'plan_type',
        'is_active',
        'is_public',
        'auto_provision',
        'includes_vat',
    ]
    search_fields = [
        'name',
        'description',
    ]
    ordering = ['plan_type', 'sort_order', 'price_monthly']

    fieldsets = (
        (_('Basic Information'), {
            'fields': (
                'name',
                'plan_type',
                'description',
                'sort_order',
            )
        }),
        (_('Pricing (RON)'), {
            'fields': (
                'price_monthly',
                'price_quarterly',
                'price_annual',
                'setup_fee',
                'includes_vat',
            )
        }),
        (_('Technical Specifications'), {
            'fields': (
                'disk_space_gb',
                'bandwidth_gb',
                'cpu_cores',
                'ram_gb',
                'email_accounts',
                'databases',
                'domains',
            ),
            'classes': ('collapse',),
        }),
        (_('Features'), {
            'fields': (
                'features',
            ),
            'classes': ('collapse',),
        }),
        (_('Availability & Provisioning'), {
            'fields': (
                'is_active',
                'is_public',
                'auto_provision',
                'provisioning_script',
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
    readonly_fields = ['created_at', 'updated_at']

    def price_monthly_display(self, obj: ServicePlan) -> str:
        """Display monthly price with VAT indicator"""
        vat_text = " (incl. VAT)" if obj.includes_vat else " (excl. VAT)"
        return f"{obj.price_monthly:.2f} RON{vat_text}"
    price_monthly_display.short_description = _('Monthly Price')

    def setup_fee_display(self, obj: ServicePlan) -> SafeString | str:
        """Display setup fee"""
        if obj.setup_fee > 0:
            return f"{obj.setup_fee:.2f} RON"
        return format_html('<span style="color: green;">Free</span>')
    setup_fee_display.short_description = _('Setup Fee')

    actions = ['activate_plans', 'deactivate_plans', 'make_public', 'make_private']

    def activate_plans(self, request: HttpRequest, queryset: QuerySet[ServicePlan]) -> None:
        """Activate selected service plans"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'Successfully activated {updated} service plans.')
    activate_plans.short_description = _('Activate selected plans')

    def deactivate_plans(self, request: HttpRequest, queryset: QuerySet[ServicePlan]) -> None:
        """Deactivate selected service plans"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'Successfully deactivated {updated} service plans.')
    deactivate_plans.short_description = _('Deactivate selected plans')

    def make_public(self, request: HttpRequest, queryset: QuerySet[ServicePlan]) -> None:
        """Make plans public on website"""
        updated = queryset.update(is_public=True)
        self.message_user(request, f'Successfully made {updated} plans public.')
    make_public.short_description = _('Make public on website')

    def make_private(self, request: HttpRequest, queryset: QuerySet[ServicePlan]) -> None:
        """Make plans private (admin only)"""
        updated = queryset.update(is_public=False)
        self.message_user(request, f'Successfully made {updated} plans private.')
    make_private.short_description = _('Make private (admin only)')


# ===============================================================================
# SERVER ADMIN
# ===============================================================================

@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    """Physical/virtual server management"""

    list_display = [
        'name',
        'hostname',
        'server_type',
        'status_display',
        'location',
        'active_services_display',
        'resource_usage_display',
        'monthly_cost_display',
    ]
    list_filter = [
        'server_type',
        'status',
        'location',
        'datacenter',
        'os_type',
        'provider',
        'is_active',
    ]
    search_fields = [
        'name',
        'hostname',
        'primary_ip',
        'location',
        'datacenter',
        'provider_instance_id',
    ]
    ordering = ['location', 'name']

    fieldsets = (
        (_('Basic Information'), {
            'fields': (
                'name',
                'hostname',
                'server_type',
                'status',
                'is_active',
            )
        }),
        (_('Network'), {
            'fields': (
                'primary_ip',
                'secondary_ips',
                'location',
                'datacenter',
            )
        }),
        (_('Hardware'), {
            'fields': (
                'cpu_model',
                'cpu_cores',
                'ram_gb',
                'disk_type',
                'disk_capacity_gb',
            )
        }),
        (_('Resource Usage'), {
            'fields': (
                'cpu_usage_percent',
                'ram_usage_percent',
                'disk_usage_percent',
                'max_services',
            ),
            'classes': ('collapse',),
        }),
        (_('Management'), {
            'fields': (
                'os_type',
                'control_panel',
                'provider',
                'provider_instance_id',
            ),
            'classes': ('collapse',),
        }),
        (_('Cost & Maintenance'), {
            'fields': (
                'monthly_cost',
                'last_maintenance',
                'next_maintenance',
            ),
            'classes': ('collapse',),
        }),
        (_('Timestamps'), {
            'fields': (
                'created_at',
                'updated_at',
            ),
            'classes': ('collapse',),
        }),
    )
    readonly_fields = ['created_at', 'updated_at']

    def status_display(self, obj: Server) -> SafeString:
        """Display status with colors"""
        colors = {
            'active': 'green',
            'maintenance': 'orange',
            'offline': 'red',
            'decommissioned': 'gray',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def active_services_display(self, obj: Server) -> SafeString | str:
        """Display active services count"""
        count = obj.active_services_count
        max_services = obj.max_services
        if max_services:
            percentage = (count / max_services) * 100
            if percentage > 90:
                color = 'red'
            elif percentage > 75:
                color = 'orange'
            else:
                color = 'green'
            return format_html(
                '<span style="color: {};">{}/{} ({}%)</span>',
                color, count, max_services, int(percentage)
            )
        return str(count)
    active_services_display.short_description = _('Services')

    def resource_usage_display(self, obj: Server) -> SafeString:
        """Display average resource usage"""
        avg_usage = obj.resource_usage_average
        if avg_usage > 90:
            color = 'red'
        elif avg_usage > 75:
            color = 'orange'
        else:
            color = 'green'

        return format_html(
            '<span style="color: {};">{:.1f}%</span><br/>'
            '<small>CPU: {}% | RAM: {}% | Disk: {}%</small>',
            color, avg_usage,
            obj.cpu_usage_percent or 0,
            obj.ram_usage_percent or 0,
            obj.disk_usage_percent or 0
        )
    resource_usage_display.short_description = _('Resource Usage')

    def monthly_cost_display(self, obj: Server) -> str:
        """Display monthly cost"""
        if obj.monthly_cost > 0:
            return f"{obj.monthly_cost:.2f} RON"
        return '-'
    monthly_cost_display.short_description = _('Monthly Cost')

    actions = ['mark_maintenance', 'mark_active']

    def mark_maintenance(self, request: HttpRequest, queryset: QuerySet[Server]) -> None:
        """Mark servers as under maintenance"""
        updated = queryset.update(status='maintenance')
        self.message_user(request, f'Successfully marked {updated} servers as under maintenance.')
    mark_maintenance.short_description = _('Mark as under maintenance')

    def mark_active(self, request: HttpRequest, queryset: QuerySet[Server]) -> None:
        """Mark servers as active"""
        updated = queryset.update(status='active')
        self.message_user(request, f'Successfully marked {updated} servers as active.')
    mark_active.short_description = _('Mark as active')


# ===============================================================================
# SERVICE ADMIN
# ===============================================================================

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    """Customer service management"""

    list_display = [
        'service_name',
        'customer',
        'service_plan',
        'status_display',
        'server',
        'price_display',
        'billing_cycle',
        'expires_at',
        'days_until_expiry_display',
    ]
    list_filter = [
        'status',
        'billing_cycle',
        'service_plan__plan_type',
        'server',
        'auto_renew',
        'setup_fee_paid',
        'created_at',
    ]
    search_fields = [
        'service_name',
        'domain',
        'username',
        'customer__name',
        'customer__company_name',
        'customer__primary_email',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = [
        'created_at',
        'updated_at',
        'price_display',
        'days_until_expiry_display',
    ]

    fieldsets = (
        (_('Service Information'), {
            'fields': (
                'customer',
                'service_plan',
                'server',
                'service_name',
                'domain',
                'username',
                'status',
            )
        }),
        (_('Billing'), {
            'fields': (
                'billing_cycle',
                'price_display',
                'setup_fee_paid',
                'auto_renew',
            )
        }),
        (_('Lifecycle'), {
            'fields': (
                'created_at',
                'updated_at',
                'activated_at',
                'suspended_at',
                'expires_at',
                'days_until_expiry_display',
            )
        }),
        (_('Resource Usage'), {
            'fields': (
                'disk_usage_mb',
                'bandwidth_usage_mb',
                'email_accounts_used',
                'databases_used',
            ),
            'classes': ('collapse',),
        }),
        (_('Provisioning'), {
            'fields': (
                'provisioning_data',
                'last_provisioning_attempt',
                'provisioning_errors',
            ),
            'classes': ('collapse',),
        }),
        (_('Notes'), {
            'fields': (
                'admin_notes',
                'suspension_reason',
            ),
            'classes': ('collapse',),
        }),
    )

    def status_display(self, obj):
        """Display status with colors"""
        colors = {
            'pending': 'orange',
            'provisioning': 'blue',
            'active': 'green',
            'suspended': 'red',
            'terminated': 'gray',
            'expired': 'purple',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def price_display(self, obj) -> str:
        """Display service price"""
        return f"{obj.price:.2f} RON"
    price_display.short_description = _('Price')

    def days_until_expiry_display(self, obj):
        """Display days until expiry with color coding"""
        days = obj.days_until_expiry
        if days == 999999:
            return format_html('<span style="color: green;">No expiry</span>')
        elif days <= 0:
            return format_html('<span style="color: red;">Expired</span>')
        elif days <= 7:
            return format_html('<span style="color: red;">{} days</span>', days)
        elif days <= 30:
            return format_html('<span style="color: orange;">{} days</span>', days)
        else:
            return format_html('<span style="color: green;">{} days</span>', days)
    days_until_expiry_display.short_description = _('Days to Expiry')

    actions = ['activate_services', 'suspend_services', 'extend_expiry']

    def activate_services(self, request, queryset) -> None:
        """Activate selected services"""
        updated = 0
        for service in queryset:
            if service.status in ['pending', 'suspended']:
                service.activate()
                updated += 1
        self.message_user(request, f'Successfully activated {updated} services.')
    activate_services.short_description = _('Activate selected services')

    def suspend_services(self, request, queryset) -> None:
        """Suspend selected services"""
        updated = 0
        for service in queryset:
            if service.status == 'active':
                service.suspend('Suspended by admin')
                updated += 1
        self.message_user(request, f'Successfully suspended {updated} services.')
    suspend_services.short_description = _('Suspend selected services')


# ===============================================================================
# PROVISIONING TASK ADMIN
# ===============================================================================

@admin.register(ProvisioningTask)
class ProvisioningTaskAdmin(admin.ModelAdmin):
    """Automated provisioning task management"""

    list_display = [
        'created_at',
        'service',
        'task_type',
        'status_display',
        'retry_count_display',
        'duration_display',
        'next_retry_at',
    ]
    list_filter = [
        'status',
        'task_type',
        'created_at',
        'service__service_plan__plan_type',
    ]
    search_fields = [
        'service__service_name',
        'service__customer__name',
        'service__customer__company_name',
        'error_message',
    ]
    date_hierarchy = 'created_at'
    readonly_fields = [
        'created_at',
        'updated_at',
        'duration_display',
        'started_at',
        'completed_at',
    ]
    ordering = ['-created_at']

    fieldsets = (
        (_('Task Information'), {
            'fields': (
                'service',
                'task_type',
                'status',
                'parameters',
            )
        }),
        (_('Execution'), {
            'fields': (
                'created_at',
                'updated_at',
                'started_at',
                'completed_at',
                'duration_display',
            )
        }),
        (_('Results'), {
            'fields': (
                'result',
                'error_message',
            ),
            'classes': ('collapse',),
        }),
        (_('Retry Logic'), {
            'fields': (
                'retry_count',
                'max_retries',
                'next_retry_at',
            )
        }),
    )

    def status_display(self, obj):
        """Display status with colors"""
        colors = {
            'pending': 'orange',
            'running': 'blue',
            'completed': 'green',
            'failed': 'red',
            'retrying': 'purple',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = _('Status')

    def retry_count_display(self, obj):
        """Display retry count with progress"""
        if obj.max_retries > 0:
            percentage = (obj.retry_count / obj.max_retries) * 100
            if percentage >= 100:
                color = 'red'
            elif percentage >= 66:
                color = 'orange'
            else:
                color = 'green'
            return format_html(
                '<span style="color: {};">{}/{}</span>',
                color, obj.retry_count, obj.max_retries
            )
        return f"{obj.retry_count}/∞"
    retry_count_display.short_description = _('Retries')

    def duration_display(self, obj) -> str:
        """Display task duration"""
        duration = obj.duration_seconds
        if duration > 0:
            if duration < 60:
                return f"{duration}s"
            elif duration < 3600:
                return f"{duration // 60}m {duration % 60}s"
            else:
                hours = duration // 3600
                minutes = (duration % 3600) // 60
                return f"{hours}h {minutes}m"
        return '-'
    duration_display.short_description = _('Duration')

    actions = ['retry_failed_tasks', 'cancel_pending_tasks']

    def retry_failed_tasks(self, request, queryset) -> None:
        """Retry failed tasks that can be retried"""
        retried = 0
        for task in queryset:
            if task.can_retry:
                task.status = 'pending'
                task.next_retry_at = timezone.now()
                task.save()
                retried += 1
        self.message_user(request, f'Successfully queued {retried} tasks for retry.')
    retry_failed_tasks.short_description = _('Retry failed tasks')

    def cancel_pending_tasks(self, request, queryset) -> None:
        """Cancel pending tasks"""
        cancelled = queryset.filter(status='pending').update(status='failed', error_message='Cancelled by admin')
        self.message_user(request, f'Successfully cancelled {cancelled} pending tasks.')
    cancel_pending_tasks.short_description = _('Cancel pending tasks')
