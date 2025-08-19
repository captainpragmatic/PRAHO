"""
Django admin configuration for Users app
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse

from .models import User, UserProfile, CustomerMembership, UserLoginLog


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom user admin with hybrid approach (system roles + customer memberships)"""
    
    list_display = [
        'email', 'get_full_name', 'staff_role', 'is_staff_user',
        'primary_customer_name', 'two_factor_enabled', 'is_active',
        'last_login', 'date_joined'
    ]
    
    list_filter = [
        'staff_role', 'two_factor_enabled', 'is_active',
        'is_staff', 'date_joined', 'last_login'
    ]
    
    search_fields = ['email', 'first_name', 'last_name']
    
    fieldsets = [
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'phone')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('System Role', {
            'fields': ('staff_role',),
            'description': 'System role for internal staff. Leave empty for customer users.'
        }),
        ('Security', {
            'fields': ('two_factor_enabled', 'two_factor_secret', 'backup_tokens')
        }),
        ('GDPR Compliance', {
            'fields': (
                'accepts_marketing', 'gdpr_consent_date',
                'last_privacy_policy_accepted'
            )
        }),
        ('Login Security', {
            'fields': (
                'last_login_ip', 'failed_login_attempts',
                'account_locked_until'
            )
        }),
        ('Audit', {
            'fields': ('created_by',)
        }),
    ]
    
    add_fieldsets = [
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    ]
    
    ordering = ['email']
    
    readonly_fields = ['date_joined', 'last_login', 'created_at', 'updated_at']
    
    def is_staff_user(self, obj):
        """Check if user is system/staff user"""
        return obj.is_staff_user
    is_staff_user.boolean = True
    is_staff_user.short_description = 'Staff User'
    
    def primary_customer_name(self, obj):
        """Get primary customer name"""
        primary = obj.primary_customer
        if primary:
            return format_html(
                '<a href="{}">{}</a>',
                reverse('admin:customers_customer_change', args=[primary.id]),
                primary.name
            )
        return '-'
    primary_customer_name.short_description = 'Primary Customer'


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """User profile admin"""
    
    list_display = [
        'user', 'preferred_language', 'timezone',
        'email_notifications', 'sms_notifications'
    ]
    
    list_filter = [
        'preferred_language', 'timezone', 'email_notifications',
        'sms_notifications', 'marketing_emails'
    ]
    
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Preferences', {
            'fields': ('preferred_language', 'timezone', 'date_format')
        }),
        ('Notifications', {
            'fields': ('email_notifications', 'sms_notifications', 'marketing_emails')
        }),
        ('Emergency Contact', {
            'fields': ('emergency_contact_name', 'emergency_contact_phone')
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']


@admin.register(CustomerMembership)
class CustomerMembershipAdmin(admin.ModelAdmin):
    """Customer membership admin for PostgreSQL-aligned user-customer relationships"""
    
    list_display = [
        'user', 'customer', 'role', 'is_primary',
        'created_at', 'created_by'
    ]
    
    list_filter = ['role', 'is_primary', 'created_at']
    
    search_fields = [
        'user__email', 'customer__name', 'customer__company_name'
    ]
    
    fieldsets = (
        ('Membership', {
            'fields': ('user', 'customer', 'role', 'is_primary')
        }),
        ('Audit', {
            'fields': ('created_by',)
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'customer', 'created_by'
        )


@admin.register(UserLoginLog)
class UserLoginLogAdmin(admin.ModelAdmin):
    """User login log admin for security monitoring"""
    
    list_display = [
        'get_user_display', 'timestamp', 'status', 'ip_address',
        'get_location', 'get_user_agent_short'
    ]
    
    list_filter = [
        'status', 'timestamp', 'country', 'city'
    ]
    
    search_fields = [
        'user__email', 'ip_address', 'user_agent', 'country', 'city'
    ]
    
    readonly_fields = [
        'user', 'timestamp', 'ip_address', 'user_agent',
        'status', 'country', 'city'
    ]
    
    date_hierarchy = 'timestamp'
    
    def get_user_display(self, obj):
        """Display user email or 'Unknown User' for null users"""
        if obj.user:
            return obj.user.email
        return "❌ Unknown User"
    get_user_display.short_description = 'User'
    get_user_display.admin_order_field = 'user__email'
    
    def get_location(self, obj):
        """Display location information"""
        if obj.country and obj.city:
            return f"🌍 {obj.city}, {obj.country}"
        elif obj.country:
            return f"🌍 {obj.country}"
        return "❓ Unknown"
    get_location.short_description = 'Location'
    
    def get_user_agent_short(self, obj):
        """Display shortened user agent"""
        ua = obj.user_agent
        if len(ua) > 50:
            return f"{ua[:47]}..."
        return ua
    get_user_agent_short.short_description = 'User Agent'
    
    def has_add_permission(self, request):
        """Login logs are created automatically"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Login logs are read-only"""
        return False
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')
