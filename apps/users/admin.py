"""
Django admin configuration for Users app
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse, path
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.shortcuts import get_object_or_404

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
        ('Two-Factor Authentication', {
            'fields': ('two_factor_enabled', 'backup_codes_count', 'two_factor_actions'),
            'description': 'Two-factor authentication status and management'
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
    
    readonly_fields = ['date_joined', 'last_login', 'created_at', 'updated_at', 'backup_codes_count', 'two_factor_actions']
    
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
    
    def backup_codes_count(self, obj):
        """Show number of backup codes remaining"""
        if not obj.two_factor_enabled:
            return '-'
        
        count = len(obj.backup_tokens)
        if count == 0:
            return format_html('<span style="color: red; font-weight: bold;">0 (No backup codes!)</span>')
        elif count <= 2:
            return format_html('<span style="color: orange; font-weight: bold;">{} (Running low)</span>', count)
        else:
            return format_html('<span style="color: green;">{}</span>', count)
    backup_codes_count.short_description = 'Backup Codes'
    
    def two_factor_actions(self, obj):
        """Admin actions for 2FA management"""
        if not obj.two_factor_enabled:
            return format_html('<em>2FA not enabled</em>')
        
        actions = []
        
        # Disable 2FA action
        disable_url = reverse('admin:users_user_disable_2fa', args=[obj.id])
        actions.append(format_html(
            '<a href="{}" onclick="return confirm(\'Are you sure you want to disable 2FA for this user?\');" '
            'style="color: red; text-decoration: none; padding: 2px 6px; border: 1px solid red; border-radius: 3px; font-size: 11px;">🔒 Disable 2FA</a>',
            disable_url
        ))
        
        # Reset backup codes action  
        reset_codes_url = reverse('admin:users_user_reset_backup_codes', args=[obj.id])
        actions.append(format_html(
            '<a href="{}" onclick="return confirm(\'This will invalidate all existing backup codes. Continue?\');" '
            'style="color: blue; text-decoration: none; padding: 2px 6px; border: 1px solid blue; border-radius: 3px; font-size: 11px; margin-left: 5px;">🔄 Reset Backup Codes</a>',
            reset_codes_url
        ))
        
        return format_html(' '.join(actions))
    two_factor_actions.short_description = '2FA Actions'
    
    def get_urls(self):
        """Add custom admin URLs for 2FA management"""
        urls = super().get_urls()
        custom_urls = [
            path(
                '<int:user_id>/disable-2fa/',
                self.admin_site.admin_view(self.disable_2fa_view),
                name='users_user_disable_2fa',
            ),
            path(
                '<int:user_id>/reset-backup-codes/',
                self.admin_site.admin_view(self.reset_backup_codes_view),
                name='users_user_reset_backup_codes',
            ),
        ]
        return custom_urls + urls
    
    def disable_2fa_view(self, request, user_id):
        """Admin view to disable 2FA for a user"""
        user = get_object_or_404(User, id=user_id)
        
        if not user.two_factor_enabled:
            messages.warning(request, f'2FA is already disabled for {user.email}')
        else:
            # Disable 2FA
            user.two_factor_enabled = False
            user.two_factor_secret = ''
            user.backup_tokens = []
            user.save(update_fields=['two_factor_enabled', '_two_factor_secret', 'backup_tokens'])
            
            # Log the admin action
            UserLoginLog.objects.create(
                user=user,
                success=True,
                action='admin_2fa_disabled',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                notes=f'2FA disabled by admin user {request.user.email}'
            )
            
            messages.success(request, f'2FA has been disabled for {user.email}')
        
        return HttpResponseRedirect(reverse('admin:users_user_change', args=[user_id]))
    
    def reset_backup_codes_view(self, request, user_id):
        """Admin view to reset backup codes for a user"""
        user = get_object_or_404(User, id=user_id)
        
        if not user.two_factor_enabled:
            messages.warning(request, f'2FA is not enabled for {user.email}')
        else:
            # Generate new backup codes
            backup_codes = user.generate_backup_codes()
            
            # Log the admin action
            UserLoginLog.objects.create(
                user=user,
                success=True,
                action='admin_backup_codes_reset',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                notes=f'Backup codes reset by admin user {request.user.email}'
            )
            
            messages.success(
                request, 
                f'New backup codes generated for {user.email}. '
                f'User should be notified to save the new codes: {", ".join(backup_codes[:3])}... (8 total)'
            )
        
        return HttpResponseRedirect(reverse('admin:users_user_change', args=[user_id]))


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
