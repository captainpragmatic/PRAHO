"""
Comprehensive audit signals for PRAHO Platform
Implements industry-standard user action auditing (GDPR, ISO 27001, NIST, SOX, PCI DSS).
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out, 
    user_login_failed
)
from django.db.models.signals import (
    post_save,
    pre_delete,
    m2m_changed
)
from django.dispatch import receiver, Signal
from django.http import HttpRequest

from apps.users.models import User, UserProfile, CustomerMembership

from .services import AuditService, AuditEventData, AuditContext

logger = logging.getLogger(__name__)

# ===============================================================================
# CUSTOM SIGNALS FOR BUSINESS-SPECIFIC USER ACTIONS
# ===============================================================================

# Profile and account management signals
profile_updated = Signal()
profile_picture_changed = Signal()
emergency_contact_updated = Signal()
notification_preferences_changed = Signal()

# Privacy and consent signals  
privacy_settings_changed = Signal()
marketing_consent_changed = Signal()
gdpr_consent_changed = Signal()
cookie_consent_updated = Signal()
privacy_policy_accepted = Signal()
terms_accepted = Signal()

# Security configuration signals
password_strength_check = Signal()
api_key_generated = Signal()
api_key_revoked = Signal()
security_settings_changed = Signal()

# Customer relationship signals
customer_membership_role_changed = Signal()
primary_customer_changed = Signal()
customer_access_granted = Signal()
customer_access_revoked = Signal()
customer_context_switched = Signal()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def _get_audit_context_from_request(request: HttpRequest | None, user: User | None = None) -> AuditContext:
    """Extract audit context from Django request"""
    if not request:
        return AuditContext(user=user)
    
    # Extract client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip_address = (
        x_forwarded_for.split(',')[0].strip() 
        if x_forwarded_for 
        else request.META.get('REMOTE_ADDR', '127.0.0.1')
    )
    
    return AuditContext(
        user=user or getattr(request, 'user', None),
        ip_address=ip_address,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        session_key=getattr(request.session, 'session_key', None) if hasattr(request, 'session') else None,
        request_id=getattr(request, 'id', None)
    )

def _get_action_category_severity(action: str) -> tuple[str, str, bool, bool]:
    """
    Get category, severity, and flags for audit action
    
    Returns: (category, severity, is_sensitive, requires_review)
    """
    # Authentication events
    if action.startswith(('login_', 'logout_', 'session_', 'account_')):
        return ('authentication', 'medium', True, action in ['account_locked', 'login_failed_2fa'])
    
    # Password events
    if action.startswith('password_'):
        severity = 'high' if action in ['password_compromised', 'password_strength_weak'] else 'medium'
        return ('authentication', severity, True, action == 'password_compromised')
    
    # 2FA events
    if action.startswith('2fa_'):
        severity = 'high' if action in ['2fa_disabled', '2fa_admin_reset'] else 'medium'
        return ('authentication', severity, True, action in ['2fa_disabled', '2fa_admin_reset'])
    
    # Profile and privacy events
    if action in ['profile_updated', 'email_changed', 'phone_updated', 'name_changed']:
        return ('account_management', 'medium', True, False)
    
    if action.startswith(('privacy_', 'gdpr_', 'marketing_consent')):
        return ('privacy', 'high', True, action.endswith('_withdrawn'))
    
    # Authorization events - including staff role changes
    if action in ['role_assigned', 'role_removed', 'permission_granted', 'permission_revoked', 'staff_role_changed']:
        return ('authorization', 'high', True, True)
    
    # Customer relationship events
    if action.startswith('customer_'):
        return ('authorization', 'medium', False, action.endswith('_revoked'))
    
    # Security events
    if action.startswith(('security_', 'suspicious_', 'brute_force', 'malicious_')):
        return ('security_event', 'critical', True, True)
    
    # Data protection events
    if action.startswith(('data_export', 'data_deletion', 'data_breach')):
        return ('data_protection', 'high', True, True)
    
    # Business operations
    if action in ['invoice_accessed', 'payment_method_added', 'order_placed']:
        return ('business_operation', 'low', False, False)
    
    # System admin events
    if action.startswith(('system_', 'backup_', 'configuration_', 'user_impersonation')):
        return ('system_admin', 'high', True, True)
    
    # Default
    return ('business_operation', 'low', False, False)


def _create_audit_event(
    action: str,
    user: User | None = None,
    content_object: Any = None,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
    description: str = '',
    request: HttpRequest | None = None,
    metadata: dict[str, Any] | None = None
) -> None:
    """
    Unified audit event creation with automatic categorization
    """
    try:
        # Get context from request
        context = _get_audit_context_from_request(request, user)
        
        # Add additional metadata
        if metadata:
            context.metadata.update(metadata)
        
        # Get action classification
        category, severity, is_sensitive, requires_review = _get_action_category_severity(action)
        
        # Add classification to metadata
        context.metadata.update({
            'category': category,
            'severity': severity,
            'is_sensitive': is_sensitive,
            'requires_review': requires_review,
            'audit_signal': True
        })
        
        # Create event data
        event_data = AuditEventData(
            event_type=action,
            content_object=content_object,
            old_values=old_values,
            new_values=new_values,
            description=description
        )
        
        # Log the event
        audit_event = AuditService.log_event(event_data, context)
        
        # Update the audit event with classification fields
        audit_event.category = category
        audit_event.severity = severity
        audit_event.is_sensitive = is_sensitive
        audit_event.requires_review = requires_review
        audit_event.save(update_fields=['category', 'severity', 'is_sensitive', 'requires_review'])
        
        logger.info(f"✅ [Audit Signal] {action} logged for user {user.email if user else 'System'} ({category}/{severity})")
        
    except Exception as e:
        # Never let audit logging break application functionality
        logger.error(f"🔥 [Audit Signal] Failed to log {action}: {e}")


# ===============================================================================
# USER PROFILE & ACCOUNT MANAGEMENT SIGNALS
# ===============================================================================

@receiver(post_save, sender=User)
def audit_user_profile_changes(sender: type[User], instance: User, created: bool, **kwargs: Any) -> None:
    """
    Audit User model changes for security and compliance
    
    Tracks critical profile changes that may affect security or privacy:
    - Email address changes (authentication impact)
    - Name changes (identity verification) 
    - Phone number changes (2FA impact)
    - Role changes (authorization impact)
    - 2FA configuration changes
    - Privacy consent changes
    """
    if created:
        # New user creation is logged by the view, not here
        return
    
    try:
        # Check if we have update_fields specified - this helps detect specific changes
        update_fields = kwargs.get('update_fields', None)
        
        # If no specific fields were updated, we need to compare with previous version
        # However, for post_save signal, we don't have the previous version easily
        # We'll need to track changes differently
        
        # For testing and development, we'll use a simplified approach
        # In production, consider using django-model-utils or similar for change tracking
        
        # Since we can't easily get the old version in post_save signal,
        # we'll create audit events based on update_fields when available
        # This is a simplified implementation for the audit system
        
        # For comprehensive change tracking, consider using:
        # 1. django-model-utils FieldTracker
        # 2. Custom pre_save signal with caching
        # 3. Database triggers
        
        # Log general profile update for now
        if update_fields:
            sensitive_fields = {'email', 'first_name', 'last_name', 'phone', 'staff_role', 'two_factor_enabled', 'accepts_marketing'}
            changed_fields = set(update_fields) & sensitive_fields
            
            if changed_fields:
                # Create specific audit events based on changed fields
                for field in changed_fields:
                    if field == 'email':
                        _create_audit_event(
                            'email_changed',
                            user=instance,
                            content_object=instance,
                            new_values={'email': instance.email},
                            description="Email address changed",
                            metadata={'security_sensitive': True, 'requires_verification': True}
                        )
                    elif field in ['first_name', 'last_name']:
                        _create_audit_event(
                            'name_changed',
                            user=instance,
                            content_object=instance,
                            new_values={'first_name': instance.first_name, 'last_name': instance.last_name},
                            description=f"Name changed to {instance.get_full_name()}",
                            metadata={'identity_change': True}
                        )
                    elif field == 'phone':
                        _create_audit_event(
                            'phone_updated',
                            user=instance,
                            content_object=instance,
                            new_values={'phone': instance.phone},
                            description="Phone number updated",
                            metadata={'affects_2fa': True, 'requires_verification': True}
                        )
                    elif field == 'staff_role':
                        _create_audit_event(
                            'staff_role_changed',
                            user=instance,
                            content_object=instance,
                            new_values={'staff_role': instance.staff_role},
                            description=f"Staff role changed to {instance.staff_role}",
                            metadata={'authorization_change': True, 'requires_review': True}
                        )
                    elif field == 'two_factor_enabled':
                        action = '2fa_enabled' if instance.two_factor_enabled else '2fa_disabled'
                        _create_audit_event(
                            action,
                            user=instance,
                            content_object=instance,
                            new_values={'two_factor_enabled': instance.two_factor_enabled},
                            description=f"2FA {'enabled' if instance.two_factor_enabled else 'disabled'}",
                            metadata={'security_configuration': True, 'requires_review': not instance.two_factor_enabled}
                        )
                    elif field == 'accepts_marketing':
                        action = 'marketing_consent_granted' if instance.accepts_marketing else 'marketing_consent_withdrawn'
                        _create_audit_event(
                            action,
                            user=instance,
                            content_object=instance,
                            new_values={'accepts_marketing': instance.accepts_marketing},
                            description=f"Marketing consent {'granted' if instance.accepts_marketing else 'withdrawn'}",
                            metadata={'gdpr_compliance': True, 'consent_change': True}
                        )
        else:
            # If no specific update_fields, log a general profile update
            _create_audit_event(
                'profile_updated',
                user=instance,
                content_object=instance,
                description="User profile updated",
                metadata={'general_update': True}
            )
        
    except Exception as e:
        logger.error(f"🔥 [Audit Signal] Failed to audit user profile changes for {instance.email}: {e}")


@receiver(post_save, sender=UserProfile)
def audit_user_profile_preferences(sender: type[UserProfile], instance: UserProfile, created: bool, **kwargs: Any) -> None:
    """Audit UserProfile changes for preference tracking"""
    if created:
        return
    
    try:
        # Similar to User model, we'll use update_fields when available
        update_fields = kwargs.get('update_fields', None)
        
        if update_fields:
            preference_fields = {
                'preferred_language', 'timezone', 'email_notifications', 
                'sms_notifications', 'marketing_emails', 'emergency_contact_name', 
                'emergency_contact_phone'
            }
            changed_fields = set(update_fields) & preference_fields
        
            if changed_fields:
                for field in changed_fields:
                    if field == 'preferred_language':
                        _create_audit_event(
                            'language_preference_changed',
                            user=instance.user,
                            content_object=instance,
                            new_values={'preferred_language': instance.preferred_language},
                            description=f"Language preference changed to {instance.preferred_language}",
                            metadata={'preference_change': True}
                        )
                    elif field == 'timezone':
                        _create_audit_event(
                            'timezone_changed',
                            user=instance.user,
                            content_object=instance,
                            new_values={'timezone': instance.timezone},
                            description=f"Timezone changed to {instance.timezone}",
                            metadata={'preference_change': True}
                        )
                    elif field in ['email_notifications', 'sms_notifications', 'marketing_emails']:
                        # Handle notification settings changes
                        notification_data = {
                            field: getattr(instance, field)
                        }
                        _create_audit_event(
                            'notification_settings_changed',
                            user=instance.user,
                            content_object=instance,
                            new_values=notification_data,
                            description=f"Notification preference changed: {field}",
                            metadata={'notification_change': True, 'channel': field}
                        )
                    elif field in ['emergency_contact_name', 'emergency_contact_phone']:
                        _create_audit_event(
                            'emergency_contact_updated',
                            user=instance.user,
                            content_object=instance,
                            new_values={
                                'name': instance.emergency_contact_name,
                                'phone': instance.emergency_contact_phone
                            },
                            description="Emergency contact information updated",
                            metadata={'security_relevant': True}
                        )
        else:
            # General profile preferences update
            _create_audit_event(
                'profile_updated',
                user=instance.user,
                content_object=instance,
                description="User profile preferences updated",
                metadata={'preferences_update': True}
            )
        
    except Exception as e:
        logger.error(f"🔥 [Audit Signal] Failed to audit user profile preferences for {instance.user.email}: {e}")


# ===============================================================================
# CUSTOMER RELATIONSHIP AUDITING
# ===============================================================================

@receiver(post_save, sender=CustomerMembership)
def audit_customer_membership_changes(sender: type[CustomerMembership], instance: CustomerMembership, created: bool, **kwargs: Any) -> None:
    """Audit customer membership changes for authorization tracking"""
    try:
        if created:
            _create_audit_event(
                'customer_membership_created',
                user=instance.user,
                content_object=instance,
                new_values={
                    'customer': str(instance.customer),
                    'role': instance.role,
                    'is_primary': instance.is_primary
                },
                description=f"Customer membership created: {instance.user.email} → {instance.customer.company_name} ({instance.role})",
                metadata={'authorization_change': True, 'customer_id': str(instance.customer.id)}
            )
        else:
            # For updates, use update_fields when available
            update_fields = kwargs.get('update_fields', None)
            
            if update_fields:
                if 'role' in update_fields:
                    _create_audit_event(
                        'customer_role_changed',
                        user=instance.user,
                        content_object=instance,
                        new_values={'role': instance.role},
                        description=f"Customer role changed to {instance.role}",
                        metadata={'authorization_change': True, 'customer_id': str(instance.customer.id), 'requires_review': True}
                    )
                
                if 'is_primary' in update_fields and instance.is_primary:
                    _create_audit_event(
                        'primary_customer_changed',
                        user=instance.user,
                        content_object=instance,
                        new_values={'new_primary': str(instance.customer)},
                        description=f"Primary customer set to {instance.customer.company_name}",
                        metadata={'authorization_change': True, 'customer_id': str(instance.customer.id)}
                    )
            else:
                # General membership update
                _create_audit_event(
                    'customer_membership_updated',
                    user=instance.user,
                    content_object=instance,
                    description=f"Customer membership updated: {instance.user.email} → {instance.customer.company_name}",
                    metadata={'authorization_change': True, 'customer_id': str(instance.customer.id)}
                )
                
    except Exception as e:
        logger.error(f"🔥 [Audit Signal] Failed to audit customer membership changes: {e}")


@receiver(pre_delete, sender=CustomerMembership)
def audit_customer_membership_deletion(sender: type[CustomerMembership], instance: CustomerMembership, **kwargs: Any) -> None:
    """Audit customer membership deletion"""
    try:
        _create_audit_event(
            'customer_membership_deleted',
            user=instance.user,
            content_object=instance,
            old_values={
                'customer': str(instance.customer),
                'role': instance.role,
                'is_primary': instance.is_primary
            },
            description=f"Customer membership removed: {instance.user.email} ← {instance.customer.company_name}",
            metadata={
                'authorization_change': True, 
                'customer_id': str(instance.customer.id),
                'access_revoked': True
            }
        )
    except Exception as e:
        logger.error(f"🔥 [Audit Signal] Failed to audit customer membership deletion: {e}")


# ===============================================================================
# CUSTOM SIGNAL HANDLERS FOR BUSINESS-SPECIFIC EVENTS
# ===============================================================================

@receiver(privacy_settings_changed)
def audit_privacy_settings_change(sender: Any, user: User, old_settings: dict[str, Any], new_settings: dict[str, Any], request: HttpRequest | None = None, **kwargs: Any) -> None:
    """Audit privacy settings changes"""
    _create_audit_event(
        'privacy_settings_changed',
        user=user,
        content_object=user,
        old_values=old_settings,
        new_values=new_settings,
        description="Privacy settings updated",
        request=request,
        metadata={'gdpr_compliance': True, 'privacy_change': True}
    )


@receiver(api_key_generated)
def audit_api_key_generation(sender: Any, user: User, api_key_info: dict[str, Any], request: HttpRequest | None = None, **kwargs: Any) -> None:
    """Audit API key generation"""
    _create_audit_event(
        'api_key_generated',
        user=user,
        content_object=user,
        new_values={'api_key_id': api_key_info.get('id'), 'name': api_key_info.get('name')},
        description=f"API key generated: {api_key_info.get('name', 'Unnamed')}",
        request=request,
        metadata={'integration_change': True, 'security_sensitive': True}
    )


@receiver(api_key_revoked)  
def audit_api_key_revocation(sender: Any, user: User, api_key_info: dict[str, Any], request: HttpRequest | None = None, **kwargs: Any) -> None:
    """Audit API key revocation"""
    _create_audit_event(
        'api_key_revoked',
        user=user,
        content_object=user,
        old_values={'api_key_id': api_key_info.get('id'), 'name': api_key_info.get('name')},
        description=f"API key revoked: {api_key_info.get('name', 'Unnamed')}",
        request=request,
        metadata={'integration_change': True, 'security_action': True}
    )


@receiver(customer_context_switched)
def audit_customer_context_switch(sender: Any, user: User, old_customer: Any, new_customer: Any, request: HttpRequest | None = None, **kwargs: Any) -> None:
    """Audit customer context switching"""
    _create_audit_event(
        'customer_context_switched',
        user=user,
        content_object=user,
        old_values={'customer': str(old_customer) if old_customer else None},
        new_values={'customer': str(new_customer) if new_customer else None},
        description=f"Customer context switched to {new_customer}",
        request=request,
        metadata={'context_change': True, 'customer_id': str(new_customer.id) if new_customer else None}
    )


# ===============================================================================
# SIGNAL REGISTRATION HELPER
# ===============================================================================

def register_audit_signals() -> None:
    """Register all audit signals - called from apps.py"""
    logger.info("✅ [Audit Signals] Comprehensive audit signals registered")
    
    # The @receiver decorators automatically register the signals
    # This function exists for explicit registration if needed