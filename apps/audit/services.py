from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import transaction
from django.utils import timezone

from apps.common.types import EmailAddress, Err, Ok, Result
from apps.tickets.models import Ticket  # Import for GDPR data export

from .models import (
    AuditAlert,
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    AuditSearchQuery,
    ComplianceLog,
    DataExport,
)

"""
Audit services for PRAHO Platform
Centralized audit logging for Romanian compliance and security.
"""


class AuditJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for audit system metadata serialization.
    
    Handles common Django and Python types that are not serializable by default:
    - UUID objects (convert to string)
    - datetime objects (convert to ISO format)
    - Decimal objects (convert to string to preserve precision)
    - Model instances (convert to string representation)
    """
    
    def default(self, obj: Any) -> Any:
        """Convert non-serializable objects to JSON-serializable formats"""
        if isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return str(obj)  # Preserve precision as string
        elif hasattr(obj, 'pk'):  # Django model instance
            return f"{obj.__class__.__name__}(pk={obj.pk})"
        elif hasattr(obj, '__dict__'):  # Generic object with attributes
            return str(obj)
        
        # Let the base class handle other types or raise TypeError
        return super().default(obj)


def serialize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """
    Safely serialize metadata dictionary for JSONField storage.
    
    Pre-processes the metadata to convert non-serializable objects
    using our custom encoder before storing in the database.
    
    Args:
        metadata: Raw metadata dictionary that may contain non-serializable objects
        
    Returns:
        Serializable metadata dictionary safe for JSONField
        
    Raises:
        TypeError: If metadata contains objects that cannot be serialized
    """
    if not metadata:
        return {}
    
    try:
        # Use our custom encoder to serialize and then deserialize
        # This ensures all objects are converted to serializable forms
        serialized_json = json.dumps(metadata, cls=AuditJSONEncoder, ensure_ascii=False)
        return json.loads(serialized_json)
    except (TypeError, ValueError) as e:
        logger.error(f"🔥 [Audit] Failed to serialize metadata: {e}")
        # Fallback: return a safe version with error information
        return {
            'serialization_error': str(e),
            'original_keys': list(metadata.keys()) if isinstance(metadata, dict) else 'not_dict',
            'timestamp': datetime.now().isoformat()
        }

if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()

class ExportScope(TypedDict):
    """Type definition for GDPR export scope configuration"""
    include_profile: bool
    include_customers: bool
    include_billing: bool
    include_tickets: bool
    include_audit_logs: bool
    include_sessions: bool
    format: str

class AuditEventType(TypedDict):
    """Type definition for audit event types"""
    event_type: str
    category: str
    severity: str
    description: str

class ComplianceReport(TypedDict):
    """Type definition for compliance reports"""
    report_type: str
    period_start: str
    period_end: str
    user_email: EmailAddress
    status: str
    violations: list[dict[str, Any]]

class ConsentHistoryEntry(TypedDict):
    """Type definition for consent history entries"""
    timestamp: str
    action: str
    description: str
    status: str
    evidence: dict[str, Any]

@dataclass
class AuditContext:
    """Parameter object for audit event context information"""
    user: User | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    session_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    actor_type: str = 'user'

@dataclass
class AuditEventData:
    """
    Parameter object for audit event data
    
    Supports models with both integer and UUID primary keys.
    The content_object.pk will be converted to string representation
    to handle mixed primary key types in the audit system.
    """
    event_type: str
    content_object: Any | None = None  # Any Django model instance
    old_values: dict[str, Any] | None = None
    new_values: dict[str, Any] | None = None
    description: str = ''

@dataclass
class TwoFactorAuditRequest:
    """Parameter object for 2FA audit events"""
    event_type: str
    user: User
    context: AuditContext = field(default_factory=AuditContext)
    description: str = ''

@dataclass
class ComplianceEventRequest:
    """Parameter object for compliance events"""
    compliance_type: str
    reference_id: str
    description: str
    user: User | None = None
    status: str = 'success'
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
logger = logging.getLogger(__name__)


class AuthenticationAuditService:
    """
    🔐 Specialized authentication audit service
    
    Features:
    - Rich metadata capture for security analysis
    - Session-level security event monitoring
    - Support for different authentication methods
    - Geographic and temporal analysis data
    - Failed login attempt tracking
    - Account lockout event logging
    """

    @staticmethod
    def log_login_success(
        user: User,
        request: Any = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_key: str | None = None,
        authentication_method: str = 'password',
        metadata: dict[str, Any] | None = None
    ) -> AuditEvent:
        """
        Log successful login event with comprehensive metadata
        
        Args:
            user: The authenticated user
            request: Django request object (optional, for extracting context)
            ip_address: Client IP address
            user_agent: Client user agent string
            session_key: Session identifier
            authentication_method: Method used (password, 2fa_totp, 2fa_backup, etc.)
            metadata: Additional metadata
        """
        # Extract context from request if provided
        if request:
            ip_address = ip_address or _get_client_ip_from_request(request)
            user_agent = user_agent or request.META.get('HTTP_USER_AGENT', '')
            session_key = session_key or request.session.session_key
        
        # Build comprehensive metadata
        auth_metadata = {
            'authentication_method': authentication_method,
            'login_timestamp': timezone.now().isoformat(),
            'user_id': str(user.id),
            'user_email': user.email,
            'user_staff_status': user.is_staff,
            'user_2fa_enabled': getattr(user, 'two_factor_enabled', False),
            'previous_login': user.last_login.isoformat() if user.last_login else None,
            'failed_attempts_before': getattr(user, 'failed_login_attempts', 0),
            'account_was_locked': getattr(user, 'is_account_locked', lambda: False)(),
            'session_info': {
                'session_key': session_key,
                'session_created': timezone.now().isoformat()
            },
            **(metadata or {})
        }
        
        # Add user agent analysis if available
        if user_agent:
            auth_metadata['user_agent_info'] = {
                'raw': user_agent,
                'truncated': user_agent[:200],  # Prevent excessively long strings
            }
        
        context = AuditContext(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            session_key=session_key,
            metadata=auth_metadata,
            actor_type='user'
        )
        
        event_data = AuditEventData(
            event_type='login_success',
            content_object=user,
            description=f"Successful login via {authentication_method} for {user.email}"
        )
        
        return AuditService.log_event(event_data, context)

    @staticmethod
    def log_login_failed(
        email: str | None = None,
        user: User | None = None,
        failure_reason: str = 'invalid_credentials',
        request: Any = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> AuditEvent:
        """
        Log failed login attempt with security-focused metadata
        
        Args:
            email: Attempted email (may not exist)
            user: User object if exists (optional)
            failure_reason: Reason for failure (invalid_password, user_not_found, account_locked, etc.)
            request: Django request object (optional)
            ip_address: Client IP address
            user_agent: Client user agent string
            metadata: Additional metadata
        """
        # Extract context from request if provided
        if request:
            ip_address = ip_address or _get_client_ip_from_request(request)
            user_agent = user_agent or request.META.get('HTTP_USER_AGENT', '')
        
        # Determine the appropriate action based on failure reason
        action_map = {
            'invalid_password': 'login_failed_password',
            'user_not_found': 'login_failed_user_not_found', 
            'account_locked': 'login_failed_account_locked',
            '2fa_verification': 'login_failed_2fa',
            'unknown': 'login_failed'
        }
        action = action_map.get(failure_reason, 'login_failed')
        
        # Build security-focused metadata
        auth_metadata = {
            'failure_reason': failure_reason,
            'attempted_email': email,
            'attempt_timestamp': timezone.now().isoformat(),
            'security_analysis': {
                'ip_based_attempt': True,
                'user_agent_provided': bool(user_agent),
            },
            **(metadata or {})
        }
        
        # Add user context if user exists
        if user:
            auth_metadata.update({
                'user_id': str(user.id),
                'user_exists': True,
                'user_active': user.is_active,
                'user_staff': user.is_staff,
                'previous_failed_attempts': getattr(user, 'failed_login_attempts', 0),
                'account_locked': getattr(user, 'is_account_locked', lambda: False)(),
                'user_2fa_enabled': getattr(user, 'two_factor_enabled', False),
            })
        else:
            auth_metadata.update({
                'user_exists': False,
                'attempted_email_format_valid': bool(email and '@' in email),
            })
        
        context = AuditContext(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=auth_metadata,
            actor_type='anonymous' if not user else 'user'
        )
        
        event_data = AuditEventData(
            event_type=action,
            content_object=user,  # May be None for non-existent users
            description=f"Failed login attempt: {failure_reason} for {email or 'unknown'}"
        )
        
        return AuditService.log_event(event_data, context)

    @staticmethod
    def log_logout(
        user: User,
        logout_reason: str = 'manual',
        request: Any = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_key: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> AuditEvent:
        """
        Log logout event with session and security context
        
        Args:
            user: The user being logged out
            logout_reason: Reason for logout (manual, session_expired, security_event, concurrent_session)
            request: Django request object (optional)
            ip_address: Client IP address
            user_agent: Client user agent string  
            session_key: Session identifier being ended
            metadata: Additional metadata
        """
        # Extract context from request if provided
        if request:
            ip_address = ip_address or _get_client_ip_from_request(request)
            user_agent = user_agent or request.META.get('HTTP_USER_AGENT', '')
            session_key = session_key or getattr(request.session, 'session_key', None)
        
        # Map logout reasons to actions
        action_map = {
            'manual': 'logout_manual',
            'session_expired': 'logout_session_expired',
            'security_event': 'logout_security_event',
            'concurrent_session': 'logout_concurrent_session'
        }
        action = action_map.get(logout_reason, 'logout_manual')
        
        # Build session and security metadata
        auth_metadata = {
            'logout_reason': logout_reason,
            'logout_timestamp': timezone.now().isoformat(),
            'user_id': str(user.id),
            'user_email': user.email,
            'session_info': {
                'session_key': session_key,
                'session_ended': timezone.now().isoformat(),
            },
            'security_context': {
                'user_2fa_enabled': getattr(user, 'two_factor_enabled', False),
                'logout_triggered_by': logout_reason,
            },
            **(metadata or {})
        }
        
        # Add login session duration if available
        if user.last_login:
            session_duration = timezone.now() - user.last_login
            auth_metadata['session_info']['duration_seconds'] = int(session_duration.total_seconds())
            auth_metadata['session_info']['duration_human'] = str(session_duration)
        
        context = AuditContext(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            session_key=session_key,
            metadata=auth_metadata,
            actor_type='user'
        )
        
        event_data = AuditEventData(
            event_type=action,
            content_object=user,
            description=f"User logout: {logout_reason} for {user.email}"
        )
        
        return AuditService.log_event(event_data, context)

    @staticmethod
    def log_account_locked(
        user: User,
        trigger_reason: str,
        request: Any = None,
        ip_address: str | None = None,
        failed_attempts: int | None = None,
        metadata: dict[str, Any] | None = None
    ) -> AuditEvent:
        """
        Log account lockout event with security details
        
        Args:
            user: The user whose account was locked
            trigger_reason: Why the account was locked
            request: Django request object (optional)
            ip_address: Client IP address
            failed_attempts: Number of failed attempts that triggered lockout
            metadata: Additional metadata
        """
        if request:
            ip_address = ip_address or _get_client_ip_from_request(request)
        
        auth_metadata = {
            'lockout_reason': trigger_reason,
            'lockout_timestamp': timezone.now().isoformat(),
            'failed_attempts_count': failed_attempts or getattr(user, 'failed_login_attempts', 0),
            'user_id': str(user.id),
            'user_email': user.email,
            'security_event': True,
            **(metadata or {})
        }
        
        context = AuditContext(
            user=user,
            ip_address=ip_address,
            metadata=auth_metadata,
            actor_type='system'
        )
        
        event_data = AuditEventData(
            event_type='account_locked',
            content_object=user,
            description=f"Account locked for {user.email}: {trigger_reason}"
        )
        
        return AuditService.log_event(event_data, context)

    @staticmethod
    def log_session_rotation(
        user: User,
        reason: str,
        request: Any = None,
        old_session_key: str | None = None,
        new_session_key: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> AuditEvent:
        """
        Log session rotation events for security tracking
        
        Args:
            user: The user whose session was rotated
            reason: Reason for rotation (2fa_change, password_change, security_event)
            request: Django request object (optional) 
            old_session_key: Previous session key
            new_session_key: New session key
            metadata: Additional metadata
        """
        auth_metadata = {
            'rotation_reason': reason,
            'rotation_timestamp': timezone.now().isoformat(),
            'user_id': str(user.id),
            'session_info': {
                'old_session_key': old_session_key,
                'new_session_key': new_session_key,
            },
            'security_enhancement': True,
            **(metadata or {})
        }
        
        context = AuditContext(
            user=user,
            ip_address=_get_client_ip_from_request(request) if request else None,
            session_key=new_session_key,
            metadata=auth_metadata,
            actor_type='system'
        )
        
        event_data = AuditEventData(
            event_type='session_rotation',
            content_object=user,
            description=f"Session rotated for {user.email}: {reason}"
        )
        
        return AuditService.log_event(event_data, context)


def _get_client_ip_from_request(request: Any) -> str:
    """Extract client IP address from Django request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    return ip if ip else '127.0.0.1'


class AuditService:
    """Centralized audit logging service"""

    @staticmethod
    def log_event(
        event_data: AuditEventData,
        context: AuditContext | None = None
    ) -> AuditEvent:
        """
        🔐 Log an audit event with full context and automatic categorization

        Args:
            event_data: AuditEventData containing event information
            context: AuditContext containing user and request context (optional)
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext()
        
        try:
            # Get content type and object ID - both are required by the model
            if event_data.content_object:
                content_type = ContentType.objects.get_for_model(event_data.content_object)
                # Convert primary key to string to handle both integers and UUIDs
                object_id = str(event_data.content_object.pk)
            else:
                # For events without a specific object, use the User model as a fallback
                # This ensures we always have valid content_type and object_id
                content_type = ContentType.objects.get_for_model(User)
                # Convert to string to handle both integer and UUID user PKs
                object_id = str(context.user.pk) if context.user else "1"  # Use system user ID=1 as fallback

            # Safely serialize metadata before storing
            serialized_metadata = serialize_metadata(context.metadata)
            
            # Get automatic categorization from metadata or determine from action
            category = context.metadata.get('category', AuditService._get_action_category(event_data.event_type))
            severity = context.metadata.get('severity', AuditService._get_action_severity(event_data.event_type))
            is_sensitive = context.metadata.get('is_sensitive', AuditService._is_action_sensitive(event_data.event_type))
            requires_review = context.metadata.get('requires_review', AuditService._requires_review(event_data.event_type))
            
            # Create audit event with categorization
            audit_event = AuditEvent.objects.create(
                user=context.user,
                actor_type=context.actor_type,
                action=event_data.event_type,
                category=category,
                severity=severity,
                is_sensitive=is_sensitive,
                requires_review=requires_review,
                content_type=content_type,
                object_id=object_id,
                old_values=event_data.old_values or {},
                new_values=event_data.new_values or {},
                description=event_data.description,
                ip_address=context.ip_address,
                user_agent=context.user_agent or '',
                request_id=context.request_id or str(uuid.uuid4()),
                session_key=context.session_key or '',
                metadata=serialized_metadata
            )

            logger.info(
                f"✅ [Audit] {event_data.event_type} event logged for user {context.user.email if context.user else 'System'} ({category}/{severity})"
            )

            return audit_event

        except Exception as e:
            logger.error(f"🔥 [Audit] Failed to log event {event_data.event_type}: {e}")
            raise
    
    @staticmethod
    def _get_action_category(action: str) -> str:
        """Determine audit event category from action type"""
        # Authentication events
        if action.startswith(('login_', 'logout_', 'session_', 'account_')):
            return 'authentication'
        
        # Password events
        if action.startswith('password_'):
            return 'authentication'
        
        # 2FA events
        if action.startswith('2fa_'):
            return 'authentication'
        
        # Profile and privacy events
        if action in ['profile_updated', 'email_changed', 'phone_updated', 'name_changed']:
            return 'account_management'
        
        if action.startswith(('privacy_', 'gdpr_', 'marketing_consent', 'cookie_consent')):
            return 'privacy'
        
        # Authorization events
        if action in ['role_assigned', 'role_removed', 'permission_granted', 'permission_revoked', 'staff_role_changed']:
            return 'authorization'
        
        # Customer relationship events
        if action.startswith('customer_'):
            return 'authorization'
        
        # Security events
        if action.startswith(('security_', 'suspicious_', 'brute_force', 'malicious_')):
            return 'security_event'
        
        # Data protection events (except data_breach which is security)
        if action.startswith(('data_export', 'data_deletion')):
            return 'data_protection'
        
        # Data breach is a security event
        if action.startswith('data_breach'):
            return 'security_event'
        
        # API/Integration events
        if action.startswith(('api_', 'webhook_')):
            return 'integration'
        
        # System admin events
        if action.startswith(('system_', 'backup_', 'configuration_', 'user_impersonation')):
            return 'system_admin'
        
        # Compliance events
        if action.startswith(('vat_', 'efactura_', 'data_retention', 'tax_rule')):
            return 'compliance'
        
        # Billing and financial events
        if action.startswith(('proforma_', 'invoice_', 'payment_', 'credit_', 'billing_', 'currency_conversion')):
            return 'business_operation'
        
        # Order management events
        if action.startswith(('order_', 'provisioning_', 'service_', 'domain_')):
            return 'business_operation'
        
        # Default to business operation
        return 'business_operation'
    
    @staticmethod
    def _get_action_severity(action: str) -> str:
        """Determine severity level from action type"""
        # Critical severity events
        critical_actions = [
            'data_breach_detected', 'security_incident_detected', 'account_compromised',
            'privilege_escalation_attempt', 'malicious_request', 'brute_force_attempt'
        ]
        
        # High severity events
        high_actions = [
            'password_compromised', '2fa_disabled', '2fa_admin_reset', 'role_assigned', 
            'role_removed', 'permission_granted', 'permission_revoked', 'staff_role_changed',
            'data_export_requested', 'data_deletion_requested', 'gdpr_consent_withdrawn', 
            'user_impersonation_started', 'system_maintenance_started', 'configuration_changed',
            'payment_failed', 'payment_fraud_detected', 'payment_chargeback_received', 
            'invoice_voided', 'invoice_refunded', 'credit_limit_changed', 'credit_hold_applied',
            'order_cancelled_admin', 'provisioning_failed', 'efactura_rejected'
        ]
        
        # Medium severity events
        medium_actions = [
            'login_success', 'login_failed', 'logout_manual', 'account_locked', 'session_rotation',
            'password_changed', '2fa_enabled', 'profile_updated', 'email_changed', 'phone_updated',
            'customer_membership_created', 'api_key_generated', 'invoice_created', 
            'invoice_paid', 'payment_succeeded', 'order_created', 'order_completed',
            'proforma_created', 'provisioning_completed', 'efactura_submitted'
        ]
        
        if action in critical_actions or action.startswith(('security_', 'suspicious_', 'data_breach')):
            return 'critical'
        elif action in high_actions or action.startswith(('data_', 'gdpr_', 'privacy_', 'marketing_consent', 'cookie_consent', 'role_', 'permission_', 'payment_fraud', 'payment_chargeback')):
            return 'high'
        elif action in medium_actions or action.startswith(('login_', 'password_', '2fa_', 'profile_', 'invoice_', 'payment_', 'order_')):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _is_action_sensitive(action: str) -> bool:
        """Determine if action involves sensitive data"""
        # Specific sensitive actions
        sensitive_actions = [
            'account_locked', 'account_unlocked', 'session_rotation', 'session_terminated',
            'suspicious_activity', 'brute_force_attempt', 'malicious_request'
        ]
        
        # Sensitive patterns
        sensitive_patterns = [
            'login_', 'logout_', 'password_', '2fa_', 'email_', 'phone_', 'profile_',
            'privacy_', 'gdpr_', 'marketing_consent', 'cookie_consent', 'data_', 'security_', 
            'role_', 'permission_', 'payment_', 'billing_', 'tax_', 'invoice_', 'credit_', 
            'proforma_', 'vat_', 'efactura_', 'order_', 'customer_'
        ]
        
        return action in sensitive_actions or any(action.startswith(pattern) for pattern in sensitive_patterns)
    
    @staticmethod
    def _requires_review(action: str) -> bool:
        """Determine if action requires manual review"""
        review_actions = [
            'account_locked', 'login_failed_2fa', 'password_compromised',
            '2fa_disabled', '2fa_admin_reset', 'role_assigned', 'role_removed',
            'permission_granted', 'permission_revoked', 'staff_role_changed',
            'privilege_escalation_attempt', 'data_export_requested', 'data_deletion_requested', 
            'gdpr_consent_withdrawn', 'security_incident_detected', 'suspicious_activity', 
            'brute_force_attempt', 'user_impersonation_started', 'configuration_changed', 
            'system_maintenance_started'
        ]
        
        return action in review_actions or action.startswith(('security_', 'data_breach', 'malicious_'))

    @staticmethod
    def log_2fa_event(request: TwoFactorAuditRequest) -> AuditEvent:
        """
        🔐 Log 2FA-specific audit event with enhanced categorization

        Supported event types:
        - 2fa_enabled, 2fa_disabled, 2fa_admin_reset
        - 2fa_backup_codes_generated, 2fa_backup_codes_viewed, 2fa_backup_code_used
        - 2fa_secret_regenerated, 2fa_verification_success, 2fa_verification_failed
        """
        # Enhance metadata with 2FA context and automatic categorization
        enhanced_metadata = {
            'event_category': 'authentication',  # 2FA is always authentication
            'category': 'authentication',
            'severity': 'high' if request.event_type in ['2fa_disabled', '2fa_admin_reset'] else 'medium',
            'is_sensitive': True,  # 2FA events are always sensitive
            'requires_review': request.event_type in ['2fa_disabled', '2fa_admin_reset'],
            'timestamp': timezone.now().isoformat(),
            **request.context.metadata
        }

        # Add user 2FA status to metadata
        if request.user:
            enhanced_metadata.update({
                'user_2fa_enabled': request.user.two_factor_enabled,
                'backup_codes_count': len(request.user.backup_tokens) if request.user.backup_tokens else 0
            })

        # Create enhanced context with metadata (metadata will be serialized in log_event)
        enhanced_context = AuditContext(
            user=request.user,
            ip_address=request.context.ip_address,
            user_agent=request.context.user_agent,
            request_id=request.context.request_id,
            session_key=request.context.session_key,
            metadata=enhanced_metadata,
            actor_type=request.context.actor_type
        )

        # Create event data
        event_data = AuditEventData(
            event_type=request.event_type,
            content_object=request.user,  # 2FA events act on the user object
            description=request.description or f"2FA {request.event_type.replace('_', ' ').title()}"
        )

        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_compliance_event(request: ComplianceEventRequest) -> ComplianceLog:
        """
        📋 Log Romanian compliance event
        
        Args:
            request: ComplianceEventRequest containing all compliance event data
        """
        try:
            # Safely serialize evidence and metadata before storing
            serialized_evidence = serialize_metadata(request.evidence)
            serialized_metadata = serialize_metadata(request.metadata)
            
            compliance_log = ComplianceLog.objects.create(
                compliance_type=request.compliance_type,
                reference_id=request.reference_id,
                description=request.description,
                user=request.user,
                status=request.status,
                evidence=serialized_evidence,
                metadata=serialized_metadata
            )

            logger.info(
                f"📋 [Compliance] {request.compliance_type} logged: {request.reference_id}"
            )

            return compliance_log

        except Exception as e:
            logger.error(f"🔥 [Compliance] Failed to log {request.compliance_type}: {e}")
            raise
    
    # ===============================================================================
    # BACKWARD COMPATIBILITY WRAPPER METHODS
    # ===============================================================================
    
    @staticmethod
    def log_event_legacy(  # noqa: PLR0913
        event_type: str,
        user: User | None = None,
        content_object: Any | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str = '',
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        session_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        actor_type: str = 'user'
    ) -> AuditEvent:
        """Legacy wrapper for backward compatibility"""
        event_data = AuditEventData(
            event_type=event_type,
            content_object=content_object,
            old_values=old_values,
            new_values=new_values,
            description=description
        )
        
        context = AuditContext(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_key=session_key,
            metadata=metadata or {},
            actor_type=actor_type
        )
        
        return AuditService.log_event(event_data, context)
    
    @staticmethod
    def log_2fa_event_legacy(  # noqa: PLR0913
        event_type: str,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        description: str = '',
        request_id: str | None = None,
        session_key: str | None = None
    ) -> AuditEvent:
        """Legacy wrapper for backward compatibility"""
        context = AuditContext(
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_key=session_key,
            metadata=metadata or {}
        )
        
        request = TwoFactorAuditRequest(
            event_type=event_type,
            user=user,
            context=context,
            description=description
        )
        
        return AuditService.log_2fa_event(request)
    
    @staticmethod
    def log_compliance_event_legacy(  # noqa: PLR0913
        compliance_type: str,
        reference_id: str,
        description: str,
        user: User | None = None,
        status: str = 'success',
        evidence: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> ComplianceLog:
        """Legacy wrapper for backward compatibility"""
        request = ComplianceEventRequest(
            compliance_type=compliance_type,
            reference_id=reference_id,
            description=description,
            user=user,
            status=status,
            evidence=evidence or {},
            metadata=metadata or {}
        )
        
        return AuditService.log_compliance_event(request)


class AuditServiceProxy:
    """Proxy class to maintain backward compatibility with existing code"""
    
    def log_event(self, *args: Any, **kwargs: Any) -> AuditEvent:
        return AuditService.log_event_legacy(*args, **kwargs)
    
    def log_2fa_event(self, *args: Any, **kwargs: Any) -> AuditEvent:
        return AuditService.log_2fa_event_legacy(*args, **kwargs)
    
    def log_compliance_event(self, *args: Any, **kwargs: Any) -> ComplianceLog:
        return AuditService.log_compliance_event_legacy(*args, **kwargs)


# Global audit service instance (backward compatible)
audit_service = AuditServiceProxy()


# ===============================================================================
# GDPR COMPLIANCE SERVICES
# ===============================================================================

class GDPRExportService:
    """
    🔒 Comprehensive GDPR data export service (Article 20 - Right to data portability)
    
    Features:
    - Complete user data collection across all related models
    - Secure JSON export with encryption
    - Automatic cleanup and expiration
    - Comprehensive audit logging
    - Romanian business compliance
    """

    @classmethod
    @transaction.atomic
    def create_data_export_request(
        cls,
        user: User,
        request_ip: str | None = None,
        export_scope: dict[str, Any] | None = None
    ) -> Result[DataExport, str]:
        """Create a new GDPR data export request"""

        try:
            # Default export scope - comprehensive user data
            if not export_scope:
                export_scope = {
                    'include_profile': True,
                    'include_customers': True,
                    'include_billing': True,
                    'include_tickets': True,
                    'include_audit_logs': True,
                    'include_sessions': False,  # Security sensitive
                    'format': 'json'
                }

            export_request = DataExport.objects.create(
                requested_by=user,
                export_type='gdpr',
                scope=export_scope,
                status='pending',
                expires_at=timezone.now() + timedelta(days=7)  # 7 days to download
            )

            # Log GDPR export request
            compliance_request = ComplianceEventRequest(
                compliance_type='gdpr_consent',
                reference_id=f"export_{export_request.id}",
                description=f"GDPR data export requested by {user.email}",
                user=user,
                status='initiated',
                evidence={'export_id': str(export_request.id), 'scope': export_scope},
                metadata={'ip_address': request_ip}
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(f"🔒 [GDPR Export] Request created for {user.email}: {export_request.id}")
            return Ok(export_request)

        except Exception as e:
            logger.error(f"🔥 [GDPR Export] Failed to create request for {user.email}: {e}")
            return Err(f"Failed to create export request: {e!s}")

    @classmethod
    @transaction.atomic
    def process_data_export(cls, export_request: DataExport) -> Result[str, str]:
        """Process and generate the actual data export file"""
        try:
            user = export_request.requested_by
            export_request.status = 'processing'
            export_request.started_at = timezone.now()
            export_request.save(update_fields=['status', 'started_at'])

            # Collect all user data
            user_data = cls._collect_user_data(user, export_request.scope)

            # Generate export file
            export_content = json.dumps(user_data, indent=2, default=str, ensure_ascii=False)

            # Generate secure filename
            file_hash = hashlib.sha256(export_content.encode()).hexdigest()[:16]
            filename = f"gdpr_export_{user.id}_{file_hash}.json"

            # Save to secure storage
            file_path = f"gdpr_exports/{filename}"
            saved_path = default_storage.save(
                file_path,
                ContentFile(export_content.encode('utf-8'))
            )

            # Update export request
            export_request.status = 'completed'
            export_request.completed_at = timezone.now()
            export_request.file_path = saved_path
            export_request.file_size = len(export_content.encode('utf-8'))
            export_request.record_count = cls._count_records(user_data)
            export_request.save(update_fields=[
                'status', 'completed_at', 'file_path', 'file_size', 'record_count'
            ])

            # Log completion
            compliance_request = ComplianceEventRequest(
                compliance_type='gdpr_consent',
                reference_id=f"export_{export_request.id}",
                description=f"GDPR data export completed for {user.email}",
                user=user,
                status='completed',
                evidence={
                    'file_size_bytes': export_request.file_size,
                    'record_count': export_request.record_count,
                    'completion_time': export_request.completed_at.isoformat()
                }
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(f"✅ [GDPR Export] Completed for {user.email}: {export_request.file_size} bytes, {export_request.record_count} records")
            return Ok(saved_path)

        except Exception as e:
            # Mark as failed
            export_request.status = 'failed'
            export_request.error_message = str(e)
            export_request.save(update_fields=['status', 'error_message'])

            logger.error(f"🔥 [GDPR Export] Processing failed for {user.email}: {e}")
            return Err(f"Export processing failed: {e!s}")

    @classmethod
    def _collect_user_data(cls, user: User, scope: dict[str, Any]) -> dict[str, Any]:
        """Collect comprehensive user data based on export scope"""
        data: dict[str, Any] = {
            'metadata': {
                'generated_at': timezone.now().isoformat(),
                'user_id': user.id,
                'export_type': 'gdpr_data_portability',
                'praho_platform_version': '1.0.0',
                'gdpr_article': 'Article 20 - Right to data portability',
                'legal_basis': 'Romanian Law 190/2018, GDPR Article 20'
            },
            'user_profile': {},
            'customers': [],
            'billing_data': [],
            'support_tickets': [],
            'audit_summary': {}
        }

        # Core user profile data
        if scope.get('include_profile', True):
            data['user_profile'] = {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': user.phone,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'staff_role': user.staff_role,
                'gdpr_consent_date': user.gdpr_consent_date.isoformat() if user.gdpr_consent_date else None,
                'accepts_marketing': user.accepts_marketing,
                'last_privacy_policy_accepted': user.last_privacy_policy_accepted.isoformat() if user.last_privacy_policy_accepted else None,
                'account_status': 'active' if user.is_active else 'inactive'
            }

        # Customer relationships and data
        if scope.get('include_customers', True):
            try:
                memberships = user.customer_memberships.select_related('customer')
                for membership in memberships:
                    customer = membership.customer
                    customer_data = {
                        'customer_id': customer.id,
                        'company_name': customer.company_name,
                        'customer_type': customer.customer_type,
                        'role': membership.role,
                        'is_primary': membership.is_primary,
                        'joined_date': membership.created_at.isoformat(),
                        'status': customer.status
                    }
                    data['customers'].append(customer_data)
            except AttributeError:
                data['customers'] = {'note': 'Customer relationships not available'}

        # Support tickets
        if scope.get('include_tickets', True):
            try:
                tickets = Ticket.objects.filter(created_by=user)
                for ticket in tickets:
                    data['support_tickets'].append({
                        'ticket_id': ticket.id,
                        'subject': ticket.subject,
                        'status': ticket.status,
                        'priority': ticket.priority,
                        'created_at': ticket.created_at.isoformat(),
                        'updated_at': ticket.updated_at.isoformat()
                    })
            except ImportError:
                data['support_tickets'] = {'note': 'Support tickets not available'}

        # Audit trail summary (privacy-focused)
        if scope.get('include_audit_logs', True):
            audit_events = AuditEvent.objects.filter(user=user).order_by('-timestamp')[:100]  # Last 100 events
            data['audit_summary'] = {
                'total_events': audit_events.count(),
                'recent_activities': [
                    {
                        'action': event.action,
                        'timestamp': event.timestamp.isoformat(),
                        'description': event.description[:100]  # Truncated for privacy
                    }
                    for event in audit_events[:10]  # Last 10 activities
                ]
            }

        return data

    @classmethod
    def _count_records(cls, user_data: dict[str, Any]) -> int:
        """Count total records in the export"""
        count = 1  # User profile
        count += len(user_data.get('customers', []))
        count += len(user_data.get('billing_data', []))
        count += len(user_data.get('support_tickets', []))
        count += len(user_data.get('audit_summary', {}).get('recent_activities', []))
        return count


class GDPRDeletionService:
    """
    🔒 GDPR data deletion and anonymization service (Article 17 - Right to erasure)
    
    Features:
    - Safe data anonymization (preserves business records)
    - Complete data deletion where legally permitted
    - Cascade handling for related data
    - Audit trail preservation
    - Romanian business law compliance
    """

    ANONYMIZATION_MAP: ClassVar[dict[str, Any]] = {
        'email': lambda: f"anonymized_{uuid.uuid4().hex[:8]}@example.com",
        'first_name': lambda: "Anonymized",
        'last_name': lambda: "User",
        'phone': lambda: "+40700000000",
        'ip_address': lambda: "0.0.0.0",
    }

    @classmethod
    @transaction.atomic
    def create_deletion_request(
        cls,
        user: User,
        deletion_type: str = 'anonymize',  # 'anonymize' or 'delete'
        request_ip: str | None = None,
        reason: str | None = None
    ) -> Result[ComplianceLog, str]:
        """Create a GDPR data deletion request"""



        try:
            # Validate deletion type
            if deletion_type not in ['anonymize', 'delete']:
                return Err("Invalid deletion type. Must be 'anonymize' or 'delete'")

            # Check if user can be deleted (business rules)
            can_delete, restriction_reason = cls._can_user_be_deleted(user)
            if not can_delete and deletion_type == 'delete':
                logger.warning(f"⚠️ [GDPR Deletion] Full deletion blocked for {user.email}: {restriction_reason}")
                deletion_type = 'anonymize'  # Force anonymization instead

            # Create compliance log entry
            compliance_request = ComplianceEventRequest(
                compliance_type='gdpr_deletion',
                reference_id=f"deletion_{user.id}_{uuid.uuid4().hex[:8]}",
                description=f"GDPR {deletion_type} requested by {user.email}. Reason: {reason or 'User request'}" +
                           (". This action is irreversible." if deletion_type == 'delete' else ""),
                user=user,
                status='requested',
                evidence={
                    'deletion_type': deletion_type,
                    'user_email': user.email,
                    'reason': reason,
                    'can_full_delete': can_delete,
                    'restriction_reason': restriction_reason
                },
                metadata={'ip_address': request_ip}
            )
            deletion_request = AuditService.log_compliance_event(compliance_request)

            logger.info(f"🔒 [GDPR Deletion] {deletion_type.capitalize()} request created for {user.email}")
            return Ok(deletion_request)

        except Exception as e:
            logger.error(f"🔥 [GDPR Deletion] Failed to create request for {user.email}: {e}")
            return Err(f"Failed to create deletion request: {e!s}")

    @classmethod
    @transaction.atomic
    def process_deletion_request(cls, deletion_request: ComplianceLog) -> Result[str, str]:
        """Process the actual data deletion/anonymization"""


        try:
            user_email = deletion_request.evidence.get('user_email', 'unknown')
            deletion_type = deletion_request.evidence.get('deletion_type', 'anonymize')

            # Get user (might be already deleted)
            try:
                user = deletion_request.user
                if not user:
                    logger.warning(f"⚠️ [GDPR Deletion] User {user_email} already deleted")
                    deletion_request.status = 'completed'
                    deletion_request.save(update_fields=['status'])
                    return Ok("User already deleted")
            except User.DoesNotExist:
                deletion_request.status = 'completed'
                deletion_request.save(update_fields=['status'])
                return Ok("User already deleted")

            # Update request status
            deletion_request.status = 'processing'
            deletion_request.save(update_fields=['status'])

            if deletion_type == 'anonymize':
                result = cls._anonymize_user_data(user)
                action_taken = "anonymized"
            else:
                result = cls._delete_user_data(user)
                action_taken = "deleted"

            if result.is_err():
                deletion_request.status = 'failed'
                deletion_request.evidence['error'] = result.error if hasattr(result, 'error') else str(result)
                deletion_request.save(update_fields=['status', 'evidence'])
                return result

            # Mark as completed
            deletion_request.status = 'completed'
            deletion_request.evidence['completed_at'] = timezone.now().isoformat()
            deletion_request.evidence['action_taken'] = action_taken
            deletion_request.save(update_fields=['status', 'evidence'])

            logger.info(f"✅ [GDPR Deletion] User data {action_taken} for {user_email}")
            return Ok(f"User data successfully {action_taken}")

        except Exception as e:
            deletion_request.status = 'failed'
            deletion_request.evidence['error'] = str(e)
            deletion_request.save(update_fields=['status', 'evidence'])
            logger.error(f"🔥 [GDPR Deletion] Processing failed: {e}")
            return Err(f"Deletion processing failed: {e!s}")

    @classmethod
    def _can_user_be_deleted(cls, user: User) -> tuple[bool, str | None]:
        """Check if user can be completely deleted based on business rules"""

        restrictions = []

        # Romanian business law - must keep tax records for 7 years
        try:
            if hasattr(user, 'customer_memberships') and user.customer_memberships.exists():
                restrictions.append("Customer relationship exists - Romanian business law compliance")
        except AttributeError:
            pass

        if restrictions:
            return False, "; ".join(restrictions)
        return True, None

    @classmethod
    def _anonymize_user_data(cls, user: User) -> Result[str, str]:
        """Anonymize user data while preserving business relationships"""


        try:
            # Store original email for logging
            original_email = user.email

            # Anonymize core user fields
            user.email = cls.ANONYMIZATION_MAP['email']()
            user.first_name = cls.ANONYMIZATION_MAP['first_name']()
            user.last_name = cls.ANONYMIZATION_MAP['last_name']()
            user.phone = cls.ANONYMIZATION_MAP['phone']()
            user.is_active = False
            user.accepts_marketing = False
            user.gdpr_consent_date = None
            user.last_privacy_policy_accepted = None

            # Clear sensitive fields
            user.set_unusable_password()
            if hasattr(user, 'two_factor_enabled'):
                user.two_factor_enabled = False
                user.two_factor_secret = ''
                user.backup_tokens = []

            user.save()

            # Anonymize audit logs (IP addresses only)
            AuditEvent.objects.filter(user=user).update(
                ip_address=cls.ANONYMIZATION_MAP['ip_address'](),
                user_agent='Anonymized'
            )

            logger.info(f"✅ [GDPR Anonymization] User {original_email} anonymized successfully")
            return Ok("User data anonymized successfully")

        except Exception as e:
            logger.error(f"🔥 [GDPR Anonymization] Failed to anonymize user {user.email}: {e}")
            return Err(f"Anonymization failed: {e!s}")

    @classmethod
    def _delete_user_data(cls, user: User) -> Result[str, str]:
        """Complete data deletion (only when legally permitted)"""


        try:
            original_email = user.email

            # Delete related data that can be safely removed
            AuditEvent.objects.filter(user=user).delete()

            # Delete user account
            user.delete()

            logger.info(f"✅ [GDPR Deletion] User {original_email} deleted successfully")
            return Ok("User data deleted successfully")

        except Exception as e:
            logger.error(f"🔥 [GDPR Deletion] Failed to delete user {user.email}: {e}")
            return Err(f"Deletion failed: {e!s}")


class GDPRConsentService:
    """
    🔒 GDPR consent management service (Article 7 - Conditions for consent)
    
    Features:
    - Consent withdrawal management
    - Consent history tracking
    - Marketing consent granular control
    - Audit trail for all consent changes
    """

    @classmethod
    @transaction.atomic
    def withdraw_consent(
        cls,
        user: User,
        consent_types: list[str],
        request_ip: str | None = None
    ) -> Result[str, str]:
        """Withdraw specific types of consent"""


        try:
            valid_types = ['data_processing', 'marketing', 'analytics', 'cookies']
            invalid_types = [ct for ct in consent_types if ct not in valid_types]
            if invalid_types:
                return Err(f"Invalid consent types: {invalid_types}")

            changes_made = []

            # Handle marketing consent withdrawal
            if 'marketing' in consent_types and user.accepts_marketing:
                user.accepts_marketing = False
                changes_made.append('marketing_communications')

            # Data processing consent withdrawal triggers anonymization
            if 'data_processing' in consent_types:
                # This is a full GDPR deletion request
                deletion_result = GDPRDeletionService.create_deletion_request(
                    user, 'anonymize', request_ip,
                    "Data processing consent withdrawn"
                )
                if deletion_result.is_err():
                    error_msg = deletion_result.error if hasattr(deletion_result, 'error') else str(deletion_result)
                    return Err(f"Failed to process consent withdrawal: {error_msg}")

                # Immediately process the deletion request
                # Type-safe extraction after confirming it's Ok
                deletion_request = deletion_result.unwrap()
                process_result = GDPRDeletionService.process_deletion_request(deletion_request)
                if process_result.is_err():
                    error_msg = process_result.error if hasattr(process_result, 'error') else str(process_result)
                    return Err(f"Failed to anonymize user data: {error_msg}")

                changes_made.append('data_processing')

            if changes_made:
                user.save()

                # Log consent withdrawal
                compliance_request = ComplianceEventRequest(
                    compliance_type='gdpr_consent',
                    reference_id=f"consent_withdrawal_{user.id}_{uuid.uuid4().hex[:8]}",
                    description=f"Consent withdrawn for: {', '.join(changes_made)}",
                    user=user,
                    status='success',
                    evidence={
                        'withdrawn_consents': consent_types,
                        'changes_made': changes_made,
                        'withdrawal_date': timezone.now().isoformat()
                    },
                    metadata={'ip_address': request_ip}
                )
                AuditService.log_compliance_event(compliance_request)

            logger.info(f"✅ [GDPR Consent] Consent withdrawn for {user.email}: {changes_made}")
            return Ok(f"Consent withdrawn for: {', '.join(changes_made)}")

        except Exception as e:
            logger.error(f"🔥 [GDPR Consent] Failed to withdraw consent for {user.email}: {e}")
            return Err(f"Consent withdrawal failed: {e!s}")

    @classmethod
    def get_consent_history(cls, user: User) -> list[ConsentHistoryEntry]:
        """Get user's consent history for transparency"""

        try:
            consent_logs = ComplianceLog.objects.filter(
                compliance_type='gdpr_consent',
                user=user
            ).order_by('-timestamp')

            # ⚡ PERFORMANCE: Use list comprehension for better performance
            history: list[ConsentHistoryEntry] = [
                {
                    'timestamp': log.timestamp.isoformat(),
                    'action': log.description,
                    'description': log.description,  # Include both for backward compatibility
                    'status': log.status,
                    'evidence': log.evidence
                }
                for log in consent_logs
            ]

            return history

        except Exception as e:
            logger.error(f"🔥 [GDPR Consent] Failed to get consent history for {user.email}: {e}")
            return []


# ===============================================================================
# BILLING AUDIT SERVICE
# ===============================================================================

class BillingAuditService:
    """
    🧾 Specialized billing audit service for Romanian compliance
    
    Features:
    - Invoice lifecycle event tracking
    - Payment processing audit trails  
    - VAT and e-Factura compliance logging
    - Credit and balance management events
    - Romanian business law compliance
    """

    @staticmethod
    def log_invoice_event(
        event_type: str,
        invoice: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log invoice-related audit event with financial context
        
        Args:
            event_type: Type of invoice event (invoice_created, invoice_paid, etc.)
            invoice: Invoice object being audited
            user: User performing the action
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values for comparison
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build invoice-specific metadata
        invoice_metadata = {
            'invoice_number': invoice.number,
            'invoice_status': invoice.status,
            'customer_id': str(invoice.customer.id),
            'customer_name': invoice.bill_to_name or invoice.customer.company_name,
            'currency': invoice.currency.code,
            'total_amount': str(invoice.total),
            'total_cents': invoice.total_cents,
            'vat_amount': str(invoice.tax_amount),
            'vat_cents': invoice.tax_cents,
            'due_date': invoice.due_at.isoformat() if invoice.due_at else None,
            'issued_date': invoice.issued_at.isoformat() if invoice.issued_at else None,
            'is_overdue': invoice.is_overdue(),
            'romanian_compliance': {
                'efactura_id': invoice.efactura_id,
                'efactura_sent': invoice.efactura_sent,
                'efactura_sent_date': invoice.efactura_sent_date.isoformat() if invoice.efactura_sent_date else None,
            },
            **context.metadata
        }
        
        # Enhanced context with invoice metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(invoice_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data
        event_data = AuditEventData(
            event_type=event_type,
            content_object=invoice,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Invoice {event_type.replace('_', ' ').title()}: {invoice.number}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_payment_event(
        event_type: str,
        payment: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log payment-related audit event with transaction context
        
        Args:
            event_type: Type of payment event (payment_succeeded, payment_failed, etc.)
            payment: Payment object being audited
            user: User performing the action
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values for comparison
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build payment-specific metadata
        payment_metadata = {
            'payment_id': str(payment.id) if hasattr(payment, 'id') else None,
            'customer_id': str(payment.customer.id),
            'customer_name': payment.customer.company_name,
            'payment_method': payment.payment_method,
            'amount': str(payment.amount),
            'amount_cents': payment.amount_cents,
            'currency': payment.currency.code,
            'status': payment.status,
            'gateway_txn_id': payment.gateway_txn_id,
            'reference_number': payment.reference_number,
            'received_at': payment.received_at.isoformat(),
            'invoice_id': str(payment.invoice.id) if payment.invoice else None,
            'invoice_number': payment.invoice.number if payment.invoice else None,
            'financial_impact': True,
            **context.metadata
        }
        
        # Enhanced context with payment metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(payment_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data  
        event_data = AuditEventData(
            event_type=event_type,
            content_object=payment,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Payment {event_type.replace('_', ' ').title()}: {payment.amount} {payment.currency.code}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_proforma_event(
        event_type: str,
        proforma: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log proforma-related audit event
        
        Args:
            event_type: Type of proforma event (proforma_created, proforma_converted, etc.)
            proforma: ProformaInvoice object being audited
            user: User performing the action
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values for comparison
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build proforma-specific metadata
        proforma_metadata = {
            'proforma_number': proforma.number,
            'customer_id': str(proforma.customer.id),
            'customer_name': proforma.bill_to_name or proforma.customer.company_name,
            'currency': proforma.currency.code,
            'total_amount': str(proforma.total),
            'total_cents': proforma.total_cents,
            'vat_amount': str(proforma.tax_amount),
            'vat_cents': proforma.tax_cents,
            'valid_until': proforma.valid_until.isoformat(),
            'is_expired': proforma.is_expired,
            'created_at': proforma.created_at.isoformat(),
            **context.metadata
        }
        
        # Enhanced context with proforma metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(proforma_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data
        event_data = AuditEventData(
            event_type=event_type,
            content_object=proforma,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Proforma {event_type.replace('_', ' ').title()}: {proforma.number}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_credit_event(
        event_type: str,
        credit_entry: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log credit ledger audit event
        
        Args:
            event_type: Type of credit event (credit_added, credit_used, etc.)
            credit_entry: CreditLedger object being audited
            user: User performing the action
            context: Additional audit context
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build credit-specific metadata
        credit_metadata = {
            'customer_id': str(credit_entry.customer.id),
            'customer_name': credit_entry.customer.company_name,
            'delta_amount': str(credit_entry.delta),
            'delta_cents': credit_entry.delta_cents,
            'reason': credit_entry.reason,
            'invoice_id': str(credit_entry.invoice.id) if credit_entry.invoice else None,
            'payment_id': str(credit_entry.payment.id) if credit_entry.payment else None,
            'created_at': credit_entry.created_at.isoformat(),
            'financial_impact': True,
            **context.metadata
        }
        
        # Enhanced context with credit metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(credit_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data
        event_data = AuditEventData(
            event_type=event_type,
            content_object=credit_entry,
            description=description or f"Credit {event_type.replace('_', ' ').title()}: {credit_entry.delta} for {credit_entry.customer.company_name}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)


# ===============================================================================
# ORDERS AUDIT SERVICE
# ===============================================================================

class OrdersAuditService:
    """
    📦 Specialized orders audit service for order lifecycle tracking
    
    Features:
    - Complete order lifecycle event tracking
    - Order item changes and provisioning status
    - Customer order behavior analysis
    - Inventory and fulfillment audit trails
    - Romanian compliance for business orders
    """

    @staticmethod
    def log_order_event(
        event_type: str,
        order: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log order-related audit event with business context
        
        Args:
            event_type: Type of order event (order_created, order_status_changed, etc.)
            order: Order object being audited
            user: User performing the action
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values for comparison
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build order-specific metadata
        order_metadata = {
            'order_number': order.order_number,
            'order_status': order.status,
            'customer_id': str(order.customer.id),
            'customer_email': order.customer_email,
            'customer_name': order.customer_name,
            'customer_company': order.customer_company,
            'customer_vat_id': order.customer_vat_id,
            'currency': order.currency.code,
            'total_amount': str(order.total),
            'total_cents': order.total_cents,
            'subtotal_cents': order.subtotal_cents,
            'tax_cents': order.tax_cents,
            'discount_cents': order.discount_cents,
            'payment_method': order.payment_method,
            'transaction_id': order.transaction_id,
            'is_draft': order.is_draft,
            'is_paid': order.is_paid,
            'can_be_cancelled': order.can_be_cancelled,
            'created_at': order.created_at.isoformat(),
            'completed_at': order.completed_at.isoformat() if order.completed_at else None,
            'expires_at': order.expires_at.isoformat() if order.expires_at else None,
            'invoice_id': str(order.invoice.id) if order.invoice else None,
            'invoice_number': order.invoice.number if order.invoice else None,
            'source_tracking': {
                'source_ip': order.source_ip,
                'user_agent': order.user_agent[:200] if order.user_agent else None,  # Truncate for storage
                'referrer': order.referrer,
                'utm_source': order.utm_source,
                'utm_medium': order.utm_medium,
                'utm_campaign': order.utm_campaign,
            },
            'items_count': order.items.count() if hasattr(order, 'items') else 0,
            **context.metadata
        }
        
        # Enhanced context with order metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(order_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data
        event_data = AuditEventData(
            event_type=event_type,
            content_object=order,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Order {event_type.replace('_', ' ').title()}: {order.order_number}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_order_item_event(
        event_type: str,
        order_item: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log order item-related audit event with product context
        
        Args:
            event_type: Type of order item event (order_item_added, order_item_updated, etc.)
            order_item: OrderItem object being audited
            user: User performing the action
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values for comparison
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build order item-specific metadata
        item_metadata = {
            'order_number': order_item.order.order_number,
            'order_status': order_item.order.status,
            'product_id': str(order_item.product.id),
            'product_name': order_item.product_name,
            'product_type': order_item.product_type,
            'billing_period': order_item.billing_period,
            'quantity': order_item.quantity,
            'unit_price': str(order_item.unit_price),
            'unit_price_cents': order_item.unit_price_cents,
            'setup_fee': str(order_item.setup_fee),
            'setup_cents': order_item.setup_cents,
            'tax_rate': str(order_item.tax_rate),
            'tax_amount': str(order_item.tax_amount),
            'tax_cents': order_item.tax_cents,
            'line_total': str(order_item.line_total),
            'line_total_cents': order_item.line_total_cents,
            'domain_name': order_item.domain_name,
            'provisioning_status': order_item.provisioning_status,
            'provisioning_notes': order_item.provisioning_notes,
            'provisioned_at': order_item.provisioned_at.isoformat() if order_item.provisioned_at else None,
            'service_id': str(order_item.service.id) if order_item.service else None,
            'config': order_item.config,
            **context.metadata
        }
        
        # Enhanced context with order item metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(item_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data
        event_data = AuditEventData(
            event_type=event_type,
            content_object=order_item,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Order Item {event_type.replace('_', ' ').title()}: {order_item.product_name} in {order_item.order.order_number}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)

    @staticmethod
    def log_provisioning_event(
        event_type: str,
        order_item: Any,
        service: Any | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
        description: str | None = None
    ) -> AuditEvent:
        """
        Log provisioning-related audit event
        
        Args:
            event_type: Type of provisioning event (provisioning_started, provisioning_completed, etc.)
            order_item: OrderItem being provisioned
            service: Service object if provisioned
            user: User performing the action
            context: Additional audit context
            description: Optional description override
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)
        
        # Build provisioning-specific metadata
        provisioning_metadata = {
            'order_number': order_item.order.order_number,
            'order_item_id': str(order_item.id),
            'product_name': order_item.product_name,
            'product_type': order_item.product_type,
            'domain_name': order_item.domain_name,
            'provisioning_status': order_item.provisioning_status,
            'provisioning_notes': order_item.provisioning_notes,
            'config': order_item.config,
            'service_id': str(service.id) if service else None,
            'service_type': service.service_type if service else None,
            'customer_id': str(order_item.order.customer.id),
            'customer_name': order_item.order.customer_name,
            **context.metadata
        }
        
        # Enhanced context with provisioning metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(provisioning_metadata),
            actor_type=context.actor_type
        )
        
        # Create audit event data using the service as content object if available
        event_data = AuditEventData(
            event_type=event_type,
            content_object=service or order_item,
            description=description or f"Provisioning {event_type.replace('_', ' ').title()}: {order_item.product_name}"
        )
        
        return AuditService.log_event(event_data, enhanced_context)


# Global service instances
billing_audit_service = BillingAuditService()
orders_audit_service = OrdersAuditService()

# ===============================================================================
# AUDIT INTEGRITY MONITORING SERVICE
# ===============================================================================

class AuditIntegrityService:
    """
    🔒 Enterprise audit data integrity monitoring service
    
    Features:
    - Cryptographic hash verification for immutable audit trails
    - Tampering detection and alerting system  
    - Gap detection in audit sequence (missing events)
    - Data consistency checks across related events
    - Automatic integrity reports and health monitoring
    - GDPR compliance validation (required fields, retention periods)
    """

    @classmethod
    @transaction.atomic
    def verify_audit_integrity(
        cls,
        period_start: datetime,
        period_end: datetime,
        check_type: str = 'hash_verification'
    ) -> Result[AuditIntegrityCheck, str]:
        """Verify audit data integrity for a given period."""
        
        try:
            # Get audit events in the period
            events = AuditEvent.objects.filter(
                timestamp__gte=period_start,
                timestamp__lt=period_end
            ).order_by('timestamp')
            
            records_checked = events.count()
            issues_found = []
            
            if check_type == 'hash_verification':
                issues_found = cls._verify_hash_chain(events)
            elif check_type == 'sequence_check':
                issues_found = cls._check_sequence_gaps(events)
            elif check_type == 'gdpr_compliance':
                issues_found = cls._check_gdpr_compliance(events)
            
            # Generate hash chain for this check
            hash_chain = cls._generate_hash_chain(events)
            
            # Determine status
            status = 'healthy'
            if len(issues_found) > 0:
                critical_issues = [i for i in issues_found if i.get('severity') == 'critical']
                if critical_issues:
                    status = 'compromised'
                else:
                    status = 'warning'
            
            # Create integrity check record
            integrity_check = AuditIntegrityCheck.objects.create(
                check_type=check_type,
                period_start=period_start,
                period_end=period_end,
                status=status,
                records_checked=records_checked,
                issues_found=len(issues_found),
                findings=issues_found,
                hash_chain=hash_chain,
                metadata={
                    'check_timestamp': timezone.now().isoformat(),
                    'checker': 'AuditIntegrityService'
                }
            )
            
            # Create alerts for critical issues
            if status == 'compromised':
                cls._create_integrity_alert(integrity_check, issues_found)
            
            logger.info(f"✅ [Audit Integrity] {check_type} check completed: {status} ({len(issues_found)} issues)")
            return Ok(integrity_check)
            
        except Exception as e:
            logger.error(f"🔥 [Audit Integrity] Verification failed: {e}")
            return Err(f"Integrity verification failed: {e!s}")
    
    @classmethod
    def _verify_hash_chain(cls, events: list[AuditEvent]) -> list[dict[str, Any]]:
        """Verify cryptographic hash chain of audit events."""
        issues = []
        
        for i, event in enumerate(events):
            # Check if event data has been modified
            expected_hash = cls._calculate_event_hash(event)
            stored_hash = event.metadata.get('integrity_hash')
            
            if stored_hash and stored_hash != expected_hash:
                issues.append({
                    'type': 'hash_mismatch',
                    'severity': 'critical',
                    'event_id': str(event.id),
                    'timestamp': event.timestamp.isoformat(),
                    'description': 'Event hash mismatch - possible tampering detected',
                    'expected_hash': expected_hash,
                    'stored_hash': stored_hash
                })
        
        return issues
    
    @classmethod
    def _check_sequence_gaps(cls, events: list[AuditEvent]) -> list[dict[str, Any]]:
        """Check for gaps in audit event sequence."""
        issues = []
        
        if not events:
            return issues
        
        # Check for time gaps that might indicate missing events
        for i in range(1, len(events)):
            prev_event = events[i-1]
            current_event = events[i]
            
            time_gap = (current_event.timestamp - prev_event.timestamp).total_seconds()
            
            # Flag suspicious gaps (more than 1 hour with no events for active users)
            if time_gap > 3600 and prev_event.user and current_event.user:
                # Check if there should have been activity
                if cls._should_have_activity(prev_event, current_event):
                    issues.append({
                        'type': 'sequence_gap',
                        'severity': 'warning',
                        'gap_start': prev_event.timestamp.isoformat(),
                        'gap_end': current_event.timestamp.isoformat(),
                        'gap_duration_seconds': int(time_gap),
                        'description': f'Suspicious gap in audit trail: {time_gap/3600:.1f} hours'
                    })
        
        return issues
    
    @classmethod
    def _check_gdpr_compliance(cls, events: list[AuditEvent]) -> list[dict[str, Any]]:
        """Check GDPR compliance of audit events."""
        issues = []
        
        for event in events:
            # Check required fields for GDPR events
            if event.category in ['privacy', 'data_protection']:
                required_fields = ['user', 'ip_address', 'description']
                missing_fields = []
                
                for field in required_fields:
                    if not getattr(event, field, None):
                        missing_fields.append(field)
                
                if missing_fields:
                    issues.append({
                        'type': 'gdpr_compliance',
                        'severity': 'high',
                        'event_id': str(event.id),
                        'missing_fields': missing_fields,
                        'description': f'GDPR event missing required fields: {missing_fields}'
                    })
        
        return issues
    
    @classmethod
    def _calculate_event_hash(cls, event: AuditEvent) -> str:
        """Calculate cryptographic hash for an audit event."""
        # Create a canonical representation of the event
        data = {
            'id': str(event.id),
            'timestamp': event.timestamp.isoformat(),
            'user_id': str(event.user.id) if event.user else None,
            'action': event.action,
            'content_type_id': event.content_type_id,
            'object_id': event.object_id,
            'description': event.description,
            'ip_address': event.ip_address,
        }
        
        # Sort and serialize for consistent hashing
        canonical_data = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_data.encode()).hexdigest()
    
    @classmethod
    def _generate_hash_chain(cls, events: list[AuditEvent]) -> str:
        """Generate a hash chain for a sequence of events."""
        if not events:
            return ''
        
        # Create chain of hashes
        chain_data = [cls._calculate_event_hash(event) for event in events]
        chain_hash = hashlib.sha256(''.join(chain_data).encode()).hexdigest()
        
        return chain_hash
    
    @classmethod
    def _should_have_activity(cls, prev_event: AuditEvent, current_event: AuditEvent) -> bool:
        """Determine if there should have been activity between events."""
        # Simple heuristic: if both events are from the same user in a short session
        if prev_event.user == current_event.user and prev_event.user:
            # Check if events are in same session
            if (prev_event.session_key == current_event.session_key and 
                prev_event.session_key):
                return True
        
        return False
    
    @classmethod
    def _create_integrity_alert(cls, integrity_check: AuditIntegrityCheck, issues: list[dict[str, Any]]) -> None:
        """Create alert for integrity issues."""
        try:
            critical_issues = [i for i in issues if i.get('severity') == 'critical']
            
            alert = AuditAlert.objects.create(
                alert_type='data_integrity',
                severity='critical' if critical_issues else 'high',
                title='Audit Data Integrity Issues Detected',
                description=f'Integrity check found {len(issues)} issues in audit data from {integrity_check.period_start} to {integrity_check.period_end}',
                evidence={
                    'integrity_check_id': str(integrity_check.id),
                    'issues': issues,
                    'records_checked': integrity_check.records_checked
                },
                metadata={
                    'check_type': integrity_check.check_type,
                    'auto_generated': True
                }
            )
            
            logger.warning(f"⚠️ [Audit Integrity] Alert created: {alert.id}")
            
        except Exception as e:
            logger.error(f"🔥 [Audit Integrity] Failed to create alert: {e}")


# ===============================================================================
# AUDIT RETENTION MANAGEMENT SERVICE
# ===============================================================================

class AuditRetentionService:
    """
    📅 Audit log retention management service
    
    Features:
    - Configurable retention periods by event category/severity
    - Automatic archiving of old audit logs
    - Romanian legal compliance (7-year financial records)
    - GDPR right-to-erasure implementation
    - Bulk deletion with approval workflows
    - Archive storage and retrieval system
    """

    @classmethod
    def apply_retention_policies(cls) -> Result[dict[str, Any], str]:
        """Apply all active retention policies to audit data."""
        
        try:
            policies = AuditRetentionPolicy.objects.filter(is_active=True)
            results = {
                'policies_applied': 0,
                'events_processed': 0,
                'events_archived': 0,
                'events_deleted': 0,
                'events_anonymized': 0,
                'errors': []
            }
            
            for policy in policies:
                try:
                    result = cls._apply_single_policy(policy)
                    results['policies_applied'] += 1
                    results['events_processed'] += result.get('processed', 0)
                    results['events_archived'] += result.get('archived', 0)
                    results['events_deleted'] += result.get('deleted', 0)
                    results['events_anonymized'] += result.get('anonymized', 0)
                    
                except Exception as e:
                    error_msg = f"Policy {policy.name} failed: {e}"
                    results['errors'].append(error_msg)
                    logger.error(f"🔥 [Retention] {error_msg}")
            
            # Log compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type='data_retention',
                reference_id=f"retention_run_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
                description=f"Retention policies applied: {results['policies_applied']} policies, {results['events_processed']} events processed",
                status='success' if not results['errors'] else 'partial',
                evidence=results
            )
            AuditService.log_compliance_event(compliance_request)
            
            logger.info(f"✅ [Retention] Policies applied: {results['policies_applied']} policies, {results['events_processed']} events processed")
            return Ok(results)
            
        except Exception as e:
            logger.error(f"🔥 [Retention] Policy application failed: {e}")
            return Err(f"Retention policy application failed: {e!s}")
    
    @classmethod
    @transaction.atomic
    def _apply_single_policy(cls, policy: AuditRetentionPolicy) -> dict[str, int]:
        """Apply a single retention policy."""
        
        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=policy.retention_days)
        
        # Build query for events to process
        queryset = AuditEvent.objects.filter(
            timestamp__lt=cutoff_date,
            category=policy.category
        )
        
        # Add severity filter if specified
        if policy.severity:
            queryset = queryset.filter(severity=policy.severity)
        
        events_to_process = list(queryset)
        result = {
            'processed': len(events_to_process),
            'archived': 0,
            'deleted': 0,
            'anonymized': 0
        }
        
        if not events_to_process:
            return result
        
        # Apply retention action
        if policy.action == 'archive':
            result['archived'] = cls._archive_events(events_to_process)
        elif policy.action == 'delete':
            result['deleted'] = cls._delete_events(events_to_process, policy)
        elif policy.action == 'anonymize':
            result['anonymized'] = cls._anonymize_events(events_to_process)
        
        return result
    
    @classmethod
    def _archive_events(cls, events: list[AuditEvent]) -> int:
        """Archive events to cold storage (placeholder - implement with actual storage)."""
        
        # For now, mark events as archived in metadata
        # In production, this would move data to cold storage (S3, etc.)
        archived_count = 0
        
        for event in events:
            event.metadata['archived'] = True
            event.metadata['archived_at'] = timezone.now().isoformat()
            event.save(update_fields=['metadata'])
            archived_count += 1
        
        return archived_count
    
    @classmethod
    def _delete_events(cls, events: list[AuditEvent], policy: AuditRetentionPolicy) -> int:
        """Delete events (only if not mandatory retention)."""
        
        # Additional safety check for mandatory retention
        if policy.is_mandatory:
            logger.warning(f"⚠️ [Retention] Attempted deletion with mandatory policy: {policy.name}")
            return 0
        
        # Check Romanian compliance (7-year financial records)
        financial_events = [e for e in events if cls._is_financial_record(e)]
        if financial_events:
            logger.warning(f"⚠️ [Retention] Blocked deletion of {len(financial_events)} financial records (Romanian compliance)")
            # Remove financial events from deletion list
            events = [e for e in events if not cls._is_financial_record(e)]
        
        deleted_count = 0
        event_ids = [e.id for e in events]
        
        if event_ids:
            deleted_count = AuditEvent.objects.filter(id__in=event_ids).delete()[0]
        
        return deleted_count
    
    @classmethod
    def _anonymize_events(cls, events: list[AuditEvent]) -> int:
        """Anonymize sensitive data in events."""
        
        anonymized_count = 0
        
        for event in events:
            # Anonymize IP addresses
            if event.ip_address:
                event.ip_address = '0.0.0.0'
            
            # Anonymize user agent
            if event.user_agent:
                event.user_agent = 'Anonymized'
            
            # Remove sensitive metadata
            if event.metadata:
                sensitive_keys = ['user_email', 'phone', 'real_name', 'address']
                for key in sensitive_keys:
                    if key in event.metadata:
                        event.metadata[key] = 'Anonymized'
            
            event.metadata['anonymized'] = True
            event.metadata['anonymized_at'] = timezone.now().isoformat()
            event.save(update_fields=['ip_address', 'user_agent', 'metadata'])
            anonymized_count += 1
        
        return anonymized_count
    
    @classmethod
    def _is_financial_record(cls, event: AuditEvent) -> bool:
        """Check if event is a financial record requiring 7-year retention."""
        
        financial_actions = [
            'invoice_created', 'invoice_paid', 'payment_succeeded', 
            'proforma_created', 'credit_added', 'vat_calculation_applied'
        ]
        
        return event.action in financial_actions or event.category == 'business_operation'


# ===============================================================================
# ADVANCED AUDIT SEARCH SERVICE
# ===============================================================================

class AuditSearchService:
    """
    🔍 Advanced audit search and filtering service
    
    Features:
    - Multi-criteria search (request_id, session_key, IP address, date ranges)
    - Advanced filter combinations (category + severity, user + action type)
    - Elasticsearch-style query builder interface
    - Saved search queries for common investigations
    - Real-time search suggestions and auto-completion
    """

    @classmethod
    def build_advanced_query(
        cls,
        filters: dict[str, Any],
        user: User
    ) -> tuple[models.QuerySet[AuditEvent], dict[str, Any]]:
        """Build advanced audit query with multiple filters and performance optimization."""
        
        # Start with base queryset
        queryset = AuditEvent.objects.select_related('user', 'content_type')
        query_info = {
            'filters_applied': [],
            'performance_hints': [],
            'estimated_cost': 'low'
        }
        
        # Apply filters
        if filters.get('user_ids'):
            queryset = queryset.filter(user_id__in=filters['user_ids'])
            query_info['filters_applied'].append('user_filter')
        
        if filters.get('actions'):
            queryset = queryset.filter(action__in=filters['actions'])
            query_info['filters_applied'].append('action_filter')
        
        if filters.get('categories'):
            queryset = queryset.filter(category__in=filters['categories'])
            query_info['filters_applied'].append('category_filter')
        
        if filters.get('severities'):
            queryset = queryset.filter(severity__in=filters['severities'])
            query_info['filters_applied'].append('severity_filter')
        
        if filters.get('start_date'):
            queryset = queryset.filter(timestamp__gte=filters['start_date'])
            query_info['filters_applied'].append('date_range_start')
        
        if filters.get('end_date'):
            queryset = queryset.filter(timestamp__lte=filters['end_date'])
            query_info['filters_applied'].append('date_range_end')
        
        if filters.get('ip_addresses'):
            ip_list = filters['ip_addresses'] if isinstance(filters['ip_addresses'], list) else [filters['ip_addresses']]
            queryset = queryset.filter(ip_address__in=ip_list)
            query_info['filters_applied'].append('ip_filter')
        
        if filters.get('request_ids'):
            request_ids = filters['request_ids'] if isinstance(filters['request_ids'], list) else [filters['request_ids']]
            queryset = queryset.filter(request_id__in=request_ids)
            query_info['filters_applied'].append('request_id_filter')
        
        if filters.get('session_keys'):
            session_keys = filters['session_keys'] if isinstance(filters['session_keys'], list) else [filters['session_keys']]
            queryset = queryset.filter(session_key__in=session_keys)
            query_info['filters_applied'].append('session_filter')
        
        if filters.get('content_types'):
            queryset = queryset.filter(content_type_id__in=filters['content_types'])
            query_info['filters_applied'].append('content_type_filter')
        
        if filters.get('search_text'):
            search_text = filters['search_text']
            queryset = queryset.filter(
                Q(description__icontains=search_text) |
                Q(old_values__icontains=search_text) |
                Q(new_values__icontains=search_text) |
                Q(action__icontains=search_text)
            )
            query_info['filters_applied'].append('text_search')
            query_info['estimated_cost'] = 'medium'  # Text search is more expensive
        
        if filters.get('is_sensitive') is not None:
            queryset = queryset.filter(is_sensitive=filters['is_sensitive'])
            query_info['filters_applied'].append('sensitivity_filter')
        
        if filters.get('requires_review') is not None:
            queryset = queryset.filter(requires_review=filters['requires_review'])
            query_info['filters_applied'].append('review_filter')
        
        # Advanced filters
        if filters.get('has_old_values'):
            if filters['has_old_values']:
                queryset = queryset.exclude(old_values={})
            else:
                queryset = queryset.filter(old_values={})
            query_info['filters_applied'].append('old_values_filter')
        
        if filters.get('has_new_values'):
            if filters['has_new_values']:
                queryset = queryset.exclude(new_values={})
            else:
                queryset = queryset.filter(new_values={})
            query_info['filters_applied'].append('new_values_filter')
        
        # Performance optimization hints
        if len(query_info['filters_applied']) > 5:
            query_info['estimated_cost'] = 'high'
            query_info['performance_hints'].append('Consider using saved queries for complex searches')
        
        if 'text_search' in query_info['filters_applied'] and len(query_info['filters_applied']) == 1:
            query_info['performance_hints'].append('Add date range or user filters to improve search performance')
        
        # Default ordering
        queryset = queryset.order_by('-timestamp')
        
        return queryset, query_info
    
    @classmethod
    @transaction.atomic
    def save_search_query(
        cls,
        name: str,
        query_params: dict[str, Any],
        user: User,
        description: str = '',
        is_shared: bool = False
    ) -> Result[AuditSearchQuery, str]:
        """Save a search query for reuse."""
        
        try:
            # Check for duplicate names for this user
            existing = AuditSearchQuery.objects.filter(
                name=name,
                created_by=user
            ).exists()
            
            if existing:
                return Err(f"Search query '{name}' already exists")
            
            search_query = AuditSearchQuery.objects.create(
                name=name,
                description=description,
                query_params=query_params,
                created_by=user,
                is_shared=is_shared
            )
            
            logger.info(f"✅ [Audit Search] Query saved: {name} by {user.email}")
            return Ok(search_query)
            
        except Exception as e:
            logger.error(f"🔥 [Audit Search] Failed to save query: {e}")
            return Err(f"Failed to save search query: {e!s}")
    
    @classmethod
    def get_search_suggestions(
        cls,
        query: str,
        user: User,
        limit: int = 10
    ) -> dict[str, list[str]]:
        """Get search suggestions for auto-completion."""
        
        suggestions = {
            'actions': [],
            'users': [],
            'ip_addresses': [],
            'descriptions': []
        }
        
        if not query or len(query) < 2:
            return suggestions
        
        try:
            # Action suggestions
            action_choices = [choice[0] for choice in AuditEvent.ACTION_CHOICES if query.lower() in choice[0].lower()]
            suggestions['actions'] = action_choices[:limit]
            
            # User suggestions (staff only for privacy)
            if user.is_staff:
                users = User.objects.filter(
                    Q(email__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query)
                ).values_list('email', flat=True)[:limit]
                suggestions['users'] = list(users)
            
            # IP address suggestions (recent ones)
            if cls._is_ip_like(query):
                recent_ips = AuditEvent.objects.filter(
                    ip_address__icontains=query,
                    timestamp__gte=timezone.now() - timedelta(days=30)
                ).values_list('ip_address', flat=True).distinct()[:limit]
                suggestions['ip_addresses'] = list(recent_ips)
            
        except Exception as e:
            logger.warning(f"⚠️ [Audit Search] Suggestion generation failed: {e}")
        
        return suggestions
    
    @classmethod
    def _is_ip_like(cls, query: str) -> bool:
        """Check if query looks like an IP address."""
        import re
        ip_pattern = r'^\d{1,3}(\.\d{0,3}){0,3}$'
        return bool(re.match(ip_pattern, query))


# Global service instances
audit_integrity_service = AuditIntegrityService()
audit_retention_service = AuditRetentionService()
audit_search_service = AuditSearchService()

# Global GDPR service instances
gdpr_export_service = GDPRExportService()
gdpr_deletion_service = GDPRDeletionService()
gdpr_consent_service = GDPRConsentService()
