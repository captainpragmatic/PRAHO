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

from .models import AuditEvent, ComplianceLog, DataExport

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
        🔐 Log an audit event with full context

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
            
            # Create audit event
            audit_event = AuditEvent.objects.create(
                user=context.user,
                actor_type=context.actor_type,
                action=event_data.event_type,
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
                f"✅ [Audit] {event_data.event_type} event logged for user {context.user.email if context.user else 'System'}"
            )

            return audit_event

        except Exception as e:
            logger.error(f"🔥 [Audit] Failed to log event {event_data.event_type}: {e}")
            raise

    @staticmethod
    def log_2fa_event(request: TwoFactorAuditRequest) -> AuditEvent:
        """
        🔐 Log 2FA-specific audit event

        Supported event types:
        - 2fa_enabled
        - 2fa_disabled
        - 2fa_admin_reset
        - 2fa_backup_codes_generated
        - 2fa_backup_codes_viewed
        - 2fa_backup_code_used
        - 2fa_secret_regenerated
        - 2fa_verification_success
        - 2fa_verification_failed
        """
        # Enhance metadata with 2FA context
        enhanced_metadata = {
            'event_category': '2fa_security',
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


# Global GDPR service instances
gdpr_export_service = GDPRExportService()
gdpr_deletion_service = GDPRDeletionService()
gdpr_consent_service = GDPRConsentService()
