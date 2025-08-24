"""
Audit services for PRAHO Platform
Centralized audit logging for Romanian compliance and security.
"""

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from typing import Optional, Dict, Any, TYPE_CHECKING
import logging
import uuid

from .models import AuditEvent, ComplianceLog

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser

User = get_user_model()
logger = logging.getLogger(__name__)


class AuditService:
    """Centralized audit logging service"""
    
    @staticmethod
    def log_event(
        event_type: str,
        user = None,
        content_object: Optional[Any] = None,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        description: str = '',
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_key: Optional[str] = None,
        metadata: Optional[Dict] = None,
        actor_type: str = 'user'
    ) -> AuditEvent:
        """
        🔐 Log an audit event with full context
        
        Args:
            event_type: Type of event (from ACTION_CHOICES or custom 2FA events)
            user: User performing the action
            content_object: Object being acted upon
            old_values: Previous values (for updates)
            new_values: New values (for updates)
            description: Human-readable description
            ip_address: Client IP address
            user_agent: Client user agent
            request_id: Request tracking ID
            session_key: Session key for correlation
            metadata: Additional event metadata
            actor_type: Type of actor (user, system, api)
        """
        try:
            # Get content type if object provided
            content_type = None
            object_id = None
            if content_object:
                content_type = ContentType.objects.get_for_model(content_object)
                object_id = content_object.pk
            
            # Create audit event
            audit_event = AuditEvent.objects.create(
                user=user,
                actor_type=actor_type,
                action=event_type,
                content_type=content_type,
                object_id=object_id,
                old_values=old_values or {},
                new_values=new_values or {},
                description=description,
                ip_address=ip_address,
                user_agent=user_agent or '',
                request_id=request_id or str(uuid.uuid4()),
                session_key=session_key or '',
                metadata=metadata or {}
            )
            
            logger.info(
                f"✅ [Audit] {event_type} event logged for user {user.email if user else 'System'}"
            )
            
            return audit_event
            
        except Exception as e:
            logger.error(f"🔥 [Audit] Failed to log event {event_type}: {e}")
            raise
    
    @staticmethod
    def log_2fa_event(
        event_type: str,
        user,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None,
        description: str = '',
        request_id: Optional[str] = None,
        session_key: Optional[str] = None
    ) -> AuditEvent:
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
            **(metadata or {})
        }
        
        # Add user 2FA status to metadata
        if user:
            enhanced_metadata.update({
                'user_2fa_enabled': user.two_factor_enabled,
                'backup_codes_count': len(user.backup_tokens) if user.backup_tokens else 0
            })
        
        return AuditService.log_event(
            event_type=event_type,
            user=user,
            content_object=user,  # 2FA events act on the user object
            description=description or f"2FA {event_type.replace('_', ' ').title()}",
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_key=session_key,
            metadata=enhanced_metadata
        )
    
    @staticmethod
    def log_compliance_event(
        compliance_type: str,
        reference_id: str,
        description: str,
        user = None,
        status: str = 'success',
        evidence: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> ComplianceLog:
        """
        📋 Log Romanian compliance event
        """
        try:
            compliance_log = ComplianceLog.objects.create(
                compliance_type=compliance_type,
                reference_id=reference_id,
                description=description,
                user=user,
                status=status,
                evidence=evidence or {},
                metadata=metadata or {}
            )
            
            logger.info(
                f"📋 [Compliance] {compliance_type} logged: {reference_id}"
            )
            
            return compliance_log
            
        except Exception as e:
            logger.error(f"🔥 [Compliance] Failed to log {compliance_type}: {e}")
            raise


# Global audit service instance
audit_service = AuditService()
