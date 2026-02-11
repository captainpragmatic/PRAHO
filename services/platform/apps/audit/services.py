from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone

from apps.common.request_ip import get_safe_client_ip
from apps.common.types import EmailAddress, Err, Ok, Result
from apps.common.validators import log_security_event
from apps.tickets.models import Ticket  # Import for GDPR data export

from .models import (
    AuditAlert,
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    AuditSearchQuery,
    ComplianceLog,
    CookieConsent,
    DataExport,
)

# Constants for audit operations
ONE_HOUR_SECONDS = 3600  # 1 hour in seconds for gap detection
HIGH_COMPLEXITY_FILTER_THRESHOLD = 5  # Number of filters that indicate high complexity
MIN_SEARCH_QUERY_LENGTH = 2  # Minimum length for search queries

# Business logic constants
HIGH_VALUE_PLAN_THRESHOLD_RON = 500  # 500 RON threshold for high-value plans
SERVER_OVERLOAD_THRESHOLD_PERCENT = 85  # 85% resource usage threshold
LONG_RUNNING_TASK_THRESHOLD_SECONDS = 1800  # 30 minutes (1800 seconds)

# Webhook health and reliability constants
WEBHOOK_HEALTHY_RESPONSE_THRESHOLD = 300  # HTTP status < 300 indicates healthy endpoint
WEBHOOK_FAST_RESPONSE_THRESHOLD_MS = 1000  # < 1000ms is considered fast response
WEBHOOK_MEDIUM_RESPONSE_THRESHOLD_MS = 3000  # < 3000ms is considered medium response
WEBHOOK_MAX_RETRY_THRESHOLD = 5  # Maximum retry attempts before failure
WEBHOOK_SUSPICIOUS_RETRY_THRESHOLD = 3  # Retry count indicating suspicious behavior


# Type definitions for security audit service
class RateLimitEventData(TypedDict):
    """Rate limit event data structure for security auditing."""

    endpoint: str
    ip_address: str
    user_agent: str
    rate_limit_key: str
    rate_limit_rate: str


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
        elif hasattr(obj, "pk"):  # Django model instance
            return f"{obj.__class__.__name__}(pk={obj.pk})"
        elif hasattr(obj, "__dict__"):  # Generic object with attributes
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
        return json.loads(serialized_json)  # type: ignore[no-any-return]
    except (TypeError, ValueError) as e:
        logger.error(f"🔥 [Audit] Failed to serialize metadata: {e}")
        # Fallback: return a safe version with error information
        return {
            "serialization_error": str(e),
            "original_keys": list(metadata.keys()) if isinstance(metadata, dict) else "not_dict",
            "timestamp": timezone.now().isoformat(),
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
    actor_type: str = "user"


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
    description: str = ""


@dataclass
class TwoFactorAuditRequest:
    """Parameter object for 2FA audit events"""

    event_type: str
    user: User
    context: AuditContext = field(default_factory=AuditContext)
    description: str = ""


@dataclass
class ComplianceEventRequest:
    """Parameter object for compliance events"""

    compliance_type: str
    reference_id: str
    description: str
    user: User | None = None
    status: str = "success"
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthenticationEventData:
    """Parameter object for authentication event data"""

    user: User
    request: Any = None
    ip_address: str | None = None
    user_agent: str | None = None
    session_key: str | None = None
    authentication_method: str = "password"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LoginFailureEventData:
    """Parameter object for login failure event data"""

    email: str | None = None
    user: User | None = None
    request: Any = None
    ip_address: str | None = None
    user_agent: str | None = None
    failure_reason: str = "invalid_credentials"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LogoutEventData:
    """Parameter object for logout event data"""

    user: User
    logout_reason: str = "manual"
    request: Any = None
    ip_address: str | None = None
    user_agent: str | None = None
    session_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountEventData:
    """Parameter object for account-related event data (lockout, session rotation)"""

    user: User
    trigger_reason: str
    request: Any = None
    ip_address: str | None = None
    failed_attempts: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRotationEventData:
    """Parameter object for session rotation event data"""

    user: User
    reason: str
    request: Any = None
    old_session_key: str | None = None
    new_session_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessEventData:
    """Parameter object for business transaction event data"""

    event_type: str
    business_object: Any  # Invoice, Payment, Order, etc.
    user: User | None = None
    context: AuditContext | None = None
    old_values: dict[str, Any] | None = None
    new_values: dict[str, Any] | None = None
    description: str | None = None


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
    def log_login_success(event_data: AuthenticationEventData) -> AuditEvent:
        """
        Log successful login event with comprehensive metadata

        Args:
            event_data: Authentication event data containing user and context info
        """
        # Extract context from request if provided
        if event_data.request:
            event_data.ip_address = event_data.ip_address or get_safe_client_ip(event_data.request)
            event_data.user_agent = event_data.user_agent or event_data.request.META.get("HTTP_USER_AGENT", "")
            event_data.session_key = event_data.session_key or event_data.request.session.session_key

        # Build comprehensive metadata
        auth_metadata = {
            "authentication_method": event_data.authentication_method,
            "login_timestamp": timezone.now().isoformat(),
            "user_id": str(event_data.user.id),
            "user_email": event_data.user.email,
            "user_staff_status": event_data.user.is_staff,
            "user_2fa_enabled": getattr(event_data.user, "two_factor_enabled", False),
            "previous_login": event_data.user.last_login.isoformat() if event_data.user.last_login else None,
            "failed_attempts_before": getattr(event_data.user, "failed_login_attempts", 0),
            "account_was_locked": getattr(event_data.user, "is_account_locked", lambda: False)(),
            "session_info": {"session_key": event_data.session_key, "session_created": timezone.now().isoformat()},
            **event_data.metadata,
        }

        # Add user agent analysis if available
        if event_data.user_agent:
            auth_metadata["user_agent_info"] = {
                "raw": event_data.user_agent,
                "truncated": event_data.user_agent[:200],  # Prevent excessively long strings
            }

        context = AuditContext(
            user=event_data.user,
            ip_address=event_data.ip_address,
            user_agent=event_data.user_agent,
            session_key=event_data.session_key,
            metadata=auth_metadata,
            actor_type="user",
        )

        audit_event_data = AuditEventData(
            event_type="login_success",
            content_object=event_data.user,
            description=f"Successful login via {event_data.authentication_method} for {event_data.user.email}",
        )

        return AuditService.log_event(audit_event_data, context)

    @staticmethod
    def log_login_failed(failure_data: LoginFailureEventData) -> AuditEvent:
        """
        Log failed login attempt with security-focused metadata

        Args:
            failure_data: Login failure event data containing email, user, and context info
        """
        # Extract context from request if provided
        if failure_data.request:
            failure_data.ip_address = failure_data.ip_address or get_safe_client_ip(failure_data.request)
            failure_data.user_agent = failure_data.user_agent or failure_data.request.META.get("HTTP_USER_AGENT", "")

        # Determine the appropriate action based on failure reason
        action_map = {
            "invalid_password": "login_failed_password",
            "user_not_found": "login_failed_user_not_found",
            "account_locked": "login_failed_account_locked",
            "2fa_verification": "login_failed_2fa",
            "unknown": "login_failed",
        }
        action = action_map.get(failure_data.failure_reason, "login_failed")

        # Build security-focused metadata
        auth_metadata = {
            "failure_reason": failure_data.failure_reason,
            "attempted_email": failure_data.email,
            "attempt_timestamp": timezone.now().isoformat(),
            "security_analysis": {
                "ip_based_attempt": True,
                "user_agent_provided": bool(failure_data.user_agent),
            },
            **failure_data.metadata,
        }

        # Add user context if user exists
        if failure_data.user:
            auth_metadata.update(
                {
                    "user_id": str(failure_data.user.id),
                    "user_exists": True,
                    "user_active": failure_data.user.is_active,
                    "user_staff": failure_data.user.is_staff,
                    "previous_failed_attempts": getattr(failure_data.user, "failed_login_attempts", 0),
                    "account_locked": getattr(failure_data.user, "is_account_locked", lambda: False)(),
                    "user_2fa_enabled": getattr(failure_data.user, "two_factor_enabled", False),
                }
            )
        else:
            auth_metadata.update(
                {
                    "user_exists": False,
                    "attempted_email_format_valid": bool(failure_data.email and "@" in failure_data.email),
                }
            )

        context = AuditContext(
            user=failure_data.user,
            ip_address=failure_data.ip_address,
            user_agent=failure_data.user_agent,
            metadata=auth_metadata,
            actor_type="anonymous" if not failure_data.user else "user",
        )

        audit_event_data = AuditEventData(
            event_type=action,
            content_object=failure_data.user,  # May be None for non-existent users
            description=f"Failed login attempt: {failure_data.failure_reason} for {failure_data.email or 'unknown'}",
        )

        return AuditService.log_event(audit_event_data, context)

    @staticmethod
    def log_logout(logout_data: LogoutEventData) -> AuditEvent:
        """
        Log logout event with session and security context

        Args:
            logout_data: Logout event data containing user and context info
        """
        # Extract context from request if provided
        if logout_data.request:
            logout_data.ip_address = logout_data.ip_address or get_safe_client_ip(logout_data.request)
            logout_data.user_agent = logout_data.user_agent or logout_data.request.META.get("HTTP_USER_AGENT", "")
            logout_data.session_key = logout_data.session_key or getattr(
                logout_data.request.session, "session_key", None
            )

        # Map logout reasons to actions
        action_map = {
            "manual": "logout_manual",
            "session_expired": "logout_session_expired",
            "security_event": "logout_security_event",
            "concurrent_session": "logout_concurrent_session",
        }
        action = action_map.get(logout_data.logout_reason, "logout_manual")

        # Build session and security metadata
        auth_metadata = {
            "logout_reason": logout_data.logout_reason,
            "logout_timestamp": timezone.now().isoformat(),
            "user_id": str(logout_data.user.id),
            "user_email": logout_data.user.email,
            "session_info": {
                "session_key": logout_data.session_key,
                "session_ended": timezone.now().isoformat(),
            },
            "security_context": {
                "user_2fa_enabled": getattr(logout_data.user, "two_factor_enabled", False),
                "logout_triggered_by": logout_data.logout_reason,
            },
            **logout_data.metadata,
        }

        # Add login session duration if available
        if logout_data.user.last_login:
            session_duration = timezone.now() - logout_data.user.last_login
            auth_metadata["session_info"]["duration_seconds"] = int(session_duration.total_seconds())
            auth_metadata["session_info"]["duration_human"] = str(session_duration)

        context = AuditContext(
            user=logout_data.user,
            ip_address=logout_data.ip_address,
            user_agent=logout_data.user_agent,
            session_key=logout_data.session_key,
            metadata=auth_metadata,
            actor_type="user",
        )

        audit_event_data = AuditEventData(
            event_type=action,
            content_object=logout_data.user,
            description=f"User logout: {logout_data.logout_reason} for {logout_data.user.email}",
        )

        return AuditService.log_event(audit_event_data, context)

    @staticmethod
    def log_account_locked(account_data: AccountEventData) -> AuditEvent:
        """
        Log account lockout event with security details

        Args:
            account_data: Account event data containing user and context info
        """
        if account_data.request:
            account_data.ip_address = account_data.ip_address or get_safe_client_ip(account_data.request)

        auth_metadata = {
            "lockout_reason": account_data.trigger_reason,
            "lockout_timestamp": timezone.now().isoformat(),
            "failed_attempts_count": account_data.failed_attempts
            or getattr(account_data.user, "failed_login_attempts", 0),
            "user_id": str(account_data.user.id),
            "user_email": account_data.user.email,
            "security_event": True,
            **account_data.metadata,
        }

        context = AuditContext(
            user=account_data.user, ip_address=account_data.ip_address, metadata=auth_metadata, actor_type="system"
        )

        audit_event_data = AuditEventData(
            event_type="account_locked",
            content_object=account_data.user,
            description=f"Account locked for {account_data.user.email}: {account_data.trigger_reason}",
        )

        return AuditService.log_event(audit_event_data, context)

    @staticmethod
    def log_session_rotation(session_data: SessionRotationEventData) -> AuditEvent:
        """
        Log session rotation events for security tracking

        Args:
            session_data: Session rotation event data containing user and context info
        """
        auth_metadata = {
            "rotation_reason": session_data.reason,
            "rotation_timestamp": timezone.now().isoformat(),
            "user_id": str(session_data.user.id),
            "session_info": {
                "old_session_key": session_data.old_session_key,
                "new_session_key": session_data.new_session_key,
            },
            "security_enhancement": True,
            **session_data.metadata,
        }

        context = AuditContext(
            user=session_data.user,
            ip_address=get_safe_client_ip(session_data.request) if session_data.request else None,
            session_key=session_data.new_session_key,
            metadata=auth_metadata,
            actor_type="system",
        )

        audit_event_data = AuditEventData(
            event_type="session_rotation",
            content_object=session_data.user,
            description=f"Session rotated for {session_data.user.email}: {session_data.reason}",
        )

        return AuditService.log_event(audit_event_data, context)


class AuditService:
    """Centralized audit logging service"""

    @staticmethod
    def log_event(event_data: AuditEventData, context: AuditContext | None = None) -> AuditEvent:
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
            category = context.metadata.get("category", AuditService._get_action_category(event_data.event_type))
            severity = context.metadata.get("severity", AuditService._get_action_severity(event_data.event_type))
            is_sensitive = context.metadata.get(
                "is_sensitive", AuditService._is_action_sensitive(event_data.event_type)
            )
            requires_review = context.metadata.get(
                "requires_review", AuditService._requires_review(event_data.event_type)
            )

            # Ensure category is never None (fallback to default)
            if category is None:
                category = "business_operation"

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
                user_agent=context.user_agent or "",
                request_id=context.request_id or str(uuid.uuid4()),
                session_key=context.session_key or "",
                metadata=serialized_metadata,
            )

            logger.info(
                f"✅ [Audit] {event_data.event_type} event logged for user {context.user.email if context.user else 'System'} ({category}/{severity})"
            )

            return audit_event

        except Exception as e:
            logger.error(f"🔥 [Audit] Failed to log event {event_data.event_type}: {e}")
            raise

    @staticmethod
    def log_simple_event(  # noqa: PLR0913
        event_type: str,
        *,
        user: Any | None = None,
        content_object: Any | None = None,
        description: str = "",
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        ip_address: str | None = None,
        actor_type: str = "user",
    ) -> AuditEvent:
        """
        🔐 Simplified audit logging method (DRY helper)

        This method provides a simpler interface for audit logging while maintaining
        the proper data structure requirements internally.

        Args:
            event_type: Type of event being logged
            user: User who performed the action (None for system actions)
            content_object: Django model instance being audited
            description: Human-readable description
            old_values: Previous values (for updates)
            new_values: New values (for updates)
            metadata: Additional metadata
            ip_address: IP address of the actor
            actor_type: Type of actor ("user", "system", "admin", etc.)

        Returns:
            AuditEvent: The created audit event
        """
        event_data = AuditEventData(
            event_type=event_type,
            content_object=content_object,
            description=description,
            old_values=old_values,
            new_values=new_values,
        )

        context = AuditContext(
            user=user,
            actor_type=actor_type,
            ip_address=ip_address,
            metadata=metadata or {},
        )

        return AuditService.log_event(event_data, context)

    @staticmethod
    def _get_action_category(action: str) -> str:
        """Determine audit event category from action type"""
        # Use a mapping approach to reduce branching complexity
        category_mappings = {
            "authentication": ["login_", "logout_", "session_", "account_", "password_", "2fa_"],
            "account_management": ["profile_updated", "email_changed", "phone_updated", "name_changed"],
            "privacy": ["privacy_", "gdpr_", "marketing_consent_", "cookie_consent_"],
            "authorization": [
                "role_assigned",
                "role_removed",
                "permission_granted",
                "permission_revoked",
                "staff_role_changed",
                "customer_",
                "privilege_escalation_attempt",
            ],
            "security_event": ["security_", "suspicious_", "brute_force_", "malicious_", "data_breach_"],
            "data_protection": ["data_export_", "data_deletion_"],
            "integration": ["api_", "webhook_"],
            "system_admin": ["system_", "backup_", "configuration_", "user_impersonation"],
            "compliance": ["vat_", "efactura_", "data_retention", "tax_rule"],
            "business_operation": [
                "proforma_",
                "invoice_",
                "payment_",
                "credit_",
                "billing_",
                "currency_conversion",
                "order_",
                "provisioning_",
                "service_",
                "domain_",
                "support_ticket_",
            ],
        }

        # Check each category's patterns
        for category, patterns in category_mappings.items():
            for pattern in patterns:
                if pattern.endswith("_"):  # Prefix pattern
                    if action.startswith(pattern):
                        return category
                elif action == pattern:
                    return category

        # Default to business operation
        return "business_operation"

    @staticmethod
    def _get_action_severity(action: str) -> str:
        """Determine severity level from action type"""
        # Critical severity events
        critical_actions = [
            "data_breach_detected",
            "security_incident_detected",
            "account_compromised",
            "malicious_request",
            "brute_force_attempt",
        ]

        # High severity events
        high_actions = [
            "password_compromised",
            "2fa_disabled",
            "2fa_admin_reset",
            "role_assigned",
            "role_removed",
            "permission_granted",
            "permission_revoked",
            "staff_role_changed",
            "data_export_requested",
            "data_deletion_requested",
            "gdpr_consent_withdrawn",
            "user_impersonation_started",
            "system_maintenance_started",
            "configuration_changed",
            "payment_failed",
            "payment_fraud_detected",
            "payment_chargeback_received",
            "invoice_voided",
            "invoice_refunded",
            "credit_limit_changed",
            "credit_hold_applied",
            "order_cancelled_admin",
            "provisioning_failed",
            "efactura_rejected",
            "privilege_escalation_attempt",
        ]

        # Medium severity events
        medium_actions = [
            "login_success",
            "login_failed",
            "logout_manual",
            "account_locked",
            "session_rotation",
            "password_changed",
            "2fa_enabled",
            "profile_updated",
            "email_changed",
            "phone_updated",
            "customer_membership_created",
            "api_key_generated",
            "invoice_paid",
            "payment_succeeded",
            "order_created",
            "order_completed",
            "proforma_created",
            "provisioning_completed",
            "efactura_submitted",
        ]

        if action in critical_actions or action.startswith(("security_", "suspicious_", "data_breach")):
            return "critical"
        elif action in high_actions or action.startswith(
            (
                "data_",
                "gdpr_",
                "privacy_",
                "marketing_consent",
                "cookie_consent",
                "role_",
                "permission_",
                "payment_fraud",
                "payment_chargeback",
            )
        ):
            return "high"
        elif action in medium_actions or action.startswith(
            ("login_", "password_", "2fa_", "profile_", "payment_", "order_")
        ):
            return "medium"
        else:
            return "low"

    @staticmethod
    def _is_action_sensitive(action: str) -> bool:
        """Determine if action involves sensitive data"""
        # Specific sensitive actions
        sensitive_actions = [
            "account_locked",
            "account_unlocked",
            "session_rotation",
            "session_terminated",
            "suspicious_activity",
            "brute_force_attempt",
            "malicious_request",
            "privilege_escalation_attempt",
        ]

        # Sensitive patterns (excluding some common business operations)
        sensitive_patterns = [
            "login_",
            "logout_",
            "password_",
            "2fa_",
            "email_",
            "phone_",
            "profile_",
            "privacy_",
            "gdpr_",
            "marketing_consent",
            "cookie_consent",
            "data_",
            "security_",
            "role_",
            "permission_",
            "payment_",
            "billing_",
            "tax_",
            "credit_",
            "proforma_",
            "vat_",
            "efactura_",
            "customer_",
        ]

        # Non-sensitive invoice actions (basic business operations)
        non_sensitive_invoice_actions = ["invoice_created", "invoice_sent"]
        if action in non_sensitive_invoice_actions:
            return False

        return action in sensitive_actions or any(action.startswith(pattern) for pattern in sensitive_patterns)

    @staticmethod
    def _requires_review(action: str) -> bool:
        """Determine if action requires manual review"""
        review_actions = [
            "account_locked",
            "login_failed_2fa",
            "password_compromised",
            "2fa_disabled",
            "2fa_admin_reset",
            "role_assigned",
            "role_removed",
            "permission_granted",
            "permission_revoked",
            "staff_role_changed",
            "privilege_escalation_attempt",
            "data_export_requested",
            "data_deletion_requested",
            "gdpr_consent_withdrawn",
            "security_incident_detected",
            "suspicious_activity",
            "brute_force_attempt",
            "user_impersonation_started",
            "configuration_changed",
            "system_maintenance_started",
        ]

        return action in review_actions or action.startswith(("security_", "data_breach", "malicious_"))

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
            "event_category": "authentication",  # 2FA is always authentication
            "category": "authentication",
            "severity": "high" if request.event_type in ["2fa_disabled", "2fa_admin_reset"] else "medium",
            "is_sensitive": True,  # 2FA events are always sensitive
            "requires_review": request.event_type in ["2fa_disabled", "2fa_admin_reset"],
            "timestamp": timezone.now().isoformat(),
            **request.context.metadata,
        }

        # Add user 2FA status to metadata
        if request.user:
            enhanced_metadata.update(
                {
                    "user_2fa_enabled": request.user.two_factor_enabled,
                    "backup_codes_count": len(request.user.backup_tokens) if request.user.backup_tokens else 0,
                }
            )

        # Create enhanced context with metadata (metadata will be serialized in log_event)
        enhanced_context = AuditContext(
            user=request.user,
            ip_address=request.context.ip_address,
            user_agent=request.context.user_agent,
            request_id=request.context.request_id,
            session_key=request.context.session_key,
            metadata=enhanced_metadata,
            actor_type=request.context.actor_type,
        )

        # Create event data
        event_data = AuditEventData(
            event_type=request.event_type,
            content_object=request.user,  # 2FA events act on the user object
            description=request.description or f"2FA {request.event_type.replace('_', ' ').title()}",
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
                metadata=serialized_metadata,
            )

            logger.info(f"📋 [Compliance] {request.compliance_type} logged: {request.reference_id}")

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
        description: str = "",
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        session_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        actor_type: str = "user",
    ) -> AuditEvent:
        """Legacy wrapper for backward compatibility"""
        event_data = AuditEventData(
            event_type=event_type,
            content_object=content_object,
            old_values=old_values,
            new_values=new_values,
            description=description,
        )

        context = AuditContext(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_key=session_key,
            metadata=metadata or {},
            actor_type=actor_type,
        )

        return AuditService.log_event(event_data, context)

    @staticmethod
    def log_2fa_event_legacy(  # noqa: PLR0913
        event_type: str,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        description: str = "",
        request_id: str | None = None,
        session_key: str | None = None,
    ) -> AuditEvent:
        """Legacy wrapper for backward compatibility"""
        context = AuditContext(
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_key=session_key,
            metadata=metadata or {},
        )

        request = TwoFactorAuditRequest(event_type=event_type, user=user, context=context, description=description)

        return AuditService.log_2fa_event(request)

    @staticmethod
    def log_compliance_event_legacy(  # noqa: PLR0913
        compliance_type: str,
        reference_id: str,
        description: str,
        user: User | None = None,
        status: str = "success",
        evidence: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ComplianceLog:
        """Legacy wrapper for backward compatibility"""
        request = ComplianceEventRequest(
            compliance_type=compliance_type,
            reference_id=reference_id,
            description=description,
            user=user,
            status=status,
            evidence=evidence or {},
            metadata=metadata or {},
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
        cls, user: User, request_ip: str | None = None, export_scope: dict[str, Any] | None = None
    ) -> Result[DataExport, str]:
        """Create a new GDPR data export request"""

        try:
            # Default export scope - comprehensive user data
            if not export_scope:
                export_scope = {
                    "include_profile": True,
                    "include_customers": True,
                    "include_billing": True,
                    "include_tickets": True,
                    "include_audit_logs": True,
                    "include_sessions": False,  # Security sensitive
                    "format": "json",
                }

            export_request = DataExport.objects.create(
                requested_by=user,
                export_type="gdpr",
                scope=export_scope,
                status="pending",
                expires_at=timezone.now() + timedelta(days=7),  # 7 days to download
            )

            # Log GDPR export request
            compliance_request = ComplianceEventRequest(
                compliance_type="gdpr_consent",
                reference_id=f"export_{export_request.id}",
                description=f"GDPR data export requested by {user.email}",
                user=user,
                status="initiated",
                evidence={"export_id": str(export_request.id), "scope": export_scope},
                metadata={"ip_address": request_ip},
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
            export_request.status = "processing"
            export_request.started_at = timezone.now()
            export_request.save(update_fields=["status", "started_at"])

            # Collect all user data
            user_data = cls._collect_user_data(user, export_request.scope)

            # Generate export file
            export_content = json.dumps(user_data, indent=2, default=str, ensure_ascii=False)

            # Generate secure filename
            file_hash = hashlib.sha256(export_content.encode()).hexdigest()[:16]
            filename = f"gdpr_export_{user.id}_{file_hash}.json"

            # Save to secure storage
            file_path = f"gdpr_exports/{filename}"
            saved_path = default_storage.save(file_path, ContentFile(export_content.encode("utf-8")))

            # Update export request
            export_request.status = "completed"
            export_request.completed_at = timezone.now()
            export_request.file_path = saved_path
            export_request.file_size = len(export_content.encode("utf-8"))
            export_request.record_count = cls._count_records(user_data)
            export_request.save(update_fields=["status", "completed_at", "file_path", "file_size", "record_count"])

            # Log completion
            compliance_request = ComplianceEventRequest(
                compliance_type="gdpr_consent",
                reference_id=f"export_{export_request.id}",
                description=f"GDPR data export completed for {user.email}",
                user=user,
                status="completed",
                evidence={
                    "file_size_bytes": export_request.file_size,
                    "record_count": export_request.record_count,
                    "completion_time": export_request.completed_at.isoformat(),
                },
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(
                f"✅ [GDPR Export] Completed for {user.email}: {export_request.file_size} bytes, {export_request.record_count} records"
            )
            return Ok(saved_path)

        except Exception as e:
            # Mark as failed
            export_request.status = "failed"
            export_request.error_message = str(e)
            export_request.save(update_fields=["status", "error_message"])

            logger.error(f"🔥 [GDPR Export] Processing failed for {user.email}: {e}")
            return Err(f"Export processing failed: {e!s}")

    @classmethod
    def get_user_exports(cls, user: User) -> list[dict[str, Any]]:
        """Get recent data export requests for a user (last 10)."""
        exports = DataExport.objects.filter(
            requested_by=user,
        ).order_by("-requested_at")[:10]
        return [
            {
                "id": str(e.id),
                "status": e.status,
                "requested_at": e.requested_at.isoformat(),
                "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                "expires_at": e.expires_at.isoformat(),
                "file_size": e.file_size,
                "record_count": e.record_count,
            }
            for e in exports
        ]

    @classmethod
    def _collect_user_data(cls, user: User, scope: dict[str, Any]) -> dict[str, Any]:
        """Collect comprehensive user data based on export scope"""
        data: dict[str, Any] = {
            "metadata": {
                "generated_at": timezone.now().isoformat(),
                "user_id": user.id,
                "export_type": "gdpr_data_portability",
                "praho_platform_version": "1.0.0",
                "gdpr_article": "Article 20 - Right to data portability",
                "legal_basis": "Romanian Law 190/2018, GDPR Article 20",
            },
            "user_profile": {},
            "customers": [],
            "billing_data": [],
            "support_tickets": [],
            "audit_summary": {},
        }

        # Core user profile data
        if scope.get("include_profile", True):
            data["user_profile"] = {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
                "date_joined": user.date_joined.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "staff_role": user.staff_role,
                "gdpr_consent_date": user.gdpr_consent_date.isoformat() if user.gdpr_consent_date else None,
                "accepts_marketing": user.accepts_marketing,
                "last_privacy_policy_accepted": user.last_privacy_policy_accepted.isoformat()
                if user.last_privacy_policy_accepted
                else None,
                "account_status": "active" if user.is_active else "inactive",
            }

        # Customer relationships and data
        if scope.get("include_customers", True):
            try:
                memberships = user.customer_memberships.select_related("customer")
                for membership in memberships:
                    customer = membership.customer
                    customer_data = {
                        "customer_id": customer.id,
                        "company_name": customer.company_name,
                        "customer_type": customer.customer_type,
                        "role": membership.role,
                        "is_primary": membership.is_primary,
                        "joined_date": membership.created_at.isoformat(),
                        "status": customer.status,
                    }
                    data["customers"].append(customer_data)
            except AttributeError:
                data["customers"] = {"note": "Customer relationships not available"}

        # Support tickets
        if scope.get("include_tickets", True):
            try:
                tickets = Ticket.objects.filter(created_by=user)
                for ticket in tickets:
                    data["support_tickets"].append(
                        {
                            "ticket_id": ticket.id,
                            "subject": ticket.title,
                            "status": ticket.status,
                            "priority": ticket.priority,
                            "created_at": ticket.created_at.isoformat(),
                            "updated_at": ticket.updated_at.isoformat(),
                        }
                    )
            except ImportError:
                data["support_tickets"] = {"note": "Support tickets not available"}

        # Audit trail summary (privacy-focused)
        if scope.get("include_audit_logs", True):
            audit_events = AuditEvent.objects.filter(user=user).order_by("-timestamp")[:100]  # Last 100 events
            data["audit_summary"] = {
                "total_events": audit_events.count(),
                "recent_activities": [
                    {
                        "action": event.action,
                        "timestamp": event.timestamp.isoformat(),
                        "description": event.description[:100],  # Truncated for privacy
                    }
                    for event in audit_events[:10]  # Last 10 activities
                ],
            }

        return data

    @classmethod
    def _count_records(cls, user_data: dict[str, Any]) -> int:
        """Count total records in the export"""
        count = 1  # User profile
        count += len(user_data.get("customers", []))
        count += len(user_data.get("billing_data", []))
        count += len(user_data.get("support_tickets", []))
        count += len(user_data.get("audit_summary", {}).get("recent_activities", []))
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
        "email": lambda: f"anonymized_{uuid.uuid4().hex[:8]}@example.com",
        "first_name": lambda: "Anonymized",
        "last_name": lambda: "User",
        "phone": lambda: "+40700000000",
        "ip_address": lambda: "0.0.0.0",
    }

    @classmethod
    @transaction.atomic
    def create_deletion_request(
        cls,
        user: User,
        deletion_type: str = "anonymize",  # 'anonymize' or 'delete'
        request_ip: str | None = None,
        reason: str | None = None,
    ) -> Result[ComplianceLog, str]:
        """Create a GDPR data deletion request"""

        try:
            # Validate deletion type
            if deletion_type not in ["anonymize", "delete"]:
                return Err("Invalid deletion type. Must be 'anonymize' or 'delete'")

            # Check if user can be deleted (business rules)
            can_delete, restriction_reason = cls._can_user_be_deleted(user)
            if not can_delete and deletion_type == "delete":
                logger.warning(f"⚠️ [GDPR Deletion] Full deletion blocked for {user.email}: {restriction_reason}")
                deletion_type = "anonymize"  # Force anonymization instead

            # Create compliance log entry
            compliance_request = ComplianceEventRequest(
                compliance_type="gdpr_deletion",
                reference_id=f"deletion_{user.id}_{uuid.uuid4().hex[:8]}",
                description=f"GDPR {deletion_type} requested by {user.email}. Reason: {reason or 'User request'}"
                + (". This action is irreversible." if deletion_type == "delete" else ""),
                user=user,
                status="requested",
                evidence={
                    "deletion_type": deletion_type,
                    "user_email": user.email,
                    "reason": reason,
                    "can_full_delete": can_delete,
                    "restriction_reason": restriction_reason,
                },
                metadata={"ip_address": request_ip},
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
            user_email = deletion_request.evidence.get("user_email", "unknown")
            deletion_type = deletion_request.evidence.get("deletion_type", "anonymize")

            # Get user (might be already deleted)
            try:
                user = deletion_request.user
                if not user:
                    logger.warning(f"⚠️ [GDPR Deletion] User {user_email} already deleted")
                    deletion_request.status = "completed"
                    deletion_request.save(update_fields=["status"])
                    return Ok("User already deleted")
            except User.DoesNotExist:
                deletion_request.status = "completed"
                deletion_request.save(update_fields=["status"])
                return Ok("User already deleted")

            # Update request status
            deletion_request.status = "processing"
            deletion_request.save(update_fields=["status"])

            if deletion_type == "anonymize":
                result = cls._anonymize_user_data(user)
                action_taken = "anonymized"
            else:
                result = cls._delete_user_data(user)
                action_taken = "deleted"

            if result.is_err():
                deletion_request.status = "failed"
                deletion_request.evidence["error"] = result.error if hasattr(result, "error") else str(result)
                deletion_request.save(update_fields=["status", "evidence"])
                return result

            # Mark as completed
            deletion_request.status = "completed"
            deletion_request.evidence["completed_at"] = timezone.now().isoformat()
            deletion_request.evidence["action_taken"] = action_taken
            deletion_request.save(update_fields=["status", "evidence"])

            logger.info(f"✅ [GDPR Deletion] User data {action_taken} for {user_email}")
            return Ok(f"User data successfully {action_taken}")

        except Exception as e:
            deletion_request.status = "failed"
            deletion_request.evidence["error"] = str(e)
            deletion_request.save(update_fields=["status", "evidence"])
            logger.error(f"🔥 [GDPR Deletion] Processing failed: {e}")
            return Err(f"Deletion processing failed: {e!s}")

    @classmethod
    def _can_user_be_deleted(cls, user: User) -> tuple[bool, str | None]:
        """Check if user can be completely deleted based on business rules"""

        restrictions = []

        # Romanian business law - must keep tax records for 7 years
        try:
            if hasattr(user, "customer_memberships") and user.customer_memberships.exists():
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
            user.email = cls.ANONYMIZATION_MAP["email"]()
            user.first_name = cls.ANONYMIZATION_MAP["first_name"]()
            user.last_name = cls.ANONYMIZATION_MAP["last_name"]()
            user.phone = cls.ANONYMIZATION_MAP["phone"]()
            user.is_active = False
            user.accepts_marketing = False
            user.gdpr_consent_date = None
            user.last_privacy_policy_accepted = None

            # Clear sensitive fields
            user.set_unusable_password()
            if hasattr(user, "two_factor_enabled"):
                user.two_factor_enabled = False
                user.two_factor_secret = ""
                user.backup_tokens = []

            user.save()

            # Anonymize audit logs (IP addresses only)
            AuditEvent.objects.filter(user=user).update(
                ip_address=cls.ANONYMIZATION_MAP["ip_address"](), user_agent="Anonymized"
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
    def withdraw_consent(cls, user: User, consent_types: list[str], request_ip: str | None = None) -> Result[str, str]:
        """Withdraw specific types of consent"""

        try:
            valid_types = ["data_processing", "marketing", "analytics", "cookies"]
            invalid_types = [ct for ct in consent_types if ct not in valid_types]
            if invalid_types:
                return Err(f"Invalid consent types: {invalid_types}")

            changes_made = []

            # Handle marketing consent withdrawal
            if "marketing" in consent_types and user.accepts_marketing:
                user.accepts_marketing = False
                changes_made.append("marketing_communications")

            # Data processing consent withdrawal triggers anonymization
            if "data_processing" in consent_types:
                # This is a full GDPR deletion request
                deletion_result = GDPRDeletionService.create_deletion_request(
                    user, "anonymize", request_ip, "Data processing consent withdrawn"
                )
                if deletion_result.is_err():
                    error_msg = deletion_result.error if hasattr(deletion_result, "error") else str(deletion_result)
                    return Err(f"Failed to process consent withdrawal: {error_msg}")

                # Immediately process the deletion request
                # Type-safe extraction after confirming it's Ok
                deletion_request = deletion_result.unwrap()
                process_result = GDPRDeletionService.process_deletion_request(deletion_request)
                if process_result.is_err():
                    error_msg = process_result.error if hasattr(process_result, "error") else str(process_result)
                    return Err(f"Failed to anonymize user data: {error_msg}")

                changes_made.append("data_processing")

            if changes_made:
                user.save()

                # Log consent withdrawal
                compliance_request = ComplianceEventRequest(
                    compliance_type="gdpr_consent",
                    reference_id=f"consent_withdrawal_{user.id}_{uuid.uuid4().hex[:8]}",
                    description=f"Consent withdrawn for: {', '.join(changes_made)}",
                    user=user,
                    status="success",
                    evidence={
                        "withdrawn_consents": consent_types,
                        "changes_made": changes_made,
                        "withdrawal_date": timezone.now().isoformat(),
                    },
                    metadata={"ip_address": request_ip},
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
            consent_logs = ComplianceLog.objects.filter(compliance_type="gdpr_consent", user=user).order_by(
                "-timestamp"
            )

            # ⚡ PERFORMANCE: Use list comprehension for better performance
            history: list[ConsentHistoryEntry] = [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "action": log.description,
                    "description": log.description,  # Include both for backward compatibility
                    "status": log.status,
                    "evidence": log.evidence,
                }
                for log in consent_logs
            ]

            return history

        except Exception as e:
            logger.error(f"🔥 [GDPR Consent] Failed to get consent history for {user.email}: {e}")
            return []

    @classmethod
    @transaction.atomic
    def record_cookie_consent(  # noqa: PLR0913
        cls,
        *,
        cookie_id: str,
        status: str,
        functional: bool = False,
        analytics: bool = False,
        marketing: bool = False,
        ip_address: str | None = None,
        user_agent: str = "",
        user_id: int | None = None,
    ) -> Result[CookieConsent, str]:
        """
        Record cookie consent from Portal (via GDPR API).

        Handles both anonymous (cookie_id only) and authenticated (user_id) consent.
        When user_id is provided with a cookie_id, also links any prior anonymous
        CookieConsent records with the same cookie_id to this user.
        """
        from .signals import cookie_consent_updated  # noqa: PLC0415  # circular import

        try:
            status_map = {
                "accepted_all": "accepted_all",
                "accepted_essential": "accepted_essential",
                "customized": "customized",
                "withdrawn": "withdrawn",
            }
            consent_status = status_map.get(status, "customized")

            user = None
            if user_id is not None:
                with contextlib.suppress(User.DoesNotExist):
                    user = User.objects.get(id=user_id, is_active=True)

            defaults = {
                "status": consent_status,
                "essential_cookies": True,
                "functional_cookies": functional,
                "analytics_cookies": analytics,
                "marketing_cookies": marketing,
                "ip_address": ip_address,
                "user_agent": (user_agent or "")[:500],
                "consent_version": "1.0",
            }

            # Always use cookie_id as the SOLE lookup key — one cookie_id = one row.
            # Using user__isnull=True in the anonymous branch would create a second
            # row after the authenticated branch sets user, leading to
            # MultipleObjectsReturned on the next authenticated call.
            # When anonymous, user is omitted from defaults so existing user
            # associations are preserved (e.g., user logs out, updates preferences).
            if user:
                defaults["user"] = user

            consent, _created = CookieConsent.objects.update_or_create(
                cookie_id=cookie_id, defaults=defaults,
            )

            # Emit signal → triggers dual audit trail:
            # 1. AuditEvent (security monitoring)
            # 2. ComplianceLog (GDPR reporting)
            # See audit_cookie_consent_change() in signals.py
            cookie_consent_updated.send(
                sender=cls,
                consent=consent,
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            logger.info(
                f"✅ [GDPR Cookie] Consent recorded: "
                f"user={'anonymous' if not user else user.email}, status={consent_status}"
            )
            return Ok(consent)

        except Exception as e:
            logger.error(f"🔥 [GDPR Cookie] Failed to record consent: {e}")
            return Err(f"Failed to record cookie consent: {e!s}")

    @classmethod
    def get_cookie_consent_history(cls, user: User) -> list[dict[str, Any]]:
        """Get cookie consent records for a user."""
        try:
            consents = CookieConsent.objects.filter(user=user).order_by("-updated_at")
            return [
                {
                    "id": str(c.id),
                    "status": c.status,
                    "essential": c.essential_cookies,
                    "functional": c.functional_cookies,
                    "analytics": c.analytics_cookies,
                    "marketing": c.marketing_cookies,
                    "consent_version": c.consent_version,
                    "created_at": c.created_at.isoformat(),
                    "updated_at": c.updated_at.isoformat(),
                }
                for c in consents
            ]
        except Exception as e:
            logger.error(f"🔥 [GDPR Cookie] Failed to get cookie history for {user.email}: {e}")
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
    def log_invoice_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log invoice-related audit event with financial context

        Args:
            event_data: Business event data containing event type, invoice, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build invoice-specific metadata
        invoice_metadata = {
            "invoice_number": event_data.business_object.number,
            "invoice_status": event_data.business_object.status,
            "customer_id": str(event_data.business_object.customer.id),
            "customer_name": event_data.business_object.bill_to_name
            or event_data.business_object.customer.company_name,
            "currency": event_data.business_object.currency.code,
            "total_amount": str(event_data.business_object.total),
            "total_cents": event_data.business_object.total_cents,
            "vat_amount": str(event_data.business_object.tax_amount),
            "vat_cents": event_data.business_object.tax_cents,
            "due_date": event_data.business_object.due_at.isoformat() if event_data.business_object.due_at else None,
            "issued_date": event_data.business_object.issued_at.isoformat()
            if event_data.business_object.issued_at
            else None,
            "is_overdue": event_data.business_object.is_overdue(),
            "romanian_compliance": {
                "efactura_id": event_data.business_object.efactura_id,
                "efactura_sent": event_data.business_object.efactura_sent,
                "efactura_sent_date": event_data.business_object.efactura_sent_date.isoformat()
                if event_data.business_object.efactura_sent_date
                else None,
            },
            **event_data.context.metadata,
        }

        # Enhanced context with invoice metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(invoice_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description
            or f"Invoice {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.number}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_payment_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log payment-related audit event with transaction context

        Args:
            event_data: Business event data containing event type, payment, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build payment-specific metadata
        payment_metadata = {
            "payment_id": str(event_data.business_object.id) if hasattr(event_data.business_object, "id") else None,
            "customer_id": str(event_data.business_object.customer.id),
            "customer_name": event_data.business_object.customer.company_name,
            "payment_method": event_data.business_object.payment_method,
            "amount": str(event_data.business_object.amount),
            "amount_cents": event_data.business_object.amount_cents,
            "currency": event_data.business_object.currency.code,
            "status": event_data.business_object.status,
            "gateway_txn_id": event_data.business_object.gateway_txn_id,
            "reference_number": event_data.business_object.reference_number,
            "received_at": event_data.business_object.received_at.isoformat(),
            "invoice_id": str(event_data.business_object.invoice.id) if event_data.business_object.invoice else None,
            "invoice_number": event_data.business_object.invoice.number if event_data.business_object.invoice else None,
            "financial_impact": True,
            **event_data.context.metadata,
        }

        # Enhanced context with payment metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(payment_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description
            or f"Payment {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.amount} {event_data.business_object.currency.code}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_proforma_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log proforma-related audit event

        Args:
            event_data: Business event data containing event type, proforma, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build proforma-specific metadata
        proforma_metadata = {
            "proforma_number": event_data.business_object.number,
            "customer_id": str(event_data.business_object.customer.id),
            "customer_name": event_data.business_object.bill_to_name
            or event_data.business_object.customer.company_name,
            "currency": event_data.business_object.currency.code,
            "total_amount": str(event_data.business_object.total),
            "total_cents": event_data.business_object.total_cents,
            "vat_amount": str(event_data.business_object.tax_amount),
            "vat_cents": event_data.business_object.tax_cents,
            "valid_until": event_data.business_object.valid_until.isoformat(),
            "is_expired": event_data.business_object.is_expired,
            "created_at": event_data.business_object.created_at.isoformat(),
            **event_data.context.metadata,
        }

        # Enhanced context with proforma metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(proforma_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description
            or f"Proforma {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.number}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_credit_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log credit ledger audit event

        Args:
            event_data: Business event data containing event type, credit entry, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build credit-specific metadata
        credit_metadata = {
            "customer_id": str(event_data.business_object.customer.id),
            "customer_name": event_data.business_object.customer.company_name,
            "delta_amount": str(event_data.business_object.delta),
            "delta_cents": event_data.business_object.delta_cents,
            "reason": event_data.business_object.reason,
            "invoice_id": str(event_data.business_object.invoice.id) if event_data.business_object.invoice else None,
            "payment_id": str(event_data.business_object.payment.id) if event_data.business_object.payment else None,
            "created_at": event_data.business_object.created_at.isoformat(),
            "financial_impact": True,
            **event_data.context.metadata,
        }

        # Enhanced context with credit metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(credit_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            description=event_data.description
            or f"Credit {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.delta} for {event_data.business_object.customer.company_name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


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
    def log_order_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log order-related audit event with business context

        Args:
            event_data: Business event data containing event type, order, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build order-specific metadata
        order_metadata = {
            "order_number": event_data.business_object.order_number,
            "order_status": event_data.business_object.status,
            "customer_id": str(event_data.business_object.customer.id),
            "customer_email": event_data.business_object.customer_email,
            "customer_name": event_data.business_object.customer_name,
            "customer_company": event_data.business_object.customer_company,
            "customer_vat_id": event_data.business_object.customer_vat_id,
            "currency": event_data.business_object.currency.code,
            "total_amount": str(event_data.business_object.total),
            "total_cents": event_data.business_object.total_cents,
            "subtotal_cents": event_data.business_object.subtotal_cents,
            "tax_cents": event_data.business_object.tax_cents,
            "discount_cents": event_data.business_object.discount_cents,
            "payment_method": event_data.business_object.payment_method,
            "transaction_id": event_data.business_object.transaction_id,
            "is_draft": event_data.business_object.is_draft,
            "is_paid": event_data.business_object.is_paid,
            "can_be_cancelled": event_data.business_object.can_be_cancelled,
            "created_at": event_data.business_object.created_at.isoformat(),
            "completed_at": event_data.business_object.completed_at.isoformat()
            if event_data.business_object.completed_at
            else None,
            "expires_at": event_data.business_object.expires_at.isoformat()
            if event_data.business_object.expires_at
            else None,
            "invoice_id": str(event_data.business_object.invoice.id) if event_data.business_object.invoice else None,
            "invoice_number": event_data.business_object.invoice.number if event_data.business_object.invoice else None,
            "source_tracking": {
                "source_ip": event_data.business_object.source_ip,
                "user_agent": event_data.business_object.user_agent[:200]
                if event_data.business_object.user_agent
                else None,  # Truncate for storage
                "referrer": event_data.business_object.referrer,
                "utm_source": event_data.business_object.utm_source,
                "utm_medium": event_data.business_object.utm_medium,
                "utm_campaign": event_data.business_object.utm_campaign,
            },
            "items_count": event_data.business_object.items.count()
            if hasattr(event_data.business_object, "items")
            else 0,
            **event_data.context.metadata,
        }

        # Enhanced context with order metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(order_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description
            or f"Order {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.order_number}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_order_item_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log order item-related audit event with product context

        Args:
            event_data: Business event data containing event type, order item, and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # Build order item-specific metadata
        item_metadata = {
            "order_number": event_data.business_object.order.order_number,
            "order_status": event_data.business_object.order.status,
            "product_id": str(event_data.business_object.product.id),
            "product_name": event_data.business_object.product_name,
            "product_type": event_data.business_object.product_type,
            "billing_period": event_data.business_object.billing_period,
            "quantity": event_data.business_object.quantity,
            "unit_price": str(event_data.business_object.unit_price),
            "unit_price_cents": event_data.business_object.unit_price_cents,
            "setup_fee": str(event_data.business_object.setup_fee),
            "setup_cents": event_data.business_object.setup_cents,
            "tax_rate": str(event_data.business_object.tax_rate),
            "tax_amount": str(event_data.business_object.tax_amount),
            "tax_cents": event_data.business_object.tax_cents,
            "line_total": str(event_data.business_object.line_total),
            "line_total_cents": event_data.business_object.line_total_cents,
            "domain_name": event_data.business_object.domain_name,
            "provisioning_status": event_data.business_object.provisioning_status,
            "provisioning_notes": event_data.business_object.provisioning_notes,
            "provisioned_at": event_data.business_object.provisioned_at.isoformat()
            if event_data.business_object.provisioned_at
            else None,
            "service_id": str(event_data.business_object.service.id) if event_data.business_object.service else None,
            "config": event_data.business_object.config,
            **event_data.context.metadata,
        }

        # Enhanced context with order item metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(item_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=event_data.business_object,
            old_values=event_data.old_values,
            new_values=event_data.new_values,
            description=event_data.description
            or f"Order Item {event_data.event_type.replace('_', ' ').title()}: {event_data.business_object.product_name} in {event_data.business_object.order.order_number}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_provisioning_event(event_data: BusinessEventData) -> AuditEvent:
        """
        Log provisioning-related audit event

        Args:
            event_data: Business event data containing event type, business object (order_item or service), and context info
        """
        # Use default context if none provided
        if event_data.context is None:
            event_data.context = AuditContext(user=event_data.user)

        # For provisioning events, business_object can be either order_item or service
        # We need to handle both cases appropriately
        order_item = None
        service = None

        # Determine if business_object is an order_item or service
        if hasattr(event_data.business_object, "order"):
            # It's an order_item
            order_item = event_data.business_object
            service = getattr(order_item, "service", None)
        else:
            # It's a service, we need to get the related order_item
            service = event_data.business_object
            order_item = getattr(service, "order_item", None) if service else None

        # Build provisioning-specific metadata
        if order_item:
            provisioning_metadata = {
                "order_number": order_item.order.order_number,
                "order_item_id": str(order_item.id),
                "product_name": order_item.product_name,
                "product_type": order_item.product_type,
                "domain_name": order_item.domain_name,
                "provisioning_status": order_item.provisioning_status,
                "provisioning_notes": order_item.provisioning_notes,
                "config": order_item.config,
                "service_id": str(service.id) if service else None,
                "service_type": service.service_type if service else None,
                "customer_id": str(order_item.order.customer.id),
                "customer_name": order_item.order.customer_name,
                **event_data.context.metadata,
            }
            product_name = order_item.product_name
        else:
            # Fallback to service-only metadata
            provisioning_metadata = {
                "service_id": str(service.id) if service else None,
                "service_type": service.service_type if service else "unknown",
                **event_data.context.metadata,
            }
            product_name = service.service_type if service else "unknown service"

        # Enhanced context with provisioning metadata
        enhanced_context = AuditContext(
            user=event_data.context.user,
            ip_address=event_data.context.ip_address,
            user_agent=event_data.context.user_agent,
            request_id=event_data.context.request_id,
            session_key=event_data.context.session_key,
            metadata=serialize_metadata(provisioning_metadata),
            actor_type=event_data.context.actor_type,
        )

        # Create audit event data using the service as content object if available, otherwise order_item
        audit_event_data = AuditEventData(
            event_type=event_data.event_type,
            content_object=service or order_item or event_data.business_object,
            description=event_data.description
            or f"Provisioning {event_data.event_type.replace('_', ' ').title()}: {product_name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


class CustomersAuditService:
    """
    👤 Specialized customers audit service for customer lifecycle tracking

    Features:
    - Complete customer lifecycle event tracking
    - Customer profile changes and compliance monitoring
    - Tax profile modifications (Romanian CUI, VAT validation)
    - Billing profile updates and credit management
    - Address management with Romanian postal compliance
    - Payment method lifecycle and security tracking
    - GDPR consent tracking and marketing preferences
    - Customer interaction notes and feedback processing
    """

    @staticmethod
    def log_customer_event(  # noqa: PLR0913
        event_type: str,
        customer: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer-related audit event with comprehensive context

        Args:
            event_type: Type of customer event (created, updated, status_changed, etc.)
            customer: Customer model instance
            user: User who triggered the event (if any)
            context: Additional audit context
            old_values: Previous values for comparison
            new_values: New values after change
            description: Human-readable description
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build customer-specific metadata
        customer_metadata = {
            "customer_id": str(customer.id),
            "customer_name": customer.name,
            "customer_type": customer.customer_type,
            "status": customer.status,
            "company_name": customer.company_name,
            "primary_email": customer.primary_email,
            "primary_phone": customer.primary_phone,
            "industry": customer.industry,
            "website": customer.website,
            "assigned_account_manager": customer.assigned_account_manager.email
            if customer.assigned_account_manager
            else None,
            "data_processing_consent": customer.data_processing_consent,
            "marketing_consent": customer.marketing_consent,
            "gdpr_consent_date": customer.gdpr_consent_date.isoformat() if customer.gdpr_consent_date else None,
            "created_at": customer.created_at.isoformat(),
            "updated_at": customer.updated_at.isoformat(),
            "created_by": customer.created_by.email if customer.created_by else None,
            "is_deleted": customer.is_deleted,
            "deleted_at": customer.deleted_at.isoformat() if customer.deleted_at else None,
            "deleted_by": customer.deleted_by.email if customer.deleted_by else None,
            # Compliance tracking
            "romanian_compliance": {
                "has_tax_profile": hasattr(customer, "tax_profile"),
                "has_billing_profile": hasattr(customer, "billing_profile"),
                "has_addresses": customer.addresses.exists() if hasattr(customer, "addresses") else False,
            },
            **context.metadata,
        }

        # Enhanced context with customer metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(customer_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=customer,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Customer {event_type.replace('_', ' ').title()}: {customer.get_display_name()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_tax_profile_event(  # noqa: PLR0913
        event_type: str,
        tax_profile: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer tax profile audit event with Romanian compliance context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build tax profile-specific metadata
        tax_metadata = {
            "customer_id": str(tax_profile.customer.id),
            "customer_name": tax_profile.customer.get_display_name(),
            "cui": tax_profile.cui,
            "registration_number": tax_profile.registration_number,
            "is_vat_payer": tax_profile.is_vat_payer,
            "vat_number": tax_profile.vat_number,
            "vat_rate": float(tax_profile.vat_rate),
            "reverse_charge_eligible": tax_profile.reverse_charge_eligible,
            "cui_valid": tax_profile.validate_cui() if tax_profile.cui else None,
            "is_romanian_entity": tax_profile.cui.startswith("RO") if tax_profile.cui else False,
            "created_at": tax_profile.created_at.isoformat(),
            "updated_at": tax_profile.updated_at.isoformat(),
            **context.metadata,
        }

        # Enhanced context with tax profile metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(tax_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=tax_profile,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Tax profile {event_type.replace('_', ' ').title()}: {tax_profile.customer.get_display_name()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_billing_profile_event(  # noqa: PLR0913
        event_type: str,
        billing_profile: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer billing profile audit event with financial context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build billing profile-specific metadata
        billing_metadata = {
            "customer_id": str(billing_profile.customer.id),
            "customer_name": billing_profile.customer.get_display_name(),
            "payment_terms": billing_profile.payment_terms,
            "credit_limit": float(billing_profile.credit_limit),
            "preferred_currency": billing_profile.preferred_currency,
            "invoice_delivery_method": billing_profile.invoice_delivery_method,
            "auto_payment_enabled": billing_profile.auto_payment_enabled,
            "account_balance": float(billing_profile.get_account_balance()),
            "created_at": billing_profile.created_at.isoformat(),
            "updated_at": billing_profile.updated_at.isoformat(),
            **context.metadata,
        }

        # Enhanced context with billing profile metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(billing_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=billing_profile,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Billing profile {event_type.replace('_', ' ').title()}: {billing_profile.customer.get_display_name()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_address_event(  # noqa: PLR0913
        event_type: str,
        address: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer address audit event with Romanian compliance context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build address-specific metadata
        address_metadata = {
            "customer_id": str(address.customer.id),
            "customer_name": address.customer.get_display_name(),
            "address_type": address.address_type,
            "address_line1": address.address_line1,
            "address_line2": address.address_line2,
            "city": address.city,
            "county": address.county,
            "postal_code": address.postal_code,
            "country": address.country,
            "is_current": address.is_current,
            "version": address.version,
            "is_validated": address.is_validated,
            "validated_at": address.validated_at.isoformat() if address.validated_at else None,
            "full_address": address.get_full_address(),
            "is_romanian_address": address.country == "România",
            "is_legal_address": address.address_type == "legal",
            "created_at": address.created_at.isoformat(),
            "updated_at": address.updated_at.isoformat(),
            **context.metadata,
        }

        # Enhanced context with address metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(address_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=address,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Address {event_type.replace('_', ' ').title()}: {address.customer.get_display_name()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_payment_method_event(  # noqa: PLR0913
        event_type: str,
        payment_method: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer payment method audit event with security context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build payment method-specific metadata (avoiding sensitive data)
        payment_metadata = {
            "customer_id": str(payment_method.customer.id),
            "customer_name": payment_method.customer.get_display_name(),
            "method_type": payment_method.method_type,
            "display_name": payment_method.display_name,
            "last_four": payment_method.last_four,
            "is_default": payment_method.is_default,
            "is_active": payment_method.is_active,
            "has_stripe_integration": bool(payment_method.stripe_payment_method_id),
            "has_bank_details": bool(payment_method.bank_details),
            "created_at": payment_method.created_at.isoformat(),
            "updated_at": payment_method.updated_at.isoformat(),
            # Security context
            "security_sensitive": True,
            "pci_compliance_required": payment_method.method_type in ["stripe_card", "bank_transfer"],
            **context.metadata,
        }

        # Enhanced context with payment method metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(payment_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=payment_method,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Payment method {event_type.replace('_', ' ').title()}: {payment_method.customer.get_display_name()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_note_event(
        event_type: str,
        note: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log customer note audit event with interaction context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build note-specific metadata
        note_metadata = {
            "customer_id": str(note.customer.id),
            "customer_name": note.customer.get_display_name(),
            "note_type": note.note_type,
            "title": note.title,
            "is_important": note.is_important,
            "is_private": note.is_private,
            "created_by": note.created_by.email if note.created_by else None,
            "created_at": note.created_at.isoformat(),
            "content_length": len(note.content) if note.content else 0,
            "is_feedback": note.note_type in ["complaint", "compliment"],
            **context.metadata,
        }

        # Enhanced context with note metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(note_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=note,
            description=description or f"Customer note {event_type.replace('_', ' ').title()}: {note.title}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


# ===============================================================================
# PROVISIONING AUDIT SERVICE
# ===============================================================================


class ProvisioningAuditService:
    """
    🔧 Provisioning audit service for PRAHO Platform
    Specialized audit logging for hosting service lifecycle management.

    Features:
    - Service plan creation, pricing changes, and availability updates
    - Service lifecycle events (provisioning, activation, suspension, termination)
    - Server infrastructure changes and capacity monitoring
    - Service relationships and dependency tracking
    - Service group coordination and billing management
    - Service domain binding and DNS configuration
    - Provisioning task execution and failure tracking
    - Romanian hosting compliance and security logging
    """

    @staticmethod
    def log_service_plan_event(  # noqa: PLR0913
        event_type: str,
        service_plan: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log service plan audit event with pricing and availability context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build service plan-specific metadata
        plan_metadata = {
            "service_plan_id": str(service_plan.id),
            "service_plan_name": service_plan.name,
            "plan_type": service_plan.plan_type,
            "price_monthly_ron": float(service_plan.price_monthly),
            "price_quarterly_ron": float(service_plan.price_quarterly) if service_plan.price_quarterly else None,
            "price_annual_ron": float(service_plan.price_annual) if service_plan.price_annual else None,
            "setup_fee_ron": float(service_plan.setup_fee),
            "includes_vat": service_plan.includes_vat,
            "is_active": service_plan.is_active,
            "is_public": service_plan.is_public,
            "auto_provision": service_plan.auto_provision,
            "sort_order": service_plan.sort_order,
            "disk_space_gb": service_plan.disk_space_gb,
            "bandwidth_gb": service_plan.bandwidth_gb,
            "email_accounts": service_plan.email_accounts,
            "databases": service_plan.databases,
            "cpu_cores": service_plan.cpu_cores,
            "ram_gb": service_plan.ram_gb,
            "created_at": service_plan.created_at.isoformat(),
            "updated_at": service_plan.updated_at.isoformat(),
            # Romanian hosting context
            "romanian_vat_compliance": service_plan.includes_vat,
            "high_value_plan": float(service_plan.price_monthly) >= HIGH_VALUE_PLAN_THRESHOLD_RON,
            **context.metadata,
        }

        # Enhanced context with service plan metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(plan_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=service_plan,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Service plan {event_type.replace('_', ' ').title()}: {service_plan.name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_server_event(  # noqa: PLR0913
        event_type: str,
        server: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log server infrastructure audit event with capacity and resource context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build server-specific metadata
        server_metadata = {
            "server_id": str(server.id),
            "server_name": server.name,
            "hostname": server.hostname,
            "server_type": server.server_type,
            "status": server.status,
            "primary_ip": str(server.primary_ip),
            "secondary_ips": server.secondary_ips,
            "location": server.location,
            "datacenter": server.datacenter,
            "cpu_model": server.cpu_model,
            "cpu_cores": server.cpu_cores,
            "ram_gb": server.ram_gb,
            "disk_type": server.disk_type,
            "disk_capacity_gb": server.disk_capacity_gb,
            "os_type": server.os_type,
            "control_panel": server.control_panel,
            "provider": server.provider,
            "provider_instance_id": server.provider_instance_id,
            "monthly_cost_ron": float(server.monthly_cost),
            "max_services": server.max_services,
            "active_services_count": server.active_services_count,
            "is_active": server.is_active,
            # Resource utilization
            "cpu_usage_percent": float(server.cpu_usage_percent) if server.cpu_usage_percent else None,
            "ram_usage_percent": float(server.ram_usage_percent) if server.ram_usage_percent else None,
            "disk_usage_percent": float(server.disk_usage_percent) if server.disk_usage_percent else None,
            "resource_usage_average": server.resource_usage_average,
            # Timestamps
            "last_maintenance": server.last_maintenance.isoformat() if server.last_maintenance else None,
            "next_maintenance": server.next_maintenance.isoformat() if server.next_maintenance else None,
            "created_at": server.created_at.isoformat(),
            "updated_at": server.updated_at.isoformat(),
            # Server health context
            "is_overloaded": server.resource_usage_average > SERVER_OVERLOAD_THRESHOLD_PERCENT,
            "needs_maintenance": server.status == "maintenance",
            "is_critical_infrastructure": server.server_type in ["vps_host", "dedicated"],
            **context.metadata,
        }

        # Enhanced context with server metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(server_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=server,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Server {event_type.replace('_', ' ').title()}: {server.name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_service_event(  # noqa: PLR0913
        event_type: str,
        service: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log service lifecycle audit event with customer and billing context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build service-specific metadata
        service_metadata = {
            "service_id": str(service.id),
            "service_name": service.service_name,
            "domain": service.domain,
            "username": service.username,
            "customer_id": str(service.customer.id),
            "customer_name": service.customer.get_display_name(),
            "customer_type": service.customer.customer_type,
            "service_plan_id": str(service.service_plan.id),
            "service_plan_name": service.service_plan.name,
            "service_plan_type": service.service_plan.plan_type,
            "server_id": str(service.server.id) if service.server else None,
            "server_name": service.server.name if service.server else None,
            "status": service.status,
            "billing_cycle": service.billing_cycle,
            "price_ron": float(service.price),
            "setup_fee_paid": service.setup_fee_paid,
            "auto_renew": service.auto_renew,
            # Resource usage
            "disk_usage_mb": service.disk_usage_mb,
            "bandwidth_usage_mb": service.bandwidth_usage_mb,
            "email_accounts_used": service.email_accounts_used,
            "databases_used": service.databases_used,
            # Service lifecycle timestamps
            "created_at": service.created_at.isoformat(),
            "activated_at": service.activated_at.isoformat() if service.activated_at else None,
            "suspended_at": service.suspended_at.isoformat() if service.suspended_at else None,
            "expires_at": service.expires_at.isoformat() if service.expires_at else None,
            "updated_at": service.updated_at.isoformat(),
            # Business context
            "is_overdue": service.is_overdue,
            "days_until_expiry": service.days_until_expiry,
            "next_billing_date": service.get_next_billing_date().isoformat()
            if service.get_next_billing_date()
            else None,
            # Romanian compliance context
            "romanian_business_service": service.customer.customer_type == "company",
            "has_cui": bool(service.customer.get_tax_profile() and service.customer.get_tax_profile().cui),
            "suspension_reason": service.suspension_reason,
            "admin_notes": service.admin_notes[:200] if service.admin_notes else None,  # Truncate for audit
            # Provisioning context
            "last_provisioning_attempt": service.last_provisioning_attempt.isoformat()
            if service.last_provisioning_attempt
            else None,
            "has_provisioning_errors": bool(service.provisioning_errors),
            **context.metadata,
        }

        # Enhanced context with service metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(service_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=service,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Service {event_type.replace('_', ' ').title()}: {service.service_name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_service_relationship_event(
        event_type: str,
        relationship: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log service relationship audit event with dependency context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build relationship-specific metadata
        relationship_metadata = {
            "relationship_id": str(relationship.id),
            "parent_service_id": str(relationship.parent_service.id),
            "parent_service_name": relationship.parent_service.service_name,
            "child_service_id": str(relationship.child_service.id),
            "child_service_name": relationship.child_service.service_name,
            "relationship_type": relationship.relationship_type,
            "billing_impact": relationship.billing_impact,
            "is_required": relationship.is_required,
            "auto_provision": relationship.auto_provision,
            "cascade_suspend": relationship.cascade_suspend,
            "cascade_terminate": relationship.cascade_terminate,
            "discount_percentage": float(relationship.discount_percentage),
            "fixed_discount_cents": relationship.fixed_discount_cents,
            "is_active": relationship.is_active,
            "notes": relationship.notes[:200] if relationship.notes else None,  # Truncate for audit
            "created_at": relationship.created_at.isoformat(),
            "updated_at": relationship.updated_at.isoformat(),
            # Business context
            "affects_billing": relationship.billing_impact in ["discounted", "included", "prorated"],
            "creates_dependency": relationship.is_required,
            "enables_automation": relationship.auto_provision,
            **context.metadata,
        }

        # Enhanced context with relationship metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(relationship_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=relationship,
            description=description
            or f"Service relationship {event_type.replace('_', ' ').title()}: {relationship.parent_service.service_name} → {relationship.child_service.service_name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_service_group_event(  # noqa: PLR0913
        event_type: str,
        service_group: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log service group audit event with coordination and billing context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build service group-specific metadata
        group_metadata = {
            "service_group_id": str(service_group.id),
            "service_group_name": service_group.name,
            "description": service_group.description[:200] if service_group.description else None,  # Truncate for audit
            "group_type": service_group.group_type,
            "customer_id": str(service_group.customer.id),
            "customer_name": service_group.customer.get_display_name(),
            "status": service_group.status,
            "billing_cycle": service_group.billing_cycle,
            "auto_provision": service_group.auto_provision,
            "coordinated_billing": service_group.coordinated_billing,
            "total_services": service_group.total_services,
            "active_services": service_group.active_services,
            "notes": service_group.notes[:200] if service_group.notes else None,  # Truncate for audit
            "created_at": service_group.created_at.isoformat(),
            "updated_at": service_group.updated_at.isoformat(),
            # Business context
            "is_complex_package": service_group.group_type in ["package", "bundle"],
            "requires_coordination": service_group.coordinated_billing or service_group.auto_provision,
            "has_multiple_services": service_group.total_services > 1,
            **context.metadata,
        }

        # Enhanced context with service group metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(group_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=service_group,
            old_values=old_values,
            new_values=new_values,
            description=description or f"Service group {event_type.replace('_', ' ').title()}: {service_group.name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_provisioning_task_event(  # noqa: PLR0913
        event_type: str,
        task: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log provisioning task audit event with execution and performance context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build provisioning task-specific metadata
        task_metadata = {
            "task_id": str(task.id),
            "task_type": task.task_type,
            "status": task.status,
            "service_id": str(task.service.id),
            "service_name": task.service.service_name,
            "customer_id": str(task.service.customer.id),
            "customer_name": task.service.customer.get_display_name(),
            "retry_count": task.retry_count,
            "max_retries": task.max_retries,
            "can_retry": task.can_retry,
            "duration_seconds": task.duration_seconds,
            "parameters": task.parameters,
            "result": task.result,
            "error_message": task.error_message[:500] if task.error_message else None,  # Truncate for audit
            # Timestamps
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "next_retry_at": task.next_retry_at.isoformat() if task.next_retry_at else None,
            "updated_at": task.updated_at.isoformat(),
            # Performance context
            "is_long_running": task.duration_seconds > LONG_RUNNING_TASK_THRESHOLD_SECONDS,
            "is_failing": task.status == "failed",
            "needs_retry": task.can_retry,
            "is_critical": task.task_type in ["create_service", "terminate_service"],
            **context.metadata,
        }

        # Enhanced context with provisioning task metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(task_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=task,
            old_values=old_values,
            new_values=new_values,
            description=description
            or f"Provisioning task {event_type.replace('_', ' ').title()}: {task.get_task_type_display()}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_service_domain_event(
        event_type: str,
        service_domain: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log service domain binding audit event with DNS and SSL context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build service domain-specific metadata
        domain_metadata = {
            "service_domain_id": str(service_domain.id),
            "service_id": str(service_domain.service.id),
            "service_name": service_domain.service.service_name,
            "domain_id": str(service_domain.domain.id),
            "domain_name": service_domain.domain.name,
            "full_domain_name": service_domain.full_domain_name,
            "domain_type": service_domain.domain_type,
            "subdomain": service_domain.subdomain,
            "dns_management": service_domain.dns_management,
            "ssl_enabled": service_domain.ssl_enabled,
            "ssl_type": service_domain.ssl_type,
            "email_routing": service_domain.email_routing,
            "catch_all_email": service_domain.catch_all_email,
            "redirect_url": service_domain.redirect_url,
            "redirect_type": service_domain.redirect_type,
            "is_active": service_domain.is_active,
            "notes": service_domain.notes[:200] if service_domain.notes else None,  # Truncate for audit
            "created_at": service_domain.created_at.isoformat(),
            "updated_at": service_domain.updated_at.isoformat(),
            # Technical context
            "requires_dns_config": service_domain.dns_management,
            "requires_ssl_setup": service_domain.ssl_enabled,
            "has_email_routing": service_domain.email_routing,
            "is_redirect": service_domain.domain_type == "redirect",
            "is_romanian_domain": service_domain.domain.name.endswith(".ro"),
            **context.metadata,
        }

        # Enhanced context with service domain metadata
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(domain_metadata),
            actor_type=context.actor_type,
        )

        # Create audit event data
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=service_domain,
            description=description
            or f"Service domain {event_type.replace('_', ' ').title()}: {service_domain.full_domain_name}",
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


# Global service instances
billing_audit_service = BillingAuditService()
orders_audit_service = OrdersAuditService()
customers_audit_service = CustomersAuditService()
provisioning_audit_service = ProvisioningAuditService()

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
        cls, period_start: datetime, period_end: datetime, check_type: str = "hash_verification"
    ) -> Result[AuditIntegrityCheck, str]:
        """Verify audit data integrity for a given period."""

        try:
            # Get audit events in the period
            events = AuditEvent.objects.filter(timestamp__gte=period_start, timestamp__lt=period_end).order_by(
                "timestamp"
            )

            records_checked = events.count()
            issues_found = []

            # Convert QuerySet to list for methods that expect list[AuditEvent]
            events_list = list(events)

            if check_type == "hash_verification":
                issues_found = cls._verify_hash_chain(events_list)
            elif check_type == "sequence_check":
                issues_found = cls._check_sequence_gaps(events_list)
            elif check_type == "gdpr_compliance":
                issues_found = cls._check_gdpr_compliance(events_list)

            # Generate hash chain for this check
            hash_chain = cls._generate_hash_chain(events_list)

            # Determine status
            status = "healthy"
            if len(issues_found) > 0:
                critical_issues = [i for i in issues_found if i.get("severity") == "critical"]
                status = "compromised" if critical_issues else "warning"

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
                metadata={"check_timestamp": timezone.now().isoformat(), "checker": "AuditIntegrityService"},
            )

            # Create alerts for critical issues
            if status == "compromised":
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

        for event in events:
            # Check if event data has been modified
            expected_hash = cls._calculate_event_hash(event)
            stored_hash = event.metadata.get("integrity_hash")

            if stored_hash and stored_hash != expected_hash:
                issues.append(
                    {
                        "type": "hash_mismatch",
                        "severity": "critical",
                        "event_id": str(event.id),
                        "timestamp": event.timestamp.isoformat(),
                        "description": "Event hash mismatch - possible tampering detected",
                        "expected_hash": expected_hash,
                        "stored_hash": stored_hash,
                    }
                )

        return issues

    @classmethod
    def _check_sequence_gaps(cls, events: list[AuditEvent]) -> list[dict[str, Any]]:
        """Check for gaps in audit event sequence."""
        issues: list[dict[str, Any]] = []

        if not events:
            return issues

        # Check for time gaps that might indicate missing events
        for i in range(1, len(events)):
            prev_event = events[i - 1]
            current_event = events[i]

            time_gap = (current_event.timestamp - prev_event.timestamp).total_seconds()

            # Flag suspicious gaps (more than 1 hour with no events for active users)
            if (
                time_gap > ONE_HOUR_SECONDS
                and prev_event.user
                and current_event.user
                and cls._should_have_activity(prev_event, current_event)
            ):
                issues.append(
                    {
                        "type": "sequence_gap",
                        "severity": "warning",
                        "gap_start": prev_event.timestamp.isoformat(),
                        "gap_end": current_event.timestamp.isoformat(),
                        "gap_duration_seconds": int(time_gap),
                        "description": f"Suspicious gap in audit trail: {time_gap / 3600:.1f} hours",
                    }
                )

        return issues

    @classmethod
    def _check_gdpr_compliance(cls, events: list[AuditEvent]) -> list[dict[str, Any]]:
        """Check GDPR compliance of audit events."""
        issues = []

        for event in events:
            # Check required fields for GDPR events
            if event.category in ["privacy", "data_protection"]:
                required_fields = ["user", "ip_address", "description"]
                missing_fields = [field for field in required_fields if not getattr(event, field, None)]

                if missing_fields:
                    issues.append(
                        {
                            "type": "gdpr_compliance",
                            "severity": "high",
                            "event_id": str(event.id),
                            "missing_fields": missing_fields,
                            "description": f"GDPR event missing required fields: {missing_fields}",
                        }
                    )

        return issues

    @classmethod
    def _calculate_event_hash(cls, event: AuditEvent) -> str:
        """Calculate cryptographic hash for an audit event."""
        # Create a canonical representation of the event
        data = {
            "id": str(event.id),
            "timestamp": event.timestamp.isoformat(),
            "user_id": str(event.user.id) if event.user else None,
            "action": event.action,
            "content_type_id": event.content_type_id,
            "object_id": event.object_id,
            "description": event.description,
            "ip_address": event.ip_address,
        }

        # Sort and serialize for consistent hashing
        canonical_data = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_data.encode()).hexdigest()

    @classmethod
    def _generate_hash_chain(cls, events: list[AuditEvent]) -> str:
        """Generate a hash chain for a sequence of events."""
        if not events:
            return ""

        # Create chain of hashes
        chain_data = [cls._calculate_event_hash(event) for event in events]
        chain_hash = hashlib.sha256("".join(chain_data).encode()).hexdigest()

        return chain_hash

    @classmethod
    def _should_have_activity(cls, prev_event: AuditEvent, current_event: AuditEvent) -> bool:
        """Determine if there should have been activity between events."""
        # Simple heuristic: if both events are from the same user in a short session
        return bool(
            prev_event.user == current_event.user
            and prev_event.user
            and prev_event.session_key == current_event.session_key
            and prev_event.session_key
        )

    @classmethod
    def _create_integrity_alert(cls, integrity_check: AuditIntegrityCheck, issues: list[dict[str, Any]]) -> None:
        """Create alert for integrity issues."""
        try:
            critical_issues = [i for i in issues if i.get("severity") == "critical"]

            alert = AuditAlert.objects.create(
                alert_type="data_integrity",
                severity="critical" if critical_issues else "high",
                title="Audit Data Integrity Issues Detected",
                description=f"Integrity check found {len(issues)} issues in audit data from {integrity_check.period_start} to {integrity_check.period_end}",
                evidence={
                    "integrity_check_id": str(integrity_check.id),
                    "issues": issues,
                    "records_checked": integrity_check.records_checked,
                },
                metadata={"check_type": integrity_check.check_type, "auto_generated": True},
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
            results: dict[str, Any] = {
                "policies_applied": 0,
                "events_processed": 0,
                "events_archived": 0,
                "events_deleted": 0,
                "events_anonymized": 0,
                "errors": [],
            }

            for policy in policies:
                try:
                    result = cls._apply_single_policy(policy)
                    results["policies_applied"] += 1
                    results["events_processed"] += result.get("processed", 0)
                    results["events_archived"] += result.get("archived", 0)
                    results["events_deleted"] += result.get("deleted", 0)
                    results["events_anonymized"] += result.get("anonymized", 0)

                except Exception as e:
                    error_msg = f"Policy {policy.name} failed: {e}"
                    results["errors"].append(error_msg)
                    logger.error(f"🔥 [Retention] {error_msg}")

            # Log compliance event
            compliance_request = ComplianceEventRequest(
                compliance_type="data_retention",
                reference_id=f"retention_run_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
                description=f"Retention policies applied: {results['policies_applied']} policies, {results['events_processed']} events processed",
                status="success" if not results["errors"] else "partial",
                evidence=results,
            )
            AuditService.log_compliance_event(compliance_request)

            logger.info(
                f"✅ [Retention] Policies applied: {results['policies_applied']} policies, {results['events_processed']} events processed"
            )
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
        queryset = AuditEvent.objects.filter(timestamp__lt=cutoff_date, category=policy.category)

        # Add severity filter if specified
        if policy.severity:
            queryset = queryset.filter(severity=policy.severity)

        events_to_process = list(queryset)
        result = {"processed": len(events_to_process), "archived": 0, "deleted": 0, "anonymized": 0}

        if not events_to_process:
            return result

        # Apply retention action
        if policy.action == "archive":
            result["archived"] = cls._archive_events(events_to_process)
        elif policy.action == "delete":
            result["deleted"] = cls._delete_events(events_to_process, policy)
        elif policy.action == "anonymize":
            result["anonymized"] = cls._anonymize_events(events_to_process)

        return result

    @classmethod
    def _archive_events(cls, events: list[AuditEvent]) -> int:
        """Archive events to cold storage (placeholder - implement with actual storage)."""

        # For now, mark events as archived in metadata
        # In production, this would move data to cold storage (S3, etc.)
        archived_count = 0

        for event in events:
            event.metadata["archived"] = True
            event.metadata["archived_at"] = timezone.now().isoformat()
            event.save(update_fields=["metadata"])
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
            logger.warning(
                f"⚠️ [Retention] Blocked deletion of {len(financial_events)} financial records (Romanian compliance)"
            )
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
                event.ip_address = "0.0.0.0"

            # Anonymize user agent
            if event.user_agent:
                event.user_agent = "Anonymized"

            # Remove sensitive metadata
            if event.metadata:
                sensitive_keys = ["user_email", "phone", "real_name", "address"]
                for key in sensitive_keys:
                    if key in event.metadata:
                        event.metadata[key] = "Anonymized"

            event.metadata["anonymized"] = True
            event.metadata["anonymized_at"] = timezone.now().isoformat()
            event.save(update_fields=["ip_address", "user_agent", "metadata"])
            anonymized_count += 1

        return anonymized_count

    @classmethod
    def _is_financial_record(cls, event: AuditEvent) -> bool:
        """Check if event is a financial record requiring 7-year retention."""

        financial_actions = [
            "invoice_created",
            "invoice_paid",
            "payment_succeeded",
            "proforma_created",
            "credit_added",
            "vat_calculation_applied",
        ]

        return event.action in financial_actions or event.category == "business_operation"


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
        cls, filters: dict[str, Any], user: User
    ) -> tuple[models.QuerySet[Any, Any], dict[str, Any]]:
        """Build advanced audit query with multiple filters and performance optimization."""
        queryset = AuditEvent.objects.select_related("user", "content_type")
        query_info = {"filters_applied": [], "performance_hints": [], "estimated_cost": "low"}

        # Apply all filter groups
        queryset = cls._apply_basic_filters(queryset, filters, query_info)
        queryset = cls._apply_date_filters(queryset, filters, query_info)
        queryset = cls._apply_technical_filters(queryset, filters, query_info)
        queryset = cls._apply_content_filters(queryset, filters, query_info)
        queryset = cls._apply_advanced_filters(queryset, filters, query_info)

        # Add performance hints
        cls._add_performance_hints(query_info)

        return queryset.order_by("-timestamp"), query_info

    @classmethod
    def _apply_basic_filters(
        cls, queryset: models.QuerySet[Any, Any], filters: dict[str, Any], query_info: dict[str, Any]
    ) -> models.QuerySet[Any, Any]:
        """Apply basic entity filters (user, action, category, severity)."""
        filter_mappings = [
            ("user_ids", "user_id__in", "user_filter"),
            ("actions", "action__in", "action_filter"),
            ("categories", "category__in", "category_filter"),
            ("severities", "severity__in", "severity_filter"),
        ]

        for filter_key, django_filter, info_key in filter_mappings:
            if filters.get(filter_key):
                queryset = queryset.filter(**{django_filter: filters[filter_key]})
                query_info["filters_applied"].append(info_key)

        return queryset

    @classmethod
    def _apply_date_filters(
        cls, queryset: models.QuerySet[Any, Any], filters: dict[str, Any], query_info: dict[str, Any]
    ) -> models.QuerySet[Any, Any]:
        """Apply date range filters with timezone awareness."""
        if filters.get("start_date"):
            start_date = filters["start_date"]
            # Convert date to timezone-aware datetime at start of day
            if isinstance(start_date, date) and not isinstance(start_date, datetime):
                start_date = datetime.combine(start_date, datetime.min.time())
                start_date = timezone.make_aware(start_date) if timezone.is_naive(start_date) else start_date
            queryset = queryset.filter(timestamp__gte=start_date)
            query_info["filters_applied"].append("date_range_start")

        if filters.get("end_date"):
            end_date = filters["end_date"]
            # Convert date to timezone-aware datetime at end of day
            if isinstance(end_date, date) and not isinstance(end_date, datetime):
                end_date = datetime.combine(end_date, datetime.max.time())
                end_date = timezone.make_aware(end_date) if timezone.is_naive(end_date) else end_date
            queryset = queryset.filter(timestamp__lte=end_date)
            query_info["filters_applied"].append("date_range_end")

        return queryset

    @classmethod
    def _apply_technical_filters(
        cls, queryset: models.QuerySet[Any, Any], filters: dict[str, Any], query_info: dict[str, Any]
    ) -> models.QuerySet[Any, Any]:
        """Apply technical filters (IP, request ID, session)."""
        list_filters = [
            ("ip_addresses", "ip_address__in", "ip_filter"),
            ("request_ids", "request_id__in", "request_id_filter"),
            ("session_keys", "session_key__in", "session_filter"),
        ]

        for filter_key, django_filter, info_key in list_filters:
            if filters.get(filter_key):
                filter_value = filters[filter_key]
                filter_list = filter_value if isinstance(filter_value, list) else [filter_value]
                queryset = queryset.filter(**{django_filter: filter_list})
                query_info["filters_applied"].append(info_key)

        if filters.get("content_types"):
            queryset = queryset.filter(content_type_id__in=filters["content_types"])
            query_info["filters_applied"].append("content_type_filter")

        return queryset

    @classmethod
    def _apply_content_filters(
        cls, queryset: models.QuerySet[Any, Any], filters: dict[str, Any], query_info: dict[str, Any]
    ) -> models.QuerySet[Any, Any]:
        """Apply content-based filters (text search, sensitivity)."""
        if filters.get("search_text"):
            search_text = filters["search_text"]
            queryset = queryset.filter(
                Q(description__icontains=search_text)
                | Q(old_values__icontains=search_text)
                | Q(new_values__icontains=search_text)
                | Q(action__icontains=search_text)
            )
            query_info["filters_applied"].append("text_search")
            query_info["estimated_cost"] = "medium"

        boolean_filters = [
            ("is_sensitive", "sensitivity_filter"),
            ("requires_review", "review_filter"),
        ]

        for filter_key, info_key in boolean_filters:
            if filters.get(filter_key) is not None:
                queryset = queryset.filter(**{filter_key: filters[filter_key]})
                query_info["filters_applied"].append(info_key)

        return queryset

    @classmethod
    def _apply_advanced_filters(
        cls, queryset: models.QuerySet[Any, Any], filters: dict[str, Any], query_info: dict[str, Any]
    ) -> models.QuerySet[Any, Any]:
        """Apply advanced value existence filters."""
        value_filters = [
            ("has_old_values", "old_values", "old_values_filter"),
            ("has_new_values", "new_values", "new_values_filter"),
        ]

        for filter_key, field_name, info_key in value_filters:
            if filters.get(filter_key) is not None:
                if filters[filter_key]:
                    queryset = queryset.exclude(**{field_name: {}})
                else:
                    queryset = queryset.filter(**{field_name: {}})
                query_info["filters_applied"].append(info_key)

        return queryset

    @classmethod
    def _add_performance_hints(cls, query_info: dict[str, Any]) -> None:
        """Add performance optimization hints to query info."""
        if len(query_info["filters_applied"]) > HIGH_COMPLEXITY_FILTER_THRESHOLD:
            query_info["estimated_cost"] = "high"
            query_info["performance_hints"].append("Consider using saved queries for complex searches")

        if "text_search" in query_info["filters_applied"] and len(query_info["filters_applied"]) == 1:
            query_info["performance_hints"].append("Add date range or user filters to improve search performance")

    @classmethod
    @transaction.atomic
    def save_search_query(
        cls, name: str, query_params: dict[str, Any], user: User, description: str = "", is_shared: bool = False
    ) -> Result[AuditSearchQuery, str]:
        """Save a search query for reuse."""

        try:
            # Check for duplicate names for this user
            existing = AuditSearchQuery.objects.filter(name=name, created_by=user).exists()

            if existing:
                return Err(f"Search query '{name}' already exists")

            search_query = AuditSearchQuery.objects.create(
                name=name, description=description, query_params=query_params, created_by=user, is_shared=is_shared
            )

            logger.info(f"✅ [Audit Search] Query saved: {name} by {user.email}")
            return Ok(search_query)

        except Exception as e:
            logger.error(f"🔥 [Audit Search] Failed to save query: {e}")
            return Err(f"Failed to save search query: {e!s}")

    @classmethod
    def get_search_suggestions(cls, query: str, user: User, limit: int = 10) -> dict[str, list[str]]:
        """Get search suggestions for auto-completion."""

        suggestions: dict[str, list[str]] = {"actions": [], "users": [], "ip_addresses": [], "descriptions": []}

        if not query or len(query) < MIN_SEARCH_QUERY_LENGTH:
            return suggestions

        try:
            # Action suggestions
            action_choices = [choice[0] for choice in AuditEvent.ACTION_CHOICES if query.lower() in choice[0].lower()]
            suggestions["actions"] = action_choices[:limit]

            # User suggestions (staff only for privacy)
            if user.is_staff:
                users = User.objects.filter(
                    Q(email__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query)
                ).values_list("email", flat=True)[:limit]
                suggestions["users"] = list(users)

            # IP address suggestions (recent ones)
            if cls._is_ip_like(query):
                recent_ips = (
                    AuditEvent.objects.filter(
                        ip_address__icontains=query, timestamp__gte=timezone.now() - timedelta(days=30)
                    )
                    .values_list("ip_address", flat=True)
                    .distinct()[:limit]
                )
                suggestions["ip_addresses"] = [ip for ip in recent_ips if ip]

        except Exception as e:
            logger.warning(f"⚠️ [Audit Search] Suggestion generation failed: {e}")

        return suggestions

    @classmethod
    def _is_ip_like(cls, query: str) -> bool:
        """Check if query looks like an IP address."""
        ip_pattern = r"^\d{1,3}(\.\d{0,3}){0,3}$"
        return bool(re.match(ip_pattern, query))


# ===============================================================================
# TICKETS AUDIT SERVICE - SLA TRACKING
# ===============================================================================


class TicketsAuditService:
    """
    🎫 Streamlined tickets audit service for SLA tracking

    Features:
    - Ticket lifecycle event tracking (open/close only)
    - SLA compliance monitoring
    - Romanian customer service standards
    - Customer satisfaction metrics
    """

    @staticmethod
    def log_ticket_opened(  # noqa: PLR0913
        ticket: Any,
        sla_metadata: dict[str, Any],
        should_escalate: bool = False,
        romanian_business_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log ticket creation event with SLA setup and Romanian business context

        Args:
            ticket: The created Ticket instance
            sla_metadata: SLA configuration and deadlines
            should_escalate: Whether ticket should be auto-escalated
            romanian_business_context: Romanian-specific customer data
            user: User who created the ticket (if available)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build comprehensive ticket metadata
        ticket_metadata = {
            "ticket_number": ticket.ticket_number,
            "title": ticket.title,
            "customer_id": str(ticket.customer.id),
            "customer_name": ticket.customer.get_display_name(),
            "priority": ticket.priority,
            "category": ticket.category.name if ticket.category else None,
            "source": ticket.source,
            "contact_email": ticket.contact_email,
            "contact_person": ticket.contact_person,
            "assigned_to": ticket.assigned_to.get_full_name() if ticket.assigned_to else None,
            "related_service_id": str(ticket.related_service.id) if ticket.related_service else None,
            "sla_tracking": sla_metadata,
            "auto_escalation_eligible": should_escalate,
            "romanian_context": romanian_business_context or {},
            "created_at": ticket.created_at.isoformat(),
            "status": ticket.status,
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(ticket_metadata),
            actor_type=context.actor_type or "support_system",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="support_ticket_created",
            content_object=ticket,
            description=f"Ticket {ticket.ticket_number} opened: {ticket.title[:100]}...",
            old_values={},
            new_values={
                "ticket_number": ticket.ticket_number,
                "title": ticket.title,
                "status": ticket.status,
                "priority": ticket.priority,
                "customer": ticket.customer.get_display_name(),
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_ticket_closed(  # noqa: PLR0913
        ticket: Any,
        old_status: str,
        new_status: str,
        sla_performance: dict[str, Any],
        service_metrics: dict[str, Any],
        romanian_compliance: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log ticket closure event with comprehensive SLA performance analysis

        Args:
            ticket: The closed Ticket instance
            old_status: Previous ticket status
            new_status: New ticket status (resolved/closed)
            sla_performance: SLA compliance metrics
            service_metrics: Customer service quality metrics
            romanian_compliance: Romanian business compliance status
            user: User who closed the ticket (if available)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Calculate resolution duration
        resolution_duration = None
        if ticket.resolved_at:
            duration = ticket.resolved_at - ticket.created_at
            resolution_duration = {
                "total_seconds": int(duration.total_seconds()),
                "hours": duration.total_seconds() / 3600,
                "business_days": duration.days,
                "human_readable": str(duration),
            }

        # Build comprehensive closure metadata
        closure_metadata = {
            "ticket_number": ticket.ticket_number,
            "customer_id": str(ticket.customer.id),
            "customer_name": ticket.customer.get_display_name(),
            "status_transition": f"{old_status} -> {new_status}",
            "resolution_duration": resolution_duration,
            "sla_performance": sla_performance,
            "service_quality": service_metrics,
            "satisfaction_data": {
                "rating": ticket.satisfaction_rating,
                "comment": bool(ticket.satisfaction_comment),
                "feedback_provided": ticket.satisfaction_rating is not None,
            },
            "closure_context": {
                "was_escalated": ticket.is_escalated,
                "final_agent": ticket.assigned_to.get_full_name() if ticket.assigned_to else None,
                "required_customer_input": ticket.requires_customer_response,
                "closure_method": "manual" if user else "automatic",
            },
            "compliance": romanian_compliance or {},
            "closed_at": timezone.now().isoformat(),
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(closure_metadata),
            actor_type=context.actor_type or "support_agent",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="support_ticket_closed",
            content_object=ticket,
            description=f"Ticket {ticket.ticket_number} closed: {old_status} -> {new_status} (SLA: {sla_performance['sla_grade']})",
            old_values={"status": old_status},
            new_values={
                "status": new_status,
                "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
                "sla_compliant": sla_performance["overall_compliance"],
                "resolution_grade": sla_performance["sla_grade"],
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


# ===============================================================================
# PRODUCTS AUDIT SERVICE - CATALOG MANAGEMENT
# ===============================================================================


class ProductsAuditService:
    """
    🛒 Streamlined products audit service for catalog management

    Features:
    - Product creation and lifecycle tracking
    - Pricing changes for grandfathered customer protection
    - Availability changes affecting customer access
    - Romanian VAT compliance and hosting service categories
    """

    @staticmethod
    def log_product_created(
        product: Any,
        romanian_business_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log product creation event with Romanian hosting context

        Args:
            product: The created Product instance
            romanian_business_context: Romanian VAT and hosting compliance
            user: User who created the product (admin/staff)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build product creation metadata
        product_metadata = {
            "product_id": str(product.id),
            "product_slug": product.slug,
            "product_name": product.name,
            "product_type": product.product_type,
            "module": product.module,
            "is_active": product.is_active,
            "is_public": product.is_public,
            "is_featured": product.is_featured,
            "includes_vat": product.includes_vat,
            "requires_domain": product.requires_domain,
            "sort_order": product.sort_order,
            "tags": product.tags,
            "created_at": product.created_at.isoformat(),
            "romanian_context": romanian_business_context or {},
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(product_metadata),
            actor_type=context.actor_type or "admin",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="product_created",
            content_object=product,
            description=f"Product created: {product.name} ({product.get_product_type_display()})",
            old_values={},
            new_values={
                "name": product.name,
                "product_type": product.product_type,
                "is_active": product.is_active,
                "includes_vat": product.includes_vat,
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_product_availability_changed(
        product: Any,
        changes: dict[str, Any],
        romanian_business_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log product availability changes affecting customer access

        Args:
            product: The modified Product instance
            changes: Dictionary of availability changes
            romanian_business_context: VAT compliance and impact assessment
            user: User who made the changes
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build availability change metadata
        availability_metadata = {
            "product_id": str(product.id),
            "product_name": product.name,
            "product_type": product.product_type,
            "changes": changes,
            "current_status": {
                "is_active": product.is_active,
                "is_public": product.is_public,
                "is_featured": product.is_featured,
                "includes_vat": product.includes_vat,
            },
            "customer_impact": changes.get("customer_impact_level", "low"),
            "romanian_context": romanian_business_context or {},
            "changed_at": timezone.now().isoformat(),
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(availability_metadata),
            actor_type=context.actor_type or "admin",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="product_availability_changed",
            content_object=product,
            description=f"Product availability changed: {product.name} - {', '.join(changes.keys())}",
            old_values={
                key: change.get("from")
                for key, change in changes.items()
                if isinstance(change, dict) and "from" in change
            },
            new_values={
                key: change.get("to") for key, change in changes.items() if isinstance(change, dict) and "to" in change
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_product_pricing_changed(  # noqa: PLR0913
        product_price: Any,
        change_type: str,
        changes: dict[str, Any],
        romanian_business_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log product pricing changes for grandfathered customer protection

        Args:
            product_price: The modified ProductPrice instance
            change_type: Type of pricing change ('price_created', 'price_updated')
            changes: Dictionary of pricing changes
            romanian_business_context: VAT compliance and billing context
            user: User who made the changes
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build pricing change metadata
        pricing_metadata = {
            "product_price_id": str(product_price.id),
            "product_id": str(product_price.product.id),
            "product_name": product_price.product.name,
            "product_type": product_price.product.product_type,
            "currency": product_price.currency.code,
            "billing_period": product_price.billing_period,
            "change_type": change_type,
            "changes": changes,
            "current_pricing": {
                "amount_cents": product_price.amount_cents,
                "amount": float(product_price.amount),
                "setup_cents": product_price.setup_cents,
                "setup_fee": float(product_price.setup_fee),
                "is_active": product_price.is_active,
                "promo_price_cents": product_price.promo_price_cents,
                "discount_percent": float(product_price.discount_percent),
            },
            "business_impact": {
                "significant_change": changes.get("price_changed", {}).get("significant", False),
                "price_increased": changes.get("price_changed", {}).get("price_increased", False),
                "grandfathered_protection": changes.get("price_changed", {}).get("price_increased", False),
            },
            "romanian_context": romanian_business_context or {},
            "changed_at": timezone.now().isoformat(),
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(pricing_metadata),
            actor_type=context.actor_type or "admin",
        )

        # Determine description based on change type
        if change_type == "price_created":
            description = f"New pricing created: {product_price.product.name} - {product_price.currency.code} {product_price.amount} ({product_price.billing_period})"
        else:
            price_change = changes.get("price_changed")
            if price_change:
                old_amount = price_change.get("from_amount", 0)
                new_amount = price_change.get("to_amount", 0)
                description = f"Pricing updated: {product_price.product.name} - {product_price.currency.code} {old_amount} → {new_amount} ({price_change.get('percent_change', 0):.1f}%)"
            else:
                description = f"Pricing updated: {product_price.product.name} - {', '.join(changes.keys())}"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="product_pricing_changed",
            content_object=product_price,
            description=description,
            old_values={
                key: change.get("from_cents") or change.get("from_amount") or change.get("from_percent")
                for key, change in changes.items()
                if isinstance(change, dict) and any(k.startswith("from_") for k in change)
            },
            new_values={
                key: change.get("to_cents") or change.get("to_amount") or change.get("to_percent")
                for key, change in changes.items()
                if isinstance(change, dict) and any(k.startswith("to_") for k in change)
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


# ===============================================================================
# INTEGRATIONS AUDIT SERVICE - WEBHOOK RELIABILITY MONITORING
# ===============================================================================


class DomainsAuditService:
    """
    🌐 Comprehensive domain management audit service

    Features:
    - Domain lifecycle tracking (registration, renewal, transfer, expiration)
    - TLD configuration and pricing change monitoring
    - Registrar management and API credential security
    - Domain security events (EPP codes, lock status, WHOIS privacy)
    - Romanian .ro domain compliance tracking
    - Cross-registrar operation logging
    """

    @staticmethod
    def log_domain_event(  # noqa: PLR0913  # Domain audit requires multiple domain-specific parameters
        event_type: str,
        domain: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
        security_context: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Log domain lifecycle and management events

        Args:
            event_type: Type of domain event (domain_registered, domain_renewed, etc.)
            domain: The Domain instance
            user: User performing the action (if applicable)
            context: Additional audit context
            old_values: Previous values for change tracking
            new_values: New values after change
            description: Human-readable event description
            security_context: Security-related metadata
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build domain event metadata
        domain_metadata = {
            "domain_id": str(domain.id),
            "domain_name": domain.name,
            "domain_status": domain.status,
            "registrar": domain.registrar.name if domain.registrar else None,
            "tld_extension": domain.tld.extension if domain.tld else None,
            "registration_date": domain.registered_at.isoformat() if domain.registered_at else None,
            "expiration_date": domain.expires_at.isoformat() if domain.expires_at else None,
            "auto_renew": domain.auto_renew_enabled,
            "whois_privacy": domain.whois_privacy_enabled,
            "domain_lock_status": domain.is_locked,
            "customer_id": str(domain.customer.id) if domain.customer else None,
            "nameservers": [ns.hostname for ns in domain.nameservers.all()] if hasattr(domain, "nameservers") else [],
            "old_values": old_values or {},
            "new_values": new_values or {},
            "security_context": security_context or {},
            **context.metadata,
        }

        # Enhanced context with domain-specific information
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(domain_metadata),
            actor_type=context.actor_type or ("user" if user else "system"),
        )

        # Generate description if not provided
        if not description:
            description = f"Domain {event_type.replace('_', ' ')}: {domain.name}"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=domain,
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_tld_event(  # noqa: PLR0913  # TLD audit requires multiple configuration parameters
        event_type: str,
        tld: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log TLD configuration and pricing changes

        Args:
            event_type: Type of TLD event (tld_created, tld_pricing_updated, etc.)
            tld: The TLD instance
            user: User performing the action
            context: Additional audit context
            old_values: Previous configuration values
            new_values: New configuration values
            description: Human-readable event description
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build TLD event metadata
        tld_metadata = {
            "tld_id": str(tld.id),
            "extension": tld.extension,
            "description": tld.description,
            "pricing": {
                "registration_cents": tld.registration_price_cents,
                "renewal_cents": tld.renewal_price_cents,
                "transfer_cents": tld.transfer_price_cents,
            },
            "is_active": tld.is_active,
            "old_values": old_values or {},
            "new_values": new_values or {},
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(tld_metadata),
            actor_type=context.actor_type or "user",
        )

        # Generate description if not provided
        if not description:
            description = f"TLD {event_type.replace('_', ' ')}: .{tld.extension}"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=tld,
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_registrar_event(  # noqa: PLR0913  # Registrar audit requires multiple security parameters
        event_type: str,
        registrar: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
        security_sensitive: bool = False,
    ) -> AuditEvent:
        """
        Log registrar configuration and security events

        Args:
            event_type: Type of registrar event (registrar_created, api_credentials_updated, etc.)
            registrar: The Registrar instance
            user: User performing the action
            context: Additional audit context
            old_values: Previous configuration values
            new_values: New configuration values
            description: Human-readable event description
            security_sensitive: Whether this event involves sensitive security data
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build registrar event metadata (sanitize sensitive data)
        registrar_metadata = {
            "registrar_id": str(registrar.id),
            "registrar_name": registrar.name,
            "api_url": registrar.api_url if not security_sensitive else "[REDACTED]",
            "is_active": registrar.is_active,
            "supported_tlds": [tld.extension for tld in registrar.supported_tlds.all()]
            if hasattr(registrar, "supported_tlds")
            else [],
            "security_event": security_sensitive,
            "old_values": old_values or {},
            "new_values": new_values or {},
            **context.metadata,
        }

        # Enhanced context with security classification
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(registrar_metadata),
            actor_type=context.actor_type or "user",
        )

        # Generate description if not provided
        if not description:
            action_desc = event_type.replace("_", " ")
            if security_sensitive:
                action_desc += " [SECURITY]"
            description = f"Registrar {action_desc}: {registrar.name}"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=registrar,
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_domain_order_event(  # noqa: PLR0913  # Order audit requires multiple order-specific parameters
        event_type: str,
        domain_order_item: Any,
        user: User | None = None,
        context: AuditContext | None = None,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log domain order processing events

        Args:
            event_type: Type of order event (domain_order_created, domain_order_processed, etc.)
            domain_order_item: The DomainOrderItem instance
            user: User performing the action
            context: Additional audit context
            old_values: Previous order values
            new_values: New order values
            description: Human-readable event description
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build domain order event metadata
        order_metadata = {
            "order_item_id": str(domain_order_item.id),
            "order_id": str(domain_order_item.order.id) if domain_order_item.order else None,
            "domain_name": domain_order_item.domain_name,
            "operation_type": domain_order_item.operation_type,
            "registrar": domain_order_item.registrar.name if domain_order_item.registrar else None,
            "tld_extension": domain_order_item.tld.extension if domain_order_item.tld else None,
            "price_cents": domain_order_item.price_cents,
            "customer_id": str(domain_order_item.order.customer.id)
            if domain_order_item.order and domain_order_item.order.customer
            else None,
            "old_values": old_values or {},
            "new_values": new_values or {},
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(order_metadata),
            actor_type=context.actor_type or ("user" if user else "system"),
        )

        # Generate description if not provided
        if not description:
            description = f"Domain order {event_type.replace('_', ' ')}: {domain_order_item.domain_name} ({domain_order_item.operation_type})"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=domain_order_item,
            description=description,
            old_values=old_values or {},
            new_values=new_values or {},
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_domain_security_event(  # noqa: PLR0913  # Security audit requires multiple security parameters
        event_type: str,
        domain: Any,
        security_action: str,
        user: User | None = None,
        context: AuditContext | None = None,
        security_metadata: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> AuditEvent:
        """
        Log domain security-related events

        Args:
            event_type: Type of security event (epp_code_generated, domain_lock_changed, etc.)
            domain: The Domain instance
            security_action: Specific security action taken
            user: User performing the action
            context: Additional audit context
            security_metadata: Security-specific metadata
            description: Human-readable event description
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build security event metadata
        security_event_metadata = {
            "domain_id": str(domain.id),
            "domain_name": domain.name,
            "security_action": security_action,
            "registrar": domain.registrar.name if domain.registrar else None,
            "customer_id": str(domain.customer.id) if domain.customer else None,
            "security_metadata": security_metadata or {},
            "timestamp": timezone.now().isoformat(),
            **context.metadata,
        }

        # Log to security system
        log_security_event(f"domain_{security_action}", security_event_metadata)

        # Enhanced context for audit system
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(security_event_metadata),
            actor_type=context.actor_type or "user",
        )

        # Generate description if not provided
        if not description:
            description = f"Domain security: {security_action} for {domain.name}"

        # Create audit event
        audit_event_data = AuditEventData(
            event_type=event_type,
            content_object=domain,
            description=description,
            old_values={},
            new_values={"security_action": security_action},
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


class SecurityAuditService:
    """
    🛡️ Security audit service for tracking security-related events

    Features:
    - Rate limiting violations
    - Authentication attacks
    - Suspicious activity patterns
    - IP-based threat monitoring
    """

    @staticmethod
    def log_rate_limit_event(
        event_data: RateLimitEventData, user: User | None = None, context: AuditContext | None = None
    ) -> AuditEvent:
        """
        Log rate limiting violations for security monitoring

        Args:
            event_data: Rate limit event data including endpoint, IP, user agent, etc.
            user: User if authenticated
            context: Additional audit context
        """
        if context is None:
            context = AuditContext(user=user)

        # Build rate limit metadata
        metadata = {
            "endpoint": event_data["endpoint"],
            "ip_address": event_data["ip_address"],
            "user_agent": event_data["user_agent"],
            "rate_limit_config": {
                "key": event_data["rate_limit_key"],
                "rate": event_data["rate_limit_rate"],
            },
            "security_classification": "rate_limit_violation",
            "risk_level": "medium",
            "timestamp": timezone.now().isoformat(),
        }

        # Add user information if authenticated
        if user:
            metadata["user_info"] = {
                "user_id": user.id,
                "email": user.email,
                "is_staff": user.is_staff,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            }

        # Log security event
        log_security_event(event_type="rate_limit_violation", details=metadata, request_ip=event_data["ip_address"])

        return AuditEvent.objects.create(
            category="security_event",
            action="rate_limit_exceeded",
            user=user,
            ip_address=event_data["ip_address"],
            user_agent=event_data["user_agent"],
            metadata=metadata,
            severity="medium",
            description=f"Rate limit exceeded for endpoint: {event_data['endpoint']}",
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(user.id) if user else "anonymous",
        )


class IntegrationsAuditService:
    """
    🔌 Streamlined integrations audit service for webhook reliability monitoring

    Features:
    - Webhook delivery success/failure tracking
    - Third-party service health monitoring
    - Reliability metrics for SLA monitoring
    - Security logging for webhook attacks
    """

    @staticmethod
    def log_webhook_success(  # noqa: PLR0913  # Webhook audit requires multiple related parameters
        webhook_event: Any,
        response_time_ms: int,
        response_status: int = 200,
        reliability_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log successful webhook delivery for reliability monitoring

        Args:
            webhook_event: The successful WebhookEvent instance
            response_time_ms: Response time in milliseconds
            response_status: HTTP status code from processing
            reliability_context: Service health and reliability metrics
            user: System user (if applicable)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Build webhook success metadata
        success_metadata = {
            "webhook_id": str(webhook_event.id),
            "source": webhook_event.source,
            "event_type": webhook_event.event_type,
            "event_id": webhook_event.event_id,
            "performance_metrics": {
                "response_time_ms": response_time_ms,
                "response_status": response_status,
                "processing_duration": webhook_event.processing_duration.total_seconds()
                if webhook_event.processing_duration
                else None,
                "retry_count": webhook_event.retry_count,
            },
            "service_health": {
                "source_service": webhook_event.source,
                "delivery_successful": True,
                "endpoint_healthy": response_status < WEBHOOK_HEALTHY_RESPONSE_THRESHOLD,
                "reliability_score": "high"
                if response_time_ms < WEBHOOK_FAST_RESPONSE_THRESHOLD_MS
                else "medium"
                if response_time_ms < WEBHOOK_MEDIUM_RESPONSE_THRESHOLD_MS
                else "low",
            },
            "security_context": {
                "ip_address": webhook_event.ip_address,
                "user_agent": webhook_event.user_agent,
                "signature_verified": bool(webhook_event.signature),
                "payload_size_bytes": len(str(webhook_event.payload)) if webhook_event.payload else 0,
            },
            "reliability_tracking": reliability_context or {},
            "processed_at": webhook_event.processed_at.isoformat() if webhook_event.processed_at else None,
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address or webhook_event.ip_address,
            user_agent=context.user_agent or webhook_event.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(success_metadata),
            actor_type=context.actor_type or "webhook_processor",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="webhook_delivery_success",
            content_object=webhook_event,
            description=f"Webhook delivered successfully: {webhook_event.source}.{webhook_event.event_type} ({response_time_ms}ms)",
            old_values={"status": "pending"},
            new_values={
                "status": "processed",
                "response_time_ms": response_time_ms,
                "response_status": response_status,
                "retry_count": webhook_event.retry_count,
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_webhook_failure(  # noqa: PLR0913  # Webhook failure audit requires multiple error context parameters
        webhook_event: Any,
        error_details: dict[str, Any],
        security_flags: dict[str, bool] | None = None,
        reliability_context: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log webhook delivery failure for reliability monitoring and security analysis

        Args:
            webhook_event: The failed WebhookEvent instance
            error_details: Failure details and error analysis
            security_flags: Security indicators for suspicious activity
            reliability_context: Service health degradation metrics
            user: System user (if applicable)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Analyze failure severity
        failure_severity = "medium"
        if webhook_event.retry_count >= WEBHOOK_MAX_RETRY_THRESHOLD:  # Max retries exhausted
            failure_severity = "high"
        elif security_flags and any(security_flags.values()):
            failure_severity = "critical"  # Security concern
        elif error_details.get("error_type") == "timeout":
            failure_severity = "low"  # Temporary issue

        # Build webhook failure metadata
        failure_metadata = {
            "webhook_id": str(webhook_event.id),
            "source": webhook_event.source,
            "event_type": webhook_event.event_type,
            "event_id": webhook_event.event_id,
            "failure_analysis": {
                "error_message": webhook_event.error_message,
                "error_type": error_details.get("error_type", "unknown"),
                "error_category": error_details.get("category", "processing_error"),
                "failure_severity": failure_severity,
                "retry_count": webhook_event.retry_count,
                "retry_exhausted": webhook_event.retry_count >= WEBHOOK_MAX_RETRY_THRESHOLD,
                "next_retry_at": webhook_event.next_retry_at.isoformat() if webhook_event.next_retry_at else None,
            },
            "service_degradation": {
                "source_service": webhook_event.source,
                "service_health_impact": error_details.get("service_impact", "low"),
                "endpoint_availability": error_details.get("endpoint_status", "unknown"),
                "failure_pattern": error_details.get("pattern", "isolated"),
            },
            "security_indicators": security_flags
            or {
                "suspicious_ip": False,
                "malformed_payload": False,
                "invalid_signature": False,
                "rate_limit_exceeded": False,
                "repeated_failures": webhook_event.retry_count > WEBHOOK_SUSPICIOUS_RETRY_THRESHOLD,
            },
            "reliability_tracking": reliability_context or {},
            "failed_at": timezone.now().isoformat(),
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address or webhook_event.ip_address,
            user_agent=context.user_agent or webhook_event.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(failure_metadata),
            actor_type=context.actor_type or "webhook_processor",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="webhook_delivery_failure",
            content_object=webhook_event,
            description=f"Webhook delivery failed: {webhook_event.source}.{webhook_event.event_type} - {error_details.get('error_type', 'unknown error')} (attempt {webhook_event.retry_count})",
            old_values={"status": "pending"},
            new_values={
                "status": "failed",
                "error_message": webhook_event.error_message,
                "retry_count": webhook_event.retry_count,
                "failure_severity": failure_severity,
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)

    @staticmethod
    def log_webhook_retry_exhausted(  # noqa: PLR0913  # Webhook retry exhaustion tracking needs comprehensive failure context
        webhook_event: Any,
        total_attempts: int,
        final_error: str,
        reliability_impact: dict[str, Any] | None = None,
        user: User | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        """
        Log webhook retry exhaustion for reliability monitoring and alerting

        Args:
            webhook_event: The failed WebhookEvent instance
            total_attempts: Total number of delivery attempts
            final_error: Final error message after all retries
            reliability_impact: Service reliability degradation assessment
            user: System user (if applicable)
            context: Additional audit context
        """
        # Use default context if none provided
        if context is None:
            context = AuditContext(user=user)

        # Calculate retry timeline
        retry_timeline = None
        if webhook_event.received_at and webhook_event.processed_at:
            total_duration = webhook_event.processed_at - webhook_event.received_at
            retry_timeline = {
                "first_attempt": webhook_event.received_at.isoformat(),
                "final_attempt": webhook_event.processed_at.isoformat(),
                "total_duration_hours": total_duration.total_seconds() / 3600,
                "retry_backoff_successful": False,
            }

        # Build retry exhaustion metadata
        exhaustion_metadata = {
            "webhook_id": str(webhook_event.id),
            "source": webhook_event.source,
            "event_type": webhook_event.event_type,
            "event_id": webhook_event.event_id,
            "retry_analysis": {
                "total_attempts": total_attempts,
                "final_error": final_error,
                "retry_pattern": "exponential_backoff",
                "max_retries_reached": True,
                "timeline": retry_timeline,
            },
            "service_reliability": {
                "source_service": webhook_event.source,
                "persistent_failure": True,
                "requires_investigation": True,
                "sla_impact": reliability_impact.get("sla_breach", False) if reliability_impact else False,
                "customer_impact": reliability_impact.get("customer_impact_level", "medium")
                if reliability_impact
                else "medium",
            },
            "alerting_context": {
                "alert_required": True,
                "escalation_needed": total_attempts >= WEBHOOK_MAX_RETRY_THRESHOLD,
                "ops_team_notification": True,
                "customer_notification_needed": reliability_impact.get("customer_visible", False)
                if reliability_impact
                else False,
            },
            "reliability_tracking": reliability_impact or {},
            "exhausted_at": timezone.now().isoformat(),
            **context.metadata,
        }

        # Enhanced context
        enhanced_context = AuditContext(
            user=context.user,
            ip_address=context.ip_address or webhook_event.ip_address,
            user_agent=context.user_agent or webhook_event.user_agent,
            request_id=context.request_id,
            session_key=context.session_key,
            metadata=serialize_metadata(exhaustion_metadata),
            actor_type=context.actor_type or "webhook_processor",
        )

        # Create audit event
        audit_event_data = AuditEventData(
            event_type="webhook_retry_exhausted",
            content_object=webhook_event,
            description=f"Webhook retry exhausted: {webhook_event.source}.{webhook_event.event_type} after {total_attempts} attempts - {final_error}",
            old_values={"status": "failed", "retry_count": total_attempts - 1},
            new_values={
                "status": "failed",
                "retry_count": total_attempts,
                "retry_exhausted": True,
                "requires_manual_intervention": True,
            },
        )

        return AuditService.log_event(audit_event_data, enhanced_context)


# Global service instances
audit_integrity_service = AuditIntegrityService()
audit_retention_service = AuditRetentionService()
audit_search_service = AuditSearchService()

# Global GDPR service instances
gdpr_export_service = GDPRExportService()
gdpr_deletion_service = GDPRDeletionService()
gdpr_consent_service = GDPRConsentService()
