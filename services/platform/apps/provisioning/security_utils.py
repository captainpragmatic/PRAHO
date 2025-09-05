"""
Security utilities for VirtualMin provisioning system.

Provides secure parameter handling, input validation, and encryption utilities
for production-grade VirtualMin operations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.common.encryption import decrypt_sensitive_data, encrypt_sensitive_data

logger = logging.getLogger(__name__)

# Security constants
IDEMPOTENCY_KEY_TTL = 3600  # 1 hour in seconds

# Domain validation constants
MAX_DOMAIN_LENGTH = 253  # RFC 1035
MIN_DOMAIN_LENGTH = 4  # Minimum for a.bc
MAX_USERNAME_LENGTH = 32
MIN_USERNAME_LENGTH = 2
MAX_TEMPLATE_NAME_LENGTH = 50
LOG_TRUNCATION_LENGTH = 100
UUID_VERSION_4 = 4

DOMAIN_VALIDATION_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
USERNAME_VALIDATION_PATTERN = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')


class ProvisioningErrorType(Enum):
    """Classification of provisioning errors for proper handling."""
    
    RETRYABLE_NETWORK = "retryable_network"
    RETRYABLE_SERVICE = "retryable_service"
    PERMANENT_VALIDATION = "permanent_validation"
    PERMANENT_AUTHORIZATION = "permanent_authorization"
    PERMANENT_RESOURCE = "permanent_resource"
    CRITICAL_SYSTEM = "critical_system"


@dataclass(frozen=True)
class SecureTaskParameters:
    """Encrypted task parameters container for sensitive data."""
    
    encrypted_payload: str
    parameter_hash: str
    created_at: str
    
    @classmethod
    def create(cls, parameters: dict[str, Any]) -> SecureTaskParameters:
        """Create secure task parameters with encryption."""
        # Create JSON payload
        payload = json.dumps(parameters, sort_keys=True, default=str)
        
        # Encrypt the payload
        encrypted_data = encrypt_sensitive_data(payload)
        encrypted_b64 = encrypted_data  # encrypt_sensitive_data already returns base64 string
        
        # Create hash for integrity verification
        parameter_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        
        return cls(
            encrypted_payload=encrypted_b64,
            parameter_hash=parameter_hash,
            created_at=timezone.now().isoformat()
        )
    
    def decrypt(self) -> dict[str, Any]:
        """Decrypt parameters and verify integrity."""
        try:
            # Decrypt (decrypt_sensitive_data expects base64 string)
            decrypted_payload = decrypt_sensitive_data(self.encrypted_payload)
            
            # Verify hash integrity
            computed_hash = hashlib.sha256(decrypted_payload.encode('utf-8')).hexdigest()
            if not secrets.compare_digest(computed_hash, self.parameter_hash):
                raise ValidationError("Parameter integrity check failed")
            
            result = json.loads(decrypted_payload)
            if not isinstance(result, dict):
                raise ValidationError("Invalid parameter format")
            return result
            
        except Exception as e:
            logger.error(f"🔥 [Security] Failed to decrypt task parameters: {e}")
            raise ValidationError(f"Parameter decryption failed: {e}") from e


class ProvisioningParametersValidator:
    """Validator for provisioning parameters with strict security checks."""
    
    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate domain name with strict security checks.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Sanitized domain name
            
        Raises:
            ValidationError: If domain is invalid or potentially malicious
        """
        if not domain:
            raise ValidationError("Domain cannot be empty")
            
        # Strip and normalize
        domain = str(domain).strip().lower()
        
        # Length validation
        if len(domain) > MAX_DOMAIN_LENGTH:
            raise ValidationError(f"Domain too long (max {MAX_DOMAIN_LENGTH} characters)")
            
        if len(domain) < MIN_DOMAIN_LENGTH:
            raise ValidationError(f"Domain too short (minimum {MIN_DOMAIN_LENGTH} characters)")
        
        # Format validation
        if not DOMAIN_VALIDATION_PATTERN.match(domain):
            raise ValidationError("Invalid domain format")
            
        # Security checks
        dangerous_patterns = [
            r'[<>"\'\x00-\x1f\x7f-\x9f]',  # Control characters and HTML/script chars
            r'\.\.+',  # Multiple consecutive dots
            r'^\.|\.$',  # Starting or ending with dot
            r'--',  # Double hyphens (except xn-- for IDN)
            r'\s',  # Any whitespace
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, domain):
                raise ValidationError(f"Domain contains dangerous pattern: {pattern}")
        
        # Check for localhost, private domains, and other dangerous domains
        dangerous_domains = [
            'localhost', '127.0.0.1', '::1',
            'internal', 'private', 'local',
            'admin', 'root', 'test', 'staging'
        ]
        
        domain_parts = domain.split('.')
        for part in domain_parts:
            if part in dangerous_domains:
                raise ValidationError(f"Domain contains restricted component: {part}")
        
        return domain
    
    @staticmethod
    def validate_username(username: str | None) -> str | None:
        """
        Validate username with security checks.
        
        Args:
            username: Username to validate (optional)
            
        Returns:
            Sanitized username or None
            
        Raises:
            ValidationError: If username is invalid
        """
        if not username:
            return None
            
        username = str(username).strip().lower()
        
        # Length validation
        if len(username) > MAX_USERNAME_LENGTH:
            raise ValidationError(f"Username too long (max {MAX_USERNAME_LENGTH} characters)")
            
        if len(username) < MIN_USERNAME_LENGTH:
            raise ValidationError(f"Username too short (minimum {MIN_USERNAME_LENGTH} characters)")
        
        # Format validation
        if not USERNAME_VALIDATION_PATTERN.match(username):
            raise ValidationError("Invalid username format (must start with letter, contain only lowercase letters, numbers, underscore, hyphen)")
        
        # Security checks - reserved usernames
        reserved_usernames = [
            'root', 'admin', 'administrator', 'www', 'mail', 'ftp',
            'mysql', 'postgres', 'apache', 'nginx', 'daemon', 'bin',
            'sys', 'sync', 'games', 'man', 'lp', 'news', 'uucp',
            'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats',
            'nobody', 'systemd', 'messagebus', 'syslog', 'usbmux'
        ]
        
        if username in reserved_usernames:
            raise ValidationError(f"Username '{username}' is reserved")
        
        return username
    
    @staticmethod
    def validate_service_id(service_id: str) -> str:
        """
        Validate service ID format.
        
        Args:
            service_id: Service UUID to validate
            
        Returns:
            Validated service ID
            
        Raises:
            ValidationError: If service ID is invalid
        """
        if not service_id:
            raise ValidationError("Service ID cannot be empty")
            
        service_id = str(service_id).strip()
        
        # Validate UUID format
        try:
            uuid_obj = uuid.UUID(service_id)
            # Ensure it's a valid UUID4
            if uuid_obj.version != UUID_VERSION_4:
                raise ValidationError("Service ID must be a valid UUID4")
        except ValueError as e:
            raise ValidationError(f"Invalid service ID format: {e}") from e
        
        return str(uuid_obj)
    
    @staticmethod
    def validate_template(template: str) -> str:
        """
        Validate template name with security checks.
        
        Args:
            template: Template name to validate
            
        Returns:
            Sanitized template name
            
        Raises:
            ValidationError: If template name is invalid
        """
        if not template:
            return "Default"
            
        template = str(template).strip()
        
        # Length validation
        if len(template) > MAX_TEMPLATE_NAME_LENGTH:
            raise ValidationError(f"Template name too long (max {MAX_TEMPLATE_NAME_LENGTH} characters)")
        
        # Security validation - only alphanumeric, spaces, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', template):
            raise ValidationError("Template name contains invalid characters")
        
        # Check for path traversal and other dangerous patterns
        dangerous_patterns = ['..', '/', '\\', '<', '>', '"', "'", '`']
        for pattern in dangerous_patterns:
            if pattern in template:
                raise ValidationError(f"Template name contains dangerous pattern: {pattern}")
        
        return template


class IdempotencyManager:
    """Manages idempotency keys for provisioning operations."""
    
    @staticmethod
    def generate_key(service_id: str, operation: str, parameters: dict[str, Any]) -> str:
        """
        Generate idempotency key for operation.
        
        Args:
            service_id: Service UUID
            operation: Operation type
            parameters: Operation parameters
            
        Returns:
            Idempotency key
        """
        # Create stable hash from parameters
        param_str = json.dumps(parameters, sort_keys=True, default=str)
        param_hash = hashlib.sha256(param_str.encode('utf-8')).hexdigest()[:16]
        
        return f"provision:{service_id}:{operation}:{param_hash}"
    
    @staticmethod
    def check_and_set(key: str, value: Any = None) -> tuple[bool, Any]:
        """
        Check if operation is already in progress and set key if not.
        
        Args:
            key: Idempotency key
            value: Value to store (optional)
            
        Returns:
            Tuple of (is_new, existing_value)
        """
        existing = cache.get(key)
        if existing is not None:
            return False, existing
        
        # Use cache.add for atomic check-and-set
        success = cache.add(key, value or "in_progress", IDEMPOTENCY_KEY_TTL)
        if success:
            return True, None
        else:
            # Race condition - someone else set it
            return False, cache.get(key)
    
    @staticmethod
    def complete(key: str, result: Any) -> None:
        """
        Mark operation as completed with result.
        
        Args:
            key: Idempotency key
            result: Operation result
        """
        cache.set(key, result, IDEMPOTENCY_KEY_TTL)
    
    @staticmethod
    def clear(key: str) -> None:
        """
        Clear idempotency key.
        
        Args:
            key: Idempotency key to clear
        """
        cache.delete(key)


class ProvisioningErrorClassifier:
    """Classifies provisioning errors for proper retry/handling logic."""
    
    # Error patterns mapped to error types
    ERROR_PATTERNS: ClassVar[dict[ProvisioningErrorType, list[str]]] = {
        ProvisioningErrorType.RETRYABLE_NETWORK: [
            r'connection\s+timeout',
            r'connection\s+error',
            r'network\s+error',
            r'dns\s+error',
            r'timeout',
            r'502\s+bad\s+gateway',
            r'503\s+service\s+unavailable',
            r'504\s+gateway\s+timeout',
        ],
        ProvisioningErrorType.RETRYABLE_SERVICE: [
            r'server\s+error',
            r'service\s+temporarily\s+unavailable',
            r'rate\s+limit',
            r'too\s+many\s+requests',
            r'server\s+busy',
            r'maintenance\s+mode',
        ],
        ProvisioningErrorType.PERMANENT_VALIDATION: [
            r'invalid\s+domain',
            r'domain\s+already\s+exists',
            r'invalid\s+username',
            r'username\s+already\s+exists',
            r'validation\s+error',
            r'bad\s+request',
            r'malformed\s+request',
        ],
        ProvisioningErrorType.PERMANENT_AUTHORIZATION: [
            r'unauthorized',
            r'access\s+denied',
            r'permission\s+denied',
            r'authentication\s+failed',
            r'invalid\s+credentials',
            r'403\s+forbidden',
            r'401\s+unauthorized',
        ],
        ProvisioningErrorType.PERMANENT_RESOURCE: [
            r'insufficient\s+disk\s+space',
            r'quota\s+exceeded',
            r'no\s+space\s+left',
            r'resource\s+limit',
            r'server\s+full',
            r'capacity\s+exceeded',
        ],
    }
    
    @staticmethod
    def classify_error(error_message: str) -> ProvisioningErrorType:
        """
        Classify error message for proper handling.
        
        Args:
            error_message: Error message to classify
            
        Returns:
            Error type classification
        """
        error_lower = error_message.lower()
        
        for error_type, patterns in ProvisioningErrorClassifier.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_lower):
                    return error_type
        
        # Default to critical system error if unclassified
        return ProvisioningErrorType.CRITICAL_SYSTEM
    
    @staticmethod
    def is_retryable(error_type: ProvisioningErrorType) -> bool:
        """
        Check if error type is retryable.
        
        Args:
            error_type: Error type to check
            
        Returns:
            True if error should be retried
        """
        return error_type in {
            ProvisioningErrorType.RETRYABLE_NETWORK,
            ProvisioningErrorType.RETRYABLE_SERVICE,
        }


def sanitize_log_parameters(params: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize parameters for safe logging without sensitive data exposure.
    
    Args:
        params: Parameters dictionary to sanitize
        
    Returns:
        Sanitized parameters safe for logging
    """
    sanitized = {}
    
    for key, value in params.items():
        if key in {'password', 'api_password', 'secret', 'token', 'key'}:
            sanitized[key] = '***REDACTED***'
        elif key in {'encrypted_password', 'encrypted_payload'}:
            sanitized[key] = f'***ENCRYPTED({len(str(value))} bytes)***'
        elif isinstance(value, str) and len(value) > LOG_TRUNCATION_LENGTH:
            # Truncate very long strings
            sanitized[key] = f"{value[:LOG_TRUNCATION_LENGTH]}...({len(value)} chars total)"
        else:
            sanitized[key] = value
    
    return sanitized


def log_security_event_safe(
    event_type: str,
    details: dict[str, Any],
    service_id: str | None = None,
    domain: str | None = None
) -> None:
    """
    Log security event with safe parameter handling.
    
    Args:
        event_type: Type of security event
        details: Event details (will be sanitized)
        service_id: Service ID if applicable
        domain: Domain if applicable
    """
    try:
        # Sanitize details for logging
        safe_details = sanitize_log_parameters(details)
        
        # Add context
        safe_details.update({
            "source_app": "provisioning",
            "virtualmin_integration": True,
            "timestamp": timezone.now().isoformat(),
        })
        
        if service_id:
            safe_details["service_id"] = service_id
        if domain:
            safe_details["domain"] = domain
        
        # Use the common security logging function
        from apps.common.validators import log_security_event  # noqa: PLC0415
        log_security_event(
            event_type=event_type,
            details=safe_details,
            request_ip="127.0.0.1"  # System-initiated events
        )
        
        logger.info(f"🔒 [Security] {event_type}: {safe_details}")
        
    except Exception as e:
        logger.error(f"🔥 [Security] Failed to log security event {event_type}: {e}")
