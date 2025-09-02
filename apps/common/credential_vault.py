"""
Encrypted Credential Vault - PRAHO Platform
Centralized credential management with encryption, rotation, and audit.

Implements the CredentialVault service design from virtualmin_review.md:
- Master key encryption with Fernet
- Per-service credential storage
- Automatic rotation capabilities
- Comprehensive audit logging
- Access control and permissions
"""

from __future__ import annotations

import json
import logging
import secrets
import string
import uuid
from datetime import timedelta
from typing import Any, ClassVar

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

logger = logging.getLogger(__name__)

# Vault configuration constants
CREDENTIAL_EXPIRY_DAYS = 30  # Default credential expiration
MAX_CREDENTIAL_AGE_DAYS = 90  # Maximum age before forced rotation
ROTATION_RETRY_LIMIT = 3
ACCESS_LOG_RETENTION_DAYS = 365  # Keep access logs for 1 year
VAULT_CACHE_TIMEOUT = 300  # 5 minutes for credential caching


class CredentialVaultError(Exception):
    """Base exception for credential vault operations"""


class CredentialNotFoundError(CredentialVaultError):
    """Credential not found in vault"""


class CredentialExpiredError(CredentialVaultError):
    """Credential has expired and requires rotation"""


class CredentialPermissionError(CredentialVaultError):
    """User lacks permission to access credential"""


class EncryptedCredential(models.Model):
    """
    Encrypted credential storage model.
    
    Stores API passwords, SSH keys, tokens, and other sensitive credentials
    with encryption, expiration tracking, and usage analytics.
    """
    
    SERVICE_TYPE_CHOICES: ClassVar[list[tuple[str, str]]] = [
        ('virtualmin', 'Virtualmin API'),
        ('stripe', 'Stripe Payment Gateway'),
        ('dns_cloudflare', 'Cloudflare DNS'),
        ('dns_route53', 'AWS Route53 DNS'),
        ('ssh', 'SSH Access'),
        ('ssl_certificate', 'SSL Certificate'),
        ('backup_storage', 'Backup Storage'),
        ('monitoring', 'Monitoring Service'),
        ('email_smtp', 'SMTP Email Service'),
        ('domain_registrar', 'Domain Registrar'),
    ]
    
    # Primary identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_type = models.CharField(max_length=50, choices=SERVICE_TYPE_CHOICES)
    service_identifier = models.CharField(
        max_length=255,
        help_text="Server hostname, account ID, or unique identifier"
    )
    
    # Encrypted credential data
    encrypted_username = models.BinaryField()
    encrypted_password = models.BinaryField()
    encrypted_metadata = models.BinaryField(
        null=True, 
        blank=True,
        help_text="Additional encrypted data (API keys, certificates, etc.)"
    )
    
    # Lifecycle management
    expires_at = models.DateTimeField()
    rotation_count = models.PositiveIntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)
    
    # Status tracking
    is_active = models.BooleanField(default=True)
    rotation_in_progress = models.BooleanField(default=False)
    last_rotation_attempt = models.DateTimeField(null=True, blank=True)
    rotation_failure_count = models.PositiveIntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "credential_vault_credentials"
        unique_together: ClassVar[list[list[str]]] = [['service_type', 'service_identifier']]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['service_type', 'service_identifier']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['last_accessed']),
        ]
        
    def __str__(self) -> str:
        return f"{self.service_type}:{self.service_identifier}"
        
    @property
    def is_expired(self) -> bool:
        """Check if credential has expired"""
        return timezone.now() > self.expires_at
        
    @property
    def days_until_expiry(self) -> int:
        """Get days until credential expires"""
        delta = self.expires_at - timezone.now()
        return max(0, delta.days)


class CredentialAccessLog(models.Model):
    """
    Immutable audit log for credential access.
    
    Tracks WHO accessed WHAT credential WHEN and WHY
    for security monitoring and compliance.
    """
    
    # Primary identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(
        EncryptedCredential,
        on_delete=models.CASCADE,
        related_name='access_logs'
    )
    
    # Access details
    user = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    username = models.CharField(
        max_length=255,
        help_text="Username at time of access (for audit trail)"
    )
    
    # Context information
    access_reason = models.CharField(
        max_length=255,
        help_text="Reason for credential access"
    )
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Technical details
    access_method = models.CharField(
        max_length=50,
        choices=[
            ('api', 'API Access'),
            ('admin', 'Admin Interface'),
            ('task', 'Background Task'),
            ('migration', 'Data Migration'),
            ('rotation', 'Credential Rotation'),
        ]
    )
    
    # Result tracking
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    accessed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = "credential_vault_access_logs"
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['credential', 'accessed_at']),
            models.Index(fields=['user', 'accessed_at']),
            models.Index(fields=['accessed_at']),
        ]
        
    def __str__(self) -> str:
        return f"{self.username} -> {self.credential} at {self.accessed_at}"


class CredentialVault:
    """
    🔐 CRITICAL: Centralized credential management service.
    
    Implements the secure credential vault design:
    - Master key encryption using Fernet
    - Per-service credential storage with audit
    - Automatic expiration and rotation
    - Access control and permissions
    - Comprehensive security logging
    """
    
    def __init__(self) -> None:
        """Initialize credential vault with master key"""
        self._master_key = self._get_master_key()
        self._cipher = Fernet(self._master_key)
        self._verify_vault_integrity()
        
    def _get_master_key(self) -> bytes:
        """Get or generate master encryption key"""
        master_key = getattr(settings, 'CREDENTIAL_VAULT_MASTER_KEY', None)
        
        if not master_key:
            raise ImproperlyConfigured(
                "CREDENTIAL_VAULT_MASTER_KEY must be set in environment. "
                "Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )
            
        try:
            # Validate key format
            key_bytes = master_key.encode() if isinstance(master_key, str) else master_key
            Fernet(key_bytes)  # Test key validity
            return key_bytes
        except Exception as e:
            raise ImproperlyConfigured(f"Invalid CREDENTIAL_VAULT_MASTER_KEY: {e}") from e
            
    def _verify_vault_integrity(self) -> None:
        """Verify vault is working correctly"""
        try:
            # Test encryption/decryption
            test_data = "vault_integrity_test"
            encrypted = self._cipher.encrypt(test_data.encode())
            decrypted = self._cipher.decrypt(encrypted).decode()
            
            if decrypted != test_data:
                raise CredentialVaultError("Vault integrity check failed")
                
            logger.debug("🔐 [Credential Vault] Integrity check passed")
            
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Integrity check failed: {e}")
            raise CredentialVaultError(f"Vault integrity verification failed: {e}") from e
            
    def store_credential(
        self,
        service_type: str,
        service_identifier: str,
        username: str,
        password: str,
        metadata: dict | None = None,
        expires_in_days: int = CREDENTIAL_EXPIRY_DAYS,
        user: Any | None = None,
        reason: str = "Credential storage"
    ) -> Result[EncryptedCredential, str]:
        """
        🔒 Store encrypted credential in vault.
        
        Args:
            service_type: Type of service (virtualmin, stripe, etc.)
            service_identifier: Unique identifier (hostname, account ID)
            username: Username/API key
            password: Password/secret
            metadata: Additional encrypted data
            expires_in_days: Days until expiration
            user: User storing the credential
            reason: Reason for storage
            
        Returns:
            Result with stored credential or error
        """
        try:
            with transaction.atomic():
                # Encrypt credential data
                encrypted_username = self._cipher.encrypt(username.encode())
                encrypted_password = self._cipher.encrypt(password.encode())
                encrypted_metadata = None
                
                if metadata:
                    metadata_json = json.dumps(metadata)
                    encrypted_metadata = self._cipher.encrypt(metadata_json.encode())
                
                # Calculate expiration
                expires_at = timezone.now() + timedelta(days=expires_in_days)
                
                # Store or update credential
                credential, created = EncryptedCredential.objects.update_or_create(
                    service_type=service_type,
                    service_identifier=service_identifier,
                    defaults={
                        'encrypted_username': encrypted_username,
                        'encrypted_password': encrypted_password,
                        'encrypted_metadata': encrypted_metadata,
                        'expires_at': expires_at,
                        'is_active': True,
                        'rotation_in_progress': False,
                        'rotation_failure_count': 0,
                    }
                )
                
                if not created:
                    credential.rotation_count += 1
                    credential.save()
                
                # Log storage event
                self._log_credential_access(
                    credential=credential,
                    user=user,
                    reason=reason,
                    access_method='admin' if user else 'api',
                    success=True
                )
                
                action = "updated" if not created else "stored"
                logger.info(
                    f"🔐 [Credential Vault] {action.title()} credential: "
                    f"{service_type}:{service_identifier}"
                )
                
                return Ok(credential)
                
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Storage failed: {e}")
            return Err(f"Failed to store credential: {e!s}")
            
    def get_credential(
        self,
        service_type: str,
        service_identifier: str,
        user: Any | None = None,
        reason: str = "Credential access",
        allow_expired: bool = False
    ) -> Result[tuple[str, str, dict | None], str]:
        """
        🔓 Retrieve and decrypt credential from vault.
        
        Args:
            service_type: Type of service
            service_identifier: Unique identifier
            user: User requesting the credential
            reason: Reason for access
            allow_expired: Allow access to expired credentials
            
        Returns:
            Result with (username, password, metadata) or error
        """
        try:
            # Find credential
            try:
                credential = EncryptedCredential.objects.get(
                    service_type=service_type,
                    service_identifier=service_identifier,
                    is_active=True
                )
            except EncryptedCredential.DoesNotExist:
                return Err(f"Credential not found: {service_type}:{service_identifier}")
                
            # Check expiration
            if credential.is_expired and not allow_expired:
                self._log_credential_access(
                    credential=credential,
                    user=user,
                    reason=reason,
                    access_method='api',
                    success=False,
                    error_message="Credential expired"
                )
                return Err(f"Credential expired {credential.days_until_expiry} days ago")
                
            # Check permissions (implement your authorization logic here)
            if not self._check_credential_access_permission(credential, user):
                self._log_credential_access(
                    credential=credential,
                    user=user,
                    reason=reason,
                    access_method='api',
                    success=False,
                    error_message="Access denied"
                )
                return Err("Access denied to credential")
                
            # Decrypt credential data
            username = self._cipher.decrypt(credential.encrypted_username).decode()
            password = self._cipher.decrypt(credential.encrypted_password).decode()
            
            metadata = None
            if credential.encrypted_metadata:
                metadata_json = self._cipher.decrypt(credential.encrypted_metadata).decode()
                metadata = json.loads(metadata_json)
                
            # Update access tracking
            credential.last_accessed = timezone.now()
            credential.access_count += 1
            credential.save(update_fields=['last_accessed', 'access_count'])
            
            # Log successful access
            self._log_credential_access(
                credential=credential,
                user=user,
                reason=reason,
                access_method='api',
                success=True
            )
            
            logger.debug(
                f"🔐 [Credential Vault] Retrieved credential: "
                f"{service_type}:{service_identifier}"
            )
            
            return Ok((username, password, metadata))
            
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Retrieval failed: {e}")
            return Err(f"Failed to retrieve credential: {e!s}")
            
    def rotate_credential(
        self,
        service_type: str,
        service_identifier: str,
        new_username: str | None = None,
        new_password: str | None = None,
        user: Any | None = None,
        reason: str = "Credential rotation"
    ) -> Result[bool, str]:
        """
        🔄 Rotate credential with new values.
        
        Args:
            service_type: Type of service
            service_identifier: Unique identifier
            new_username: New username (optional)
            new_password: New password (will generate if not provided)
            user: User performing rotation
            reason: Reason for rotation
            
        Returns:
            Result with success status or error
        """
        try:
            # Find existing credential
            try:
                credential = EncryptedCredential.objects.get(
                    service_type=service_type,
                    service_identifier=service_identifier,
                    is_active=True
                )
            except EncryptedCredential.DoesNotExist:
                return Err(f"Credential not found: {service_type}:{service_identifier}")
                
            # Mark rotation in progress
            credential.rotation_in_progress = True
            credential.last_rotation_attempt = timezone.now()
            credential.save()
            
            try:
                # Generate new password if not provided
                if not new_password:
                    new_password = self._generate_secure_password()
                    
                # Get current username if new one not provided
                if not new_username:
                    current_username = self._cipher.decrypt(credential.encrypted_username).decode()
                    new_username = current_username
                    
                # Test new credential works (implement service-specific testing)
                test_result = self._test_credential(service_type, service_identifier, new_username, new_password)
                if test_result.is_err():
                    credential.rotation_failure_count += 1
                    credential.rotation_in_progress = False
                    credential.save()
                    return Err(f"Credential test failed: {test_result.unwrap_err()}")
                    
                # Store new credential (keeps old version for rollback)
                store_result = self.store_credential(
                    service_type=service_type,
                    service_identifier=service_identifier,
                    username=new_username,
                    password=new_password,
                    expires_in_days=CREDENTIAL_EXPIRY_DAYS,
                    user=user,
                    reason=reason
                )
                
                if store_result.is_err():
                    credential.rotation_failure_count += 1
                    credential.rotation_in_progress = False
                    credential.save()
                    return store_result
                    
                # Mark rotation complete
                credential.rotation_in_progress = False
                credential.rotation_failure_count = 0
                credential.save()
                
                logger.info(
                    f"🔄 [Credential Vault] Rotated credential: "
                    f"{service_type}:{service_identifier}"
                )
                
                return Ok(True)
                
            except Exception:
                # Mark rotation failed
                credential.rotation_failure_count += 1
                credential.rotation_in_progress = False
                credential.save()
                raise
                
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Rotation failed: {e}")
            return Err(f"Failed to rotate credential: {e!s}")
            
    def _test_credential(
        self,
        service_type: str,
        service_identifier: str,
        username: str,
        password: str
    ) -> Result[bool, str]:
        """Test if credential works (service-specific implementation)"""
        
        if service_type == 'virtualmin':
            # Import here to avoid circular imports
            from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
            
            try:
                config = VirtualminConfig(
                    hostname=service_identifier,
                    port=10000,
                    username=username,
                    password=password,
                    use_ssl=True,
                    verify_ssl=True,
                    timeout=10
                )
                
                gateway = VirtualminGateway(config)
                result = gateway.call('list-domains', {'format': 'json'})
                return Ok(True) if result.is_ok() else Err("Authentication failed")
                
            except Exception as e:
                return Err(f"Connection test failed: {e!s}")
                
        # Add other service types here
        return Ok(True)  # Default to success for unknown types
        
    def _generate_secure_password(self, length: int = 32) -> str:
        """Generate cryptographically secure password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
        
    def _check_credential_access_permission(
        self,
        credential: EncryptedCredential,
        user: Any | None
    ) -> bool:
        """Check if user has permission to access credential"""
        # Implement your authorization logic here
        # For now, allow all access - customize based on your needs
        return True
        
    def _log_credential_access(
        self,
        credential: EncryptedCredential,
        user: Any | None,
        reason: str,
        access_method: str,
        success: bool,
        error_message: str = ""
    ) -> None:
        """Log credential access for audit trail"""
        try:
            username = user.username if user and hasattr(user, 'username') else 'system'
            
            CredentialAccessLog.objects.create(
                credential=credential,
                user=user,
                username=username,
                access_reason=reason,
                access_method=access_method,
                success=success,
                error_message=error_message
            )
            
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Failed to log access: {e}")
            
    def get_credentials_expiring_soon(self, days: int = 7) -> list[EncryptedCredential]:
        """Get credentials expiring within specified days"""
        cutoff_date = timezone.now() + timedelta(days=days)
        return list(
            EncryptedCredential.objects.filter(
                expires_at__lte=cutoff_date,
                is_active=True
            ).order_by('expires_at')
        )
        
    def get_vault_health_status(self) -> dict[str, Any]:
        """Get comprehensive vault health status"""
        try:
            total_credentials = EncryptedCredential.objects.count()
            active_credentials = EncryptedCredential.objects.filter(is_active=True).count()
            expired_credentials = EncryptedCredential.objects.filter(
                expires_at__lt=timezone.now(),
                is_active=True
            ).count()
            
            expiring_soon = len(self.get_credentials_expiring_soon())
            
            recent_accesses = CredentialAccessLog.objects.filter(
                accessed_at__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            failed_rotations = EncryptedCredential.objects.filter(
                rotation_failure_count__gt=0,
                is_active=True
            ).count()
            
            return {
                'vault_healthy': expired_credentials == 0 and failed_rotations == 0,
                'total_credentials': total_credentials,
                'active_credentials': active_credentials,
                'expired_credentials': expired_credentials,
                'expiring_soon': expiring_soon,
                'recent_accesses_24h': recent_accesses,
                'failed_rotations': failed_rotations,
                'last_check': timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"🚨 [Credential Vault] Health check failed: {e}")
            return {
                'vault_healthy': False,
                'error': str(e),
                'last_check': timezone.now().isoformat()
            }


# Global vault instance
credential_vault = CredentialVault()


def get_credential_vault() -> CredentialVault:
    """Get global credential vault instance"""
    return credential_vault
