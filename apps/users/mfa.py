"""
===============================================================================
MULTI-FACTOR AUTHENTICATION (MFA) MODULE 🔐
===============================================================================

Unified module for all MFA methods in PRAHO Platform:
- TOTP (Time-based One-Time Passwords) 
- Backup codes
- WebAuthn/Passkeys
- SMS (future)
- Biometrics (future)

This keeps all authentication factors in one place for better maintainability
and follows the principle of single responsibility for security-critical code.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from typing import Optional, Dict, List, Tuple, Any
import logging
import string
import random
import pyotp
import qrcode
import io
import base64
import json

User = get_user_model()
logger = logging.getLogger(__name__)


# ===============================================================================
# WEBAUTHN/PASSKEYS MODELS
# ===============================================================================

class WebAuthnCredential(models.Model):
    """
    🔐 WebAuthn/Passkey credentials for passwordless authentication
    
    This model stores WebAuthn credentials (passkeys) for users.
    Implementation ready for future WebAuthn integration.
    """
    
    CREDENTIAL_TYPE_CHOICES = [
        ('public-key', 'Public Key'),
        ('passkey', 'Passkey'),
    ]
    
    TRANSPORT_CHOICES = [
        ('usb', 'USB'),
        ('nfc', 'NFC'),
        ('ble', 'Bluetooth Low Energy'),
        ('internal', 'Internal (Touch ID, Face ID)'),
        ('hybrid', 'Hybrid'),
    ]
    
    # Relationships
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='webauthn_credentials'
    )
    
    # WebAuthn specification fields
    credential_id = models.TextField(unique=True)  # Base64URL encoded
    public_key = models.TextField()  # Base64URL encoded public key
    credential_type = models.CharField(
        max_length=20, 
        choices=CREDENTIAL_TYPE_CHOICES,
        default='public-key'
    )
    
    # Authenticator details
    aaguid = models.CharField(max_length=36, blank=True)  # Authenticator AAGUID
    transports = models.JSONField(default=list, blank=True)  # Available transports
    sign_count = models.PositiveIntegerField(default=0)  # Signature counter
    
    # User-friendly identification
    name = models.CharField(max_length=100)  # User-defined name
    device_type = models.CharField(max_length=50, blank=True)  # Phone, laptop, etc.
    
    # Security metadata
    backup_eligible = models.BooleanField(default=False)
    backup_state = models.BooleanField(default=False)
    user_verified = models.BooleanField(default=False)
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'webauthn_credentials'  # Use original table name from migration
        verbose_name = 'WebAuthn Credential'
        verbose_name_plural = 'WebAuthn Credentials'
        indexes = [
            # Core performance indexes with consistent 2FA naming
            models.Index(fields=['user', '-created_at'], name='idx_tfa_webauthn_user_created'),
            models.Index(fields=['credential_id'], name='idx_tfa_webauthn_credential_id'),
            models.Index(fields=['is_active', '-last_used'], name='idx_tfa_webauthn_active_used'),
            
            # Additional performance indexes for 2FA operations
            models.Index(fields=['user'], name='idx_tfa_webauthn_user_lookup'),
            models.Index(fields=['aaguid'], name='idx_tfa_webauthn_aaguid'),
            models.Index(fields=['credential_type'], name='idx_tfa_webauthn_type'),
            models.Index(fields=['is_active'], name='idx_tfa_webauthn_active'),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.user.email})"
    
    def mark_as_used(self):
        """Mark credential as recently used"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])


# ===============================================================================
# TOTP/2FA SERVICE
# ===============================================================================

class TOTPService:
    """
    🔐 Time-based One-Time Password (TOTP) Service
    
    Handles TOTP generation, verification, and QR code creation for 2FA.
    """
    
    # Configuration
    TOTP_ISSUER_NAME = getattr(settings, 'TOTP_ISSUER_NAME', 'PRAHO Platform')
    TOTP_PERIOD = getattr(settings, 'TOTP_PERIOD', 30)
    TOTP_DIGITS = getattr(settings, 'TOTP_DIGITS', 6)
    TIME_WINDOW_TOLERANCE = getattr(settings, 'TOTP_TIME_WINDOW', 1)  # ±30 seconds
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def verify_token(user, token: str, request=None) -> bool:
        """
        🔍 Verify TOTP token with replay protection and time window tolerance
        """
        try:
            if not user.two_factor_enabled or not user.two_factor_secret:
                return False
            
            # Check if code was recently used (prevent replay)
            cache_key = f"totp_used:{user.id}:{token}"
            if cache.get(cache_key):
                logger.warning(f"⚠️ [TOTP] Replay attempt detected for user {user.email}")
                return False
            
            # Verify with time window tolerance for clock drift
            totp = pyotp.TOTP(user.two_factor_secret)
            if totp.verify(token, valid_window=TOTPService.TIME_WINDOW_TOLERANCE):
                # Mark token as used for 90 seconds (3 * 30-second periods)
                cache.set(cache_key, True, 90)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"🔥 [TOTP] Verification error for {user.email}: {e}")
            return False
    
    @staticmethod
    def generate_qr_code(user, secret: str) -> str:
        """
        📱 Generate QR code for authenticator app setup
        
        Returns:
            Base64-encoded PNG image data
        """
        try:
            # Generate TOTP provisioning URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user.email,
                issuer_name=TOTPService.TOTP_ISSUER_NAME
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create image
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            qr_buffer = io.BytesIO()
            qr_img.save(qr_buffer, 'PNG')
            qr_data = base64.b64encode(qr_buffer.getvalue()).decode()
            
            logger.info(f"✅ [TOTP] QR code generated for {user.email}")
            return qr_data
            
        except Exception as e:
            logger.error(f"🔥 [TOTP] Failed to generate QR code for {user.email}: {e}")
            raise


# ===============================================================================
# BACKUP CODES SERVICE
# ===============================================================================

class BackupCodeService:
    """
    🎫 Backup Code Service
    
    Handles generation, verification, and management of backup codes for 2FA recovery.
    """
    
    BACKUP_CODES_COUNT = getattr(settings, 'BACKUP_CODES_COUNT', 8)
    BACKUP_CODE_LENGTH = 8
    
    @staticmethod
    def generate_codes(user) -> List[str]:
        """
        Generate new backup codes and store hashed versions in user model
        
        Returns:
            List of plain text backup codes (for one-time display)
        """
        codes = []
        hashed_codes = []
        
        for _ in range(BackupCodeService.BACKUP_CODES_COUNT):
            code = ''.join(random.choices(string.digits, k=BackupCodeService.BACKUP_CODE_LENGTH))
            codes.append(code)
            hashed_codes.append(make_password(code))
        
        user.backup_tokens = hashed_codes
        return codes
    
    @staticmethod
    def verify_and_consume_code(user, code: str) -> bool:
        """
        Verify and consume a backup code (one-time use)
        
        Returns:
            True if code was valid and consumed
        """
        if not user.backup_tokens:
            return False
        
        for i, hashed_code in enumerate(user.backup_tokens):
            if check_password(code, hashed_code):
                # Remove used backup code
                user.backup_tokens.pop(i)
                user.save(update_fields=['backup_tokens'])
                return True
        
        return False
    
    @staticmethod
    def get_remaining_count(user) -> int:
        """Get number of remaining backup codes"""
        return len(user.backup_tokens) if user.backup_tokens else 0


# ===============================================================================
# WEBAUTHN/PASSKEYS SERVICE
# ===============================================================================

class WebAuthnService:
    """
    🔐 WebAuthn/Passkeys Service
    
    Handles FIDO2/WebAuthn authentication for passwordless login.
    Currently a framework for future implementation.
    """
    
    @staticmethod
    def is_supported() -> bool:
        """
        Check if WebAuthn is supported and configured
        
        Returns:
            False for now, True when implemented
        """
        return False  # TODO: Implement WebAuthn support
    
    @staticmethod
    def generate_registration_options(user) -> Optional[Dict[str, Any]]:
        """
        Generate WebAuthn registration options for a user
        
        Args:
            user: User to generate options for
            
        Returns:
            WebAuthn registration options or None if not supported
        """
        if not WebAuthnService.is_supported():
            logger.info(f"📱 [WebAuthn] Not yet implemented for user {user.email}")
            return None
        
        # TODO: Implement with webauthn library
        # from webauthn import generate_registration_options
        # return generate_registration_options(...)
        
        return None
    
    @staticmethod
    def verify_registration(user, credential_data: Dict[str, Any]) -> bool:
        """
        Verify and store a new WebAuthn credential
        
        Args:
            user: User registering the credential
            credential_data: WebAuthn credential data
            
        Returns:
            True if credential was successfully registered
        """
        if not WebAuthnService.is_supported():
            logger.warning(f"📱 [WebAuthn] Registration attempted but not implemented for {user.email}")
            return False
        
        # TODO: Implement credential verification and storage
        return False
    
    @staticmethod
    def generate_authentication_options(user) -> Optional[Dict[str, Any]]:
        """
        Generate WebAuthn authentication options
        
        Args:
            user: User to authenticate
            
        Returns:
            WebAuthn authentication options or None
        """
        if not WebAuthnService.is_supported():
            return None
        
        # TODO: Implement authentication options generation
        return None
    
    @staticmethod
    def verify_authentication(user, authentication_data: Dict[str, Any]) -> bool:
        """
        Verify WebAuthn authentication
        
        Args:
            user: User to authenticate
            authentication_data: WebAuthn authentication data
            
        Returns:
            True if authentication is valid
        """
        if not WebAuthnService.is_supported():
            return False
        
        # TODO: Implement authentication verification
        return False


# ===============================================================================
# UNIFIED MFA SERVICE (ORCHESTRATOR)
# ===============================================================================

class MFAService:
    """
    🔐 Multi-Factor Authentication Service (Orchestrator)
    
    This is the main service that coordinates all MFA methods:
    - TOTP/2FA
    - Backup codes  
    - WebAuthn/Passkeys
    - Future methods (SMS, biometrics, etc.)
    
    Includes comprehensive audit logging and security features.
    """
    
    @staticmethod
    def enable_totp(user, request=None) -> Tuple[str, List[str]]:
        """
        🔐 Enable TOTP/2FA for user with audit logging
        
        Returns:
            Tuple of (totp_secret, backup_codes)
        """
        try:
            if user.two_factor_enabled:
                raise ValueError("TOTP/2FA is already enabled for this user")
            
            # Generate TOTP secret
            secret = TOTPService.generate_secret()
            
            # Enable 2FA
            user.two_factor_enabled = True
            user.two_factor_secret = secret  # This uses the encrypted setter
            
            # Generate backup codes
            backup_codes = BackupCodeService.generate_codes(user)
            user.save()
            
            # 📊 Audit log the enablement
            from apps.audit.services import audit_service
            
            metadata = {
                'method': 'TOTP',
                'backup_codes_generated': len(backup_codes),
                'timestamp': timezone.now().isoformat(),
            }
            
            if request:
                metadata.update({
                    'session_id': request.session.session_key,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                })
            
            audit_service.log_2fa_event(
                event_type='2fa_enabled',
                user=user,
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT') if request else None,
                metadata=metadata,
                description=f"TOTP/2FA enabled for user {user.email}"
            )
            
            logger.info(f"✅ [MFA] TOTP enabled for user {user.email}")
            return secret, backup_codes
            
        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to enable TOTP for user {user.email}: {e}")
            raise
    
    @staticmethod
    def disable_totp(user, admin_user=None, reason: Optional[str] = None, request=None) -> bool:
        """
        🔓 Disable TOTP/2FA with audit trail
        
        Args:
            user: User to disable TOTP for
            admin_user: Admin performing the action (if any)
            reason: Reason for disabling
            request: HTTP request for context
        """
        try:
            if not user.two_factor_enabled:
                raise ValueError("TOTP/2FA is not enabled for this user")
            
            # Clear 2FA data
            user.two_factor_enabled = False
            user.two_factor_secret = ''
            user.backup_tokens = []
            user.save()
            
            # 📊 Audit log the disablement
            from apps.audit.services import audit_service
            
            metadata = {
                'timestamp': timezone.now().isoformat(),
                'reason': reason or 'User requested',
            }
            
            event_type = '2fa_disabled'
            description = f"TOTP/2FA disabled for user {user.email}"
            
            if admin_user and admin_user != user:
                metadata.update({
                    'admin_id': str(admin_user.id),
                    'admin_email': admin_user.email,
                })
                event_type = '2fa_admin_reset'
                description = f"TOTP/2FA disabled by admin {admin_user.email} for user {user.email}"
            
            audit_service.log_2fa_event(
                event_type=event_type,
                user=user,
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT') if request else None,
                metadata=metadata,
                description=description
            )
            
            logger.warning(f"⚠️ [MFA] TOTP disabled for user {user.email} by {admin_user.email if admin_user else 'self'}")
            return True
            
        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to disable TOTP for user {user.email}: {e}")
            raise
    
    @staticmethod
    def generate_backup_codes(user, request=None) -> List[str]:
        """
        🎫 Generate new backup codes with audit
        """
        try:
            if not user.two_factor_enabled:
                raise ValueError("TOTP/2FA must be enabled to generate backup codes")
            
            codes = BackupCodeService.generate_codes(user)
            user.save()
            
            # 📊 Audit log generation
            from apps.audit.services import audit_service
            
            audit_service.log_2fa_event(
                event_type='2fa_backup_codes_generated',
                user=user,
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT') if request else None,
                metadata={
                    'count': len(codes),
                    'timestamp': timezone.now().isoformat(),
                    'previous_codes_invalidated': True,
                }
            )
            
            logger.info(f"✅ [MFA] Generated {len(codes)} backup codes for {user.email}")
            return codes
            
        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to generate backup codes for {user.email}: {e}")
            raise
    
    @staticmethod
    def verify_mfa_code(user, code: str, request=None) -> Dict[str, Any]:
        """
        🔍 Verify MFA code (TOTP or backup code) with enhanced security and audit logging
        
        Returns:
            {
                'success': bool,
                'method': str,  # 'totp', 'backup_code', 'webauthn', etc.
                'remaining_backup_codes': int,
                'rate_limited': bool,
                'replay_detected': bool
            }
        """
        result = {
            'success': False,
            'method': None,
            'remaining_backup_codes': BackupCodeService.get_remaining_count(user),
            'rate_limited': False,
            'replay_detected': False
        }
        
        try:
            if not user.two_factor_enabled:
                raise ValueError("MFA is not enabled for this user")
            
            # Rate limiting check
            if not MFAService._check_rate_limit(user):
                result['rate_limited'] = True
                logger.warning(f"⚠️ [MFA] Rate limit exceeded for user {user.email}")
                return result
            
            # Check if it's a TOTP code (6 digits)
            if len(code) == TOTPService.TOTP_DIGITS and code.isdigit():
                success = TOTPService.verify_token(user, code, request)
                if success:
                    result.update({
                        'success': True,
                        'method': 'totp'
                    })
                    
            # Check if it's a backup code (8 digits)
            elif len(code) == BackupCodeService.BACKUP_CODE_LENGTH and code.isdigit():
                success = BackupCodeService.verify_and_consume_code(user, code)
                if success:
                    result.update({
                        'success': True,
                        'method': 'backup_code',
                        'remaining_backup_codes': BackupCodeService.get_remaining_count(user)
                    })
                    
                    # 📊 Audit backup code usage
                    from apps.audit.services import audit_service
                    
                    audit_service.log_2fa_event(
                        event_type='2fa_backup_code_used',
                        user=user,
                        ip_address=request.META.get('REMOTE_ADDR') if request else None,
                        user_agent=request.META.get('HTTP_USER_AGENT') if request else None,
                        metadata={
                            'remaining_codes': result['remaining_backup_codes'],
                            'timestamp': timezone.now().isoformat()
                        }
                    )
            
            # 📊 Audit verification attempt
            from apps.audit.services import audit_service
            
            event_type = '2fa_verification_success' if result['success'] else '2fa_verification_failed'
            audit_service.log_2fa_event(
                event_type=event_type,
                user=user,
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT') if request else None,
                metadata={
                    'method': result['method'],
                    'timestamp': timezone.now().isoformat(),
                    'rate_limited': result['rate_limited'],
                    'replay_detected': result['replay_detected']
                }
            )
            
            if result['success']:
                logger.info(f"✅ [MFA] Successful {result['method']} verification for {user.email}")
            else:
                logger.warning(f"⚠️ [MFA] Failed verification for {user.email}")
                
            return result
            
        except Exception as e:
            logger.error(f"🔥 [MFA] Verification error for {user.email}: {e}")
            result['success'] = False
            return result
    
    @staticmethod
    def generate_qr_code(user, secret: str) -> str:
        """
        📱 Generate QR code for TOTP setup
        
        Returns:
            Base64-encoded PNG image data
        """
        return TOTPService.generate_qr_code(user, secret)
    
    @staticmethod
    def get_user_mfa_status(user) -> Dict[str, Any]:
        """
        📊 Get comprehensive MFA status for a user
        
        Returns:
            {
                'totp_enabled': bool,
                'backup_codes_count': int,
                'webauthn_credentials': int,
                'last_used': datetime,
                'methods_available': list
            }
        """
        return {
            'totp_enabled': user.two_factor_enabled,
            'backup_codes_count': BackupCodeService.get_remaining_count(user),
            'webauthn_credentials': user.webauthn_credentials.filter(is_active=True).count() if hasattr(user, 'webauthn_credentials') else 0,
            'methods_available': MFAService._get_available_methods(user),
        }
    
    # ===============================================================================
    # PRIVATE HELPER METHODS
    # ===============================================================================
    
    @staticmethod
    def _check_rate_limit(user) -> bool:
        """
        🚦 Rate limit MFA verification attempts
        """
        cache_key = f"mfa_attempts:{user.id}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 5:  # Max 5 attempts per 5 minutes
            logger.error(f"🔥 [MFA] Rate limit exceeded for user {user.email}")
            return False
        
        cache.set(cache_key, attempts + 1, 300)  # 5 minute window
        return True
    
    @staticmethod
    def _get_available_methods(user) -> List[str]:
        """Get list of available MFA methods for user"""
        methods = []
        
        if user.two_factor_enabled:
            methods.append('totp')
        
        if BackupCodeService.get_remaining_count(user) > 0:
            methods.append('backup_codes')
        
        if WebAuthnService.is_supported():
            methods.append('webauthn')
        
        return methods


# ===============================================================================
# EXPORTED SERVICES
# ===============================================================================

# Main MFA service (use this in views and other code)
mfa_service = MFAService()

# Individual services for specific use cases
totp_service = TOTPService()
backup_code_service = BackupCodeService()
webauthn_service = WebAuthnService()

# Legacy alias for backward compatibility (remove after migration)
two_factor_service = mfa_service
