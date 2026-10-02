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

import base64
import io
import logging
import secrets
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Union, cast

import pyotp
import qrcode
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.cache import cache
from django.db import models, transaction
from django.http import HttpRequest
from django.utils import timezone

from apps.audit.services import AuditContext, AuditService, TwoFactorAuditRequest  # For MFA audit logging
from apps.common.constants import MAX_LOGIN_ATTEMPTS

# Educational Example: This demonstrates different type annotation patterns
# Pattern 1: Using TYPE_CHECKING (RECOMMENDED) - Fixed for most functions
if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()

# ===============================================================================
# 🎓 EDUCATIONAL TYPE ANNOTATION EXAMPLES
# ===============================================================================
#
# The following 4 MyPy errors are intentionally LEFT UNFIXED for learning:
#
# 1. Django Field Nullable Generics (line 122):
#    - Error: "DateTimeField is nullable but its generic get type parameter is not optional"
#    - Learning: Django model fields with null=True need Optional[] type annotations
#    - Fix: Use Optional[datetime] or datetime | None for nullable fields
#
# 2. Django Choice Field Translation Issues (throughout codebase):
#    - Error: "_StrPromise incompatible with str in choice field tuples"
#    - Learning: Django's gettext_lazy returns _StrPromise objects, not strings
#    - Fix: Use proper typing for choice tuples or cast to str
#
# 3. Django ManyToMany Field Type Inference:
#    - Error: "Need type annotation for customers field" (if it occurs)
#    - Learning: Django ManyToMany fields sometimes need explicit typing
#    - Fix: Use proper type annotations for relationship fields
#
# 4. Django Model Manager Generic Typing:
#    - Error: Complex generic type issues in model managers
#    - Learning: Django's BaseUserManager needs proper generic parameters
#    - Fix: Use proper generic types and TYPE_CHECKING patterns
#
# These represent common Django + MyPy integration challenges that developers
# encounter when adding type safety to existing Django codebases.
# ===============================================================================
logger = logging.getLogger(__name__)

# Optional WebAuthn library shim for tests that patch it
try:  # pragma: no cover - presence is test-patched
    import webauthn  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    webauthn = None


# ===============================================================================
# WEBAUTHN/PASSKEYS MODELS
# ===============================================================================


class WebAuthnCredential(models.Model):
    """
    🔐 WebAuthn/Passkey credentials for passwordless authentication

    This model stores WebAuthn credentials (passkeys) for users.
    Implementation ready for future WebAuthn integration.
    """

    CREDENTIAL_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("public-key", "Public Key"),
        ("passkey", "Passkey"),
    )

    TRANSPORT_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("usb", "USB"),
        ("nfc", "NFC"),
        ("ble", "Bluetooth Low Energy"),
        ("internal", "Internal (Touch ID, Face ID)"),
        ("hybrid", "Hybrid"),
    )

    # Relationships
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="webauthn_credentials")

    # WebAuthn specification fields
    credential_id = models.TextField()  # Base64URL encoded; unique per user
    public_key = models.TextField()  # Base64URL encoded public key
    credential_type = models.CharField(max_length=20, choices=CREDENTIAL_TYPE_CHOICES, default="public-key")

    # Authenticator details
    aaguid = models.CharField(max_length=36, blank=True)  # Authenticator AAGUID
    # Single transport (simple choice) kept for compatibility with tests
    transport = models.CharField(max_length=20, blank=True, choices=TRANSPORT_CHOICES, default="")
    # Keep future-ready field for multiple transports
    transports = models.JSONField(default=list, blank=True)
    sign_count = models.PositiveIntegerField(default=0)  # Signature counter

    # User-friendly identification
    name = models.CharField(max_length=100)  # User-defined name
    device_type = models.CharField(max_length=50, blank=True)  # Phone, laptop, etc.

    # Security metadata
    backup_eligible = models.BooleanField(default=False)
    backup_state = models.BooleanField(default=False)
    user_verified = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    objects = models.Manager()  # Explicit manager for mypy

    class Meta:
        db_table = "user_webauthn_credentials"
        verbose_name = "WebAuthn Credential"
        verbose_name_plural = "WebAuthn Credentials"
        constraints: ClassVar = [models.UniqueConstraint(fields=["user", "credential_id"], name="uniq_user_credential")]
        indexes: ClassVar[tuple[models.Index, ...]] = (
            # Core performance indexes with consistent 2FA naming
            models.Index(fields=["user", "-created_at"], name="idx_tfa_webauthn_user_created"),
            models.Index(fields=["credential_id"], name="idx_tfa_webauthn_credential_id"),
            models.Index(fields=["is_active", "-last_used"], name="idx_tfa_webauthn_active_used"),
            # Additional performance indexes
            models.Index(fields=["user", "is_active"], name="idx_tfa_webauthn_user_active"),
            # Additional performance indexes for 2FA operations
            models.Index(fields=["user"], name="idx_tfa_webauthn_user_lookup"),
            models.Index(fields=["aaguid"], name="idx_tfa_webauthn_aaguid"),
            models.Index(fields=["credential_type"], name="idx_tfa_webauthn_type"),
            models.Index(fields=["is_active"], name="idx_tfa_webauthn_active"),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.user.email})"

    def mark_as_used(self) -> None:
        """Mark credential as recently used"""
        self.last_used = timezone.now()
        self.sign_count = (self.sign_count or 0) + 1
        self.save(update_fields=["last_used", "sign_count"])


# ===============================================================================
# TOTP/2FA SERVICE
# ===============================================================================


class TOTPService:
    """
    🔐 Time-based One-Time Password (TOTP) Service

    Handles TOTP generation, verification, and QR code creation for 2FA.
    """

    # Configuration
    TOTP_ISSUER_NAME = getattr(settings, "TOTP_ISSUER_NAME", "PRAHO Platform")
    TOTP_PERIOD = getattr(settings, "TOTP_PERIOD", 30)
    TOTP_DIGITS = getattr(settings, "TOTP_DIGITS", 6)
    TIME_WINDOW_TOLERANCE = getattr(settings, "TOTP_TIME_WINDOW", 1)  # ±30 seconds

    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()

    @staticmethod
    def verify_token(user_or_secret: Any, token: str, request: Any = None) -> bool:
        """
        🔍 Verify TOTP token with replay protection and time window tolerance
        """
        try:
            # Support both (user, token) and (secret, token) signatures
            secret: str
            user: Any | None = None
            if isinstance(user_or_secret, str):
                secret = user_or_secret
            else:
                user = user_or_secret
                if not getattr(user, "two_factor_enabled", False):
                    return False
                secret = cast(str, getattr(user, "two_factor_secret", ""))
            if not secret or not token:
                return False

            # Check if code was recently used (prevent replay)
            if user is not None:
                cache_key = f"totp_used:{user.id}:{token}"
                if cache.get(cache_key):
                    logger.warning("⚠️ [TOTP] Replay attempt detected")
                    return False

            # Verify with time window tolerance for clock drift
            totp = pyotp.TOTP(secret)
            if totp.verify(token, valid_window=TOTPService.TIME_WINDOW_TOLERANCE):
                # Mark token as used for 90 seconds (3 * 30-second periods)
                if user is not None:
                    cache.set(cache_key, True, 90)
                return True

            return False

        except Exception as e:
            logger.error(f"🔥 [TOTP] Verification error: {e}")
            return False

    @staticmethod
    def generate_qr_code(user: "User", secret: str) -> str:
        """
        📱 Generate QR code for authenticator app setup

        Returns:
            Base64-encoded PNG image data
        """
        try:
            # Generate TOTP provisioning URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=TOTPService.TOTP_ISSUER_NAME)

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
            qr_img.save(qr_buffer, "PNG")
            qr_data = base64.b64encode(qr_buffer.getvalue()).decode()

            logger.info(f"✅ [TOTP] QR code generated for {user.email}")
            return qr_data

        except Exception as e:
            logger.error(f"🔥 [TOTP] Failed to generate QR code for {user.email}: {e}")
            raise

    @staticmethod
    def generate_qr_code_url(user_email: str, secret: str, issuer: str | None = None) -> str:
        """Generate an otpauth provisioning URI."""
        issuer_name = issuer or TOTPService.TOTP_ISSUER_NAME
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=issuer_name)

    @staticmethod
    def generate_qr_code_image(user_email: str, secret: str) -> str | None:
        """Generate a data URL PNG for the provisioning URI.

        Returns data URL string or None on failure (tests expect graceful failure).
        """
        try:
            uri = TOTPService.generate_qr_code_url(user_email=user_email, secret=secret)
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf)
            data = base64.b64encode(buf.getvalue()).decode()
            return f"data:image/png;base64,{data}"
        except Exception as e:  # pragma: no cover - exercised by patched test
            logger.error(f"🔥 [TOTP] QR image generation failed: {e}")
            return None


# ===============================================================================
# BACKUP CODES SERVICE
# ===============================================================================


class BackupCodeService:
    """
    🎫 Backup Code Service

    Handles generation, verification, and management of backup codes for 2FA recovery.
    """

    BACKUP_CODES_COUNT = getattr(settings, "BACKUP_CODES_COUNT", 8)
    BACKUP_CODE_LENGTH = 8

    @staticmethod
    def generate_codes(user: "User") -> list[str]:
        """
        Generate new backup codes and store hashed versions in user model

        Returns:
            List of plain text backup codes (for one-time display)
        """
        codes = []
        hashed_codes = []

        for _ in range(BackupCodeService.BACKUP_CODES_COUNT):
            code = "".join(secrets.choice(string.digits) for _ in range(BackupCodeService.BACKUP_CODE_LENGTH))
            codes.append(code)
            hashed_codes.append(make_password(code))

        user.backup_tokens = hashed_codes
        return codes

    @staticmethod
    def verify_and_consume_code(user: "User", code: str) -> bool:
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
                user.save(update_fields=["backup_tokens"])
                return True

        return False

    @staticmethod
    def get_remaining_count(user: "User") -> int:
        """Get number of remaining backup codes"""
        return len(user.backup_tokens) if user.backup_tokens else 0


# ===============================================================================
# WEBAUTHN/PASSKEYS SERVICE
# ===============================================================================


class WebAuthnService:
    """
    🔐 WebAuthn/Passkeys Service

    Handles FIDO2/WebAuthn authentication for passwordless login.
    Unfinished scaffolding that fails closed (#596): without a verification library every
    verification is refused, and no login path calls it yet.
    """

    @staticmethod
    def _library_provides(function_name: str) -> bool:
        return webauthn is not None and hasattr(webauthn, function_name)

    @staticmethod
    def is_supported() -> bool:
        """True only when a WebAuthn verification library is importable."""
        return WebAuthnService._library_provides("verify_authentication_response")

    @staticmethod
    def generate_registration_options(request: HttpRequest, user: "User") -> dict[str, Any]:
        """
        Generate WebAuthn registration options for a user

        Args:
            user: User to generate options for

        Returns:
            WebAuthn registration options or None if not supported
        """
        # Generate a random challenge and exclude existing credentials
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        request.session["webauthn_challenge"] = challenge

        existing = WebAuthnCredential.objects.filter(user=user).values_list("credential_id", flat=True)
        options: dict[str, Any] = {
            "challenge": challenge,
            "rp": {
                "name": getattr(settings, "TOTP_ISSUER_NAME", "PRAHO Platform"),
            },
            "user": {
                "id": str(user.pk),
                "name": user.email,
                "displayName": user.get_full_name(),
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "excludeCredentials": [{"type": "public-key", "id": cred_id} for cred_id in existing],
        }
        return options

    @staticmethod
    def verify_registration(user: "User", credential_data: dict[str, Any]) -> bool:
        """Refuse: a structure check proves nothing about the key (#596).

        It used to store any well-formed payload with public_key="unknown". Registration
        goes through verify_registration_response, which needs a verification library.
        """
        logger.warning(f"📱 [WebAuthn] Unverified registration refused for {user.email}")
        return False

    @staticmethod
    def generate_authentication_options(request: HttpRequest, user: "User") -> dict[str, Any]:
        """
        Generate WebAuthn authentication options

        Args:
            user: User to authenticate

        Returns:
            WebAuthn authentication options or None
        """
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        request.session["webauthn_challenge"] = challenge
        creds = WebAuthnCredential.objects.filter(user=user, is_active=True)
        options: dict[str, Any] = {
            "challenge": challenge,
            "allowCredentials": [{"type": "public-key", "id": c.credential_id} for c in creds],
            "userVerification": "preferred",
        }
        return options

    @staticmethod
    def verify_authentication(request: HttpRequest, user: "User", authentication_data: dict[str, Any]) -> bool:
        """
        Verify a WebAuthn assertion against the challenge this server issued.

        Fails closed: no stored challenge, no verification library, an unverified result or a
        signature counter that did not advance all refuse. The challenge is popped from the
        session, so each one is single-use, and the new counter comes from the verified result,
        never from the client.
        """
        challenge = request.session.pop("webauthn_challenge", None)
        if not challenge or not WebAuthnService.is_supported():
            return False

        try:
            credential_id = authentication_data.get("id")
            credential = WebAuthnCredential.objects.filter(
                user=user, credential_id=credential_id, is_active=True
            ).first()
            if not credential_id or credential is None:
                logger.warning(f"📱 [WebAuthn] Unknown credential for {user.email}")
                return False

            result = webauthn.verify_authentication_response(
                authentication_data,
                expected_credential_public_key=credential.public_key,
                expected_challenge=challenge,
            )
            new_sign_count = result.get("new_sign_count") if result and result.get("verified") else None
            if type(new_sign_count) is not int:
                logger.warning(f"📱 [WebAuthn] Authentication verification failed for {user.email}")
                return False
            if credential.sign_count > 0 and new_sign_count <= credential.sign_count:
                logger.error(f"📱 [WebAuthn] Signature counter did not advance for {user.email}")
                return False

            credential.sign_count = new_sign_count
            credential.last_used = timezone.now()
            credential.save(update_fields=["last_used", "sign_count"])
            logger.info(f"✅ [WebAuthn] Authentication verified for {user.email}")
            return True

        except Exception as e:
            logger.error(f"🔥 [WebAuthn] Authentication verification error for {user.email}: {e}")
            return False

    @staticmethod
    def get_user_credentials(user: "User", *, include_inactive: bool = False) -> list["WebAuthnCredential"]:
        qs = WebAuthnCredential.objects.filter(user=user)
        if not include_inactive:
            qs = qs.filter(is_active=True)
        return list(qs)

    @staticmethod
    def delete_credential(user: "User", credential_identifier: int | str) -> bool:
        try:
            if isinstance(credential_identifier, int):
                cred = WebAuthnCredential.objects.get(pk=credential_identifier, user=user)
            else:
                cred = WebAuthnCredential.objects.get(credential_id=credential_identifier, user=user)
            with transaction.atomic():
                cred.delete()
                MFAService.apply_state_change(user, action="rotate")
            return True
        except WebAuthnCredential.DoesNotExist:
            return False

    @staticmethod
    def verify_registration_response(
        request: HttpRequest, registration_data: dict[str, Any], device_name: str
    ) -> dict[str, Any]:
        """Verify a registration response and persist a credential.

        A minimal shim around a `webauthn` verification library (patched in tests). Without
        the library, a server-issued challenge or a verified public key, nothing is stored.
        """
        refused: dict[str, Any] = {"success": False, "error": "Registration verification failed"}
        # Single-use, and only ever the challenge this server issued (#596).
        challenge = request.session.pop("webauthn_challenge", None)
        if not challenge or not WebAuthnService._library_provides("verify_registration_response"):
            return refused
        try:
            result = webauthn.verify_registration_response(registration_data, challenge=challenge)
            public_key = result.get("credential_public_key") if result and result.get("verified") else None
            if isinstance(public_key, bytes):
                public_key = base64.b64encode(public_key).decode()
            credential_id = registration_data.get("id")
            if not public_key or not isinstance(public_key, str) or not credential_id:
                return refused

            with transaction.atomic():
                cred = WebAuthnCredential.objects.create(
                    user=cast("User", request.user),
                    credential_id=credential_id,
                    public_key=public_key,
                    name=device_name,
                    sign_count=int(result.get("sign_count") or 0),
                    is_active=True,
                )
                MFAService.apply_state_change(cred.user, action="rotate")
            return {"success": True, "credential": cred}
        except Exception as e:  # pragma: no cover
            logger.error(f"🔥 [WebAuthn] Registration response verification error: {e}")
            return {"success": False, "error": "Internal error"}


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
    def apply_state_change(
        user: "User",
        *,
        action: Literal["enable", "disable", "recover", "rotate"],
        audit_event: TwoFactorAuditRequest | None = None,
    ) -> None:
        """Persist MFA state and its revocation version in one transaction.

        "rotate" bumps the version without touching the TOTP fields: a WebAuthn credential was
        added or removed, which changes what the account accepts as a second factor.

        "recover" (a password reset) bumps the version but keeps enrolled MFA, as the API reset
        does: a reset link proves control of the mailbox, not of the second factor. Only a
        leftover secret on an account without 2FA is dropped.
        """
        from .models import UserCredentialVersion  # noqa: PLC0415

        if action not in {"enable", "disable", "recover", "rotate"}:
            raise ValueError("Unsupported MFA state change")
        with transaction.atomic():
            # Serialize first-row creation and coordinate with enrollment API locks.
            locked_user = User.objects.select_for_update().get(pk=user.pk)
            if action == "enable" and locked_user.two_factor_enabled:
                raise ValueError("TOTP/2FA is already enabled for this user")
            credential_version, _created = UserCredentialVersion.objects.select_for_update().get_or_create(
                user_id=user.pk
            )
            if action == "recover":
                if not locked_user.two_factor_enabled:
                    user.two_factor_secret = ""
                    user.save(update_fields=["_two_factor_secret"])
            elif action != "rotate":
                user.two_factor_enabled = action == "enable"
                if action != "enable":
                    user.two_factor_secret = ""
                    user.backup_tokens = []
                if audit_event is None:
                    user.save(update_fields=["two_factor_enabled", "_two_factor_secret", "backup_tokens"])
                else:
                    # A detailed service event replaces the model signal's generic event.
                    User.objects.filter(pk=user.pk).update(
                        two_factor_enabled=user.two_factor_enabled,
                        _two_factor_secret=user._two_factor_secret,
                        backup_tokens=user.backup_tokens,
                    )
            UserCredentialVersion.objects.filter(pk=credential_version.pk).update(version=models.F("version") + 1)
            credential_version.refresh_from_db(fields=["version"])
            if audit_event is not None:
                AuditService.log_2fa_event(audit_event)
        # Replace a previously cached version (including a cached missing row).
        user.credential_version = credential_version

    @staticmethod
    def enable_totp(
        user: "User", request: HttpRequest | None = None, *, secret: str | None = None
    ) -> tuple[str, list[str]]:
        """
        🔐 Enable TOTP/2FA for user with audit logging

        Returns:
            Tuple of (totp_secret, backup_codes)
        """
        try:
            if user.two_factor_enabled:
                raise ValueError("TOTP/2FA is already enabled for this user")

            # Preserve the verified enrollment secret when supplied by a web view.
            secret = secret or TOTPService.generate_secret()
            user.two_factor_secret = secret

            backup_codes = BackupCodeService.generate_codes(user)

            # 📊 Audit log the enablement
            metadata = {
                "method": "TOTP",
                "backup_codes_generated": len(backup_codes),
                "timestamp": timezone.now().isoformat(),
            }

            if request:
                metadata.update(
                    {
                        "session_id": request.session.session_key,
                        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                    }
                )

            MFAService.apply_state_change(
                user,
                action="enable",
                audit_event=TwoFactorAuditRequest(
                    event_type="2fa_enabled",
                    user=user,
                    context=AuditContext(
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
                        metadata=metadata,
                    ),
                    description=f"TOTP/2FA enabled for user {user.email}",
                ),
            )

            logger.info(f"✅ [MFA] TOTP enabled for user {user.email}")
            return secret, backup_codes

        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to enable TOTP for user {user.email}: {e}")
            raise

    @staticmethod
    def disable_totp(
        user: "User",
        admin_user: Union["User", None] = None,
        reason: str | None = None,
        request: HttpRequest | None = None,
    ) -> bool:
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

            # 📊 Audit log the disablement
            metadata = {
                "timestamp": timezone.now().isoformat(),
                "reason": reason or "User requested",
            }

            event_type = "2fa_disabled"
            description = f"TOTP/2FA disabled for user {user.email}"

            if admin_user and admin_user != user:
                metadata.update(
                    {
                        "admin_id": str(admin_user.id),
                        "admin_email": admin_user.email,
                    }
                )
                event_type = "2fa_admin_reset"
                description = f"TOTP/2FA disabled by admin {admin_user.email} for user {user.email}"

            MFAService.apply_state_change(
                user,
                action="disable",
                audit_event=TwoFactorAuditRequest(
                    event_type=event_type,
                    user=user,
                    context=AuditContext(
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
                        metadata=metadata,
                    ),
                    description=description,
                ),
            )

            logger.warning(
                f"⚠️ [MFA] TOTP disabled for user {user.email} by {admin_user.email if admin_user else 'self'}"
            )
            return True

        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to disable TOTP for user {user.email}: {e}")
            raise

    @staticmethod
    def generate_backup_codes(user: "User", request: HttpRequest | None = None) -> list[str]:
        """
        🎫 Generate new backup codes with audit
        """
        try:
            if not user.two_factor_enabled:
                raise ValueError("TOTP/2FA must be enabled to generate backup codes")

            codes = BackupCodeService.generate_codes(user)
            user.save()

            # 📊 Audit log generation
            AuditService.log_2fa_event(
                TwoFactorAuditRequest(
                    event_type="2fa_backup_codes_generated",
                    user=user,
                    context=AuditContext(
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
                        metadata={
                            "count": len(codes),
                            "timestamp": timezone.now().isoformat(),
                            "previous_codes_invalidated": True,
                        },
                    ),
                )
            )

            logger.info(f"✅ [MFA] Generated {len(codes)} backup codes for {user.email}")
            return codes

        except Exception as e:
            logger.error(f"🔥 [MFA] Failed to generate backup codes for {user.email}: {e}")
            raise

    @staticmethod
    def verify_mfa_code(user: "User", code: str, request: HttpRequest | None = None) -> dict[str, Any]:
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
        result: dict[str, Any] = {
            "success": False,
            "method": None,
            "remaining_backup_codes": BackupCodeService.get_remaining_count(user),
            "rate_limited": False,
            "replay_detected": False,
        }

        try:
            if not user.two_factor_enabled:
                raise ValueError("MFA is not enabled for this user")

            # Rate limiting check
            if not MFAService._check_rate_limit(user):
                result["rate_limited"] = True
                logger.warning(f"⚠️ [MFA] Rate limit exceeded for user {user.email}")
                return result

            # Check if it's a TOTP code (6 digits)
            if len(code) == TOTPService.TOTP_DIGITS and code.isdigit():
                success = TOTPService.verify_token(user, code, request)
                if success:
                    result.update({"success": True, "method": "totp"})

            # Check if it's a backup code (8 digits)
            elif len(code) == BackupCodeService.BACKUP_CODE_LENGTH and code.isdigit():
                success = BackupCodeService.verify_and_consume_code(user, code)
                if success:
                    result.update(
                        {
                            "success": True,
                            "method": "backup_code",
                            "remaining_backup_codes": BackupCodeService.get_remaining_count(user),
                        }
                    )

                    # 📊 Audit backup code usage
                    AuditService.log_2fa_event(
                        TwoFactorAuditRequest(
                            event_type="2fa_backup_code_used",
                            user=user,
                            context=AuditContext(
                                ip_address=request.META.get("REMOTE_ADDR") if request else None,
                                user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
                                metadata={
                                    "remaining_codes": result["remaining_backup_codes"],
                                    "timestamp": timezone.now().isoformat(),
                                },
                            ),
                        )
                    )

            # 📊 Audit verification attempt
            event_type = "2fa_verification_success" if result["success"] else "2fa_verification_failed"
            AuditService.log_2fa_event(
                TwoFactorAuditRequest(
                    event_type=event_type,
                    user=user,
                    context=AuditContext(
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
                        metadata={
                            "method": result["method"],
                            "timestamp": timezone.now().isoformat(),
                            "rate_limited": result["rate_limited"],
                            "replay_detected": result["replay_detected"],
                        },
                    ),
                )
            )

            if result["success"]:
                logger.info(f"✅ [MFA] Successful {result['method']} verification for {user.email}")
            else:
                logger.warning(f"⚠️ [MFA] Failed verification for {user.email}")

            return result

        except Exception as e:
            logger.error(f"🔥 [MFA] Verification error for {user.email}: {e}")
            result["success"] = False
            return result

    @staticmethod
    def generate_qr_code(user: "User", secret: str) -> str:
        """
        📱 Generate QR code for TOTP setup

        Returns:
            Base64-encoded PNG image data
        """
        return TOTPService.generate_qr_code(user, secret)

    @staticmethod
    def get_user_mfa_status(user: "User") -> dict[str, Any]:
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
            "totp_enabled": user.two_factor_enabled,
            "backup_codes_count": BackupCodeService.get_remaining_count(user),
            "webauthn_credentials": user.webauthn_credentials.filter(is_active=True).count()
            if hasattr(user, "webauthn_credentials")
            else 0,
            "methods_available": MFAService._get_available_methods(user),
        }

    # Public helpers used by views and tests
    @staticmethod
    def is_mfa_enabled(user: "User") -> bool:
        return bool(
            user.two_factor_enabled
            or BackupCodeService.get_remaining_count(user) > 0
            or (hasattr(user, "webauthn_credentials") and user.webauthn_credentials.filter(is_active=True).exists())
        )

    @staticmethod
    def get_enabled_methods(user: "User") -> list[str]:
        return MFAService._get_available_methods(user)

    @staticmethod
    def verify_second_factor(request: HttpRequest, user: "User", method: str, token: str) -> dict[str, Any]:
        """Verify the provided second-factor token for the given method."""
        result: dict[str, Any] = {"success": False}

        # Rate limiting
        if not MFAService._check_rate_limit(user):
            result["error"] = "Rate limit exceeded"
            # Generic audit for compatibility with enhanced tests
            AuditService.log_simple_event(
                event_type="mfa_verification_failed", user=user, metadata={"reason": "rate_limited"}
            )
            return result

        try:
            if method == "totp":
                ok = TOTPService.verify_token(user, token, request)
                result.update({"success": ok, "method": "totp"})
            elif method == "backup_code":
                ok = (
                    user.verify_backup_code(token)
                    if hasattr(user, "verify_backup_code")
                    else BackupCodeService.verify_and_consume_code(user, token)
                )
                result.update({"success": ok, "method": "backup_code"})
            else:
                result["error"] = f"Unsupported MFA method: {method}"
                AuditService.log_simple_event(
                    event_type="mfa_verification_failed", user=user, metadata={"method": method}
                )
                return result

            # Audit via generic interface for tests
            AuditService.log_simple_event(
                event_type="mfa_verification_success" if result["success"] else "mfa_verification_failed",
                user=user,
                metadata={"method": method, "ip": request.META.get("REMOTE_ADDR")},
            )
            if not result["success"]:
                result["error"] = "Invalid MFA token"
            return result
        except Exception as e:  # pragma: no cover
            logger.error(f"🔥 [MFA] verify_second_factor error: {e}")
            result["error"] = "Internal error"
            return result

    @staticmethod
    def disable_all_mfa_methods(request: HttpRequest, user: "User") -> dict[str, Any]:
        """Disable TOTP, clear backup codes, and remove WebAuthn credentials."""
        try:
            with transaction.atomic():
                MFAService.apply_state_change(user, action="disable")
                WebAuthnCredential.objects.filter(user=user).delete()
            AuditService.log_simple_event(
                event_type="mfa_disabled", user=user, metadata={"by": getattr(request.user, "email", None)}
            )
            return {"success": True}
        except Exception as e:  # pragma: no cover
            logger.error(f"🔥 [MFA] disable_all_mfa_methods error: {e}")
            return {"success": False, "error": "Internal error"}

    # ===============================================================================
    # PRIVATE HELPER METHODS
    # ===============================================================================

    @staticmethod
    def _check_rate_limit(user: "User") -> bool:
        """
        🚦 Rate limit MFA verification attempts
        """
        cache_key = f"mfa_attempts:{user.id}"
        attempts = cache.get(cache_key, 0)

        if attempts >= MAX_LOGIN_ATTEMPTS:  # Max attempts per 5 minutes
            logger.error(f"🔥 [MFA] Rate limit exceeded for user {user.email}")
            return False

        cache.set(cache_key, attempts + 1, 300)  # 5 minute window
        return True

    @staticmethod
    def _reset_rate_limit(user: "User") -> None:
        """Give back the attempt budget after a verified login, so honest logins never drain it."""
        cache.delete(f"mfa_attempts:{user.id}")

    @staticmethod
    def _get_available_methods(user: "User") -> list[str]:
        """Get list of available MFA methods for user"""
        methods = []

        if user.two_factor_enabled:
            methods.append("totp")

        if BackupCodeService.get_remaining_count(user) > 0:
            methods.append("backup_codes")

        if WebAuthnService.is_supported() and WebAuthnCredential.objects.filter(user=user, is_active=True).exists():
            methods.append("webauthn")

        return methods


# ===============================================================================
# LOGIN SECOND FACTOR (shared by every login path)
# ===============================================================================


# The staff web login sets this request attribute to "2fa_totp" or "2fa_backup_code" just
# before login(); the user_logged_in audit handler reads it as the authentication method.
LOGIN_METHOD_REQUEST_ATTR = "_praho_2fa_method"


@dataclass(frozen=True)
class SecondFactorResult:
    """Outcome of one login second-factor check.

    rate_limited means the per-user attempt budget was exhausted and the code was never
    checked; it is still a failure and has already been charged to the lockout.
    """

    accepted: bool
    method: Literal["totp", "backup_code"] | None
    rate_limited: bool


def verify_login_second_factor(locked_user: "User", code: str, request: HttpRequest | None) -> SecondFactorResult:
    """Check a TOTP or backup code at login; a failure counts toward the account lockout.

    Shared by portal_login_api, obtain_token and the staff web mfa_verify, so every login
    path accepts exactly the same codes. The caller holds select_for_update on locked_user
    inside the transaction it lets commit on failure, because the failed attempt is meant to
    count: reaching this check took the correct password, so the failure is attributable.
    """
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("verify_login_second_factor needs the caller's row lock inside a transaction")

    if code:
        outcome = MFAService.verify_mfa_code(locked_user, code, request)
        if outcome["success"]:
            MFAService._reset_rate_limit(locked_user)
            return SecondFactorResult(accepted=True, method=outcome["method"], rate_limited=False)
        rate_limited = bool(outcome["rate_limited"])
    else:
        rate_limited = False
    locked_user.increment_failed_login_attempts()
    return SecondFactorResult(accepted=False, method=None, rate_limited=rate_limited)


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
