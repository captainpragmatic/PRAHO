# ===============================================================================
# USER API SERIALIZERS 🔐
# ===============================================================================

import io
import logging
import re
import time
from typing import TYPE_CHECKING, Any, cast

import pyotp
import qrcode
import qrcode.image.svg
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django_q.tasks import async_task
from rest_framework import serializers

from apps.common.localisation import DATE_FORMAT_CHOICES, LANGUAGE_CHOICES
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event
from apps.users.mfa import MFAService

if TYPE_CHECKING:
    from apps.users.models import User

User = get_user_model()

# 2FA Token length constants
TOTP_TOKEN_LENGTH = 6  # Standard TOTP tokens are 6 digits
BACKUP_CODE_LENGTH = 8  # Backup codes are 8 digits

logger = logging.getLogger(__name__)


# ===============================================================================
# API TOKEN SERIALIZERS 🔑
# ===============================================================================


class StrictCharField(serializers.CharField):
    """CharField that rejects non-string input instead of coercing numbers to text."""

    def to_internal_value(self, data: Any) -> str:
        if not isinstance(data, str):
            self.fail("invalid")
        return cast(str, super().to_internal_value(data))


class TokenObtainRequestSerializer(serializers.Serializer):
    """
    Validates the optional token-shaping fields of obtain_token (ADR-0031).

    email/password are checked by the credential flow before this runs; this
    guards the fields that reach storage and security logs. The name feeds
    security log lines verbatim, so control characters are rejected to prevent
    forged log entries (CWE-117).
    """

    name = StrictCharField(required=False, default="default", max_length=100)
    description = StrictCharField(required=False, default="", allow_blank=True, max_length=500)
    ttl_days = serializers.IntegerField(required=False, allow_null=True, min_value=1)

    def validate_name(self, value: str) -> str:
        if not value.isprintable():
            raise serializers.ValidationError(_("Token name must not contain control characters."))
        return value


# ===============================================================================
# TWO-FACTOR AUTHENTICATION SERIALIZERS 📱
# ===============================================================================


class MFASetupSerializer(serializers.Serializer):
    """
    Serializer for 2FA setup initialization.
    Generates QR code and secret for authenticator app setup.
    """

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Generate 2FA secret and QR code for user.
        """
        user = self.context["user"]

        # Generate new secret
        secret = pyotp.random_base32()

        # Store secret temporarily (not enabled yet)
        user.two_factor_secret = secret
        user.save(update_fields=["_two_factor_secret"])

        # Generate QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="PRAHO Platform")

        # Create QR code as SVG
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Generate SVG image
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        svg_io = io.BytesIO()
        img.save(svg_io)
        svg_content = svg_io.getvalue().decode("utf-8")

        logger.info(f"🔐 [2FA Setup] Secret generated for user: {user.email}")

        return {
            "secret": secret,
            "qr_code_svg": svg_content,
            "provisioning_uri": provisioning_uri,
            "manual_entry_key": secret,
        }


class MFAVerifySerializer(serializers.Serializer):
    """
    Serializer for 2FA token verification during setup.
    """

    token = serializers.CharField(max_length=8, min_length=6)

    def validate_token(self, value: str) -> str:
        """Validate token format"""
        if not value.isdigit():
            raise serializers.ValidationError(_("Token must contain only digits."))
        if len(value) == BACKUP_CODE_LENGTH and not self.context["user"].two_factor_enabled:
            raise serializers.ValidationError(_("Finish setup with the 6-digit code."))
        return value

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Verify 2FA token and enable 2FA for user.
        """
        user = self.context["user"]
        token = validated_data["token"]

        if not user.two_factor_secret:
            raise serializers.ValidationError(_("2FA setup not initialized. Please start setup first."))

        # Verify token
        totp = pyotp.TOTP(user.two_factor_secret)

        # Check if it's a 6-digit TOTP token
        if len(token) == TOTP_TOKEN_LENGTH:
            if totp.verify(token, valid_window=1):  # Allow 30 seconds window
                with transaction.atomic():
                    backup_codes = user.generate_backup_codes()
                    MFAService.apply_state_change(user, action="enable")

                logger.info(f"✅ [2FA] Two-factor authentication enabled for user: {user.email}")

                return {"success": True, "message": "2FA enabled successfully", "backup_codes": backup_codes}
            else:
                raise serializers.ValidationError(_("Invalid verification code. Please try again."))

        # Check if it's an 8-digit backup code
        elif len(token) == BACKUP_CODE_LENGTH:
            if user.verify_backup_code(token):
                logger.info(f"✅ [2FA] Backup code used for user: {user.email}")
                return {
                    "success": True,
                    "message": "Backup code verified successfully",
                    "backup_codes_remaining": len(user.backup_tokens),
                }
            else:
                raise serializers.ValidationError(_("Invalid backup code."))

        else:
            raise serializers.ValidationError(_("Invalid token length."))


class MFADisableSerializer(serializers.Serializer):
    """
    Serializer for disabling 2FA.
    """

    token = serializers.CharField(max_length=8, min_length=6)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate password and 2FA token"""
        user = self.context["user"]

        # Verify password
        if not user.check_password(data["password"]):
            raise serializers.ValidationError(_("Invalid password."))

        # Verify 2FA token
        token = data["token"]
        if not user.two_factor_enabled:
            raise serializers.ValidationError(_("2FA is not enabled for this account."))

        # Verify current token
        if not MFAService.verify_mfa_code(user, token, self.context.get("request"))["success"]:
            raise serializers.ValidationError(_("Invalid verification code."))

        return data

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Disable 2FA for user.
        """
        user = self.context["user"]

        MFAService.apply_state_change(user, action="disable")

        logger.warning(f"⚠️ [2FA] Two-factor authentication disabled for user: {user.email}")

        return {"success": True, "message": "2FA disabled successfully"}


# ===============================================================================
# PASSWORD RESET SERIALIZERS 🔑
# ===============================================================================


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset requests.
    """

    email = serializers.EmailField()

    @staticmethod
    def accepted_response() -> dict[str, Any]:
        """Acknowledge the request without exposing account or delivery status."""
        return {
            "success": True,
            "message": str(
                _(
                    "If an eligible account exists and email delivery is available, "
                    "you will receive password reset instructions."
                )
            ),
        }

    def validate_email(self, value: str) -> str:
        """Normalize email"""
        return value.lower().strip()

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """Queue the reset mail. The same work for every address: no account lookup here.

        A worker looks the account up and sends the mail (apps.users.tasks.send_password_reset_email),
        so neither the answer nor its timing says whether the address has an account.
        """
        from apps.users.services import portal_public_origin  # noqa: PLC0415

        portal_public_origin()
        # ack_failure: a failed send is never redelivered hours later (see the task).
        async_task("apps.users.tasks.send_password_reset_email", validated_data["email"], time.time(), ack_failure=True)
        return self.accepted_response()


class RegistrationConfirmSerializer(serializers.Serializer):
    """What the mailbox holder supplies to finish a pending registration."""

    registration_id = serializers.UUIDField()
    token = serializers.CharField(max_length=128, write_only=True)
    password = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)
    password_confirm = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)
    data_processing_consent = serializers.BooleanField()
    marketing_consent = serializers.BooleanField(default=False)

    def validate_data_processing_consent(self, value: bool) -> bool:
        if not value:
            raise serializers.ValidationError(_("Data processing consent is required."))
        return value

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": _("Passwords do not match.")})
        return data


class InvalidPasswordResetLink(serializers.ValidationError):
    default_detail = _("Invalid or expired reset link.")
    default_code = "invalid_reset_link"


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    """

    token = serializers.CharField(max_length=128, write_only=True)
    uid = serializers.CharField(max_length=128)
    new_password = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)
    new_password_confirm = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate matching passwords, the reset token, and password policy."""
        if data["new_password"] != data["new_password_confirm"]:
            raise serializers.ValidationError(_("Passwords do not match."))

        user = data["uid"]
        if not default_token_generator.check_token(user, data["token"]):
            raise serializers.ValidationError({"token": _("Invalid or expired reset link.")})
        try:
            validate_password(data["new_password"], user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"new_password": exc.messages}) from exc
        return data

    def validate_uid(self, value: str) -> "User":
        """Validate UID and get user"""
        try:
            uid = force_str(urlsafe_base64_decode(value))
            user = User.objects.get(pk=uid, is_active=True)
            return user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise InvalidPasswordResetLink() from None

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Reset user password with valid token.
        """
        token = validated_data["token"]
        new_password = validated_data["new_password"]
        with transaction.atomic():
            try:
                user = User.objects.select_for_update().get(pk=validated_data["uid"].pk, is_active=True)
            except User.DoesNotExist:
                raise InvalidPasswordResetLink() from None
            # Recheck against the locked row: a simultaneous reset may have consumed it.
            if not default_token_generator.check_token(user, token):
                raise InvalidPasswordResetLink()
            try:
                validate_password(new_password, user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError({"new_password": exc.messages}) from exc
            user.set_password(new_password)
            user.failed_login_attempts = 0
            user.account_locked_until = None
            fields = ["password", "failed_login_attempts", "account_locked_until"]
            # Password recovery does not replace the second factor.
            if not user.two_factor_enabled:
                user.two_factor_secret = ""
                fields.append("_two_factor_secret")
            user.save(update_fields=fields)
            request = self.context.get("request")
            log_security_event(
                "password_reset_completed", {"user_id": user.pk}, get_safe_client_ip(request) if request else None
            )

        logger.info(f"✅ [Password Reset] Password reset completed for user: {user.email}")

        return {"success": True, "message": "Password reset successfully. You can now login with your new password."}


class ProfileUpdateSerializer(serializers.Serializer):
    """Validate the entire profile update before either user or profile is saved."""

    first_name = serializers.CharField(required=False, allow_blank=True, max_length=30)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=30)
    phone = serializers.CharField(required=False, allow_blank=True, max_length=20)
    preferred_language = serializers.ChoiceField(choices=LANGUAGE_CHOICES, required=False, allow_blank=True)
    timezone = serializers.CharField(required=False, allow_blank=True, max_length=50)
    date_format = serializers.ChoiceField(choices=DATE_FORMAT_CHOICES, required=False, allow_blank=True)
    email_notifications = serializers.BooleanField(required=False)
    sms_notifications = serializers.BooleanField(required=False)
    marketing_emails = serializers.BooleanField(required=False)

    def validate_phone(self, value: str) -> str:
        """Keep the same phone contract across both profile endpoints."""
        normalized = re.sub(r"[\s.]", "", value)
        if normalized and not re.fullmatch(r"(?:\+40|0)[0-9]{9}", normalized):
            raise serializers.ValidationError(_("Invalid Romanian phone number format."))
        return normalized

    def validate_timezone(self, value: str) -> str:
        from apps.common.localisation import validate_timezone  # noqa: PLC0415

        validate_timezone(value)
        return value

    def update(self, instance: "User", validated_data: dict[str, Any]) -> "User":
        from apps.users.models import UserProfile  # noqa: PLC0415  # Runtime cross-app dependency

        with transaction.atomic():
            profile, _created = UserProfile.objects.get_or_create(user=instance)
            user_fields = {"first_name", "last_name", "phone"}
            for key, value in validated_data.items():
                setattr(instance if key in user_fields else profile, key, value)
            changed_user_fields = sorted(user_fields.intersection(validated_data))
            if changed_user_fields:
                instance.save(update_fields=changed_user_fields)
            changed_profile_fields = sorted(set(validated_data).difference(user_fields))
            if changed_profile_fields:
                profile.save(update_fields=[*changed_profile_fields, "updated_at"])
        # Replace any previously cached reverse relation before serializing the response.
        instance.profile = profile
        return instance
