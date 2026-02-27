# ===============================================================================
# USER API SERIALIZERS 🔐
# ===============================================================================

import io
import logging
from typing import Any

import pyotp
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

User = get_user_model()

# 2FA Token length constants
TOTP_TOKEN_LENGTH = 6  # Standard TOTP tokens are 6 digits
BACKUP_CODE_LENGTH = 8  # Backup codes are 8 digits

logger = logging.getLogger(__name__)


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
        user = self.context["request"].user

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
        return value

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Verify 2FA token and enable 2FA for user.
        """
        user = self.context["request"].user
        token = validated_data["token"]

        if not user.two_factor_secret:
            raise serializers.ValidationError(_("2FA setup not initialized. Please start setup first."))

        # Verify token
        totp = pyotp.TOTP(user.two_factor_secret)

        # Check if it's a 6-digit TOTP token
        if len(token) == TOTP_TOKEN_LENGTH:
            if totp.verify(token, valid_window=1):  # Allow 30 seconds window
                # Enable 2FA
                user.two_factor_enabled = True

                # Generate backup codes
                backup_codes = user.generate_backup_codes()
                user.save()

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
    password = serializers.CharField(write_only=True)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate password and 2FA token"""
        user = self.context["request"].user

        # Verify password
        if not user.check_password(data["password"]):
            raise serializers.ValidationError(_("Invalid password."))

        # Verify 2FA token
        token = data["token"]
        if not user.two_factor_enabled:
            raise serializers.ValidationError(_("2FA is not enabled for this account."))

        # Verify current token
        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(token, valid_window=1) and (
            (len(token) == BACKUP_CODE_LENGTH and not user.verify_backup_code(token))
            or len(token) != BACKUP_CODE_LENGTH
        ):
            raise serializers.ValidationError(_("Invalid verification code."))

        return data

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Disable 2FA for user.
        """
        user = self.context["request"].user

        # Disable 2FA
        user.two_factor_enabled = False
        user.two_factor_secret = ""
        user.backup_tokens = []
        user.save(update_fields=["two_factor_enabled", "_two_factor_secret", "backup_tokens"])

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

    def validate_email(self, value: str) -> str:
        """Normalize email"""
        return value.lower().strip()

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Send password reset email if user exists.
        """
        email = validated_data["email"]

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            # Don't reveal if user exists or not for security
            logger.warning(f"🚨 [Password Reset] Reset requested for non-existent email: {email}")
            return {"success": True, "message": "If the email exists, a reset link has been sent."}

        # Generate reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Prepare email context
        context = {
            "user": user,
            "domain": getattr(settings, "DOMAIN_NAME", "localhost:8700"),
            "uid": uid,
            "token": token,
            "protocol": "https" if getattr(settings, "USE_HTTPS", False) else "http",
        }

        # Render email templates
        subject = _("Password Reset Request - PRAHO Platform")
        text_message = render_to_string("users/emails/password_reset.txt", context)
        html_message = render_to_string("users/emails/password_reset.html", context)

        try:
            # Send email
            send_mail(
                subject=subject,
                message=text_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )

            logger.info(f"📧 [Password Reset] Reset email sent to: {user.email}")

        except Exception as e:
            logger.error(f"🔥 [Password Reset] Failed to send email to {user.email}: {e}")
            raise serializers.ValidationError(_("Failed to send reset email. Please try again later.")) from e

        return {"success": True, "message": "If the email exists, a reset link has been sent."}


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    """

    token = serializers.CharField()
    uid = serializers.CharField()
    new_password = serializers.CharField(min_length=12, write_only=True)
    new_password_confirm = serializers.CharField(min_length=12, write_only=True)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate passwords match"""
        if data["new_password"] != data["new_password_confirm"]:
            raise serializers.ValidationError(_("Passwords do not match."))
        return data

    def validate_uid(self, value: str) -> Any:
        """Validate UID and get user"""
        try:
            uid = force_str(urlsafe_base64_decode(value))
            user = User.objects.get(pk=uid, is_active=True)
            return user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError(_("Invalid reset link.")) from None

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Reset user password with valid token.
        """
        user = validated_data["uid"]  # Already validated to be User object
        token = validated_data["token"]
        new_password = validated_data["new_password"]

        # Verify token
        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError(_("Invalid or expired reset link."))

        # Reset password
        user.set_password(new_password)
        user.save()

        # Clear any 2FA setup in progress (security measure)
        if not user.two_factor_enabled:
            user.two_factor_secret = ""
            user.save(update_fields=["_two_factor_secret"])

        logger.info(f"✅ [Password Reset] Password reset completed for user: {user.email}")

        return {"success": True, "message": "Password reset successfully. You can now login with your new password."}
