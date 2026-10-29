# ===============================================================================
# USER API SERIALIZERS 🔐
# ===============================================================================

import io
import logging
import time
from typing import TYPE_CHECKING, Any, cast

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

from apps.common.identity_fields import normalize_phone
from apps.common.localisation import DATE_FORMAT_CHOICES, LANGUAGE_CHOICES
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event
from apps.settings.services import get_brand_name
from apps.users.credentials import check_password_locked, proof_passed
from apps.users.mfa import MFAService, TOTPService
from apps.users.pending_totp import discard as discard_pending_totp
from apps.users.pending_totp import get_or_create_pending
from apps.users.security_notices import notify_credential_change

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
        """The pending enrolment's secret and its QR code (ADR-0058).

        The same secret comes back on every call until it is confirmed or expires, so the page
        the Portal shows again after a mistyped code still matches the app the customer scanned.
        Nothing is written to the user row until the enrolment is confirmed.
        """
        user = self.context["user"]
        secret = get_or_create_pending(user)

        # Generate QR code: customers see the brand in their authenticator app; staff see "PRAHO Platform"
        provisioning_uri = TOTPService.generate_qr_code_url(user.email, secret, issuer=get_brand_name())

        # Create QR code as SVG
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Generate SVG image
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        svg_io = io.BytesIO()
        img.save(svg_io)
        svg_content = svg_io.getvalue().decode("utf-8")

        logger.info(f"🔐 [2FA Setup] Pending secret offered to user: {user.email}")

        return {
            "secret": secret,
            "qr_code_svg": svg_content,
            "provisioning_uri": provisioning_uri,
            "manual_entry_key": secret,
        }


class MFAVerifySerializer(serializers.Serializer):
    """Confirming setup: a 6-digit code from the app and the current password (#689).

    Only the shape is checked here. complete_enrolment checks both values on the locked row.
    """

    token = serializers.RegexField(
        regex=rf"^\d{{{TOTP_TOKEN_LENGTH}}}$",
        error_messages={"invalid": _("Enter the 6-digit code from your authenticator app.")},
    )
    password = serializers.CharField(write_only=True, trim_whitespace=False)


class MFADisableSerializer(serializers.Serializer):
    """
    Serializer for disabling 2FA.
    """

    token = serializers.CharField(max_length=8, min_length=6)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate password and 2FA token on the user row the view has locked."""
        user = self.context["user"]

        # One answer for an account without 2FA, a locked account, a wrong password and a wrong
        # code. An account without 2FA is refused before its password is checked, so the answer
        # never tells a right password from a wrong one. The code is checked only after the
        # password, so a backup code offered with a wrong password is not spent.
        incorrect = _("The password or the code is incorrect.")
        if not user.two_factor_enabled or not check_password_locked(
            user, data["password"], source=self.context.get("check", "mfa_disable")
        ):
            raise serializers.ValidationError(incorrect)

        if not MFAService.verify_mfa_code(user, data["token"], self.context.get("request"))["success"]:
            raise serializers.ValidationError(incorrect)

        proof_passed(user)
        return data

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Disable 2FA for user, audited with the browser behind the Portal call.
        """
        user = self.context["user"]

        MFAService.disable_totp(user, request=self.context.get("request"), origin=self.context.get("origin"))

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


class RegistrationLinkSerializer(serializers.Serializer):
    """A pending registration's link, as the mailbox holder received it."""

    registration_id = serializers.UUIDField()
    token = serializers.CharField(max_length=128, write_only=True)


class RegistrationConfirmSerializer(serializers.Serializer):
    """What the mailbox holder supplies to finish a pending registration."""

    registration_id = serializers.UUIDField()
    token = serializers.CharField(max_length=128, write_only=True)
    password = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)
    password_confirm = serializers.CharField(min_length=12, write_only=True, trim_whitespace=False)
    marketing_consent = serializers.BooleanField(default=False)
    # The Terms of Service accepted, and the release the confirmer was shown (from the preview).
    terms_accepted = serializers.BooleanField(default=False)
    terms_document_id = serializers.UUIDField(required=False, allow_null=True, default=None)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": _("Passwords do not match.")})
        if data.get("terms_accepted") and data.get("terms_document_id") is None:
            # Without the release shown, every attempt would be refused as "terms changed".
            raise serializers.ValidationError({"terms_document_id": _("Send the Terms of Service release accepted.")})
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
            # A setup secret shown before the reset must not be confirmable after it (ADR-0058).
            discard_pending_totp(user.pk)
            notify_credential_change(user.pk, "password_changed")
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
        """The number in international form: the portal sends it so, having known the person's country."""
        return normalize_phone(value)

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
