"""A TOTP secret waiting for its first code: one row per person, never the user row or the session.

The staff web setup kept the secret in the session and the API kept it on the user row,
and the API made a new one on every call, so one mistyped code broke the authenticator a
customer had just scanned. Both paths now share this row (ADR-0058):

- It is offered again while it is fresh, and each showing extends its life, so someone who
  scans and is then slow to type the code is not handed a different secret.
- It is consumed by the enrolment that confirms it, inside the transaction that enables 2FA,
  with the password and the code checked on the locked user row.
- It is dropped when the password is reset or changed, when 2FA is disabled or reset, and
  when the account is anonymised.

Lock order is the user row, then this row, everywhere, so concurrent first visits create one
row and an enrolment never races its own restart.

The secret is AES-256-GCM encrypted and bound to this row, as PendingRegistration binds a CNP.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Literal

import pyotp
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.encryption import decrypt_sensitive_data, encrypt_sensitive_data

from .credentials import check_password_locked, proof_passed

if TYPE_CHECKING:
    from django.http import HttpRequest

    from .mfa import BrowserOrigin
    from .models import User

DEFAULT_TTL_MINUTES = 15


class PendingTOTPEnrolment(models.Model):
    """A secret shown to someone setting up an authenticator, until they confirm it with a code."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="pending_totp_enrolment"
    )
    # Set with set_secret(), read with secret(). Never logged, never serialised.
    secret_encrypted = models.TextField()
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users_pending_totp_enrolments"
        verbose_name = _("Pending TOTP enrolment")
        verbose_name_plural = _("Pending TOTP enrolments")

    def __str__(self) -> str:
        return f"Pending TOTP enrolment {self.pk}"

    def _aad(self) -> bytes:
        return f"{self._meta.db_table}:secret_encrypted:{self.pk}".encode()

    def set_secret(self, secret: str) -> None:
        self.secret_encrypted = encrypt_sensitive_data(secret, aad=self._aad())

    def secret(self) -> str:
        """Raises DecryptionError for ciphertext that is not this row's."""
        return decrypt_sensitive_data(self.secret_encrypted, aad=self._aad())


def enrolment_lifetime() -> timedelta:
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Circular: settings imports users

    minutes = SettingsService.get_integer_setting("users.totp_enrolment_ttl_minutes", DEFAULT_TTL_MINUTES)
    return timedelta(minutes=max(minutes, 1))


def _lock_user(user_pk: int) -> User:
    from .models import User  # noqa: PLC0415  # Circular: models import this module's app

    return User.objects.select_for_update().get(pk=user_pk)


def _locked_row(user_pk: int) -> PendingTOTPEnrolment | None:
    return PendingTOTPEnrolment.objects.select_for_update().filter(user_id=user_pk).first()


def _new_row(user_pk: int) -> PendingTOTPEnrolment:
    row = PendingTOTPEnrolment(user_id=user_pk, expires_at=timezone.now() + enrolment_lifetime())
    row.set_secret(pyotp.random_base32())
    row.save()
    return row


def get_or_create_pending(user: User) -> str:
    """The secret to show: the fresh one already offered, with its life extended, or a new one."""
    with transaction.atomic():
        _lock_user(user.pk)
        row = _locked_row(user.pk)
        if row is not None and row.expires_at > timezone.now():
            row.expires_at = timezone.now() + enrolment_lifetime()
            row.save(update_fields=["expires_at", "updated_at"])
            return row.secret()
        if row is not None:
            row.delete()
        return _new_row(user.pk).secret()


def restart(user: User) -> str:
    """A new secret, for someone who asked to start over."""
    with transaction.atomic():
        _lock_user(user.pk)
        PendingTOTPEnrolment.objects.filter(user_id=user.pk).delete()
        return _new_row(user.pk).secret()


def discard(user_pk: int) -> None:
    """Drop a pending enrolment. The caller holds the user row lock when inside a transaction."""
    PendingTOTPEnrolment.objects.filter(user_id=user_pk).delete()


EnrolmentStatus = Literal["enabled", "incorrect", "expired", "already_enabled"]


@dataclass(frozen=True)
class EnrolmentResult:
    status: EnrolmentStatus
    backup_codes: list[str] = field(default_factory=list)
    # The account as committed by the enrolment, so a session binds to its new credentials.
    user: User | None = None


def complete_enrolment(
    user_pk: int,
    *,
    password: str,
    code: str,
    request: HttpRequest | None,
    origin: BrowserOrigin | None = None,
) -> EnrolmentResult:
    """Enable TOTP when the password and a code from the pending secret are both right.

    One transaction, user row first: the password is checked on the locked row, so a password
    changed meanwhile is not accepted, a locked account is refused and a wrong password counts
    toward the lockout; the code may be from the previous 30-second step, as at sign-in; a wrong
    password and a wrong code get the same answer and leave the enrolment in place. origin names
    the browser when the request is the Portal's.
    """
    from .mfa import MFAService, TOTPService  # noqa: PLC0415  # Circular: mfa imports models
    from .models import User  # noqa: PLC0415

    with transaction.atomic():
        locked_user = _lock_user(user_pk)
        if locked_user.two_factor_enabled:
            return EnrolmentResult("already_enabled")
        row = _locked_row(user_pk)
        if row is None or row.expires_at <= timezone.now():
            return EnrolmentResult("expired")
        secret = row.secret()
        if not check_password_locked(locked_user, password) or not TOTPService.verify_enrolment_code(
            locked_user, secret, code
        ):
            return EnrolmentResult("incorrect")
        proof_passed(locked_user)
        _secret, backup_codes = MFAService.enable_totp(locked_user, request, secret=secret, origin=origin)
        row.delete()
        enrolled = User.objects.select_related("credential_version").get(pk=user_pk)
    return EnrolmentResult("enabled", backup_codes, enrolled)
