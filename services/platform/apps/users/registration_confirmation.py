"""Mail a pending registration's link, confirm it, and clean up what was never confirmed.

See apps.users.pending_registration for why a registration waits for its mailbox holder.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Q
from django.template.loader import render_to_string
from django.utils import timezone, translation
from django.utils.translation import gettext, gettext_noop

from apps.common import counters
from apps.common.types import Err, Ok, Result
from apps.common.validators import SecureInputValidator, log_security_event
from apps.settings.services import get_default_from_email

from .models import User
from .pending_registration import CLEANUP_MARGIN, CONFIRMATION_LINK_LIFETIME, PendingRegistration
from .services import SecureUserRegistrationService, portal_public_origin

if TYPE_CHECKING:
    from datetime import datetime

    from apps.customers.models import Customer

logger = logging.getLogger(__name__)

# A registration mail is only worth sending soon after it was asked for. Older requests are dropped.
DELIVERY_MAX_AGE_SECONDS = 15 * 60
# At most one registration mail per address in this window, whatever it says.
RECIPIENT_COOLDOWN_SECONDS = 10 * 60

ConfirmRefusalCode = Literal["invalid_link", "password_rejected", "details_unavailable", "unavailable"]


@dataclass(frozen=True)
class ConfirmRefusal:
    code: ConfirmRefusalCode
    messages: list[str] = field(default_factory=list)


def _recipient_cooldown_key(email: str) -> str:
    digest = hashlib.sha256(email.strip().casefold().encode()).hexdigest()
    return f"registration_mail:{digest}"


def _skip_reason(row: PendingRegistration) -> str | None:
    """Why this row gets no mail now, or None. The cooldown is charged last, for every address."""
    if row.consumed_at is not None or row.sent_at is not None:
        return "already_sent"
    age = (timezone.now() - row.created_at).total_seconds()
    if age > DELIVERY_MAX_AGE_SECONDS:
        logger.warning("⚠️ [Registration] Not sent: the request is %d s old", age)
        return "stale"
    if counters.increment(_recipient_cooldown_key(row.email), RECIPIENT_COOLDOWN_SECONDS) > 1:
        logger.info("💡 [Registration] Not sent: the address had a registration mail in the last 10 minutes")
        return "cooldown"
    return None


def deliver(registration_id: str) -> dict[str, Any]:
    """Mail one pending registration: its confirmation link, or "you already have an account".

    The cooldown is charged before anything depends on the address, so it cannot tell an
    existing account from a new one. Raises on unexpected errors; the task wrapper turns them
    into a result.
    """
    row = PendingRegistration.objects.filter(pk=registration_id).first()
    skip = "missing" if row is None else _skip_reason(row)
    if row is None or skip is not None:
        return {"sent": False, "reason": skip}

    try:
        base = portal_public_origin()
    except ImproperlyConfigured as exc:
        logger.error("🔥 [Registration] Not sent: %s", exc)
        return {"sent": False, "reason": "configuration"}

    existing_account = User.objects.filter(email__iexact=row.email).exists()
    if existing_account:
        template, context = "existing_account", {"login_url": f"{base}/login/", "reset_url": f"{base}/password-reset/"}
        subject = gettext_noop("You already have a PRAHO account")
    else:
        template, context = "confirm", {"confirm_url": f"{base}/register/confirm/{row.pk}/{row.token()}/"}
        subject = gettext_noop("Confirm your PRAHO account")

    with translation.override(row.language):
        sent = send_mail(
            subject=gettext(subject),
            message=render_to_string(f"users/emails/registration_{template}.txt", context),
            from_email=get_default_from_email(),
            recipient_list=[row.email],
            html_message=render_to_string(f"users/emails/registration_{template}.html", context),
            fail_silently=False,
        )
    if not sent:
        raise OSError("Email backend did not accept the registration message")

    if existing_account:
        row.delete()
        logger.info("📧 [Registration] Existing-account notice sent for a pending registration")
        return {"sent": True, "kind": "existing_account"}
    row.sent_at = timezone.now()
    row.save(update_fields=["sent_at", "updated_at"])
    logger.info("📧 [Registration] Confirmation link sent for pending registration %s", row.pk)
    return {"sent": True, "kind": "confirm"}


def confirm(  # noqa: PLR0913  # One argument per value the mailbox holder supplies
    registration_id: str,
    token: str,
    password: str,
    *,
    accepts_marketing: bool,
    request_ip: str | None = None,
    user_agent: str | None = None,
) -> Result[tuple[User, Customer], ConfirmRefusal]:
    """Create the account a pending registration describes, with the password its confirmer chose.

    The row is locked, so two confirmations of one link create one account. A refusal before the
    account is created leaves the row usable, except that a used or expired link stays refused.
    """
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: cross-app model at call time

    with transaction.atomic():
        row = PendingRegistration.objects.select_for_update().filter(pk=registration_id).first()
        if row is None or not row.token_matches(token) or not row.is_usable():
            return Err(ConfirmRefusal("invalid_link"))

        user_data = {
            **row.user_data,
            "email": row.email,
            "password": password,
            "accepts_marketing": accepts_marketing,
            "gdpr_consent_date": timezone.now(),
        }
        candidate = User(
            email=row.email, first_name=user_data.get("first_name", ""), last_name=user_data.get("last_name", "")
        )
        try:
            validate_password(password, candidate)
        except ValidationError as exc:
            return Err(ConfirmRefusal("password_rejected", list(exc.messages)))

        company_name = str(row.customer_data.get("company_name", "")).strip()
        if (
            User.objects.filter(email__iexact=row.email).exists()
            or Customer.objects.filter(company_name__iexact=company_name).exists()
        ):
            return Err(ConfirmRefusal("details_unavailable"))
        try:
            SecureInputValidator.validate_user_data_dict(user_data)
        except ValidationError:
            return Err(ConfirmRefusal("details_unavailable"))

        customer_data = {**row.customer_data, "data_processing_consent": True}
        result = SecureUserRegistrationService.create_customer_owner(user_data, customer_data, request_ip, user_agent)
        if isinstance(result, Err):
            # The core rolled its own savepoint back, so no user or customer exists. Only its
            # security log entry is left to commit, and the row stays usable for a retry.
            return Err(ConfirmRefusal("unavailable"))

        user, customer = result.unwrap()
        row.consumed_at = timezone.now()
        row.save(update_fields=["consumed_at", "updated_at"])
        log_security_event(
            "pending_registration_confirmed",
            {"registration_id": str(row.pk), "user_id": user.id, "customer_id": customer.id},
            request_ip,
        )
        return Ok((user, customer))


def cleanup(now: datetime | None = None) -> int:
    """Delete confirmed rows and rows whose link has expired or was never sent in time."""
    now = now or timezone.now()
    cutoff = now - CONFIRMATION_LINK_LIFETIME - CLEANUP_MARGIN
    deleted, _ = PendingRegistration.objects.filter(
        Q(consumed_at__isnull=False) | Q(sent_at__lt=cutoff) | Q(sent_at__isnull=True, created_at__lt=cutoff)
    ).delete()
    return deleted
