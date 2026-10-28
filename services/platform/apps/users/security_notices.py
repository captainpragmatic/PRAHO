"""Tell the account holder when their 2FA or password changes (#689).

The notification preferences promise "security alerts (login attempts, 2FA)". The chokepoints
every path goes through (MFAService and apply_password_change) write the notice, so the staff
pages, the Portal's API and the operator command all send it. It goes to the account's own
address, in its language.

A notice is a queued email (notifications.EmailService) written in the transaction that makes the
change: it commits with the change, is never sent for a change that rolled back, and the email
queue delivers it and retries it. It used to be queued only after the commit, and one whose
queueing or whose send failed was lost.

Writing a notice runs in its own savepoint. One that cannot be written is logged and dropped: it
must never undo the change or hide its result, such as recovery codes the person has to see now.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

from django.template.loader import render_to_string
from django.utils import translation
from django.utils.translation import gettext

from apps.common.transactions import best_effort_atomic

from .models import User

if TYPE_CHECKING:
    from apps.customers.models import Customer

logger = logging.getLogger(__name__)

SecurityNotice = Literal["2fa_enabled", "2fa_disabled", "2fa_reset", "backup_codes", "password_changed"]


def _subject(event: str) -> str:
    """The notice's subject, in the active language."""
    subjects = {
        "2fa_enabled": gettext("Two-factor authentication was turned on"),
        "2fa_disabled": gettext("Two-factor authentication was turned off"),
        "2fa_reset": gettext("Two-factor authentication was reset"),
        "backup_codes": gettext("New backup codes were created"),
        "password_changed": gettext("Your password was changed"),
    }
    return subjects[event]


def language_of(user: User) -> str:
    """The language a person reads their notices in: theirs, else the platform's default."""
    from apps.common.localisation_services import (  # noqa: PLC0415  # ADR-0007: cross-app, deferred
        get_localisation_defaults,
        user_localisation_preferences,
    )

    return user_localisation_preferences(user).get("preferred_language") or get_localisation_defaults().default_language


def queue_notice(
    to: str, event: str, *, language: str, context: dict[str, Any], customer: Customer | None = None
) -> None:
    """Write one notice as a queued email in the current transaction; never raises."""
    from apps.notifications.services import EmailService  # noqa: PLC0415  # ADR-0007: cross-app, deferred

    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        with translation.override(language):
            context = {**context, "event": event}
            subject = _subject(event)
            text_message = render_to_string("users/emails/security_notice.txt", context)
            html_message = render_to_string("users/emails/security_notice.html", context)
        result = EmailService.send_email(
            to=to,
            subject=subject,
            body_text=text_message,
            body_html=html_message,
            customer=customer,
            template_key=f"security_notice:{event}",
            priority="high",
            track_opens=False,
            track_clicks=False,
            async_send=True,
        )
        if not result.success:
            logger.warning("⚠️ [Security] Notice %s not queued: %s", event, result.error)


def notify_credential_change(
    user_pk: int, event: SecurityNotice, *, actor_email: str = "", by_operator: bool = False
) -> None:
    """Write the notice for a change to the account's own 2FA or password; never raises.

    actor_email names an administrator who acted on someone else's account. by_operator marks
    a reset run from the server's command line, which has no account to name.
    """
    with best_effort_atomic(logger=logger, scope="Security", message=f"Notice {event} not written"):
        user = User.objects.filter(pk=user_pk, is_active=True).select_related("profile").first()
        if user is None:
            logger.info("💡 [Security Notice] Not sent: no active account %s", user_pk)
            return
        context = {"user": user, "actor_email": actor_email, "by_operator": by_operator}
        queue_notice(user.email, event, language=language_of(user), context=context)
