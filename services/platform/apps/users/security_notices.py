"""Tell the account holder when their 2FA or password changes (#689).

The notification preferences promise "security alerts (login attempts, 2FA)". A notice is
queued once the change commits, by the chokepoints every path goes through (MFAService and
apply_password_change), so the staff pages, the Portal's API and the operator command all send
it. The notice goes to the account's own address, in its language, from a Django-Q worker.

A notice that cannot be queued is logged and dropped: it must never undo the change or hide
its result, such as recovery codes the person has to see now.
"""

from __future__ import annotations

import logging
from typing import Literal

from django.db import transaction
from django_q.tasks import async_task

logger = logging.getLogger(__name__)

SecurityNotice = Literal["2fa_enabled", "2fa_disabled", "2fa_reset", "backup_codes", "password_changed"]


def notify_credential_change(
    user_pk: int, event: SecurityNotice, *, actor_email: str = "", by_operator: bool = False
) -> None:
    """Queue the notice for after the surrounding transaction commits; never raises.

    actor_email names an administrator who acted on someone else's account. by_operator marks
    a reset run from the server's command line, which has no account to name.
    """

    def enqueue() -> None:
        try:
            async_task(
                "apps.users.tasks.deliver_security_notice",
                user_pk,
                event,
                actor_email,
                by_operator,
                ack_failure=True,
            )
        except Exception:
            logger.exception("🔥 [Security] Notice enqueue failed for user %s (%s)", user_pk, event)

    try:
        transaction.on_commit(enqueue, robust=True)
    except Exception:
        logger.exception("🔥 [Security] Notice not scheduled for user %s (%s)", user_pk, event)
