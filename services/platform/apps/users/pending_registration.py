"""A customer registration waiting for its mailbox holder to confirm it.

Registering creates no user and no customer. It stores what was submitted, and a worker mails the
address: a link to finish creating the account, or, when the address already has one, a note that
it does. Whoever confirms the link chooses the password, so nobody can set a password on an
account for an address they do not control, and the request itself never looks the address up.

The link's token is derived from the row and SECRET_KEY, not stored. A re-sent mail carries the
same link, and a row that no longer exists has no valid token.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import ClassVar

from django.db import models
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.translation import gettext_lazy as _

TOKEN_SALT = "praho.users.pending-registration"  # noqa: S105  # HMAC key salt name, not a secret
# How long a confirmation link works, from when its mail was sent.
CONFIRMATION_LINK_LIFETIME = timedelta(hours=24)
# Cleanup waits this much longer, so it never deletes a row a confirmation is still reading.
CLEANUP_MARGIN = timedelta(hours=1)


class PendingRegistration(models.Model):
    """What a registration submitted, kept until it is confirmed, superseded or expired."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_("Email"), db_index=True)
    # first_name, last_name, phone. Never a password.
    user_data = models.JSONField(default=dict)
    # customer_type, company_name, vat_number and the billing address fields.
    customer_data = models.JSONField(default=dict)
    language = models.CharField(max_length=10, default="en")
    sent_at = models.DateTimeField(null=True, blank=True)
    consumed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users_pending_registrations"
        verbose_name = _("Pending registration")
        verbose_name_plural = _("Pending registrations")
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["created_at"])]

    def __str__(self) -> str:
        return f"Pending registration {self.pk}"

    def token(self) -> str:
        """The link token: an HMAC of this row's random, never-reused id under SECRET_KEY."""
        return salted_hmac(TOKEN_SALT, str(self.pk), algorithm="sha256").hexdigest()

    def token_matches(self, token: str) -> bool:
        return constant_time_compare(self.token(), token)

    def is_usable(self, now: datetime | None = None) -> bool:
        """Sent, not yet confirmed, and within the link's lifetime."""
        now = now or timezone.now()
        return self.consumed_at is None and self.sent_at is not None and now < self.sent_at + CONFIRMATION_LINK_LIFETIME
