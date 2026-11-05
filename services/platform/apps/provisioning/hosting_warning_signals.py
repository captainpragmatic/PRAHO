"""After-commit warning receipt recovery; account publication never touches a mail row."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from .hosting_warning_delivery import ACCEPTED_EMAIL_STATES, enqueue_warning_sweep
from .hosting_warning_models import HostingWarningDelivery

if TYPE_CHECKING:
    from apps.notifications.models import EmailLog


@receiver(post_save, sender="notifications.EmailLog", dispatch_uid="hosting_warning_mail_receipt")
def warning_mail_receipt(sender: object, instance: EmailLog, **kwargs: object) -> None:
    if (
        instance.status in ACCEPTED_EMAIL_STATES
        and HostingWarningDelivery.objects.filter(email_log_id=instance.pk).exists()
    ):
        transaction.on_commit(enqueue_warning_sweep, robust=True)
