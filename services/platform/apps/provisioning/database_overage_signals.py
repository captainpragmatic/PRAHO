"""A terminated account closes its database overage episode, whichever path terminated it."""

from __future__ import annotations

from typing import Any

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from .virtualmin_models import VirtualminAccount


@receiver(post_save, sender=VirtualminAccount, dispatch_uid="database_overage_follows_termination")
def close_overage_on_termination(
    sender: type[VirtualminAccount], instance: VirtualminAccount, raw: bool = False, **kwargs: Any
) -> None:
    if raw or instance.status != "terminated":
        return
    from . import database_overage_admission  # noqa: PLC0415  # Deferred: imports the episode service

    account_id = instance.pk
    # Once the termination commits, so a rollback never closes an episode; looked up then, so tests can patch it.
    transaction.on_commit(lambda: database_overage_admission.on_account_terminated(account_id))
