"""A model whose every save runs in a transaction, so its pre_save checks share it.

A `pre_save` receiver that reads another row under a lock only holds that lock until its own
statement ends when the caller is in autocommit: the save that follows then runs unguarded. The
GDPR erasure guard (apps/customers/erasure_guard.py) is such a receiver, so the models it guards
save inside a transaction when the caller has none. A save already inside one is left as it is,
with no extra savepoint, so a caller's error handling is unchanged.
"""

from __future__ import annotations

from typing import Any

from django.db import models, transaction


class TransactionalSaveModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if transaction.get_connection(kwargs.get("using")).in_atomic_block:
            super().save(*args, **kwargs)
            return
        with transaction.atomic(using=kwargs.get("using")):
            super().save(*args, **kwargs)
