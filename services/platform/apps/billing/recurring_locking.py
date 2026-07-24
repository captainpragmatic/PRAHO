"""Database ordering boundary for recurring charge submission and revocation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from django.db import transaction

from apps.customers.models import Customer
from apps.settings.models import SystemSetting

RECURRING_AUTO_COLLECTION_SETTING_KEY = "billing.recurring_auto_collection_enabled"


def lock_recurring_collection_customer(customer_id: int) -> Customer:
    """Lock the shared customer boundary before changing recurring collection authority."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Recurring collection customer locks require an atomic transaction")
    # NO KEY UPDATE still conflicts with every boundary participant but permits
    # FK inserts (for example, a manual Payment) that reference this customer.
    return Customer.objects.select_for_update(of=("self",), no_key=True).get(pk=customer_id)


@contextmanager
def recurring_charge_submission_boundary(customer_id: int) -> Iterator[str | None]:
    """Serialize the durable submission claim with authorization revocation."""
    # The setting and customer rows protect the same SHORT transaction that
    # commits the durable claim. A disable that wins the setting lock is observed
    # before submission; a claim that wins first commits before the disable can
    # return. Both locks are released before the gateway round-trip.
    with transaction.atomic():
        setting = (
            SystemSetting.objects.select_for_update(of=("self",))
            .filter(key=RECURRING_AUTO_COLLECTION_SETTING_KEY)
            .first()
        )
        if setting is None or setting.get_typed_value() is not True:
            yield "Recurring automatic collection is disabled"
            return
        lock_recurring_collection_customer(customer_id)
        yield None
