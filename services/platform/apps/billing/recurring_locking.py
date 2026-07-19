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
    """Serialize the final authorization check and gateway submission with revocation."""
    # Serialize against an in-flight kill-switch flip with a SHORT locked read
    # that COMMITS before the gateway round-trip. A disable already holding the
    # setting-row lock still blocks this charge from starting (the FOR UPDATE
    # read waits behind it, then observes the committed disable), but the lock
    # is released before the customer lock and the Stripe call — so one hung
    # gateway call can neither stall the kill switch for operators nor serialize
    # every other customer's recurring charge behind this single global row.
    with transaction.atomic():
        setting = (
            SystemSetting.objects.select_for_update(of=("self",))
            .filter(key=RECURRING_AUTO_COLLECTION_SETTING_KEY)
            .first()
        )
        collection_enabled = setting is not None and setting.get_typed_value() is True
    if not collection_enabled:
        yield "Recurring automatic collection is disabled"
        return

    # Per-customer serialization against revocation is preserved here and DOES
    # span the gateway call (the #316 fix): a revocation for this customer waits
    # for the in-flight charge, by policy.
    with transaction.atomic():
        lock_recurring_collection_customer(customer_id)
        # Re-read the switch AFTER acquiring the customer lock: a disable may have
        # committed while this charge queued behind another worker on the customer
        # lock. Without this, a pre-authorized worker would submit against an
        # already-disabled switch. Latest committed value — no lock held across
        # the gateway call.
        setting = SystemSetting.objects.filter(key=RECURRING_AUTO_COLLECTION_SETTING_KEY).first()
        if setting is None or setting.get_typed_value() is not True:
            yield "Recurring automatic collection is disabled"
            return
        yield None
