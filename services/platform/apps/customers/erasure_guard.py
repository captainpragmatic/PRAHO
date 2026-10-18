"""No write brings an erased person back (GDPR erasure, owner decision O5).

The erasure anonymises an individual customer and its non-fiscal copies (orders, proformas,
unissued invoices, addresses, the tax profile's CNP) with queryset updates, and marks the customer
with `anonymized_at`, under a lock on the customer row. A writer that read the customer before
then could still save the person's identity afterwards: a staff form's full save, an order built
from an address read earlier, a new member. Reloading cannot help when the stale data came from
the caller, so the write is refused instead.

Each guarded save checks the customer only when it would add identity: a new row, or a change to
an identity field. It then reads `anonymized_at` under the same row lock, so it waits for an
erasure in progress, and refuses with `CustomerErasedError` once the customer is erased. Whichever
commits first, the person is gone: the erasure's updates scrub a row the writer committed before
it, and a writer that comes after is refused. Saves that touch no identity (credit, status,
totals) never take the lock.

Invoices are not guarded: their creation is payment convergence (ADR-0038), and a refusal there
would roll a recorded payment back. Conversion copies the buyer from the proforma row it locks,
which the erasure has already scrubbed.

Lock order: the person's User row, then customers in pk order. A writer that holds an order or
proforma row lock when it takes the customer lock inverts that order; PostgreSQL detects the
deadlock and aborts one side, which rolls back whole and can be retried.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.db.models.signals import pre_save
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


class CustomerErasedError(PermissionDenied):
    """The customer's personal data was erased; this write would add it back."""

    def __init__(self, customer_id: int) -> None:
        super().__init__(_("This customer's personal data was erased. Its record can no longer take personal data."))
        self.customer_id = customer_id


# Model label -> identity fields. A new row of a model listed with None is refused outright.
_IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "customers.Customer": ("name", "company_name", "primary_email", "primary_phone", "website", "anonymized_at"),
    "customers.CustomerAddress": ("label", "address_line1", "address_line2", "city", "county", "postal_code"),
    "customers.CustomerTaxProfile": ("cnp",),
    "users.CustomerMembership": (),
    "orders.Order": ("customer_email", "customer_name", "customer_company", "customer_vat_id", "billing_address"),
    "billing.ProformaInvoice": (
        "bill_to_name",
        "bill_to_email",
        "bill_to_tax_id",
        "bill_to_cnp",
        "bill_to_registration_number",
        "bill_to_address1",
        "bill_to_address2",
        "bill_to_city",
        "bill_to_region",
        "bill_to_postal",
    ),
}
# Models whose new rows are refused for an erased customer. A Customer row is never new to its own erasure.
_REFUSE_NEW = frozenset(label for label in _IDENTITY_FIELDS if label != "customers.Customer")

# Models the erasure scrubs that are deliberately not guarded, with the reason.
UNGUARDED_SCRUBS: dict[str, str] = {
    "Invoice": "creation is payment convergence (ADR-0038); conversion copies the scrubbed proforma",
}

GUARDED_MODELS: list[type[models.Model]] = []


def _customer_id(instance: models.Model) -> int | None:
    """The customer's id, without loading a deferred field (that read can fail and poison the save)."""
    if instance._meta.label == "customers.Customer":
        return cast("int | None", instance.pk)
    if "customer_id" in instance.__dict__:
        return cast("int | None", instance.__dict__["customer_id"])
    stored = type(instance)._base_manager.filter(pk=instance.pk).values_list("customer_id", flat=True).first()
    return cast("int | None", stored)


def customer_is_erased(customer_id: int) -> bool:
    """Whether the customer was erased, read under its row lock when inside a transaction."""
    from .customer_models import Customer  # noqa: PLC0415  # Deferred: models import this module's app

    rows = Customer.all_objects.filter(pk=customer_id)
    if connection.in_atomic_block:
        rows = rows.select_for_update(of=("self",))
    return rows.filter(anonymized_at__isnull=False).exists()


def _changes_identity(instance: models.Model, fields: tuple[str, ...], update_fields: Any) -> bool:
    if update_fields is not None:
        fields = tuple(field for field in fields if field in update_fields)
    if not fields:
        return False
    rows = type(instance)._base_manager.filter(pk=instance.pk)
    if connection.in_atomic_block:
        # The row's own lock, which its UPDATE takes anyway: a plain read would see the row as it
        # was before an erasure still in progress, and miss that this save puts the person back.
        rows = rows.select_for_update(of=("self",))
    stored = rows.first()
    if stored is None:
        return True
    return any(getattr(instance, field) != getattr(stored, field) for field in fields)


def refuse_identity_for_erased_customer(
    sender: type[models.Model], instance: models.Model, raw: bool = False, update_fields: Any = None, **_: Any
) -> None:
    """pre_save: refuse a save that would put identity back on an erased customer."""
    if raw:
        return
    label = sender._meta.label
    adding = instance._state.adding
    if adding and label not in _REFUSE_NEW:
        return
    if not adding and not _changes_identity(instance, _IDENTITY_FIELDS[label], update_fields):
        return
    customer_id = _customer_id(instance)
    if customer_id is not None and customer_is_erased(customer_id):
        logger.warning("⚠️ [GDPR] Refused a %s write that would restore erased customer %s", label, customer_id)
        raise CustomerErasedError(customer_id)


def connect() -> None:
    """Register the guard on every model whose identity the erasure removes."""
    from django.apps import apps  # noqa: PLC0415

    for label in _IDENTITY_FIELDS:
        model = apps.get_model(label)
        GUARDED_MODELS.append(model)
        pre_save.connect(refuse_identity_for_erased_customer, sender=model, dispatch_uid=f"erasure_guard:{label}")
