"""ORM guards for the issued invoice ledger, including bulk write paths."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from .invoice_models import Invoice as InvoiceModel
    from .invoice_models import InvoiceLine


class InvoiceQuerySet(models.QuerySet["InvoiceModel"]):
    @transaction.atomic
    def update(self, **kwargs: Any) -> int:
        normalized = set(kwargs) | {f"{key}_id" for key in kwargs}
        if normalized & self.model._LOCKED_FIELDS and any(
            value is not None for value in self.select_for_update().values_list("locked_at", flat=True)
        ):
            raise ValidationError(_("Cannot modify the fiscal snapshot of an issued invoice."))
        return super().update(**kwargs)

    @transaction.atomic
    def delete(self) -> tuple[int, dict[str, int]]:
        if any(value is not None for value in self.select_for_update().values_list("locked_at", flat=True)):
            raise ValidationError(_("Cannot delete issued invoices."))
        return super().delete()

    def bulk_create(self, objs: Iterable[InvoiceModel], *args: Any, **kwargs: Any) -> list[InvoiceModel]:
        _reject_upsert(args, kwargs)
        return super().bulk_create(objs, *args, **kwargs)


class InvoiceLineQuerySet(models.QuerySet["InvoiceLine"]):
    def _check_unlocked(self) -> None:
        from .invoice_models import Invoice  # noqa: PLC0415  # Avoid model import cycle.

        parents = Invoice.objects.select_for_update().filter(pk__in=self.values("invoice_id")).order_by("pk")
        if any(parent.locked_at for parent in parents):
            raise ValidationError(_("Cannot modify lines on an issued invoice."))

    @transaction.atomic
    def update(self, **kwargs: Any) -> int:
        if set(kwargs) - {"service", "service_id", "billing_cycle", "billing_cycle_id"}:
            self._check_unlocked()
            if "invoice" in kwargs or "invoice_id" in kwargs:
                from .invoice_models import Invoice  # noqa: PLC0415  # Avoid model import cycle.

                target = kwargs.get("invoice_id", kwargs.get("invoice"))
                if not isinstance(target, (int, Invoice)):
                    raise ValidationError(_("Invoice reassignment requires an explicit unlocked invoice."))
                target_id = target.pk if isinstance(target, Invoice) else target
                target_parent = Invoice.objects.select_for_update().filter(pk=target_id).first()
                if target_parent and target_parent.locked_at:
                    raise ValidationError(_("Cannot add lines to an issued invoice."))
        return super().update(**kwargs)

    @transaction.atomic
    def delete(self) -> tuple[int, dict[str, int]]:
        self._check_unlocked()
        return super().delete()

    def bulk_create(self, objs: Iterable[InvoiceLine], *args: Any, **kwargs: Any) -> list[InvoiceLine]:
        from .invoice_models import Invoice  # noqa: PLC0415  # Avoid model import cycle.

        _reject_upsert(args, kwargs)
        objects = list(objs)
        with transaction.atomic():
            parents = Invoice.objects.select_for_update().filter(pk__in={line.invoice_id for line in objects})
            if any(parent.locked_at for parent in parents):
                raise ValidationError(_("Cannot add lines to an issued invoice."))
            return super().bulk_create(objects, *args, **kwargs)


def _reject_upsert(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """An INSERT conflict must never overwrite a locked row through a draft object."""
    update_conflicts_position = 2
    positional = len(args) > update_conflicts_position and args[update_conflicts_position]
    if positional or kwargs.get("update_conflicts"):
        raise ValidationError(_("Invoice ledger upserts are unsupported; use the guarded update path."))
