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


_WRONG_WAY_MESSAGE = _(
    "A line must point the way its document does: a credit note's lines are negative, an invoice's are not."
)


def _refuse_objects_pointing_against_their_document(
    objects: list[InvoiceLine], parents: Iterable[InvoiceModel]
) -> None:
    """The rule `InvoiceLine.save()` applies, for the one bulk path that skips it.

    `bulk_create` does not call `save()`, and it already locks and iterates its parents to check
    `locked_at` - so this costs no further query. The objects carry their final values, which
    makes the check exact here.

    Only strictly wrong-signed amounts are refused. Zero points nowhere, matching the non-strict
    header constraints on `Invoice`, and this path is how every credit note's negated lines are
    written, so it must pass for them.
    """
    from .invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Avoid model import cycle.

    kinds = {parent.pk: parent.document_kind for parent in parents}
    for line in objects:
        kind = kinds.get(line.invoice_id)
        if kind is None:
            # No such parent; the foreign key is about to say so more clearly.
            continue
        amounts = (line.unit_price_cents, line.tax_cents, line.line_total_cents)
        reversing = kind == DOCUMENT_KIND_CREDIT_NOTE
        if any(amount > 0 for amount in amounts) if reversing else any(amount < 0 for amount in amounts):
            raise ValidationError(_WRONG_WAY_MESSAGE)


class InvoiceLineQuerySet(models.QuerySet["InvoiceLine"]):
    def _check_unlocked(self) -> None:
        from .invoice_models import Invoice  # noqa: PLC0415  # Avoid model import cycle.

        parents = Invoice.objects.select_for_update().filter(pk__in=self.values("invoice_id")).order_by("pk")
        if any(parent.locked_at for parent in parents):
            raise ValidationError(_("Cannot modify lines on an issued invoice."))

    def _refuse_rows_pointing_against_their_document(self, pks: list[Any]) -> None:
        """Judge the rows as they now stand, rather than predicting what the update will do.

        Checked AFTER the write, inside this method's own transaction, so raising rolls it back.
        That is deliberate: an update can set a literal, an `F()` expression, the parent, or any
        combination, and the only way to be right about every one of them is to read what actually
        landed. `save()` carries the same rule and this path never reaches it - a single
        `update(invoice=credit_note)` moved positive lines onto a credit note.

        The primary keys are captured before the write because reassigning `invoice` can move the
        rows out of this queryset's own filter.
        """
        from .invoice_models import DOCUMENT_KIND_CREDIT_NOTE, InvoiceLine  # noqa: PLC0415  # cycle

        wrong_way = (
            models.Q(
                invoice__document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            )
            & (models.Q(unit_price_cents__gt=0) | models.Q(tax_cents__gt=0) | models.Q(line_total_cents__gt=0))
        ) | (
            ~models.Q(invoice__document_kind=DOCUMENT_KIND_CREDIT_NOTE)
            & (models.Q(unit_price_cents__lt=0) | models.Q(tax_cents__lt=0) | models.Q(line_total_cents__lt=0))
        )
        if InvoiceLine.objects.filter(pk__in=pks).filter(wrong_way).exists():
            raise ValidationError(_WRONG_WAY_MESSAGE)

    @transaction.atomic
    def update(self, **kwargs: Any) -> int:
        signed = {"unit_price_cents", "tax_cents", "line_total_cents", "invoice", "invoice_id"}
        judge_direction = bool(signed & set(kwargs))
        # Captured before the write: reassigning `invoice` can move these rows out of this
        # queryset's filter, and then there would be nothing left to re-read.
        pks = list(self.values_list("pk", flat=True)) if judge_direction else []
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
        updated = super().update(**kwargs)
        if judge_direction:
            self._refuse_rows_pointing_against_their_document(pks)
        return updated

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
            # Iterating `parents` above filled the result cache, so this reuses it rather than
            # issuing a second locked read.
            _refuse_objects_pointing_against_their_document(objects, parents)
            return super().bulk_create(objects, *args, **kwargs)


def _reject_upsert(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """An INSERT conflict must never overwrite a locked row through a draft object."""
    update_conflicts_position = 2
    positional = len(args) > update_conflicts_position and args[update_conflicts_position]
    if positional or kwargs.get("update_conflicts"):
        raise ValidationError(_("Invoice ledger upserts are unsupported; use the guarded update path."))
