"""The durable record that a settled refund owes (or does not owe) a fiscal correction.

A refund moves money. Whether it also has to reduce an issued invoice is a separate,
fiscal question, and answering it inside settlement was the mistake this model exists to
avoid: a provider call or a numbering failure must never roll back money that has already
moved. So completion only RECORDS the obligation, and whatever settles it later works from
this row.

One row per source, never per invoice:

* a direct refund owns its correction (`source_refund`);
* a refund that is one leg of a tender command shares the command's correction
  (`source_command`), because one customer instruction is one correction however many
  payment legs carried it.

The unique one-to-one links are what make duplicate creation impossible, including under
concurrent completions; the CHECK constraint is what makes "exactly one source" true for
every row rather than for every code path that remembered.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from django_fsm import FSMField, transition

if TYPE_CHECKING:
    from .invoice_models import Invoice

STATE_PENDING = "pending"
STATE_NOT_REQUIRED = "not_required"
STATE_ATTACHED = "attached"

# The obligation was resolved to no issued, numbered invoice, so there is no fiscal
# document a correction could reduce.
REASON_NO_FISCAL_DOCUMENT = "no_fiscal_document"

# Links that identify WHAT is being corrected and WHY. Each may be written once; after that
# a different value would silently re-point a fiscal decision at another document or another
# refund, which is exactly the kind of rewrite an obligation record exists to prevent.
_LINKS_IMMUTABLE_ONCE_SET: frozenset[str] = frozenset(
    {"original_id", "source_refund_id", "source_command_id", "credit_note_id"}
)


def _normalized_link_fields(names: Iterable[str]) -> set[str]:
    """Map `original` and `original_id` (and their siblings) to the attname the guard compares."""
    normalized: set[str] = set()
    for name in names:
        attname = name if name.endswith("_id") else f"{name}_id"
        if attname in _LINKS_IMMUTABLE_ONCE_SET:
            normalized.add(attname)
    return normalized


class FiscalCorrectionQuerySet(models.QuerySet["FiscalCorrection"]):
    """The bulk write paths, which skip `save()` and therefore its guard."""

    @transaction.atomic
    def update(self, **kwargs: Any) -> int:
        targeted = _normalized_link_fields(kwargs)
        if targeted:
            rows = self.select_for_update().values_list(*sorted(targeted))
            if any(value is not None for row in rows for value in row):
                raise ValidationError(_("A fiscal correction's source, original and credit note cannot be re-pointed."))
        return super().update(**kwargs)

    def bulk_create(self, objs: Iterable[FiscalCorrection], *args: Any, **kwargs: Any) -> list[FiscalCorrection]:
        update_conflicts_position = 2
        positional = len(args) > update_conflicts_position and args[update_conflicts_position]
        if positional or kwargs.get("update_conflicts"):
            raise ValidationError(_("Fiscal correction upserts are unsupported; they would overwrite a fixed link."))
        return super().bulk_create(objs, *args, **kwargs)


class FiscalCorrection(models.Model):
    """One refund's (or one tender command's) fiscal correction obligation."""

    STATE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (STATE_PENDING, _("Pending")),
        (STATE_NOT_REQUIRED, _("Not required")),
        (STATE_ATTACHED, _("Attached to a provider credit note")),
    )

    NOT_REQUIRED_REASON_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (REASON_NO_FISCAL_DOCUMENT, _("No issued, numbered invoice to correct")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    original = models.ForeignKey(
        "billing.Invoice",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="fiscal_corrections",
        help_text=_("The issued invoice this correction reduces; empty only when no fiscal document exists"),
    )
    source_refund = models.OneToOneField(
        "billing.Refund",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="fiscal_correction",
        help_text=_("The direct refund this correction answers for"),
    )
    source_command = models.OneToOneField(
        "promotions.TenderRefundCommand",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="fiscal_correction",
        help_text=_("The tender refund command whose legs this correction answers for"),
    )

    # Wide enough for the issuance states that follow (allocating, issuing, issued, ...).
    state = FSMField(max_length=24, choices=STATE_CHOICES, default=STATE_PENDING, protected=True)

    credit_note = models.OneToOneField(
        "billing.Invoice",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="settled_fiscal_correction",
        help_text=_("The credit note that settles this correction"),
    )
    not_required_reason = models.CharField(max_length=64, blank=True, choices=NOT_REQUIRED_REASON_CHOICES)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = FiscalCorrectionQuerySet.as_manager()

    class Meta:
        db_table = "billing_fiscal_corrections"
        verbose_name = _("Fiscal Correction")
        verbose_name_plural = _("Fiscal Corrections")
        indexes = (
            models.Index(fields=["state", "created_at"], name="bill_fiscorr_state_created"),
            models.Index(fields=["original", "state"], name="bill_fiscorr_original_state"),
        )
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(
                    (models.Q(source_refund__isnull=False) & models.Q(source_command__isnull=True))
                    | (models.Q(source_refund__isnull=True) & models.Q(source_command__isnull=False))
                ),
                name="fiscal_correction_exactly_one_source",
            ),
            models.CheckConstraint(
                condition=models.Q(state__in=[STATE_PENDING, STATE_NOT_REQUIRED, STATE_ATTACHED]),
                name="fiscal_correction_state_valid_values",
            ),
            # Every state but `not_required` acts on a document, so it needs one.
            models.CheckConstraint(
                condition=models.Q(original__isnull=False) | models.Q(state=STATE_NOT_REQUIRED),
                name="fiscal_correction_original_unless_not_required",
            ),
            models.CheckConstraint(
                condition=~models.Q(state=STATE_ATTACHED) | models.Q(credit_note__isnull=False),
                name="fiscal_correction_attached_has_credit_note",
            ),
            # A "not required" outcome clears an obligation, so it must say why.
            models.CheckConstraint(
                condition=~models.Q(state=STATE_NOT_REQUIRED) | ~models.Q(not_required_reason=""),
                name="fiscal_correction_not_required_has_reason",
            ),
        ]

    def __str__(self) -> str:
        source = f"refund {self.source_refund_id}" if self.source_refund_id else f"command {self.source_command_id}"
        return f"FiscalCorrection({source}, {self.state})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        update_fields = kwargs.get("update_fields")
        checked = (
            _normalized_link_fields(update_fields) if update_fields is not None else set(_LINKS_IMMUTABLE_ONCE_SET)
        )
        if checked and not self._state.adding:
            persisted = type(self).objects.filter(pk=self.pk).values(*sorted(checked)).first()
            if persisted is not None:
                changed = sorted(
                    field
                    for field in checked
                    if persisted[field] is not None and getattr(self, field) != persisted[field]
                )
                if changed:
                    raise ValidationError(
                        _("A fiscal correction's %(fields)s cannot be re-pointed once set.")
                        % {"fields": ", ".join(changed)}
                    )
        super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[FiscalCorrection] | None = None,
    ) -> None:
        """Let refresh_from_db repopulate the protected FSM field (same override as Refund)."""
        fsm_fields = ["state"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @transition(field=state, source=STATE_PENDING, target=STATE_ATTACHED)
    def attach_credit_note(self, credit_note: Invoice) -> None:
        """Settle this obligation with a credit note that already exists and is numbered."""
        from .invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Avoid model import cycle.

        if credit_note.document_kind != DOCUMENT_KIND_CREDIT_NOTE or credit_note.reverses_invoice_id is None:
            raise ValidationError(_("Only a credit note can settle a fiscal correction."))
        if credit_note.reverses_invoice_id != self.original_id:
            raise ValidationError(_("The credit note reverses a different invoice from this correction's original."))
        if not credit_note.number:
            raise ValidationError(_("Only an issued, numbered credit note can settle a fiscal correction."))
        self.credit_note = credit_note
