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
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from django_fsm import RETURN_VALUE, FSMField, transition

if TYPE_CHECKING:
    from .invoice_models import Invoice

STATE_PENDING = "pending"
STATE_NOT_REQUIRED = "not_required"
STATE_ATTACHED = "attached"
# The built-in issuance lifecycle (ADR-0053). `allocated` holds a frozen allocation and no
# document yet; `issued` holds a numbered credit note that has not reached the customer;
# `communicated` is the same note once it has. `failed` is retryable and never re-allocates:
# a failure after allocation keeps the allocation it failed with.
STATE_ALLOCATED = "allocated"
STATE_ISSUED = "issued"
STATE_COMMUNICATED = "communicated"
STATE_FAILED = "failed"

# The states in which this correction is settled by a credit note it names.
STATES_WITH_CREDIT_NOTE: frozenset[str] = frozenset({STATE_ATTACHED, STATE_ISSUED, STATE_COMMUNICATED})
# The states that hold an allocation, so the amounts are frozen. `failed` may or may not.
STATES_WITH_ALLOCATION: frozenset[str] = frozenset({STATE_ALLOCATED, STATE_ISSUED, STATE_COMMUNICATED})

# The obligation was resolved to no issued, numbered invoice, so there is no fiscal
# document a correction could reduce.
REASON_NO_FISCAL_DOCUMENT = "no_fiscal_document"
# The refund returned money the invoice never needed (an overpayment or a duplicate payment):
# what is still held covers everything not yet credited, so nothing fiscal changed.
REASON_COVERED_BY_COLLECTIONS = "covered_by_collections"
# Earlier corrections already credit the whole invoice.
REASON_FULLY_CREDITED = "fully_credited"

# Why a correction is `failed`. Every one is retried by the sweep; the code says what a retry needs.
FAILURE_ALLOCATION_REFUSED = "allocation_refused"
FAILURE_ISSUANCE_ERROR = "issuance_error"
# The original already has a credit note, and until the one-reversal-per-original constraint is
# dropped (PR A3) a second one cannot be written. Parked, never forced.
FAILURE_SECOND_CREDIT_NOTE = "awaiting_second_credit_note_support"

# e-Factura submission of the credit note (RO only), tracked apart from issuance and communication
# so that reaching `communicated` never takes a note out of e-Factura recovery.
EFACTURA_NOT_DUE = "not_due"
EFACTURA_PENDING = "pending"
EFACTURA_NOT_APPLICABLE = "not_applicable"
EFACTURA_WAITING_FOR_ORIGINAL = "waiting_for_original"
EFACTURA_ORIGINAL_REJECTED = "original_rejected"
EFACTURA_SUBMITTED = "submitted"
EFACTURA_FAILED = "failed"
# What the sweep retries. A rejected original needs a person, so it is not here.
EFACTURA_RETRYABLE: frozenset[str] = frozenset({EFACTURA_PENDING, EFACTURA_WAITING_FOR_ORIGINAL, EFACTURA_FAILED})

# Fields that may be written once and never changed after. The links identify WHAT is being
# corrected and WHY, and a different value would silently re-point a fiscal decision at another
# document or refund. The allocation is the amount a credit note was (or will be) issued for:
# recomputing it on a retry could credit a different amount from the one already decided. The
# communication date is the D390 period of the note (OPANAF 705/2020), set by the first send.
_WRITE_ONCE_FIELDS: frozenset[str] = frozenset(
    {
        "original_id",
        "source_refund_id",
        "source_command_id",
        "credit_note_id",
        "allocated_at",
        "base_cents",
        "tax_cents",
        "discount_cents",
        "total_cents",
        "vat_residue_cents",
        "communicated_at",
        "fiscal_date",
    }
)


def _normalized_link_fields(names: Iterable[str]) -> set[str]:
    """Map `original` and `original_id` (and the plain write-once fields) to the attname compared."""
    normalized: set[str] = set()
    for name in names:
        attname = name if name in _WRITE_ONCE_FIELDS else f"{name}_id"
        if attname in _WRITE_ONCE_FIELDS:
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
                raise ValidationError(
                    _("A fiscal correction's source, original, credit note, allocation and communication are fixed.")
                )
        return super().update(**kwargs)

    def bulk_create(self, objs: Iterable[FiscalCorrection], *args: Any, **kwargs: Any) -> list[FiscalCorrection]:
        update_conflicts_position = 2
        positional = len(args) > update_conflicts_position and args[update_conflicts_position]
        if positional or kwargs.get("update_conflicts"):
            raise ValidationError(_("Fiscal correction upserts are unsupported; they would overwrite a fixed link."))
        return super().bulk_create(objs, *args, **kwargs)


def _has_allocation(instance: models.Model) -> bool:
    """Transition condition: an allocation has been written and frozen."""
    return cast("FiscalCorrection", instance).allocated_at is not None


def _has_no_allocation(instance: models.Model) -> bool:
    """Transition condition: nothing is allocated yet, so a decision may still be taken."""
    return cast("FiscalCorrection", instance).allocated_at is None


class FiscalCorrection(models.Model):
    """One refund's (or one tender command's) fiscal correction obligation."""

    STATE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (STATE_PENDING, _("Pending")),
        (STATE_NOT_REQUIRED, _("Not required")),
        (STATE_ATTACHED, _("Attached to a provider credit note")),
        (STATE_ALLOCATED, _("Allocated, awaiting issuance")),
        (STATE_ISSUED, _("Credit note issued")),
        (STATE_COMMUNICATED, _("Credit note sent to the customer")),
        (STATE_FAILED, _("Failed, will be retried")),
    )

    NOT_REQUIRED_REASON_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (REASON_NO_FISCAL_DOCUMENT, _("No issued, numbered invoice to correct")),
        (REASON_COVERED_BY_COLLECTIONS, _("The refund returned money the invoice did not need")),
        (REASON_FULLY_CREDITED, _("Earlier corrections already credit the whole invoice")),
    )

    FAILURE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (FAILURE_ALLOCATION_REFUSED, _("The amount could not be allocated")),
        (FAILURE_ISSUANCE_ERROR, _("The credit note could not be issued")),
        (FAILURE_SECOND_CREDIT_NOTE, _("The original already has a credit note")),
    )

    EFACTURA_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        (EFACTURA_NOT_DUE, _("Not due")),
        (EFACTURA_PENDING, _("Pending")),
        (EFACTURA_NOT_APPLICABLE, _("Not applicable")),
        (EFACTURA_WAITING_FOR_ORIGINAL, _("Waiting for the original to be accepted")),
        (EFACTURA_ORIGINAL_REJECTED, _("Original rejected, needs review")),
        (EFACTURA_SUBMITTED, _("Submitted")),
        (EFACTURA_FAILED, _("Failed, will be retried")),
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

    # The issuance lifecycle. Communication and e-Factura have their own status below.
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

    # The allocation: what the credit note credits, signed the way a credit note's header is
    # (every amount <= 0). Written once, together, and frozen from then on.
    allocated_at = models.DateTimeField(null=True, blank=True)
    base_cents = models.BigIntegerField(null=True, blank=True, help_text=_("Allocated taxable base (signed)"))
    tax_cents = models.BigIntegerField(null=True, blank=True, help_text=_("Allocated VAT (signed)"))
    discount_cents = models.BigIntegerField(null=True, blank=True, help_text=_("Allocated document discount (signed)"))
    total_cents = models.BigIntegerField(null=True, blank=True, help_text=_("Allocated gross (signed)"))
    vat_residue_cents = models.BigIntegerField(
        null=True,
        blank=True,
        help_text=_("VAT of the original this credit note leaves un-reversed (negative: reverses beyond it)"),
    )

    # Why the last attempt failed; kept after a later success as history in the audit trail only.
    failure_code = models.CharField(max_length=64, blank=True, choices=FAILURE_CHOICES)
    last_error = models.TextField(blank=True)

    # Communication: the first successful send sets both, once. The fiscal date is that send's
    # Romanian calendar date, which places the note in its D390 period.
    communicated_at = models.DateTimeField(null=True, blank=True)
    fiscal_date = models.DateField(null=True, blank=True)
    communication_attempts = models.PositiveIntegerField(default=0)
    communication_error = models.TextField(blank=True)
    # A sender's claim on the one send that dates the note. Taken and committed before the send, so a
    # second worker sees it and stays out; a claim older than the lease is presumed dead and retaken.
    communication_claimed_at = models.DateTimeField(null=True, blank=True)

    efactura_status = FSMField(max_length=24, choices=EFACTURA_CHOICES, default=EFACTURA_NOT_DUE, protected=True)
    efactura_error = models.TextField(blank=True)
    # Re-checks of a held or failed filing back off instead of running every sweep forever.
    efactura_attempts = models.PositiveIntegerField(default=0)
    efactura_next_attempt_at = models.DateTimeField(null=True, blank=True)

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
            models.Index(fields=["efactura_status", "created_at"], name="bill_fiscorr_efactura_created"),
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
                condition=models.Q(
                    state__in=[
                        STATE_PENDING,
                        STATE_NOT_REQUIRED,
                        STATE_ATTACHED,
                        STATE_ALLOCATED,
                        STATE_ISSUED,
                        STATE_COMMUNICATED,
                        STATE_FAILED,
                    ]
                ),
                name="fiscal_correction_state_valid_values",
            ),
            # Every state but `not_required` acts on a document, so it needs one.
            models.CheckConstraint(
                condition=models.Q(original__isnull=False) | models.Q(state=STATE_NOT_REQUIRED),
                name="fiscal_correction_original_unless_not_required",
            ),
            # Both directions: a correction settled by a note names it, and only such a one may, or
            # a row holding a note would look "already linked" and never transition.
            models.CheckConstraint(
                condition=(models.Q(state__in=sorted(STATES_WITH_CREDIT_NOTE)) & models.Q(credit_note__isnull=False))
                | (~models.Q(state__in=sorted(STATES_WITH_CREDIT_NOTE)) & models.Q(credit_note__isnull=True)),
                name="fiscal_correction_credit_note_iff_settled",
            ),
            # A "not required" outcome clears an obligation, so it must say why.
            models.CheckConstraint(
                condition=~models.Q(state=STATE_NOT_REQUIRED) | ~models.Q(not_required_reason=""),
                name="fiscal_correction_not_required_has_reason",
            ),
            # An allocation is all four amounts with its timestamp, or none of them, and it is a
            # credit: nothing positive, and the gross is the base plus the VAT.
            models.CheckConstraint(
                condition=(
                    models.Q(
                        allocated_at__isnull=True,
                        base_cents__isnull=True,
                        tax_cents__isnull=True,
                        discount_cents__isnull=True,
                        total_cents__isnull=True,
                        vat_residue_cents__isnull=True,
                    )
                    | models.Q(
                        allocated_at__isnull=False,
                        base_cents__lte=0,
                        tax_cents__lte=0,
                        discount_cents__lte=0,
                        total_cents__lt=0,
                        total_cents=models.F("base_cents") + models.F("tax_cents"),
                        vat_residue_cents__isnull=False,
                    )
                ),
                name="fiscal_correction_allocation_complete",
            ),
            # Allocated and later states stand on an allocation; pending and the outcomes that issue
            # nothing here (not required, attached to a provider note) never hold one.
            models.CheckConstraint(
                condition=(
                    models.Q(state__in=sorted(STATES_WITH_ALLOCATION), allocated_at__isnull=False)
                    | models.Q(state__in=[STATE_PENDING, STATE_NOT_REQUIRED, STATE_ATTACHED], allocated_at__isnull=True)
                    | models.Q(state=STATE_FAILED)
                ),
                name="fiscal_correction_allocation_matches_state",
            ),
            # Communicated exactly when the first send was recorded, with its fiscal date.
            models.CheckConstraint(
                condition=(
                    models.Q(state=STATE_COMMUNICATED, communicated_at__isnull=False, fiscal_date__isnull=False)
                    | (
                        ~models.Q(state=STATE_COMMUNICATED)
                        & models.Q(communicated_at__isnull=True, fiscal_date__isnull=True)
                    )
                ),
                name="fiscal_correction_communicated_has_date",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    efactura_status__in=[
                        EFACTURA_NOT_DUE,
                        EFACTURA_PENDING,
                        EFACTURA_NOT_APPLICABLE,
                        EFACTURA_WAITING_FOR_ORIGINAL,
                        EFACTURA_ORIGINAL_REJECTED,
                        EFACTURA_SUBMITTED,
                        EFACTURA_FAILED,
                    ]
                ),
                name="fiscal_correction_efactura_valid_values",
            ),
            # Only a built-in note that exists has an e-Factura submission to track.
            models.CheckConstraint(
                condition=models.Q(efactura_status=EFACTURA_NOT_DUE)
                | models.Q(state__in=[STATE_ISSUED, STATE_COMMUNICATED]),
                name="fiscal_correction_efactura_needs_issued_note",
            ),
        ]

    def __str__(self) -> str:
        source = f"refund {self.source_refund_id}" if self.source_refund_id else f"command {self.source_command_id}"
        return f"FiscalCorrection({source}, {self.state})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        update_fields = kwargs.get("update_fields")
        checked = _normalized_link_fields(update_fields) if update_fields is not None else set(_WRITE_ONCE_FIELDS)
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
                        _("A fiscal correction's %(fields)s cannot be changed once set.")
                        % {"fields": ", ".join(changed)}
                    )
        super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[FiscalCorrection] | None = None,
    ) -> None:
        """Let refresh_from_db repopulate the protected FSM fields (same override as Refund)."""
        fsm_fields = ["state", "efactura_status"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @property
    def is_allocated(self) -> bool:
        return self.allocated_at is not None

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

    @transition(
        field=state, source=[STATE_PENDING, STATE_FAILED], target=STATE_NOT_REQUIRED, conditions=[_has_no_allocation]
    )
    def mark_not_required(self, reason: str) -> None:
        """Nothing fiscal changed. Only before an allocation: an allocated amount is owed."""
        if reason not in {choice for choice, _label in self.NOT_REQUIRED_REASON_CHOICES}:
            raise ValidationError(_("Unknown not-required reason."))
        self.not_required_reason = reason

    @transition(
        field=state, source=[STATE_PENDING, STATE_FAILED], target=STATE_ALLOCATED, conditions=[_has_no_allocation]
    )
    def allocate(
        self, *, base_cents: int, tax_cents: int, discount_cents: int, at: datetime, vat_residue_cents: int = 0
    ) -> None:
        """Freeze what the credit note will credit, as magnitudes stored signed (<= 0)."""
        if min(base_cents, tax_cents, discount_cents) < 0 or base_cents + tax_cents <= 0:
            raise ValidationError(_("An allocation credits a positive amount."))
        self.base_cents = -base_cents
        self.tax_cents = -tax_cents
        self.discount_cents = -discount_cents
        self.total_cents = -(base_cents + tax_cents)
        self.vat_residue_cents = vat_residue_cents
        self.allocated_at = at
        self.failure_code = ""
        self.last_error = ""

    @transition(field=state, source=[STATE_PENDING, STATE_ALLOCATED, STATE_FAILED], target=STATE_FAILED)
    def fail(self, *, code: str, error: str) -> None:
        """Record a retryable failure. The allocation, if any, is kept exactly as it was."""
        self.failure_code = code
        self.last_error = error[:2000]

    @transition(field=state, source=[STATE_ALLOCATED, STATE_FAILED], target=STATE_ISSUED, conditions=[_has_allocation])
    def record_issued(self, credit_note: Invoice) -> None:
        """Link the built-in credit note just numbered for this allocation."""
        from .invoice_models import DOCUMENT_KIND_CREDIT_NOTE  # noqa: PLC0415  # Avoid model import cycle.

        if (
            credit_note.document_kind != DOCUMENT_KIND_CREDIT_NOTE
            or credit_note.reverses_invoice_id != self.original_id
        ):
            raise ValidationError(_("The credit note must reverse this correction's original."))
        if not credit_note.number or credit_note.locked_at is None:
            raise ValidationError(_("Only an issued, numbered credit note can settle a fiscal correction."))
        if (credit_note.subtotal_cents, credit_note.tax_cents, credit_note.total_cents) != (
            self.base_cents,
            self.tax_cents,
            self.total_cents,
        ):
            raise ValidationError(_("The credit note does not carry this correction's allocation."))
        self.credit_note = credit_note
        self.failure_code = ""
        self.last_error = ""

    @transition(field=state, source=STATE_ISSUED, target=STATE_COMMUNICATED)
    def record_communicated(self, *, at: datetime, fiscal_date: date) -> None:
        """The first successful send: it dates the note for D390, so it is recorded once."""
        self.communicated_at = at
        self.fiscal_date = fiscal_date
        self.communication_attempts += 1
        self.communication_error = ""
        self.communication_claimed_at = None

    def record_communication_failure(self, error: str) -> None:
        """A send that failed stays visible; the sweep tries again. Not a state change."""
        self.communication_attempts += 1
        self.communication_error = error[:2000]
        self.communication_claimed_at = None

    def claim_communication(self, *, now: datetime, lease: timedelta) -> bool:
        """Take the right to send, unless the note was sent or another sender holds a live claim.

        The caller holds this row's lock and commits the claim BEFORE sending, so the email itself
        happens outside any transaction and a racing worker sees the claim rather than a second send.
        """
        if self.state != STATE_ISSUED or self.communicated_at is not None:
            return False
        if self.communication_claimed_at is not None and self.communication_claimed_at > now - lease:
            return False
        self.communication_claimed_at = now
        return True

    @transition(field=efactura_status, source=EFACTURA_NOT_DUE, target=EFACTURA_PENDING)
    def owe_efactura(self) -> None:
        """A built-in note was issued; whether it is filed with ANAF is decided afterwards."""

    @transition(
        field=efactura_status,
        source=sorted(EFACTURA_RETRYABLE),
        target=RETURN_VALUE(
            EFACTURA_NOT_APPLICABLE,
            EFACTURA_WAITING_FOR_ORIGINAL,
            EFACTURA_ORIGINAL_REJECTED,
            EFACTURA_SUBMITTED,
            EFACTURA_FAILED,
        ),
    )
    def record_efactura(self, outcome: str, error: str = "", *, next_attempt_at: datetime | None = None) -> str:
        """Record where the credit note's e-Factura submission stands, and when to look again."""
        self.efactura_error = error[:2000]
        self.efactura_attempts += 1
        self.efactura_next_attempt_at = next_attempt_at
        return outcome
