"""Owner-scoped warning policy evidence and independently recoverable mail deliveries."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, TypeVar

from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

WarningModelT = TypeVar("WarningModelT", bound="WarningLifecycle")


class WarningEvidenceQuerySet(models.QuerySet[WarningModelT]):
    def _protected_fields(self) -> set[str]:
        fields = {"phase", *self.model.immutable_fields, *self.model.linked_fields}
        return fields | {field.removesuffix("_id") for field in fields if field.endswith("_id")}

    def update(self, **kwargs: Any) -> int:
        if set(kwargs) & self._protected_fields():
            raise ValidationError(_("Warning evidence cannot be overwritten."))
        return super().update(**kwargs)

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        if set(fields) & self._protected_fields():
            raise ValidationError(_("Warning evidence cannot be overwritten."))
        return super().bulk_update(objs, fields, batch_size=batch_size)


class WarningLifecycle(ConcurrentTransitionMixin, models.Model):
    immutable_fields: ClassVar[tuple[str, ...]] = ()
    linked_fields: ClassVar[tuple[str, ...]] = ()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        alias = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        fields = (*self.immutable_fields, *self.linked_fields)
        old = type(self)._base_manager.using(alias).filter(pk=self.pk).values("phase", *fields).first()
        if old is not None:
            frozen = self.immutable_fields + (self.linked_fields if old["phase"] != "pending" else ())
            if self._state.adding or any(getattr(self, field) != old[field] for field in frozen):
                raise ValidationError(_("Warning evidence cannot be overwritten."))
        else:
            kwargs["force_insert"] = True
        kwargs["using"] = alias
        super().save(*args, **kwargs)

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        saved = self.__dict__.pop("phase", None) if fields is None or "phase" in fields else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved is not None:
                self.__dict__["phase"] = saved
            raise


class HostingWarningState(models.Model):
    """Account publication owns this row; it never acquires a customer mail lock."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        "provisioning.VirtualminAccount", on_delete=models.CASCADE, related_name="warning_states"
    )
    resource = models.CharField(max_length=12, choices=(("disk", _("Disk")), ("bandwidth", _("Bandwidth"))))
    service_id_snapshot = models.PositiveBigIntegerField()
    customer_id_snapshot = models.PositiveBigIntegerField()
    owner_scope = models.UUIDField()
    policy_state = models.JSONField(default=dict)
    condition = models.PositiveSmallIntegerField(null=True)
    availability = models.CharField(max_length=12, default="unknown")
    reading = models.ForeignKey("provisioning.UsageReading", null=True, on_delete=models.SET_NULL, related_name="+")
    recipient_hash = models.CharField(max_length=64, blank=True)
    handover_fingerprint = models.CharField(max_length=64, blank=True)
    last_poll = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "provisioning_hosting_warning_state"
        db_table_comment = "Current raw-byte warning condition, hourly hysteresis and owner/month scope."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("account", "resource"), name="hosting_warning_account_resource"),
            models.CheckConstraint(
                condition=models.Q(condition__isnull=True) | models.Q(condition__in=(80, 95, 100)),
                name="hosting_warning_condition_valid",
            ),
        ]


class HostingWarningIntent(WarningLifecycle):
    """Immutable scope/episode/recipient evidence; the phase evolves under row locks."""

    state = models.ForeignKey(HostingWarningState, on_delete=models.CASCADE, related_name="intents")
    identity = models.CharField(max_length=64, unique=True)
    service_id_snapshot = models.PositiveBigIntegerField()
    customer_id_snapshot = models.PositiveBigIntegerField()
    owner_scope = models.UUIDField()
    resource = models.CharField(max_length=12)
    generation = models.PositiveBigIntegerField()
    threshold = models.PositiveSmallIntegerField()
    recipient_hash = models.CharField(max_length=64)
    channel = models.CharField(max_length=12, default="email")
    kind = models.CharField(max_length=12, default="crossing")
    due_at = models.DateTimeField(db_index=True)
    reading = models.ForeignKey("provisioning.UsageReading", null=True, on_delete=models.SET_NULL, related_name="+")
    scope_snapshot = models.JSONField()
    evidence_snapshot = models.JSONField()
    parent = models.ForeignKey("self", null=True, on_delete=models.SET_NULL, related_name="reminders")
    phase = FSMField(default="pending", max_length=16, protected=True)
    refusal_reason = models.CharField(max_length=80, blank=True)
    immutable_fields = (
        "state_id",
        "identity",
        "service_id_snapshot",
        "customer_id_snapshot",
        "owner_scope",
        "resource",
        "generation",
        "threshold",
        "recipient_hash",
        "channel",
        "kind",
        "due_at",
        "scope_snapshot",
        "evidence_snapshot",
    )
    objects = WarningEvidenceQuerySet["HostingWarningIntent"].as_manager()

    class Meta:
        db_table = "provisioning_hosting_warning_intent"
        db_table_comment = "Dedupe-bound warning episode recipient and reminder evidence, with no plaintext identity."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=models.Q(threshold__in=(80, 95, 100)), name="hosting_warning_threshold_valid"
            ),
            models.CheckConstraint(condition=models.Q(generation__gte=1), name="hosting_warning_generation_positive"),
        ]

    @transition(field=phase, source="pending", target="linked")
    def link(self) -> None:
        """One active delivery part owns this intent before queue publication."""

    @transition(field=phase, source=["pending", "linked"], target="pending")
    def requeue(self) -> None:
        """A proven undispatched version can be replaced after policy re-evaluation."""

    @transition(field=phase, source=["pending", "linked"], target="cancelled")
    def cancel(self, reason: str) -> None:
        self.refusal_reason = reason

    @transition(field=phase, source=["pending", "linked"], target="delivered")
    def delivered(self) -> None:
        """The linked EmailLog has provider acceptance, rather than merely queue admission."""


class HostingWarningDelivery(WarningLifecycle):
    immutable_fields = ("customer_id_snapshot", "recipient_hash", "version")
    linked_fields = ("email_log_id", "intent_snapshot")
    customer_id_snapshot = models.PositiveBigIntegerField()
    recipient_hash = models.CharField(max_length=64)
    version = models.PositiveIntegerField(default=1)
    parent = models.ForeignKey("self", null=True, on_delete=models.SET_NULL, related_name="replacements")
    phase = FSMField(default="pending", max_length=16, protected=True)
    email_log = models.OneToOneField(
        "notifications.EmailLog", null=True, on_delete=models.SET_NULL, related_name="hosting_warning_delivery"
    )
    intent_snapshot = models.JSONField()
    first_dispatch_claimed_at = models.DateTimeField(null=True)
    accepted_at = models.DateTimeField(null=True)
    refused_at = models.DateTimeField(null=True)
    refusal_reason = models.CharField(max_length=80, blank=True)
    certainty = models.CharField(max_length=20, default="never_dispatched")
    objects = WarningEvidenceQuerySet["HostingWarningDelivery"].as_manager()

    class Meta:
        db_table = "provisioning_hosting_warning_delivery"
        db_table_comment = "One immutable warning body version and its linked transport/dispatch certainty."

    @transition(field=phase, source="pending", target="linked")
    def link(self) -> None:
        if self.email_log_id is None:
            raise ValidationError(_("A warning delivery requires its stored email before queue publication."))

    @transition(field=phase, source=["linked", "dispatching"], target="dispatching")
    def dispatch(self) -> None:
        self.first_dispatch_claimed_at = self.first_dispatch_claimed_at or timezone.now()
        self.certainty = "uncertain"

    @transition(field=phase, source=["linked", "dispatching"], target="accepted")
    def accept(self, accepted_at: Any) -> None:
        self.accepted_at = accepted_at
        self.certainty = "accepted"

    @transition(field=phase, source=["pending", "linked", "dispatching"], target="refused")
    def refuse(self, reason: str) -> None:
        self.refusal_reason = reason
        self.refused_at = timezone.now()
        self.certainty = "uncertain" if self.first_dispatch_claimed_at else "never_dispatched"


class HostingWarningDeliveryPart(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    delivery = models.ForeignKey(HostingWarningDelivery, on_delete=models.CASCADE, related_name="parts")
    intent = models.ForeignKey(HostingWarningIntent, on_delete=models.CASCADE, related_name="delivery_parts")
    active = models.BooleanField(default=True)

    class Meta:
        db_table = "provisioning_hosting_warning_delivery_part"
        db_table_comment = "An intent has at most one send-eligible delivery; refused versions retain their parts."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("delivery", "intent"), name="hosting_warning_delivery_intent"),
            models.UniqueConstraint(
                fields=("intent",), condition=models.Q(active=True), name="hosting_warning_active_delivery"
            ),
        ]
