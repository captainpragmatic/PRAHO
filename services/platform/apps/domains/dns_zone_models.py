"""Customer DNS zones, immutable import revisions and recoverable provider operations."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, ClassVar, cast

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

from .dns_zone_import import normalize_zone_name

_BINDING_FIELDS = (
    "name",
    "customer_id",
    "provider",
    "provider_account_id",
    "provider_zone_id",
    "service_id",
    "account_id",
    "account_hostname_id",
)


class HostedZoneQuerySet(models.QuerySet["HostedZone"]):
    def bulk_create(self, objs: Any, *args: Any, **kwargs: Any) -> list[HostedZone]:
        values = list(objs)
        for zone in values:
            zone.name = normalize_zone_name(zone.name)
        return super().bulk_create(values, *args, **kwargs)

    def update(self, **kwargs: Any) -> int:
        for relation in ("customer", "service", "account", "account_hostname"):
            if relation in kwargs:
                value = kwargs.pop(relation)
                kwargs[f"{relation}_id"] = value.pk if value is not None else None
        for field in _BINDING_FIELDS:
            if field in kwargs:
                value = normalize_zone_name(kwargs[field]) if field == "name" else kwargs[field]
                if (
                    self.exclude(**{field: value})
                    .exclude(**{f"{field}__isnull": True})
                    .exclude(**{field: ""} if field in {"provider_account_id", "provider_zone_id"} else {})
                    .exists()
                ):
                    raise ValidationError(_("A hosted zone binding cannot be replaced"))
                kwargs[field] = value
        return super().update(**kwargs)


class HostedZone(ConcurrentTransitionMixin, models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT, related_name="hosted_zones")
    service = models.ForeignKey(
        "provisioning.Service", null=True, blank=True, on_delete=models.SET_NULL, related_name="hosted_zones"
    )
    account = models.ForeignKey(
        "provisioning.VirtualminAccount", null=True, blank=True, on_delete=models.SET_NULL, related_name="hosted_zones"
    )
    account_hostname = models.ForeignKey(
        "provisioning.AccountHostname", null=True, blank=True, on_delete=models.PROTECT, related_name="hosted_zones"
    )
    domain = models.ForeignKey(
        "domains.Domain", null=True, blank=True, on_delete=models.SET_NULL, related_name="hosted_zones"
    )
    name = models.CharField(max_length=253)
    provider = models.CharField(max_length=30, default="cloudflare")
    provider_account_id = models.CharField(max_length=128, blank=True)
    provider_zone_id = models.CharField(max_length=128, blank=True)
    provider_status = models.CharField(max_length=40, blank=True)
    assigned_nameservers = models.JSONField(default=list, blank=True)
    provider_plan = models.CharField(max_length=30, default="free")
    enrollment_binding = models.JSONField(default=dict, blank=True)
    managed_ttl_evidence = models.JSONField(default=dict, blank=True)
    current_revision = models.PositiveIntegerField(default=0)
    confirmed_revision = models.PositiveIntegerField(null=True, blank=True)
    applied_revision = models.PositiveIntegerField(null=True, blank=True)
    readiness = models.JSONField(default=dict, blank=True)
    activation = models.JSONField(default=dict, blank=True)
    deletion = models.JSONField(default=dict, blank=True)
    dnssec = models.JSONField(default=dict, blank=True)
    status = FSMField(default="pending_import", max_length=24, protected=True, db_index=True)
    last_error = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = HostedZoneQuerySet.as_manager()

    class Meta:
        db_table = "domain_hosted_zones"
        db_table_comment = "Customer-owned DNS zone with a fixed provider binding and evidenced lifecycle."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["name"], condition=~models.Q(status="deleted"), name="hosted_zone_live_name_unique"
            ),
            models.UniqueConstraint(
                fields=["provider", "provider_account_id", "provider_zone_id"],
                condition=~models.Q(provider_zone_id=""),
                name="hosted_zone_provider_binding_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=("pending_import", "awaiting_ns", "active", "deleting", "deleted", "failed")
                ),
                name="hosted_zone_valid_status",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.name = normalize_zone_name(self.name)
        old = type(self).objects.filter(pk=self.pk).values(*_BINDING_FIELDS).first()
        if old and any(
            old[field] not in (None, "") and getattr(self, field) != old[field] for field in _BINDING_FIELDS
        ):
            raise ValidationError(_("A hosted zone binding cannot be replaced"))
        super().save(*args, **kwargs)

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        previous = self.__dict__.pop("status", None)
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__["status"] = previous
            raise

    def can_offer_nameservers(self) -> bool:
        checked = self.readiness.get("checked_at")
        try:
            when = parse_datetime(checked) if isinstance(checked, str) else None
        except ValueError:
            return False
        return bool(
            self.current_revision
            and self.confirmed_revision == self.applied_revision == self.current_revision
            and self.readiness.get("revision") == self.current_revision
            and self.readiness.get("complete") is True
            and self.readiness.get("ds_safe") is True
            and when is not None
            and timezone.is_aware(when)
            and when >= timezone.now() - timedelta(hours=1)
        )

    def can_activate(self) -> bool:
        return bool(
            self.can_offer_nameservers()
            and self.provider_status == "active"
            and self.activation.get("revision") == self.current_revision
            and self.activation.get("parent_ns_verified") is True
            and self.activation.get("inventory_verified") is True
        )

    def can_delete(self) -> bool:
        return bool(
            self.deletion.get("revision") == self.current_revision
            and all(self.deletion.get(key) is True for key in ("export_verified", "parent_moved_away", "ds_safe"))
        )

    @transition(
        field=status,
        source="pending_import",
        target="awaiting_ns",
        conditions=[lambda zone: cast("HostedZone", zone).can_offer_nameservers()],
    )
    def await_nameservers(self) -> None:
        """A confirmed complete inventory and safe unsigned handover permit instructions."""

    @transition(
        field=status,
        source="awaiting_ns",
        target="active",
        conditions=[lambda zone: cast("HostedZone", zone).can_activate()],
    )
    def activate(self) -> None:
        """Parent delegation, provider status and exact current inventory agree."""
        self.activation = {**self.activation, "activated_at": timezone.now().isoformat()}

    @transition(field=status, source=("pending_import", "awaiting_ns", "active", "deleting"), target="failed")
    def fail(self) -> None:
        """Preserve operation evidence for an explicit retry or staff reconciliation."""

    @transition(field=status, source="failed", target="pending_import")
    def retry(self) -> None:
        """Retry uses the same provider binding and durable operation checkpoints."""

    @transition(
        field=status,
        source=("pending_import", "awaiting_ns", "active", "failed"),
        target="deleting",
        conditions=[lambda zone: cast("HostedZone", zone).can_delete()],
    )
    def start_deleting(self) -> None:
        """Whole-zone deletion has its own export and move-away proof."""

    @transition(
        field=status,
        source="deleting",
        target="deleted",
        conditions=[lambda zone: cast("HostedZone", zone).deletion.get("provider_absent") is True],
    )
    def mark_deleted(self) -> None:
        """The exact owned provider zone was conclusively removed."""


_REVISION_FIELDS = (
    "zone_id",
    "number",
    "raw_upload",
    "raw_digest",
    "inventory_digest",
    "manifest_digest",
    "inventory",
    "manifest",
    "replacements",
    "normalizations",
    "binding",
    "valid",
    "errors",
)


class HostedZoneRevisionQuerySet(models.QuerySet["HostedZoneImportRevision"]):
    def update(self, **kwargs: Any) -> int:
        if set(kwargs).intersection((*_REVISION_FIELDS, "zone", "confirmed_at", "confirmed_by", "confirmed_by_id")):
            raise ValidationError(_("An import revision and its confirmation cannot be rewritten"))
        return super().update(**kwargs)


class HostedZoneImportRevision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    zone = models.ForeignKey(HostedZone, on_delete=models.PROTECT, related_name="revisions")
    number = models.PositiveIntegerField()
    raw_upload = models.BinaryField(editable=False)
    raw_digest = models.CharField(max_length=64)
    inventory_digest = models.CharField(max_length=64)
    manifest_digest = models.CharField(max_length=64)
    inventory = models.JSONField(default=list)
    manifest = models.JSONField(default=list)
    replacements = models.JSONField(default=list)
    normalizations = models.JSONField(default=list)
    binding = models.JSONField(default=dict)
    valid = models.BooleanField(default=False)
    errors = models.JSONField(default=list)
    crosscheck = models.JSONField(default=dict)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    confirmed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = HostedZoneRevisionQuerySet.as_manager()

    class Meta:
        db_table = "domain_hosted_zone_import_revisions"
        db_table_comment = "Private complete zone-file inventory, desired revision and exact customer confirmation."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["zone", "number"], name="hosted_zone_revision_number_unique")
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        old = type(self).objects.filter(pk=self.pk).values(*_REVISION_FIELDS, "confirmed_at", "confirmed_by_id").first()
        if old:
            fields = set(kwargs.get("update_fields") or (*_REVISION_FIELDS, "confirmed_at", "confirmed_by_id"))
            values = {field: getattr(self, field) for field in _REVISION_FIELDS}
            values["raw_upload"] = bytes(values["raw_upload"])
            old["raw_upload"] = bytes(old["raw_upload"])
            if any(old[field] != values[field] for field in _REVISION_FIELDS if field in fields):
                raise ValidationError(_("An import revision cannot be rewritten"))
            if old["confirmed_at"] is not None and (
                ("confirmed_at" in fields and self.confirmed_at != old["confirmed_at"])
                or (
                    fields.intersection(("confirmed_by", "confirmed_by_id"))
                    and self.confirmed_by_id != old["confirmed_by_id"]
                )
            ):
                raise ValidationError(_("An import confirmation cannot be rewritten"))
        super().save(*args, **kwargs)


class HostedZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    zone = models.ForeignKey(HostedZone, on_delete=models.PROTECT, related_name="records")
    name = models.CharField(max_length=253)
    record_type = models.CharField(max_length=16)
    rdata = models.JSONField(default=dict)
    rdata_digest = models.CharField(max_length=64)
    ttl = models.PositiveIntegerField()
    managed_by = models.CharField(
        max_length=12,
        default="imported",
        choices=[("imported", "Imported"), ("customer", "Customer"), ("praho", "PRAHO")],
    )
    managed_slot = models.CharField(max_length=40, blank=True)
    provider_record_id = models.CharField(max_length=128, blank=True)
    desired_revision = models.PositiveIntegerField(default=1)
    applied_revision = models.PositiveIntegerField(null=True, blank=True)
    applied_rdata = models.JSONField(default=dict, blank=True)
    applied_ttl = models.PositiveIntegerField(null=True, blank=True)
    proxied = models.BooleanField(default=False)
    desired_deleted = models.BooleanField(default=False)
    evidence = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_hosted_zone_records"
        db_table_comment = "Stable customer DNS record slots, provenance and confirmed provider state."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["zone", "name", "record_type", "rdata_digest"],
                condition=models.Q(desired_deleted=False),
                name="hosted_zone_live_record_unique",
            ),
            models.UniqueConstraint(
                fields=["zone", "managed_slot"],
                condition=models.Q(desired_deleted=False) & ~models.Q(managed_slot=""),
                name="hosted_zone_live_managed_slot_unique",
            ),
        ]

    @property
    def owner_tag(self) -> str:
        return f"praho:hosted-zone-record:{self.pk}"


class HostedZoneOperation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    zone = models.ForeignKey(HostedZone, on_delete=models.PROTECT, related_name="operations")
    revision = models.ForeignKey(HostedZoneImportRevision, on_delete=models.PROTECT, related_name="operations")
    kind = models.CharField(max_length=24)
    phase = models.CharField(max_length=40, default="queued")
    status = models.CharField(max_length=16, default="pending", db_index=True)
    evidence = models.JSONField(default=dict, blank=True)
    cursor = models.PositiveIntegerField(default=0)
    lease_token = models.UUIDField(null=True, blank=True)
    lease_until = models.DateTimeField(null=True, blank=True, db_index=True)
    worker_started_at = models.DateTimeField(null=True, blank=True)
    next_attempt_at = models.DateTimeField(default=timezone.now, db_index=True)
    registrar_operation = models.ForeignKey("domains.DomainOperation", null=True, blank=True, on_delete=models.PROTECT)
    last_error = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "domain_hosted_zone_operations"
        db_table_comment = "Fenced resumable DNS provider intents, checkpoints and ambiguous outcomes."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["zone"],
                condition=models.Q(status__in=("pending", "running", "waiting", "parked")),
                name="hosted_zone_one_active_operation",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(lease_token__isnull=True, lease_until__isnull=True)
                    | models.Q(lease_token__isnull=False, lease_until__isnull=False)
                ),
                name="hosted_zone_complete_operation_lease",
            ),
        ]
