"""Immutable component scope and source responsibilities, independent of account placement."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

Record = TypeVar("Record", bound="ComponentRecord")


class ComponentRecordQuerySet(models.QuerySet[Record]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Component migration history cannot be overwritten."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Component migration history cannot be deleted."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Component migration history cannot be overwritten."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[Record]:
        raise ValidationError(_("Component migration history must be recorded individually."))


class ComponentRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ComponentRecordQuerySet.as_manager()

    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding or type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError(_("Component migration history cannot be overwritten."))
        self.full_clean()
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Component migration history cannot be deleted."))


class ComponentMigrationReview(ComponentRecord):
    """One native inspection and exact component proposal, without authorizing mutation."""

    account = models.ForeignKey(
        "provisioning.VirtualminAccount", on_delete=models.PROTECT, related_name="component_reviews"
    )
    source_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="component_reviews_out"
    )
    target_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="component_reviews_in"
    )
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    policy_version = models.CharField(max_length=40)
    source_identity = models.CharField(max_length=64)
    target_identity = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    authority_digest = models.CharField(max_length=64)
    manifest = models.JSONField()

    class Meta:
        db_table = "provisioning_component_migration_review"
        db_table_comment = "Immutable inspected scope for moving selected website components."
        ordering = ("-created_at", "-pk")

    def clean(self) -> None:
        from .component_migration_manifest import ComponentManifest  # noqa: PLC0415

        manifest = ComponentManifest.parse(self.manifest)
        source = manifest.as_json()["source"]
        if (
            self.source_server_id == self.target_server_id
            or source["server_uuid"] != str(self.source_server_id)
            or source["connection_identity"] != self.source_identity
            or manifest.digest != self.digest
            or manifest.authority_digest != self.authority_digest
            or source["domain"] != self.account.domain
            or source["owner"] != self.account.virtualmin_username
        ):
            raise ValidationError(_("Component evidence must match the exact account, source and reviewed scope."))


class ComponentMigrationApproval(ComponentRecord):
    review = models.OneToOneField(ComponentMigrationReview, on_delete=models.PROTECT, related_name="approval")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    reason = models.CharField(max_length=2000)
    backup_responsibility = models.CharField(max_length=2000)

    class Meta:
        db_table = "provisioning_component_migration_approval"
        db_table_comment = "Operator acceptance of selected migration impact and retained source duties."

    def clean(self) -> None:
        if not self.reason.strip() or not self.backup_responsibility.strip():
            raise ValidationError(
                _("Accept the component impact and independent source backup responsibility explicitly.")
            )


class SourceServiceObligation(ComponentRecord):
    """The original native domain remains a live service even after account.server changes."""

    source_server = models.ForeignKey(
        "provisioning.VirtualminServer", on_delete=models.PROTECT, related_name="retained_source_services"
    )
    migration = models.OneToOneField(
        "provisioning.VirtualminMigration", on_delete=models.PROTECT, related_name="source_obligation"
    )
    source_domain_id = models.CharField(max_length=30, validators=[RegexValidator(r"\A[0-9]{1,30}\Z")])
    domain = models.CharField(max_length=253)
    owner = models.CharField(max_length=80)
    retained_services = models.JSONField()
    backup_responsible = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    backup_responsibility = models.CharField(max_length=2000)

    class Meta:
        db_table = "provisioning_source_service_obligation"
        db_table_comment = "Retained source mail DNS and authentication duties after website migration."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=("source_server", "source_domain_id"), name="unique_retained_source_domain")
        ]

    def clean(self) -> None:
        if (
            not isinstance(self.retained_services, list)
            or not self.retained_services
            or any(service not in {"mail", "dns", "mysql", "authentication"} for service in self.retained_services)
            or len(set(self.retained_services)) != len(self.retained_services)
        ):
            raise ValidationError(_("Specify the exact retained source services."))
        if not self.backup_responsibility.strip():
            raise ValidationError(_("A named operator must accept responsibility for retained source backups."))
        if self.migration_id and (
            self.migration.source_server_id != self.source_server_id
            or self.migration.account.domain != self.domain
            or self.migration.account.virtualmin_username != self.owner
            or self.migration.contract != "imported_web"
        ):
            raise ValidationError(_("The retained source identity must match its component migration."))


def retained_source_refusal(server_id: uuid.UUID) -> str | None:
    """Account placement cannot prove that retained source mail, DNS or databases are gone."""
    if SourceServiceObligation.objects.filter(source_server_id=server_id, release__isnull=True).exists():
        return str(
            _(
                "Node has retained source services and independent backup responsibilities; resolve them before teardown."
            )
        )
    return None


class SourceServiceRelease(ComponentRecord):
    """Append-only resolution after native absence and a named backup handoff."""

    obligation = models.OneToOneField(SourceServiceObligation, on_delete=models.PROTECT, related_name="release")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    backup_handoff = models.CharField(max_length=2000)
    source_identity = models.CharField(max_length=64, validators=[RegexValidator(r"\A[0-9a-f]{64}\Z")])
    native_absence_digest = models.CharField(max_length=64, validators=[RegexValidator(r"\A[0-9a-f]{64}\Z")])

    class Meta:
        db_table = "provisioning_source_service_release"
        db_table_comment = "Immutable verified release of retained source service and backup duties."

    def clean(self) -> None:
        if not self.backup_handoff.strip():
            raise ValidationError(_("Describe the resolved source services and independent backup handoff."))
