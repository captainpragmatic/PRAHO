"""Immutable migration ceilings with only preauthorized overlay decreases."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import NAMESPACE_URL, uuid5

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .hosting_limit_models import HostingLimitApplication
from .hosting_limit_policy import effective_disk_limit
from .hosting_raise_policy import RaiseTerms
from .hosting_raise_service import current_raise_terms, expire_hosting_raise
from .service_models import Service

if TYPE_CHECKING:
    from .virtualmin_migration_models import VirtualminMigration
    from .virtualmin_models import VirtualminProvisioningJob

_LEGACY_FIELDS = frozenset(
    {
        "application_id",
        "base_revision",
        "overlay_revision",
        "overlay_expires_at",
        "owner_id",
        "disk_cap_mib",
        "bandwidth_mib",
    }
)
REVIEW_SCHEMA = 2


def _original(migration: VirtualminMigration) -> tuple[HostingLimitApplication, dict[str, Any]]:
    frozen = migration.pre_migration_snapshot.get("hosting_limits")
    if not isinstance(frozen, dict) or frozenset(frozen) not in {
        _LEGACY_FIELDS,
        _LEGACY_FIELDS | {"schema", "overlay_extra_mib"},
    }:
        raise ValidationError(_("This migration has no supported immutable hosting-limit review."))
    original = HostingLimitApplication.objects.get(pk=frozen["application_id"])
    expiry = original.overlay_expires_at.isoformat() if original.overlay_expires_at else None
    if (
        original.service_id != migration.account.service_id
        or type(frozen["base_revision"]) is not int
        or frozen["base_revision"] != original.revision
        or type(frozen["overlay_revision"]) is not int
        or frozen["overlay_revision"] != original.overlay_revision
        or frozen["overlay_expires_at"] != expiry
        or frozen["owner_id"] != str(original.authority.get("customer_id"))
        or frozen["bandwidth_mib"] != original.bandwidth_allowance_mib
        or frozen["disk_cap_mib"]
        != effective_disk_limit(original.disk_allowance_mib, extra_mib=original.overlay_extra_mib)
        or (
            "schema" in frozen
            and (
                type(frozen["schema"]) is not int
                or frozen["schema"] != REVIEW_SCHEMA
                or type(frozen["overlay_extra_mib"]) is not int
                or frozen["overlay_extra_mib"] != original.overlay_extra_mib
            )
        )
        or (
            "schema" not in frozen
            and (original.overlay_revision != 0 or original.overlay_extra_mib != 0 or expiry is not None)
        )
    ):
        raise ValidationError(_("The migration's reviewed allowance or overlay evidence changed."))
    return original, frozen


def _within_review(original: HostingLimitApplication, terms: RaiseTerms, owner_id: int) -> bool:
    if str(original.authority.get("customer_id")) != str(owner_id) or terms.extra_mib > original.overlay_extra_mib:
        return False
    if original.overlay_expires_at is None:
        return terms.expires_at is None and terms.revision == 0 and terms.extra_mib == 0
    return (
        terms.expires_at is not None
        and terms.expires_at <= original.overlay_expires_at
        and terms.revision >= original.overlay_revision
    )


def reviewed_parent_application(migration: VirtualminMigration) -> HostingLimitApplication:
    """Keep reviewed base; materialize only current R within its accepted ceiling.

    A financial assignment received while the move is held remains a separate
    outbox for after release. No reviewed record or original application changes.
    """
    with transaction.atomic():
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=migration.account.service_id)
        expire_hosting_raise(service.pk)
        original, _frozen = _original(migration)
        return _derive_reviewed_application(original, service)


def _derive_reviewed_application(original: HostingLimitApplication, service: Service) -> HostingLimitApplication:
    """Caller holds Service and has validated the parent's immutable review."""
    terms = current_raise_terms(service.pk, service.customer_id)
    if not _within_review(original, terms, service.customer_id):
        raise ValidationError(_("Current temporary resources exceed the immutable native-parent review."))
    existing = HostingLimitApplication.objects.filter(
        service=service, revision=original.revision, overlay_revision=terms.revision
    ).first()
    if existing is not None:
        if not _history_matches(original, existing, service.customer_id):
            raise ValidationError(_("The existing reviewed overlay application has different terms."))
        return existing
    return HostingLimitApplication.objects.create(
        service=service,
        revision=original.revision,
        **terms.application_fields(),
        submission_id=uuid5(NAMESPACE_URL, f"praho:reviewed-overlay:{original.pk}:{terms.revision}"),
        expected_plan_id=original.expected_plan_id,
        target_plan_id=original.target_plan_id,
        disk_allowance_mib=original.disk_allowance_mib,
        bandwidth_allowance_mib=original.bandwidth_allowance_mib,
        policy_version=original.policy_version,
        reason="Apply only the current preauthorized overlay within the immutable native-parent ceiling",
        authority={
            "kind": "held_reviewed_overlay",
            "customer_id": str(service.customer_id),
            "reviewed_application_id": str(original.pk),
            "preauthorized_expiry": "acknowledged",
        },
    )


def _history_matches(original: HostingLimitApplication, application: HostingLimitApplication, owner_id: int) -> bool:
    terms = RaiseTerms(application.overlay_revision, application.overlay_extra_mib, application.overlay_expires_at)
    return bool(
        _within_review(original, terms, owner_id)
        and application.service_id == original.service_id
        and application.revision == original.revision
        and application.disk_allowance_mib == original.disk_allowance_mib
        and application.bandwidth_allowance_mib == original.bandwidth_allowance_mib
        and application.expected_plan_id == original.expected_plan_id
        and application.target_plan_id == original.target_plan_id
        and application.policy_version == original.policy_version
        and str(application.authority.get("customer_id")) == str(owner_id)
    )


def reviewed_job_application(job: VirtualminProvisioningJob) -> HostingLimitApplication:
    from .hosting_parent_limits import (  # noqa: PLC0415 -- Shared immutable original admission, avoiding a model import cycle.
        frozen_parent_application,
    )

    original = frozen_parent_application(job)
    with transaction.atomic():
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=original.service_id)
        expire_hosting_raise(service.pk)
        original = frozen_parent_application(job)
        return _derive_reviewed_application(original, service)


def reviewed_job_application_matches(
    job: VirtualminProvisioningJob, application: HostingLimitApplication, *, historical: bool = False
) -> bool:
    """Database-only bounded proof; historical is only for never-issued transfer."""
    from .hosting_parent_limits import frozen_parent_application  # noqa: PLC0415

    try:
        original = frozen_parent_application(job)
        service = Service.objects.get(pk=application.service_id)
        terms = current_raise_terms(service.pk, service.customer_id)
        return bool(
            _history_matches(original, application, service.customer_id)
            and (
                historical
                or (application.overlay_revision, application.overlay_extra_mib, application.overlay_expires_at)
                == (terms.revision, terms.extra_mib, terms.expires_at)
            )
        )
    except (
        ValidationError,
        HostingLimitApplication.DoesNotExist,
        Service.DoesNotExist,
        KeyError,
        ValueError,
        TypeError,
    ):
        return False


def issued_reviewed_parent(application: HostingLimitApplication, parent: dict[str, Any]) -> bool:
    """A current issued parent may repair within its original ceiling after native I/O."""
    if parent.get("job_id"):
        from .hosting_parent_limits import held_parent_cap_repair_issued  # noqa: PLC0415

        return held_parent_cap_repair_issued(application, parent)
    from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

    identifier = parent.get("migration_id")
    if not isinstance(identifier, str):
        return False
    migration = VirtualminMigration.objects.filter(pk=identifier).first()
    return bool(
        migration is not None
        and migration.restore_issued
        and migration.status in {"restoring", "verifying", "activating"}
        and str(migration.lease_token) == parent.get("token")
        and migration.worker_lease_expires_at is not None
        and migration.worker_lease_expires_at > timezone.now()
        and str(migration.target_server_id) == parent.get("native_server_id")
        and migration.pre_migration_snapshot.get("hosting_limits", {}).get("application_id")
        == parent.get("approved_application_id")
        and parent.get("frozen_application_id") == str(application.pk)
        and reviewed_application_matches(migration, application)
    )


def reviewed_application_matches(migration: VirtualminMigration, application: HostingLimitApplication) -> bool:
    """Database-only exact admission predicate; it never derives or mutates terms."""
    try:
        original, _frozen = _original(migration)
    except (ValidationError, HostingLimitApplication.DoesNotExist, KeyError, ValueError, TypeError):
        return False
    service = Service.objects.get(pk=application.service_id)
    terms = current_raise_terms(service.pk, service.customer_id)
    if not _within_review(original, terms, service.customer_id):
        return False
    return bool(
        (application.overlay_revision, application.overlay_extra_mib, application.overlay_expires_at)
        == (terms.revision, terms.extra_mib, terms.expires_at)
        and reviewed_application_history_matches(migration, application)
    )


def reviewed_application_history_matches(migration: VirtualminMigration, application: HostingLimitApplication) -> bool:
    """Retained never-issued history may be older than the current overlay."""
    try:
        original, frozen = _original(migration)
        service = Service.objects.get(pk=application.service_id)
        terms = RaiseTerms(application.overlay_revision, application.overlay_extra_mib, application.overlay_expires_at)
        if not _within_review(original, terms, service.customer_id):
            return False
        cap = effective_disk_limit(application.disk_allowance_mib, extra_mib=terms.extra_mib)
    except (
        ValidationError,
        HostingLimitApplication.DoesNotExist,
        Service.DoesNotExist,
        ValueError,
        KeyError,
        TypeError,
    ):
        return False
    if cap is None or type(frozen["disk_cap_mib"]) is not int:
        return False
    return _history_matches(original, application, service.customer_id) and cap <= frozen["disk_cap_mib"]
