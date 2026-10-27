"""Bounded admission on the existing worker for Platform-mediated customer backups."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from croniter import croniter
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.infrastructure.imported_backup_transport import server_transport_ready
from apps.settings.services import SettingsService
from apps.settings.setup_checklist import storage_configured

from .virtualmin_backup_service import backup_storage_configuration
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from .virtualmin_service import VirtualminBackupManagementService

SCHEDULED_ACTOR = "scheduled_platform_backup"
MAX_CANDIDATES = 50
CRON_FIELDS = 5
logger = logging.getLogger(__name__)
if TYPE_CHECKING:
    from apps.common.system_status import SubsystemStatus


def _completed_proof(identity: str) -> Q:
    return Q(
        status="completed",
        result__status="completed",
        result__s3_info__storage_identity=identity,
        result__s3_info__metadata_key__regex=r"^virtualmin-backups/[^/\s]+/metadata[.]json$",
        result__checksum_sha256__regex=r"^[a-f0-9]{64}$",
    )


def backup_configuration() -> tuple[bool, str]:
    schedule = str(SettingsService.get_setting("node_deployment.backup_schedule", "0 2 * * *") or "")
    enabled = bool(
        SettingsService.get_setting("node_deployment.backup_enabled", True)
        and SettingsService.get_setting("node_deployment.backup_storage", "platform") == "platform"
        and croniter.is_valid(schedule)
        and len(schedule.split()) == CRON_FIELDS
        and storage_configured()
    )
    return enabled, schedule


def schedule_customer_backup() -> int:
    from apps.common.status_models import SystemCheckState  # noqa: PLC0415  # Cross-app model boundary (ADR-0007).

    enabled, schedule = backup_configuration()
    if not enabled:
        return 0
    due = croniter(schedule, timezone.localtime(timezone.now())).get_prev(datetime)
    with transaction.atomic():
        guard, _ = SystemCheckState.objects.get_or_create(check_key="hosting_backup_scheduler", node=None)
        guard = SystemCheckState.objects.select_for_update().get(pk=guard.pk)
        jobs = VirtualminProvisioningJob.objects.filter(
            operation="backup_domain", parameters__initiated_by=SCHEDULED_ACTOR
        )
        if jobs.filter(status__in=("pending", "running", "attention")).exists():
            return 0
        covered = jobs.filter(account_id=OuterRef("pk"), created_at__gte=due).filter(
            ~Q(status="completed") | _completed_proof(backup_storage_configuration().identity)
        )
        accounts = (
            VirtualminAccount.objects.filter(
                status__in=("active", "suspended"), server__status="active", created_at__lte=due
            )
            .annotate(covered=Exists(covered))
            .filter(covered=False)
        )
        try:
            cursor = UUID(str(guard.details.get("scan_after", "")))
        except ValueError:
            cursor = None
        accounts = accounts.select_related("server").order_by("pk")
        candidates = list((accounts.filter(pk__gt=cursor) if cursor else accounts)[:MAX_CANDIDATES])
        if not candidates and cursor:
            candidates = list(accounts[:MAX_CANDIDATES])
        for account in candidates:
            guard.details = {**guard.details, "scan_after": str(account.pk)}
            if server_transport_ready(account.server).is_err():
                continue
            admitted = VirtualminBackupManagementService(account.server).create_backup_job(
                account, initiated_by=SCHEDULED_ACTOR
            )
            if admitted.is_ok():
                guard.save(update_fields=["details", "updated_at"])
                return 1
        if not candidates:
            guard.details.pop("scan_after", None)
        guard.save(update_fields=["details", "updated_at"])
    return 0


def continue_after_completed_backup(job: VirtualminProvisioningJob) -> None:
    """Register only after the current token completed a scheduled standalone backup."""
    if (
        job.operation != "backup_domain"
        or job.parameters.get("initiated_by") != SCHEDULED_ACTOR
        or job.parameters.get("chain_role", "standalone") != "standalone"
    ):
        return

    def admit_next() -> None:
        try:
            schedule_customer_backup()
        except Exception:
            logger.error("🔥 [Backups] Next scheduled backup could not be admitted; periodic recovery will retry")

    transaction.on_commit(admit_next)


def customer_backup_health() -> SubsystemStatus:
    from apps.common.system_status import StatusLevel, SubsystemStatus  # noqa: PLC0415

    enabled, schedule = backup_configuration()
    name = _("Customer hosting backups")
    if not enabled:
        return SubsystemStatus(name, StatusLevel.AMBER, _("Configure hosting backups"))
    due = croniter(schedule, timezone.localtime(timezone.now())).get_prev(datetime)
    accounts = VirtualminAccount.objects.filter(status__in=("active", "suspended"), created_at__lte=due)
    expected = accounts.count()
    if not expected:
        return SubsystemStatus(name, StatusLevel.GREY, _("No customer backups due yet"))
    jobs = VirtualminProvisioningJob.objects.filter(
        operation="backup_domain", parameters__initiated_by=SCHEDULED_ACTOR, created_at__gte=due, account__in=accounts
    )
    storage_identity = backup_storage_configuration().identity
    completed = set(jobs.filter(_completed_proof(storage_identity)).values_list("account_id", flat=True))
    failed = jobs.filter(status__in=("failed", "attention")).exists()
    detail = _("%(done)s/%(expected)s scheduled customer backups completed off-server.") % {
        "done": len(completed),
        "expected": expected,
    }
    if len(completed) == expected:
        return SubsystemStatus(name, StatusLevel.GREEN, _("Customer backups completed"), detail)
    if failed or timezone.now() >= due + timedelta(hours=2):
        return SubsystemStatus(name, StatusLevel.RED, _("Customer backups failed or overdue"), detail)
    return SubsystemStatus(name, StatusLevel.AMBER, _("Customer backups queued or running"), detail)
