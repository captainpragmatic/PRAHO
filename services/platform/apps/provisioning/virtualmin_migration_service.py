"""Round 1a resume contract; transport and orchestration arrive in Round 1b."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Literal, TypedDict
from uuid import UUID, uuid4

from apps.common.types import Err, Ok, Result

from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_models import VirtualminProvisioningJob

logger = logging.getLogger(__name__)


class MigrationResumeOutcome(TypedDict):
    action: Literal["busy"]
    migration_id: str
    lease_acquired: bool


def resume_migration(job: VirtualminProvisioningJob) -> Result[MigrationResumeOutcome, str]:
    """Probe fencing and return BUSY without performing migration work.

    Both contention and the acquired-lease placeholder return Ok. The retry
    worker's existing claim remains recoverable by its bounded expiry protocol.
    Neither the migration nor its provisioning job is marked completed here.
    """
    try:
        migration_id = UUID(str(job.parameters["migration_id"]))
        migration = VirtualminMigration.objects.get(pk=migration_id)
    except (KeyError, TypeError, ValueError, VirtualminMigration.DoesNotExist):
        return Err("migration not found")

    acquired = migration.acquire_lease(uuid4(), timedelta(minutes=5))
    logger.info(
        "✅ [VirtualminMigration] BUSY foundation placeholder: migration=%s lease_acquired=%s",
        migration.pk,
        acquired,
    )
    outcome: MigrationResumeOutcome = {
        "action": "busy",
        "migration_id": str(migration.pk),
        "lease_acquired": acquired,
    }
    return Ok(outcome)
