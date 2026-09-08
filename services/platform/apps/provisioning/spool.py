"""Shared transfer-spool capacity accounting for backup and migration fetches."""

from __future__ import annotations

import logging
import shutil
from datetime import timedelta
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result, Retriability

from .virtualmin_migration_models import SpoolReservation, SpoolRoot

logger = logging.getLogger(__name__)

# Conservative floor for size estimates so an idle account still reserves
# something meaningful (metadata, small sites).
MIN_ESTIMATED_BYTES = 256 * 1024 * 1024


def estimated_transfer_bytes(disk_usage_mb: int) -> int:
    """Per-job transfer estimate: 1.5x current usage, floored (existing pattern)."""
    return max(int(disk_usage_mb * 1.5) * 1024 * 1024, MIN_ESTIMATED_BYTES)


def _spool_root() -> SpoolRoot:
    root, _created = SpoolRoot.objects.get_or_create(singleton=True)
    return root


def acquire_spool_reservation(
    spool_dir: Path, archive_name: str, expected_bytes: int, owner: str, ttl_seconds: int
) -> Result[SpoolReservation, str]:
    """Serialize capacity admission on the singleton root row, then reserve.

    The lock is held only for the milliseconds of sample+sum+insert — never
    across a transfer. The playbook's own free-space assert stays the hard
    floor underneath this accounting.
    """
    with transaction.atomic():
        SpoolRoot.objects.select_for_update().get(pk=_spool_root().pk)
        SpoolReservation.objects.filter(expires_at__lt=timezone.now()).delete()
        reserved = sum(SpoolReservation.objects.values_list("expected_bytes", flat=True))
        free = shutil.disk_usage(spool_dir).free if spool_dir.exists() else 0
        if free - reserved < expected_bytes:
            logger.warning("⚠️ [Spool] Capacity reserved: free=%s reserved=%s wanted=%s", free, reserved, expected_bytes)
            return Err("Transfer spool capacity is reserved; retry later", retriability=Retriability.RETRIABLE)
        reservation = SpoolReservation.objects.create(
            archive_name=archive_name,
            expected_bytes=expected_bytes,
            owner=owner,
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )
    return Ok(reservation)


def release_spool_reservation(archive_name: str) -> None:
    SpoolReservation.objects.filter(archive_name=archive_name).delete()
