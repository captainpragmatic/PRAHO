"""Orphaned media sweeper: deletes stored files that no row names (ADR-0057).

File storage is not transactional. A write site deletes what it stored when a failure it can see
rolls its transaction back; a crash, or a commit that fails after the write site returned, leaves
a file that no row names. The sweeper owns those, for two prefixes only:

- ``tickets/attachments/``: random names from ``generate_secure_filename``, named by
  ``TicketAttachment.file``;
- ``gdpr_exports/``: ``<export id>.enc``, named by ``DataExport.file_path``.

Billing documents are never swept: every referenced fiscal document is kept, and the billing
writers clean up their own failures. A file is deleted only when its name matches its owner's
pattern, its storage modification time is older than the grace period, and no row names it when
checked again immediately before the delete. An export's name is reused when it is regenerated;
that is safe only because storage never hands out a name that exists (``get_available_name``, and
``file_overwrite=False`` on S3).

The grace period bounds how long a writer may hold a file before its row commits; it does not
enforce it. Gunicorn's timeout ends requests and Django-Q's ends tasks, and the startup check keeps
the grace period at least four times the longest task budget Django-Q's settings show. Management
commands have no limit.

After a database restore, files newer than the backup have no row. Both restore scripts pause the
sweeper for ``RESTORE_PAUSE`` (``media_sweep.paused_until``), so those files can be reconciled first.

On S3 with versioning, a delete leaves noncurrent versions behind: sweeping alone does not prove
that a file is gone, nor that nothing encrypted under a retired key remains.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import TypedDict

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import Storage, default_storage
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

GRACE_PERIOD = timedelta(hours=24)
RESTORE_PAUSE = timedelta(days=7)
PAUSE_SETTING = "media_sweep.paused_until"
TASK_BUDGET_MULTIPLE = 4
# get_available_name's collision suffix: an underscore and seven random letters or digits.
_SUFFIX = r"(?:_[A-Za-z0-9]{7})?"
ATTACHMENT_NAME = re.compile(rf"tickets/attachments/ticket_\d{{8}}_\d{{6}}_[0-9a-f]{{32}}{_SUFFIX}\.[a-z0-9]+")
EXPORT_NAME = re.compile(
    rf"gdpr_exports/(?P<export_id>[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}){_SUFFIX}\.enc"
)
# Storage paths staff can configure: each must stay out of the swept prefixes.
CONFIGURABLE_PATHS = ("efactura.storage.xml_path",)


class SweepResult(TypedDict):
    deleted: int
    kept_young: int
    kept_referenced: int
    kept_unknown: int
    failed: int
    paused: bool


def _delete_unreferenced_attachment(storage: Storage, name: str, match: re.Match[str]) -> bool:
    from apps.tickets.models import TicketAttachment  # noqa: PLC0415  # Deferred: common loads before tickets

    with transaction.atomic():
        if TicketAttachment.objects.filter(file=name).exists():
            return False
        _audit_and_delete(storage, name, "ticket_attachment")
    return True


def _delete_unreferenced_export(storage: Storage, name: str, match: re.Match[str]) -> bool:
    from apps.audit.models import DataExport  # noqa: PLC0415  # Deferred: common loads before audit

    with transaction.atomic():
        # Processing holds this row's lock while it writes and records the file (export_files.py).
        list(DataExport.objects.select_for_update().filter(pk=match["export_id"]).values_list("pk", flat=True))
        if DataExport.objects.filter(file_path=name).exists():
            return False
        _audit_and_delete(storage, name, "gdpr_export")
    return True


_OWNERS: tuple[tuple[str, re.Pattern[str], Callable[[Storage, str, re.Match[str]], bool]], ...] = (
    ("tickets/attachments/", ATTACHMENT_NAME, _delete_unreferenced_attachment),
    ("gdpr_exports/", EXPORT_NAME, _delete_unreferenced_export),
)


def _audit_and_delete(storage: Storage, name: str, owner: str) -> None:
    """Record the deletion, then delete: a failed delete rolls the record back with the transaction."""
    from apps.audit.services import AuditService  # noqa: PLC0415  # Deferred: audit imports common

    AuditService.log_simple_event(
        "delete",
        description=f"Deleted orphaned media file {name}",
        actor_type="system",
        metadata={"reason": "orphaned_media_sweep", "path": name, "owner": owner},
    )
    storage.delete(name)


def _list_files(storage: Storage, prefix: str) -> Iterator[str]:
    """Every file under `prefix`, by its storage-relative name; a missing prefix holds none."""
    try:
        directories, files = storage.listdir(prefix)
    except FileNotFoundError:
        return
    for file in files:
        yield f"{prefix}{file}"
    for directory in directories:
        yield from _list_files(storage, f"{prefix}{directory}/")


def _paused_until() -> datetime | None:
    from apps.settings.models import SystemSetting  # noqa: PLC0415  # Deferred: common loads before settings

    # The row, not the settings cache: a restore brings back the cache table as it was at backup time.
    value = SystemSetting.get_value_by_key(PAUSE_SETTING, "")
    if not value:
        return None
    try:
        until = datetime.fromisoformat(str(value))
    except ValueError:
        logger.error("🔥 [MediaSweep] %s is not a date (%r); the sweep stays paused", PAUSE_SETTING, value)
        return datetime.max.replace(tzinfo=UTC)
    return until if timezone.is_aware(until) else until.replace(tzinfo=UTC)


def sweep_orphaned_media(*, storage: Storage | None = None) -> SweepResult:
    """Delete old files under the swept prefixes that no row names; keep and count everything else."""
    storage = storage or default_storage
    now = timezone.now()
    result = SweepResult(deleted=0, kept_young=0, kept_referenced=0, kept_unknown=0, failed=0, paused=False)
    paused_until = _paused_until()
    if paused_until is not None and paused_until > now:
        logger.warning("⚠️ [MediaSweep] Paused until %s; nothing was deleted", paused_until.isoformat())
        result["paused"] = True
        return result

    for prefix, pattern, delete_unreferenced in _OWNERS:
        for name in _list_files(storage, prefix):
            match = pattern.fullmatch(name)
            if match is None:
                continue  # Not a name this sweeper's owners write
            try:
                modified: datetime | None = storage.get_modified_time(name)
            except Exception as exc:  # No time, or gone since the listing (S3 answers a ClientError, not OSError)
                modified = None
                logger.warning("⚠️ [MediaSweep] Kept %s: its age is unknown (%s)", name, type(exc).__name__)
            if modified is None or timezone.is_naive(modified):
                result["kept_unknown"] += 1
                continue
            if now - modified < GRACE_PERIOD:
                result["kept_young"] += 1
                continue
            try:
                deleted = delete_unreferenced(storage, name, match)
            except Exception:
                logger.exception("🔥 [MediaSweep] Could not delete %s", name)
                result["failed"] += 1
                continue
            result["deleted" if deleted else "kept_referenced"] += 1

    logger.info(
        "✅ [MediaSweep] Deleted %(deleted)d orphaned files; kept %(kept_young)d young, "
        "%(kept_referenced)d referenced, %(kept_unknown)d of unknown age; %(failed)d failed",
        result,
    )
    return result


def validate_sweep_configuration() -> None:
    """Fail startup when the grace period cannot outlast a task, or a storage path reaches a swept prefix."""
    from apps.settings.catalog import CATALOG_BY_KEY  # noqa: PLC0415  # Deferred: the catalog imports settings services

    q_cluster = getattr(settings, "Q_CLUSTER", {})
    # `retry` is set above the longest per-task timeout (base.py), so it bounds every task budget.
    budget = timedelta(seconds=max(int(q_cluster.get("timeout") or 0), int(q_cluster.get("retry") or 0)))
    if TASK_BUDGET_MULTIPLE * budget > GRACE_PERIOD:
        raise ImproperlyConfigured(
            f"The media sweep grace period ({GRACE_PERIOD}) must be at least {TASK_BUDGET_MULTIPLE} times "
            f"the longest Django-Q task budget ({budget}), or it can delete a file whose row is still being written"
        )
    for key in CONFIGURABLE_PATHS:
        definition = CATALOG_BY_KEY[key]
        pattern = (definition.validation or {})["pattern"]
        # A database value is validated when it is written; this covers the default and the deployment's.
        deployment_value = getattr(settings, key.replace(".", "_").upper(), None)
        for value in (definition.default, deployment_value):
            if value is not None and re.fullmatch(pattern, str(value)) is None:
                raise ImproperlyConfigured(f"{key} must stay under its own prefix, never a swept one: {value!r}")
