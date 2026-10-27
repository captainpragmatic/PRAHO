"""Fixed deployment-runner bridge for Platform offsite backup artifacts."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import BinaryIO, cast
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from botocore.exceptions import BotoCoreError, ClientError
from croniter import croniter
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac

from apps.common.platform_backup import TRANSFER_CHUNK, BackupArtifact, PlatformBackupPublisher
from apps.common.status_models import SystemCheckState
from apps.common.status_observations import CheckClaim, Observation, claim_check, finish_check
from apps.provisioning.virtualmin_backup_service import (
    BackupStorageConfiguration,
    backup_storage_client,
    backup_storage_configuration,
)
from apps.settings.services import SettingsService
from apps.settings.setup_checklist import clear_setup_cache, storage_configured

logger = logging.getLogger(__name__)
MAX_MANIFEST_BYTES = 16384
PAIR_SIZE = 2
CRON_FIELDS = 5


def storage_identity(configuration: BackupStorageConfiguration | None = None) -> str:
    values = [
        (configuration or backup_storage_configuration()).identity,
        str(SettingsService.get_setting("backup.platform_offsite_enabled", False)),
    ]
    return salted_hmac("praho.platform-backup.v1", json.dumps(values), algorithm="sha256").hexdigest()


def _file_artifact(path: Path, role: str) -> BackupArtifact:
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
        raise ValueError("Backup must be an owned regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(TRANSFER_CHUNK):
            digest.update(block)
    file_format = "tar-gzip" if role == "media" else "postgres-custom" if path.suffix == ".dump" else "sql-gzip"
    artifact = BackupArtifact(role, path.stat().st_size, digest.hexdigest(), file_format)
    artifact.validate()
    return artifact


def _streamed_artifacts() -> tuple[list[BackupArtifact], dict[str, object] | None]:
    raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Backup manifest too large")
    payload = json.loads(raw)
    recovery = None
    if isinstance(payload, dict):
        if set(payload) != {"artifacts", "recovery"} or not isinstance(payload["recovery"], dict):
            raise ValueError("Invalid recovery manifest")
        recovery = payload["recovery"]
        payload = payload["artifacts"]
    if not isinstance(payload, list) or len(payload) != PAIR_SIZE:
        raise ValueError("Expected two backup artifact descriptions")
    artifacts = []
    for item in payload:
        if not isinstance(item, dict) or set(item) != {"role", "size", "sha256", "format"}:
            raise ValueError("Invalid backup artifact description")
        if type(item["size"]) is not int or not all(
            isinstance(item[name], str) for name in ("role", "sha256", "format")
        ):
            raise ValueError("Invalid backup artifact types")
        artifacts.append(BackupArtifact(item["role"], item["size"], item["sha256"], item["format"]))
    return artifacts, recovery


def _upload_local_pair(
    publisher: PlatformBackupPublisher, run_id: UUID, database: Path, media: Path | None
) -> list[BackupArtifact]:
    expected = database.with_name(database.name.removesuffix(".dump").removesuffix(".sql.gz") + ".media.tar.gz")
    if media != expected:
        raise ValueError("Database and media must be the same backup pair")
    artifacts = []
    for role, path in (("database", database), ("media", media)):
        artifact = _file_artifact(path, role)
        with path.open("rb") as stream:
            publisher.upload(run_id, artifact, stream)
        artifacts.append(artifact)
    return artifacts


class Command(BaseCommand):
    help = "Publish a verified database/media backup pair to configured private S3 storage"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--register-runner", choices=("native", "docker"))
        parser.add_argument("--runner-disabled", action="store_true")
        parser.add_argument("--schedule", default="0 2 * * *")
        parser.add_argument("--schedule-timezone", default=settings.TIME_ZONE)
        parser.add_argument("--database", type=Path)
        parser.add_argument("--media", type=Path)
        parser.add_argument("--backup-id", type=UUID)
        parser.add_argument("--artifact", choices=("database", "media"))
        parser.add_argument("--size", type=int)
        parser.add_argument("--sha256")
        parser.add_argument("--format", choices=("postgres-custom", "sql-gzip", "tar-gzip"), default="sql-gzip")
        parser.add_argument("--finalize", action="store_true")
        parser.add_argument("--report-failure", action="store_true")
        parser.add_argument("--check-enabled", action="store_true")

    def handle(self, *args: object, **options: object) -> None:
        if options.get("check_enabled"):
            self.stdout.write(
                "enabled" if SettingsService.get_setting("backup.platform_offsite_enabled", False) else "disabled"
            )
            return
        if options.get("register_runner"):
            self._register(
                str(options["register_runner"]),
                str(options["schedule"]),
                str(options["schedule_timezone"]),
                enabled=not options.get("runner_disabled"),
            )
            return
        if not options.get("report_failure") and not SettingsService.get_setting(
            "backup.platform_offsite_enabled", False
        ):
            self.stdout.write("Platform off-server upload disabled; local backup retained")
            return
        run_id = cast(UUID | None, options.get("backup_id")) or uuid4()
        claim = self._claim(
            run_id,
            start=bool(
                options.get("database") or options.get("artifact") == "database" or options.get("report_failure")
            ),
        )
        try:
            if options.get("report_failure"):
                self._report(claim, run_id, success=False)
                return
            if not storage_configured():
                raise ValueError("Configure private off-server S3 storage first")
            configuration = backup_storage_configuration()
            if storage_identity(configuration) != claim.input_identity:
                raise ValueError("Storage configuration changed before upload")
            bucket = configuration.bucket
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
                raise ValueError("Invalid backup bucket")
            publisher = PlatformBackupPublisher(backup_storage_client(configuration), bucket, claim.state_id)
            artifacts: list[BackupArtifact] = []
            recovery = None
            if options.get("database"):
                artifacts = _upload_local_pair(
                    publisher, run_id, cast(Path, options["database"]), cast(Path | None, options.get("media"))
                )
            elif options.get("artifact"):
                artifact = BackupArtifact(
                    str(options["artifact"]),
                    int(str(options.get("size"))),
                    str(options.get("sha256")),
                    str(options["format"]),
                )
                publisher.upload(run_id, artifact, cast(BinaryIO, sys.stdin.buffer))
                return
            elif options.get("finalize"):
                artifacts, recovery = _streamed_artifacts()
            else:
                raise ValueError("Specify a complete local pair or a streamed artifact")
            publisher.publish(
                run_id, artifacts, recovery=recovery, before_publish=lambda: self._verify_current_claim(claim)
            )
            self._report(claim, run_id, success=True)
            self.stdout.write("Verified off-server database and media backup")
        except (BotoCoreError, ClientError, OSError, ValueError, TypeError) as error:
            self._report(claim, run_id, success=False)
            logger.error("🔥 [Backup] Off-server backup %s failed (%s)", run_id, type(error).__name__)
            raise CommandError(
                "Off-server backup failed; local artifacts retained. Check storage configuration and private logs."
            ) from None

    def _verify_current_claim(self, claim: CheckClaim) -> None:
        if (
            storage_identity() != claim.input_identity
            or not SystemCheckState.objects.filter(
                pk=claim.state_id,
                claim_token=claim.token,
                sequence=claim.sequence,
                configuration_generation=claim.generation,
                lease_until__gt=timezone.now(),
            ).exists()
        ):
            raise ValueError("Backup configuration or execution ownership changed")

    def _register(self, source: str, schedule: str, schedule_timezone: str, *, enabled: bool) -> None:
        if len(schedule.split()) != CRON_FIELDS or not croniter.is_valid(schedule):
            raise CommandError("Invalid backup schedule")
        try:
            ZoneInfo(schedule_timezone)
        except (ValueError, ZoneInfoNotFoundError):
            raise CommandError("Invalid backup schedule timezone") from None
        with transaction.atomic():
            row, _ = SystemCheckState.objects.get_or_create(check_key="platform_backup", node=None)
            row = SystemCheckState.objects.select_for_update().get(pk=row.pk)
            row.details = {
                **row.details,
                "source": source,
                "schedule": schedule,
                "schedule_timezone": schedule_timezone,
                "runner_enabled": enabled,
                "configuration_applied": True,
                "command_version": 1,
            }
            row.save()
            transaction.on_commit(clear_setup_cache)

    def _claim(self, run_id: UUID, *, start: bool) -> CheckClaim:
        with transaction.atomic():
            row = SystemCheckState.objects.select_for_update().filter(check_key="platform_backup", node=None).first()
            if (
                row
                and row.details.get("run_id") == str(run_id)
                and row.claim_token
                and row.lease_until
                and row.lease_until > timezone.now()
            ):
                assert row.last_attempt_at is not None
                return CheckClaim(
                    row.id,
                    row.claim_token,
                    row.configuration_generation,
                    row.sequence,
                    row.input_identity,
                    row.last_attempt_at,
                )
            if not start:
                raise CommandError("No active database upload for this backup")
            claim = claim_check("platform_backup", identity=storage_identity(), lease_time=timedelta(hours=4))
            if claim is None:
                raise CommandError("Another Platform backup is in progress")
            row = SystemCheckState.objects.get(pk=claim.state_id)
            row.details = {**row.details, "run_id": str(run_id), "attempt_at": timezone.now().isoformat()}
            row.save(update_fields=["details", "updated_at"])
            return claim

    def _report(self, claim: CheckClaim, run_id: UUID, *, success: bool) -> None:
        row = SystemCheckState.objects.get(pk=claim.state_id)
        details = {**row.details, "run_id": str(run_id)}
        if success:
            details["offsite_completed_at"] = timezone.now().isoformat()
        accepted = finish_check(
            claim,
            identity=storage_identity,
            observation=Observation(
                "green" if success else "red", "backup_completed" if success else "backup_failed", details
            ),
        )
        if not accepted:
            raise CommandError("Backup result was superseded; no success was recorded")
        transaction.on_commit(clear_setup_cache)
