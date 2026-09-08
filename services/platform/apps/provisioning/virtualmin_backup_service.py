"""
Virtualmin Backup Service - PRAHO Platform
Comprehensive backup and restore service for stateful data preservation.

Implements the critical missing functionality for "Cattle Not Pets" architecture:
- Email stores backup/restore
- Database backup/restore
- File uploads backup/restore
- SSL certificates backup/restore
- S3 integration with encryption
- Backup verification and integrity checks
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from django.core.cache import cache
from django.utils import timezone

from apps.common.security_decorators import (
    audit_service_call,
    monitor_performance,
)
from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.settings.services import SettingsService

from .virtualmin_gateway import (
    VirtualminConfig,
    VirtualminGateway,
    explicit_rejection,
    has_explicit_success,
)
from .virtualmin_models import VirtualminAccount, VirtualminServer

try:
    import boto3
except ImportError:
    boto3 = None


@dataclass
class BackupConfig:
    """Configuration object for backup operations."""

    backup_type: str = "full"
    include_email: bool = True
    include_databases: bool = True
    include_files: bool = True
    include_ssl: bool = True


@dataclass
class RestoreConfig:
    """Configuration object for restore operations."""

    backup_id: str
    restore_email: bool = True
    restore_databases: bool = True
    restore_files: bool = True
    restore_ssl: bool = True
    force_restore: bool = False


logger = logging.getLogger(__name__)

# Backup configuration constants
_DEFAULT_BACKUP_RETENTION_DAYS = 90  # Keep backups for 90 days (configurable via SettingsService)

# Per-invocation allowance for the pre-subprocess ssh-wait/hostkey phase
# (readiness 180s + lookup 10s + scan 30s + slack) and the S3 completion tail.
_SSH_SETUP_MARGIN_SECONDS = 240
_S3_COMPLETION_MARGIN_SECONDS = 300


def backup_task_timeout(estimated_bytes: int) -> int:
    """Size-derived task budget: backup-domain + fetch + S3 upload + margins.

    Uses the JOB'S OWN size estimate (never the 50GB global ceiling, which
    would exceed the broker visibility window and reject every admission).
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    backup_timeout = SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", 1800)
    transfer_timeout = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
    mib_s = max(1, SettingsService.get_integer_setting("provisioning.backup_min_transfer_mib_s", 10))
    s3_stage = estimated_bytes // (mib_s * 1024 * 1024) + _S3_COMPLETION_MARGIN_SECONDS
    return backup_timeout + transfer_timeout + _SSH_SETUP_MARGIN_SECONDS + s3_stage + 300


BACKUP_VERIFICATION_TIMEOUT = 300  # 5 minutes for verification (structural)
BACKUP_COMPRESSION_LEVEL = 6  # Balance between speed and compression (structural)
_DEFAULT_MAX_BACKUP_SIZE_GB = 50  # Maximum backup size in GB (configurable via SettingsService)
BACKUP_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks for S3 upload (structural)
S3_MULTIPART_THRESHOLD = 100 * 1024 * 1024  # 100MB threshold for multipart (structural)

# Archive staging path ON THE REMOTE VIRTUALMIN NODE (sent as an API
# parameter), never a controller-local tempfile.
_REMOTE_ARCHIVE_DIR = "/tmp"  # noqa: S108  # Remote node path, not a local tempfile

# Cache keys for backup status
BACKUP_STATUS_CACHE_PREFIX = "virtualmin_backup_status_"
BACKUP_PROGRESS_CACHE_PREFIX = "virtualmin_backup_progress_"
CACHE_TIMEOUT = 3600  # 1 hour


class VirtualminBackupError(Exception):
    """Base exception for backup operations"""


class VirtualminBackupSizeError(VirtualminBackupError):
    """Backup exceeds size limits"""


class VirtualminBackupVerificationError(VirtualminBackupError):
    """Backup verification failed"""


class VirtualminBackupIntegrityError(VirtualminBackupError):
    """Backup integrity check failed"""


class VirtualminBackupService:
    """
    🛡️ Critical: Virtualmin backup service for stateful data preservation.

    This service implements the missing functionality that makes "Cattle Not Pets"
    architecture actually work - preserving customer data across server replacements.
    """

    def __init__(self, server: VirtualminServer):
        self.server = server
        self._s3_client = None
        self._backup_bucket = None

    def _call_checked(
        self, gateway: VirtualminGateway, program: str, params: dict[str, Any], timeout_seconds: int
    ) -> Result[dict[str, Any], str]:
        """Gateway call with the explicit-success discipline (no dead ok-branches)."""
        result = gateway.call(program, params, timeout_seconds=timeout_seconds)
        if result.is_err():
            return Err(f"{program} failed: {result.unwrap_err()}", retriability=retriability_of(result))
        response = result.unwrap()
        if not response.success:
            rejection = explicit_rejection(response.raw_response)
            if rejection is None:
                # Uncertainty about a possibly-executed command — never definite.
                return Err(f"{program} ambiguous: response could not be interpreted", retriability=Retriability.UNKNOWN)
            return Err(f"{program} rejected: {rejection}", retriability=Retriability.NOT_RETRIABLE)
        if not has_explicit_success(response):
            return Err(f"{program} lacked an explicit synchronous success response", retriability=Retriability.UNKNOWN)
        return Ok(response.data)

    def _backup_command_timeout(self) -> int:
        return SettingsService.get_integer_setting("provisioning.migration_backup_timeout_seconds", 1800)

    def _execute_backup_by_type(
        self, config: BackupConfig, account: VirtualminAccount, backup_id: str, backup_metadata: dict[str, Any]
    ) -> Result[Any, str]:
        """Execute backup based on configuration type"""
        backup_type = config.backup_type
        if backup_type == "full":
            return self._execute_full_backup(account, backup_id, backup_metadata, config)
        elif backup_type == "config_only":
            return self._execute_config_backup(account, backup_id, backup_metadata)
        else:
            # Incremental backups were removed in #431 v1: the previous code
            # never passed the chosen base into the command and silently fell
            # back to full, stranding archives. Honest refusal until a real
            # incremental contract exists.
            return Err(f"Unsupported backup type: {backup_type}")

    def _backup_workflow_chain(  # noqa: PLR0911  # Complexity: cohesive workflow
        self, account: VirtualminAccount, backup_id: str, backup_metadata: dict[str, Any], config: BackupConfig
    ) -> Result[dict[str, Any], str]:
        """Execute the backup workflow as a chain of operations"""
        # Validate backup preconditions
        validation_result = self._validate_backup_preconditions(account)
        if validation_result.is_err():
            return Err(validation_result.unwrap_err())

        # Stage boundary: a superseded runner must not dispatch remote work.
        if not self._owns_execution():
            return Err("Backup execution superseded; no remote work performed")

        # Execute backup based on type
        backup_result = self._execute_backup_by_type(config, account, backup_id, backup_metadata)
        if backup_result.is_err():
            self._update_backup_progress(backup_id, "failed", 100)
            return Err(backup_result.unwrap_err())

        # The archive is written by the remote Virtualmin backup-domain API; it
        # lives on the node until the fetch playbook pulls it into the spool
        # (and deletes the remote temp copy after a validated transfer).
        backup_metadata["backup_path"] = backup_result.unwrap()
        backup_metadata["backup_location"] = "remote"
        backup_metadata["backup_host"] = self.server.hostname

        # Transport: remote node -> controller spool (checksum-evidenced).
        self._update_backup_progress(backup_id, "fetching", 70)
        fetch_result = self._fetch_archive_to_spool(backup_metadata)
        if fetch_result.is_err():
            self._update_backup_progress(backup_id, "failed", 100)
            return Err(fetch_result.unwrap_err())

        try:
            # Verify backup integrity (local spool file vs the remote checksum).
            self._update_backup_progress(backup_id, "verifying", 85)
            verification_result = self._verify_backup_integrity(backup_id, backup_metadata)
            if verification_result.is_err():
                self._update_backup_progress(backup_id, "failed", 100)
                return Err(verification_result.unwrap_err())

            # Stage boundary: no publication after a takeover rotated our token.
            if not self._owns_execution():
                self._update_backup_progress(backup_id, "failed", 100)
                return Err("Backup execution superseded; archive not published")

            # Finalize the manifest BEFORE publishing: a metadata object in S3
            # must never claim in_progress or omit its checksum.
            backup_metadata["status"] = "completed"
            backup_metadata["completed_at"] = timezone.now().isoformat()

            # Upload to S3 with encryption (archive first, metadata LAST).
            self._update_backup_progress(backup_id, "uploading", 90)
            upload_result = self._upload_backup_to_s3(backup_id, backup_metadata)
            if upload_result.is_err():
                self._update_backup_progress(backup_id, "failed", 100)
                return upload_result
        finally:
            self._release_spool_artifacts(backup_metadata)

        # Finalize backup
        self._update_backup_progress(backup_id, "completed", 100)
        final_metadata = self._finalize_backup_metadata(backup_metadata, upload_result.unwrap())
        logger.info(f"Backup completed successfully: {backup_id}")
        return Ok(final_metadata)

    @audit_service_call("backup_domain")
    def backup_domain(
        self,
        account: VirtualminAccount,
        config: BackupConfig | None = None,
        progress_key: str | None = None,
        ownership: Callable[[], bool] | None = None,
    ) -> Result[dict[str, Any], str]:
        """
        Create comprehensive backup of Virtualmin domain.

        Args:
            account: Virtualmin account to backup
            backup_type: "full", "incremental", or "config_only"
            include_email: Include email stores and settings
            include_databases: Include MySQL/PostgreSQL databases
            include_files: Include web files and uploads
            include_ssl: Include SSL certificates and keys

        Returns:
            Result with backup metadata or error message
        """
        if config is None:
            config = BackupConfig()

        logger.info(f"Starting {config.backup_type} backup for account {account.domain}")

        try:
            # Initialize backup session; progress is keyed by the caller's key
            # (the job id) when provided so the status page can follow it.
            backup_id = self._generate_backup_id(account)
            self._progress_key: str | None = progress_key or backup_id
            self._ownership = ownership
            backup_metadata = self._initialize_backup_metadata(account, config.backup_type, backup_id, config)
            self._update_backup_progress(backup_id, "initializing", 0)

            # Execute backup workflow
            return self._backup_workflow_chain(account, backup_id, backup_metadata, config)

        except Exception as e:
            logger.error(f"Backup failed for account {account.domain}: {e}")
            if "backup_id" in locals():
                self._update_backup_progress(backup_id, "failed", 100)
            return Err(f"Backup operation failed: {e!s}")
        finally:
            self._progress_key = None
            self._ownership = None

    def _owns_execution(self) -> bool:
        """Stage-boundary ownership check; True when no fencing was requested."""
        checker = getattr(self, "_ownership", None)
        return True if checker is None else bool(checker())

    @monitor_performance(max_duration_seconds=600, alert_threshold=120)
    @audit_service_call("restore_domain")
    def restore_domain(  # noqa: PLR0913  # Execution-context seams (job id, fencing, evidence sink)
        self,
        account: VirtualminAccount,
        config: RestoreConfig,
        target_server: VirtualminServer | None = None,
        progress_key: str | None = None,
        ownership: Callable[[], bool] | None = None,
        note_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> Result[dict[str, Any], str]:
        """Restore a domain from a published backup (transport-based, fail-closed).

        Ambiguous remote outcomes return Err with UNKNOWN retriability — the
        job layer parks those for operator attention instead of failing them.
        """
        target_server = target_server or self.server
        logger.info(f"Starting restore for account {account.domain} from backup {config.backup_id}")
        restore_id = self._generate_restore_id(account, config.backup_id)
        self._progress_key = progress_key or restore_id
        self._ownership = ownership
        try:
            self._update_restore_progress(restore_id, "initializing", 0)
            return self._restore_workflow(account, config, target_server, restore_id, note_sink)
        except Exception as e:
            logger.error(f"Restore failed for account {account.domain}: {e}")
            self._update_restore_progress(restore_id, "failed", 100)
            return Err(f"Restore operation failed: {e!s}")
        finally:
            self._progress_key = None
            self._ownership = None

    def _restore_workflow(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Distinct fail-closed gates
        self,
        account: VirtualminAccount,
        config: RestoreConfig,
        target_server: VirtualminServer,
        restore_id: str,
        note_sink: Callable[[dict[str, Any]], None] | None,
    ) -> Result[dict[str, Any], str]:
        from .spool import release_spool_reservation  # noqa: PLC0415

        if not (config.restore_email and config.restore_databases and config.restore_files and config.restore_ssl):
            return Err(
                "Component-selective restore is not supported yet; all components must be enabled",
                retriability=Retriability.NOT_RETRIABLE,
            )

        # Download the archive + manifest into the spool (checksum-mandatory).
        self._update_restore_progress(restore_id, "downloading", 10)
        download = self._download_backup_to_spool(config.backup_id)
        if download.is_err():
            return Err(download.unwrap_err(), retriability=retriability_of(download))
        spool_path, metadata = download.unwrap()
        archive_name = str(metadata["archive_name"])
        remote_pushed = False
        # C3 fail-safe: an EXCEPTION after the push must NOT delete the pushed
        # archive — it is the operator's reconciliation artifact.
        determinate = False
        try:
            # Authorization: the backup must belong to THIS account and domain.
            if str(metadata.get("praho_service_id")) != str(account.service_id):
                return Err(
                    "Backup does not belong to this account's service; restore refused",
                    retriability=Retriability.NOT_RETRIABLE,
                )
            if str(metadata.get("domain")) != account.domain:
                return Err(
                    "Backup domain does not match the target account; restore refused",
                    retriability=Retriability.NOT_RETRIABLE,
                )

            # Target ownership/state gate (force can NEVER override ownership).
            self._update_restore_progress(restore_id, "verifying_target", 25)
            gate = self._target_domain_gate(target_server, account, force=config.force_restore)
            if gate.is_err():
                return Err(gate.unwrap_err(), retriability=retriability_of(gate))
            domain_exists = gate.unwrap()

            # Safety backup of the live target BEFORE any destructive dispatch.
            if domain_exists:
                self._update_restore_progress(restore_id, "safety_backup", 35)
                safety = VirtualminBackupService(target_server).backup_domain(
                    account=account, config=BackupConfig(), ownership=self._ownership
                )
                if safety.is_err():
                    return Err(
                        f"Pre-restore safety backup failed: {safety.unwrap_err()}",
                        retriability=Retriability.NOT_RETRIABLE,
                    )
                safety_id = str(safety.unwrap().get("backup_id", ""))
                if note_sink is not None:
                    note_sink({"safety_backup_id": safety_id})
            else:
                safety_id = ""

            if not self._owns_execution():
                return Err(
                    "Restore execution superseded; no destructive work performed",
                    retriability=Retriability.NOT_RETRIABLE,
                )

            # Push the archive to the target node.
            self._update_restore_progress(restore_id, "pushing", 55)
            push = self._push_archive_to_target(target_server, archive_name, str(metadata["checksum_sha256"]))
            if push.is_err():
                determinate = True  # nothing destructive was issued
                return Err(push.unwrap_err(), retriability=retriability_of(push))
            remote_pushed = True

            # Staleness re-check immediately before the destructive call.
            regate = self._target_domain_gate(target_server, account, force=config.force_restore)
            if regate.is_err():
                determinate = True  # nothing destructive was issued
                return Err(
                    f"Pre-restore re-check failed: {regate.unwrap_err()}", retriability=Retriability.NOT_RETRIABLE
                )
            # W1: a domain that APPEARED during the transfer never got its safety
            # backup — refuse rather than overwrite it.
            if regate.unwrap() and not domain_exists:
                determinate = True
                return Err(
                    "Target domain appeared during the transfer and has no safety backup; restore refused",
                    retriability=Retriability.NOT_RETRIABLE,
                )

            if not self._owns_execution():
                return Err(
                    "Restore execution superseded; no destructive work performed",
                    retriability=Retriability.NOT_RETRIABLE,
                )

            # The one destructive call, explicit-success required.
            self._update_restore_progress(restore_id, "restoring", 70)
            gateway = VirtualminGateway(VirtualminConfig(server=target_server))
            restore_result = self._call_checked(
                gateway,
                "restore-domain",
                {
                    "domain": account.domain,
                    "source": f"{_REMOTE_ARCHIVE_DIR}/{archive_name}",
                    "all-features": True,
                },
                self._backup_command_timeout(),
            )
            if restore_result.is_err():
                determinate = retriability_of(restore_result) is not Retriability.UNKNOWN
                return Err(
                    f"Restore failed: {restore_result.unwrap_err()}",
                    retriability=retriability_of(restore_result),
                )

            # Post-restore verification (uncertainty here is NOT a definite failure).
            self._update_restore_progress(restore_id, "verifying", 90)
            verify = self._verify_restored_domain(target_server, account)
            if verify.is_err():
                return Err(
                    f"Restore issued but could not be verified: {verify.unwrap_err()}",
                    retriability=Retriability.UNKNOWN,
                )

            determinate = True
            self._update_restore_progress(restore_id, "completed", 100)
            return Ok(
                {
                    "restore_id": restore_id,
                    "backup_id": config.backup_id,
                    "safety_backup_id": safety_id,
                    "domain": account.domain,
                    "completed_at": timezone.now().isoformat(),
                }
            )
        finally:
            # Spool copy is re-downloadable from S3 — always remove + release.
            try:
                Path(spool_path).unlink(missing_ok=True)
            except OSError:
                logger.warning("⚠️ [Restore] Spool cleanup failed for %s", spool_path)
            release_spool_reservation(archive_name)
            # The pushed remote archive is removed only on DETERMINATE outcomes;
            # an uncertain restore keeps it for operator reconciliation.
            if remote_pushed and determinate:
                self._cleanup_remote_archive(target_server, archive_name)

    def _target_domain_gate(
        self, target_server: VirtualminServer, account: VirtualminAccount, *, force: bool
    ) -> Result[bool, str]:
        """Fail-closed target inspection. Ok(True)=live domain, Ok(False)=absent."""
        from .virtualmin_migration_service import list_migration_domains  # noqa: PLC0415

        gateway = VirtualminGateway(VirtualminConfig(server=target_server))
        listing = list_migration_domains(gateway)
        if listing.is_err():
            return Err(f"Target listing failed: {listing.unwrap_err()}", retriability=Retriability.NOT_RETRIABLE)
        rows = [row for row in listing.unwrap() if row["domain"] == account.domain]
        if not rows:
            return Ok(False)
        row = rows[0]
        if not row["username"] or row["username"] != account.virtualmin_username:
            return Err(
                "Target domain exists with unknown or foreign ownership; restore refused regardless of force",
                retriability=Retriability.NOT_RETRIABLE,
            )
        if row["enabled"] is None:
            return Err(
                "Target domain state is unverifiable; restore refused regardless of force",
                retriability=Retriability.NOT_RETRIABLE,
            )
        if not force:
            return Err(
                "Target domain is live; restoring would overwrite current data — enable force restore to override",
                retriability=Retriability.NOT_RETRIABLE,
            )
        return Ok(True)

    def _push_archive_to_target(
        self, target_server: VirtualminServer, archive_name: str, expected_sha256: str
    ) -> Result[None, str]:
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

        deployment = getattr(target_server, "node_deployment", None)
        if deployment is None:
            return Err(
                f"Server {target_server.hostname} is manually registered (no managed node_deployment); "
                "archive transport is unavailable"
            )
        transfer_timeout = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
        variables: dict[str, Any] = {
            "archive_name": archive_name,
            "spool_dir": str(self._spool_dir()),
            "expected_sha256": expected_sha256,
        }
        result = AnsibleService().run_playbook(
            deployment, "virtualmin_backup_push.yml", variables, timeout_seconds=transfer_timeout
        )
        if result.is_err() or not result.unwrap().success:
            detail = result.unwrap_err() if result.is_err() else "playbook reported failure or timed out"
            return Err(f"Backup archive push failed: {detail}", retriability=Retriability.NOT_RETRIABLE)
        return Ok(None)

    def _verify_restored_domain(self, target_server: VirtualminServer, account: VirtualminAccount) -> Result[None, str]:
        from .virtualmin_migration_service import list_migration_domains  # noqa: PLC0415

        gateway = VirtualminGateway(VirtualminConfig(server=target_server))
        listing = list_migration_domains(gateway)
        if listing.is_err():
            return Err(listing.unwrap_err())
        rows = [row for row in listing.unwrap() if row["domain"] == account.domain]
        if len(rows) != 1 or rows[0]["username"] != account.virtualmin_username:
            return Err("restored domain missing or owner mismatch on the target listing")
        return Ok(None)

    def _cleanup_remote_archive(self, target_server: VirtualminServer, archive_name: str) -> None:
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

        deployment = getattr(target_server, "node_deployment", None)
        if deployment is None:
            return
        try:
            AnsibleService().run_playbook(
                deployment, "virtualmin_remote_cleanup.yml", {"archive_name": archive_name}, timeout_seconds=300
            )
        except Exception:
            logger.warning("⚠️ [Restore] Remote archive cleanup failed for %s", archive_name)

    def list_backups(
        self, account: VirtualminAccount | None = None, backup_type: str | None = None, max_age_days: int | None = None
    ) -> Result[list[dict[str, Any]], str]:
        """List available backups with filtering options."""
        if max_age_days is None:
            max_age_days = SettingsService.get_integer_setting(
                "provisioning.backup_retention_days", _DEFAULT_BACKUP_RETENTION_DAYS
            )
        try:
            s3_client = self._get_s3_client()
            bucket_name = self._get_backup_bucket()

            # #431: the account filter is applied to metadata below, NOT to the S3 prefix.
            # Archives and metadata are stored under virtualmin-backups/{backup_id}/, so a
            # domain-scoped prefix ("virtualmin-backups/{domain}/") matched no key at all and
            # an account-scoped list always returned zero backups — indistinguishable from
            # "this account has no backups". Keeping the existing key layout means archives
            # already in S3 stay listable; the cost is O(all retained metadata) GETs per
            # account-scoped list (acceptable while buckets are small; a by-service metadata
            # index under virtualmin-backups/by-service/{service_id}/ is the structural fix
            # if that ever hurts).
            prefix = "virtualmin-backups/"

            # List objects from S3
            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            backups = []
            cutoff_date = timezone.now() - timedelta(days=max_age_days)

            for page in pages:
                for obj in page.get("Contents", []):
                    if obj["Key"].endswith(".json"):  # Metadata files
                        try:
                            # Get metadata
                            metadata_obj = s3_client.get_object(Bucket=bucket_name, Key=obj["Key"])
                            metadata = json.loads(metadata_obj["Body"].read())

                            # Apply filters. Account identity is the STABLE service id, never
                            # the domain: a primary-domain rename would hide the account's own
                            # earlier backups, and a domain released by customer A and later
                            # registered by customer B must not surface A's archives in B's
                            # list (the restore view trusts this list — a domain match would
                            # let A's archive be restored into B's account). Metadata without
                            # a service id is unattributable and fails closed. str() both
                            # sides: JSON round-trips UUIDs as strings.
                            if account:
                                metadata_sid = metadata.get("praho_service_id")
                                if metadata_sid is None or str(metadata_sid) != str(account.service_id):
                                    continue

                            if backup_type and metadata.get("backup_type") != backup_type:
                                continue

                            backup_date = datetime.fromisoformat(metadata["created_at"])
                            if backup_date < cutoff_date:
                                continue

                            backups.append(metadata)

                        except Exception as e:
                            logger.warning(f"Failed to parse backup metadata {obj['Key']}: {e}")

            # Sort by creation date (newest first)
            backups.sort(key=lambda x: x["created_at"], reverse=True)

            return Ok(backups)

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return Err(f"Failed to list backups: {e!s}")

    def delete_backup(self, backup_id: str) -> Result[dict[str, Any], str]:
        """Delete backup from S3 storage."""
        try:
            s3_client = self._get_s3_client()
            bucket_name = self._get_backup_bucket()

            # List all objects for this backup
            prefix = f"virtualmin-backups/{backup_id}"
            objects_to_delete = []

            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            for page in pages:
                objects_to_delete.extend([{"Key": obj["Key"]} for obj in page.get("Contents", [])])

            if not objects_to_delete:
                return Err(f"Backup {backup_id} not found")

            # Delete objects
            s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objects_to_delete})

            logger.info(f"Deleted backup {backup_id} ({len(objects_to_delete)} objects)")
            return Ok(
                {
                    "backup_id": backup_id,
                    "deleted_objects": len(objects_to_delete),
                    "deleted_at": timezone.now().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return Err(f"Failed to delete backup: {e!s}")

    def get_backup_status(self, backup_id: str) -> dict[str, Any]:
        """Get current backup operation status."""
        progress_key = f"{BACKUP_PROGRESS_CACHE_PREFIX}{backup_id}"
        return cast(
            dict[str, Any],
            cache.get(progress_key, {"status": "unknown", "progress": 0, "message": "No status available"}),
        )

    def get_restore_status(self, restore_id: str) -> dict[str, Any]:
        """Get current restore operation status."""
        progress_key = f"virtualmin_restore_progress_{restore_id}"
        return cast(
            dict[str, Any],
            cache.get(progress_key, {"status": "unknown", "progress": 0, "message": "No status available"}),
        )

    # Private implementation methods

    def _get_s3_client(self) -> boto3.client:
        """Get configured S3 client."""
        if self._s3_client is None:
            aws_access_key = SettingsService.get_setting("backup.aws_access_key_id")
            aws_secret_key = SettingsService.get_setting("backup.aws_secret_access_key")
            aws_region = SettingsService.get_setting("backup.aws_region", "eu-west-1")

            self._s3_client = boto3.client(
                "s3", aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region
            )
        return self._s3_client

    def _get_backup_bucket(self) -> str:
        """Get S3 backup bucket name."""
        if self._backup_bucket is None:
            bucket_value = SettingsService.get_setting("backup.s3_bucket_name")
            self._backup_bucket = str(bucket_value) if bucket_value is not None else None  # type: ignore[assignment]

            if self._backup_bucket is None:
                raise ValueError("S3 backup bucket name is not configured")

        return self._backup_bucket  # type: ignore[unreachable]

    def _generate_backup_id(self, account: VirtualminAccount) -> str:
        """Stable-ish identity for S3 keys; uuid suffix kills same-second collisions."""
        timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        domain_hash = hashlib.sha256(account.domain.encode()).hexdigest()[:8]
        return f"{account.domain}_{timestamp}_{domain_hash}_{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _generate_archive_name() -> str:
        """UUID-only remote/spool filename: no tenant strings in remote paths."""
        return f"virtualmin_backup_{uuid.uuid4().hex}.tar.gz"

    def _generate_restore_id(self, account: VirtualminAccount, backup_id: str) -> str:
        """Generate unique restore identifier."""
        timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        return f"{account.domain}_restore_{timestamp}_{backup_id[:8]}"

    def _initialize_backup_metadata(
        self, account: VirtualminAccount, backup_type: str, backup_id: str, config: BackupConfig
    ) -> dict[str, Any]:
        """Initialize backup metadata structure."""
        return {
            "backup_id": backup_id,
            "domain": account.domain,
            "server_hostname": self.server.hostname,
            "backup_type": backup_type,
            "created_at": timezone.now().isoformat(),
            # str() for JSON type-stability: the account filter in list_backups compares
            # str()-normalized ids, so the stored form survives pk-type changes and JSON
            # round-trips. (Service.pk is a BigAutoField today; do NOT source this from
            # account.praho_service_id — that UUIDField holds an int-coerced UUID.)
            "praho_service_id": str(account.service_id),
            "include_email": config.include_email,
            "include_databases": config.include_databases,
            "include_files": config.include_files,
            "include_ssl": config.include_ssl,
            "version": "1.0",
            "status": "in_progress",
            "archive_name": self._generate_archive_name(),
            "disk_usage_mb": account.current_disk_usage_mb or 0,
        }

    def _update_backup_progress(self, backup_id: str, status: str, progress: int) -> None:
        """Update backup progress in cache (keyed by the caller's key when set)."""
        cache_id = getattr(self, "_progress_key", None) or backup_id
        progress_key = f"{BACKUP_PROGRESS_CACHE_PREFIX}{cache_id}"
        cache.set(
            progress_key,
            {"backup_id": backup_id, "status": status, "progress": progress, "updated_at": timezone.now().isoformat()},
            CACHE_TIMEOUT,
        )

    def _update_restore_progress(self, restore_id: str, status: str, progress: int) -> None:
        """Update restore progress in cache."""
        progress_key = f"virtualmin_restore_progress_{restore_id}"
        cache.set(
            progress_key,
            {
                "restore_id": restore_id,
                "status": status,
                "progress": progress,
                "updated_at": timezone.now().isoformat(),
            },
            CACHE_TIMEOUT,
        )

    def _spool_dir(self) -> Path:
        return Path(
            str(SettingsService.get_setting("provisioning.migration_spool_dir", "/var/lib/praho/migration-spool"))
        )

    def _fetch_archive_to_spool(  # noqa: PLR0911  # Distinct transport refusals
        self, metadata: dict[str, Any]
    ) -> Result[None, str]:
        """Pull the remote archive into the controller spool and delete the remote copy."""
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

        from .spool import (  # noqa: PLC0415
            acquire_spool_reservation,
            estimated_transfer_bytes,
            release_spool_reservation,
        )

        deployment = getattr(self.server, "node_deployment", None)
        if deployment is None:
            return Err(
                f"Server {self.server.hostname} is manually registered (no managed node_deployment); "
                "archive transport is unavailable"
            )
        archive_name = str(metadata["archive_name"])
        spool = self._spool_dir()
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        if spool.is_symlink() or spool.stat().st_mode & 0o077:
            return Err("Transfer spool must be a private directory", retriability=Retriability.NOT_RETRIABLE)
        transfer_timeout = SettingsService.get_integer_setting("provisioning.migration_transfer_timeout_seconds", 3600)
        expected = estimated_transfer_bytes(int(metadata.get("disk_usage_mb") or 0))
        owner = f"job:{self._progress_key}" if getattr(self, "_progress_key", None) else f"backup:{archive_name}"
        reservation = acquire_spool_reservation(spool, archive_name, expected, owner, transfer_timeout + 300)
        if reservation.is_err():
            return Err(reservation.unwrap_err())
        try:
            variables: dict[str, Any] = {
                "archive_name": archive_name,
                "spool_dir": str(spool),
                "spool_free_bytes": shutil.disk_usage(spool).free,
            }
            result = AnsibleService().run_playbook(
                deployment, "virtualmin_backup_fetch.yml", variables, timeout_seconds=transfer_timeout
            )
            if result.is_err() or not result.unwrap().success:
                detail = result.unwrap_err() if result.is_err() else "playbook reported failure or timed out"
                return Err(f"Backup archive fetch failed: {detail}")
            checksums = set(re.findall(r"BACKUP_SHA256=([0-9a-f]{64})(?![0-9a-f])", result.unwrap().stdout))
            if len(checksums) != 1:
                return Err("Backup fetch did not return exactly one SHA-256")
            metadata["checksum_sha256_remote"] = checksums.pop()
            metadata["backup_path"] = str(spool / archive_name)
            metadata["backup_location"] = "spool"
            return Ok(None)
        except Exception as error:
            return Err(f"Backup archive fetch failed: {error}")
        finally:
            release_spool_reservation(archive_name)

    def _release_spool_artifacts(self, metadata: dict[str, Any]) -> None:
        """Remove the spool file on determinate exits; never mask the outcome."""
        if metadata.get("backup_location") != "spool":
            return
        try:
            path = Path(str(metadata.get("backup_path", "")))
            if path.exists():
                path.unlink()
        except OSError as error:
            logger.warning("⚠️ [Backup] Spool cleanup failed: %s", error)

    def _validate_backup_preconditions(self, account: VirtualminAccount) -> Result[None, str]:
        """Validate that backup can proceed safely."""
        # Transport capability gate BEFORE any remote archive is created:
        # a manually-registered server has no Ansible path off the node.
        if getattr(self.server, "node_deployment", None) is None:
            return Err(
                f"Server {self.server.hostname} is manually registered (no managed node_deployment); "
                "archive transport is unavailable"
            )
        # Check server connectivity
        config = VirtualminConfig(server=self.server)
        gateway = VirtualminGateway(config)
        ping_result = gateway.ping_server()
        if not ping_result:
            return Err(f"Server {self.server.hostname} is unreachable")

        # Check account exists on server
        account_info_result = gateway.get_domain_info(account.domain)
        if account_info_result.is_err():
            return Err(f"Failed to get domain info: {account_info_result.unwrap_err()}")

        account_info = account_info_result.unwrap()
        if not account_info.get("disk_usage_mb"):
            return Err(f"Domain {account.domain} not found on server")

        # Check available disk space (rough estimate)
        disk_info = account_info.get("disk_usage_mb", 0)
        account_info.get("disk_quota_mb", 0)

        # Estimate backup size (typically 1.5x of current usage for full backup with compression)
        estimated_backup_size_mb = int(disk_info * 1.5)

        # Check if backup would exceed size limits
        max_backup_size_gb = SettingsService.get_integer_setting(
            "provisioning.max_backup_size_gb", _DEFAULT_MAX_BACKUP_SIZE_GB
        )
        if estimated_backup_size_mb > (max_backup_size_gb * 1024):
            return Err(f"Estimated backup size ({estimated_backup_size_mb}MB) exceeds limit ({max_backup_size_gb}GB)")

        logger.debug(
            f"Backup preconditions validated for {account.domain}: "
            f"disk_usage={disk_info}MB, estimated_backup={estimated_backup_size_mb}MB"
        )

        return Ok(None)

    def _execute_full_backup(
        self, account: VirtualminAccount, backup_id: str, metadata: dict[str, Any], config: BackupConfig
    ) -> Result[str, str]:
        """Execute full domain backup using Virtualmin API."""
        try:
            vm_config = VirtualminConfig(server=self.server)
            gateway = VirtualminGateway(vm_config)

            dest = f"{_REMOTE_ARCHIVE_DIR}/{metadata['archive_name']}"
            backup_params: dict[str, Any] = {
                "domain": account.domain,
                "dest": dest,
                "all-features": True,
                "all-virtualservers": False,
                "newformat": True,
            }

            # Add feature-specific flags
            if not config.include_email:
                backup_params["skip-features"] = "mail"
            if not config.include_databases:
                skip_features = str(backup_params.get("skip-features", ""))
                backup_params["skip-features"] = skip_features + ",mysql" if skip_features else "mysql"
            if not config.include_files:
                skip_features = str(backup_params.get("skip-features", ""))
                backup_params["skip-features"] = skip_features + ",dir" if skip_features else "dir"
            if not config.include_ssl:
                skip_features = str(backup_params.get("skip-features", ""))
                backup_params["skip-features"] = skip_features + ",ssl" if skip_features else "ssl"

            # Execute backup
            self._update_backup_progress(backup_id, "backing_up", 30)
            backup_result = self._call_checked(gateway, "backup-domain", backup_params, self._backup_command_timeout())
            if backup_result.is_err():
                return Err(backup_result.unwrap_err())

            return Ok(dest)

        except Exception as e:
            logger.error(f"Full backup execution failed: {e}")
            return Err(f"Full backup failed: {e!s}")

    def _execute_config_backup(
        self, account: VirtualminAccount, backup_id: str, metadata: dict[str, Any]
    ) -> Result[str, str]:
        """Execute configuration-only backup."""
        try:
            vm_config = VirtualminConfig(server=self.server)
            gateway = VirtualminGateway(vm_config)

            dest = f"{_REMOTE_ARCHIVE_DIR}/{metadata['archive_name']}"
            backup_params: dict[str, Any] = {
                "domain": account.domain,
                "dest": dest,
                "only-features": "virtualmin,dir",  # Config and basic structure only
                "newformat": True,
            }

            self._update_backup_progress(backup_id, "backing_up_config", 50)
            backup_result = self._call_checked(gateway, "backup-domain", backup_params, self._backup_command_timeout())
            if backup_result.is_err():
                return Err(backup_result.unwrap_err())

            return Ok(dest)

        except Exception as e:
            logger.error(f"Config backup execution failed: {e}")
            return Err(f"Config backup failed: {e!s}")

    def _verify_backup_integrity(  # noqa: PLR0911, PLR0912, C901  # Complexity: multi-step business logic
        self, backup_id: str, metadata: dict[str, Any]
    ) -> Result[None, str]:  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic
        """Verify backup file integrity and completeness."""

        try:
            # Defense-in-depth: a still-remote archive means the fetch step was
            # skipped — never pretend a controller-local file exists.
            if metadata.get("backup_location") != "spool":
                host = metadata.get("backup_host", self.server.hostname)
                return Err(
                    f"Backup archive has not been fetched into the spool (location="
                    f"{metadata.get('backup_location', 'unknown')}, host={host}); refusing to verify"
                )

            backup_path = str(metadata["backup_path"])

            # 1. File existence check
            if not os.path.exists(backup_path):
                return Err(f"Backup file not found: {backup_path}")

            # 2. File size verification
            file_size = os.path.getsize(backup_path)
            if file_size == 0:
                return Err("Backup file is empty")

            max_backup_size_gb = SettingsService.get_integer_setting(
                "provisioning.max_backup_size_gb", _DEFAULT_MAX_BACKUP_SIZE_GB
            )
            max_size_bytes = max_backup_size_gb * 1024 * 1024 * 1024
            if file_size > max_size_bytes:
                return Err(f"Backup file exceeds size limit: {file_size} bytes > {max_size_bytes} bytes")

            # 3. Transfer-evidence check FIRST: the spool bytes must match the
            # checksum observed on the node before any structural parsing.
            file_hash = hashlib.sha256()
            with open(backup_path, "rb") as f:
                for chunk in iter(lambda: f.read(BACKUP_CHUNK_SIZE), b""):
                    file_hash.update(chunk)

            checksum = file_hash.hexdigest()
            expected_remote = metadata.get("checksum_sha256_remote")
            if not expected_remote:
                return Err("Backup transfer evidence missing (no remote checksum); refusing to publish")
            if checksum != expected_remote:
                return Err(
                    f"Backup archive checksum mismatch: spool={checksum} remote={expected_remote}; "
                    "transfer corruption suspected"
                )
            metadata["checksum_sha256"] = checksum

            # 4. Archive structure verification
            try:
                with tarfile.open(backup_path, "r:gz") as tar:
                    members = tar.getnames()
                    if not members:
                        return Err("Backup archive is empty")

                    # Update metadata with archive info
                    metadata["file_count"] = len(members)
                    metadata["file_size_bytes"] = file_size
            except tarfile.TarError as e:
                return Err(f"Invalid backup archive: {e}")

            # 5. Feature completeness check
            expected_features = []
            if metadata.get("include_email"):
                expected_features.append("mail")
            if metadata.get("include_databases"):
                expected_features.append("mysql")
            if metadata.get("include_files"):
                expected_features.append("dir")
            if metadata.get("include_ssl"):
                expected_features.append("ssl")

            metadata["verified_at"] = timezone.now().isoformat()
            metadata["verification_status"] = "passed"

            logger.info(f"Backup {backup_id} verified: {file_size} bytes, {metadata.get('file_count', 0)} files")
            return Ok(None)

        except Exception as e:
            logger.error(f"Backup verification failed for {backup_id}: {e}")
            return Err(f"Backup verification failed: {e}")

    def _upload_backup_to_s3(self, backup_id: str, metadata: dict[str, Any]) -> Result[dict[str, Any], str]:
        """Upload backup files to S3 with encryption."""

        try:
            s3_client = self._get_s3_client()
            bucket_name = self._get_backup_bucket()

            # Defense-in-depth: only a fetched spool archive may be published.
            if metadata.get("backup_location") != "spool":
                return Err(
                    f"Cannot upload backup {backup_id}: archive is not in the controller spool "
                    f"(location={metadata.get('backup_location', 'unknown')})"
                )

            backup_path = str(metadata["backup_path"])

            if not os.path.exists(backup_path):
                return Err(f"Backup file not found for upload: {backup_path}")

            backup_key = f"virtualmin-backups/{backup_id}/backup.tar.gz"
            file_size = os.path.getsize(backup_path)

            # Use multipart upload for large files
            if file_size > S3_MULTIPART_THRESHOLD:
                logger.info(f"Using multipart upload for {backup_id} ({file_size} bytes)")
                transfer_config = boto3.s3.transfer.TransferConfig(
                    multipart_threshold=S3_MULTIPART_THRESHOLD,
                    multipart_chunksize=BACKUP_CHUNK_SIZE,
                    use_threads=True,
                )

                s3_client.upload_file(
                    backup_path,
                    bucket_name,
                    backup_key,
                    ExtraArgs={
                        "ServerSideEncryption": "AES256",
                        "ContentType": "application/gzip",
                        "Metadata": {
                            "backup_id": backup_id,
                            "domain": metadata.get("domain", "unknown"),
                            "backup_type": metadata.get("backup_type", "full"),
                        },
                    },
                    Config=transfer_config,
                )
            else:
                # Direct upload for smaller files
                with open(backup_path, "rb") as f:
                    s3_client.put_object(
                        Bucket=bucket_name,
                        Key=backup_key,
                        Body=f,
                        ServerSideEncryption="AES256",
                        ContentType="application/gzip",
                        Metadata={
                            "backup_id": backup_id,
                            "domain": metadata.get("domain", "unknown"),
                            "backup_type": metadata.get("backup_type", "full"),
                        },
                    )

            # #326: upload metadata AFTER the archive succeeds. Previously metadata was written
            # first, so an interrupted backup left a metadata.json in S3 with no archive — listed
            # as restorable and skipping checksum verification. Writing it last means a metadata
            # object only ever exists alongside its archive.
            metadata_key = f"virtualmin-backups/{backup_id}/metadata.json"
            s3_client.put_object(
                Bucket=bucket_name,
                Key=metadata_key,
                Body=json.dumps(metadata, indent=2),
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )

            # Clean up local backup file after successful upload
            try:
                os.remove(backup_path)
                logger.debug(f"Cleaned up local backup file: {backup_path}")
            except OSError as e:
                logger.warning(f"Failed to clean up local backup file: {e}")

            upload_info = {
                "metadata_key": metadata_key,
                "backup_key": backup_key,
                "s3_bucket": bucket_name,
                "file_size_bytes": file_size,
                "uploaded_at": timezone.now().isoformat(),
            }

            logger.info(f"Successfully uploaded backup {backup_id} to S3 ({file_size} bytes)")
            return Ok(upload_info)

        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            return Err(f"S3 upload failed: {e!s}")

    def _finalize_backup_metadata(self, metadata: dict[str, Any], upload_info: dict[str, Any]) -> dict[str, Any]:
        """Finalize backup metadata with completion info."""
        metadata.update({"status": "completed", "completed_at": timezone.now().isoformat(), "s3_info": upload_info})
        return metadata

    def _download_backup_to_spool(  # noqa: PLR0911  # Distinct fail-closed gates
        self, backup_id: str
    ) -> Result[tuple[str, dict[str, Any]], str]:
        """Download the archive + manifest into the reserved spool (checksum-mandatory)."""
        from .spool import acquire_spool_reservation, release_spool_reservation  # noqa: PLC0415

        try:
            s3_client = self._get_s3_client()
            bucket_name = self._get_backup_bucket()

            metadata_key = f"virtualmin-backups/{backup_id}/metadata.json"
            try:
                metadata_response = s3_client.get_object(Bucket=bucket_name, Key=metadata_key)
                metadata = json.loads(metadata_response["Body"].read())
            except s3_client.exceptions.NoSuchKey:
                return Err(f"Backup metadata not found: {backup_id}", retriability=Retriability.NOT_RETRIABLE)

            if not metadata.get("checksum_sha256"):
                return Err(
                    "Backup manifest lacks a checksum; refusing to restore unverifiable data",
                    retriability=Retriability.NOT_RETRIABLE,
                )
            if not metadata.get("archive_name"):
                return Err(
                    "Backup manifest lacks an archive name; legacy backups are not restorable",
                    retriability=Retriability.NOT_RETRIABLE,
                )

            backup_key = f"virtualmin-backups/{backup_id}/backup.tar.gz"
            try:
                file_size = int(s3_client.head_object(Bucket=bucket_name, Key=backup_key)["ContentLength"])
            except Exception:
                return Err(f"Backup file not found in S3: {backup_id}", retriability=Retriability.NOT_RETRIABLE)

            spool = self._spool_dir()
            spool.mkdir(mode=0o700, parents=True, exist_ok=True)
            if spool.is_symlink() or spool.stat().st_mode & 0o077:
                return Err("Transfer spool must be a private directory", retriability=Retriability.NOT_RETRIABLE)
            archive_name = str(metadata["archive_name"])
            local_path = str(spool / archive_name)
            transfer_timeout = SettingsService.get_integer_setting(
                "provisioning.migration_transfer_timeout_seconds", 3600
            )
            owner = f"job:{self._progress_key}" if getattr(self, "_progress_key", None) else f"restore:{archive_name}"
            reservation = acquire_spool_reservation(spool, archive_name, file_size, owner, transfer_timeout + 300)
            if reservation.is_err():
                return Err(reservation.unwrap_err())

            logger.info(f"Downloading backup {backup_id} from S3 ({file_size} bytes)")
            download_ok = False
            try:
                s3_client.download_file(bucket_name, backup_key, local_path)

                downloaded_size = os.path.getsize(local_path)
                if downloaded_size != file_size:
                    os.remove(local_path)
                    return Err(
                        f"Downloaded file size mismatch: expected {file_size}, got {downloaded_size}",
                        retriability=Retriability.NOT_RETRIABLE,
                    )

                file_hash = hashlib.sha256()
                with open(local_path, "rb") as f:
                    for chunk in iter(lambda: f.read(BACKUP_CHUNK_SIZE), b""):
                        file_hash.update(chunk)
                if file_hash.hexdigest() != metadata["checksum_sha256"]:
                    os.remove(local_path)
                    return Err("Backup checksum verification failed", retriability=Retriability.NOT_RETRIABLE)
                download_ok = True
            finally:
                # W2: a refused download must not hold phantom spool capacity for
                # the reservation TTL. Success keeps it; the restore workflow's
                # finally releases it once consumed.
                if not download_ok:
                    release_spool_reservation(archive_name)

            logger.info(f"Successfully downloaded backup {backup_id} ({file_size} bytes)")
            return Ok((local_path, metadata))

        except Exception as e:
            logger.error(f"S3 download failed for backup {backup_id}: {e}")
            return Err(f"S3 download failed: {e!s}")
