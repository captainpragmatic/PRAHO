"""
File Integrity Monitoring (FIM) Service.

Provides comprehensive file integrity monitoring for security compliance:
- Cryptographic hash tracking of critical files
- Change detection and alerting
- Baseline establishment and comparison
- Integration with audit logging
- Support for file whitelisting and exclusions

Security Standards:
- PCI DSS Requirement 11.5 (File Integrity Monitoring)
- CIS Control 3 (Data Protection)
- ISO 27001 A.12.4 (Logging and Monitoring)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Final

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


class FileChangeType(Enum):
    """Types of file changes detected."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    PERMISSIONS_CHANGED = "permissions_changed"
    OWNER_CHANGED = "owner_changed"


class FileSeverity(Enum):
    """Severity levels for monitored files."""

    CRITICAL = "critical"  # Security-sensitive files
    HIGH = "high"  # Configuration files
    MEDIUM = "medium"  # Application code
    LOW = "low"  # Static assets


@dataclass(frozen=True)
class FileMetadata:
    """Metadata about a monitored file."""

    path: str
    hash: str
    size: int
    mode: int
    mtime: float
    uid: int
    gid: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "hash": self.hash,
            "size": self.size,
            "mode": oct(self.mode),
            "mtime": self.mtime,
            "uid": self.uid,
            "gid": self.gid,
        }

    @classmethod
    def from_path(cls, file_path: Path) -> "FileMetadata":
        """Create metadata from a file path."""
        stat_info = file_path.stat()
        file_hash = cls._calculate_hash(file_path)

        return cls(
            path=str(file_path),
            hash=file_hash,
            size=stat_info.st_size,
            mode=stat_info.st_mode,
            mtime=stat_info.st_mtime,
            uid=stat_info.st_uid,
            gid=stat_info.st_gid,
        )

    @staticmethod
    def _calculate_hash(file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


@dataclass
class FileChange:
    """Represents a detected file change."""

    path: str
    change_type: FileChangeType
    severity: FileSeverity
    detected_at: datetime
    previous_metadata: FileMetadata | None = None
    current_metadata: FileMetadata | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage/logging."""
        return {
            "path": self.path,
            "change_type": self.change_type.value,
            "severity": self.severity.value,
            "detected_at": self.detected_at.isoformat(),
            "previous": self.previous_metadata.to_dict() if self.previous_metadata else None,
            "current": self.current_metadata.to_dict() if self.current_metadata else None,
            "details": self.details,
        }


@dataclass
class FIMConfig:
    """Configuration for File Integrity Monitoring."""

    # Directories to monitor (relative to BASE_DIR)
    monitored_paths: list[str] = field(default_factory=lambda: [
        "config/settings",
        "apps/common",
        "apps/users",
        "apps/audit",
    ])

    # File patterns to include
    include_patterns: list[str] = field(default_factory=lambda: [
        "*.py",
        "*.yml",
        "*.yaml",
        "*.json",
        "*.conf",
    ])

    # File patterns to exclude
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.pyc",
        "__pycache__/*",
        "*.log",
        ".git/*",
        "migrations/*",
    ])

    # Critical files (always monitored, highest severity)
    critical_files: list[str] = field(default_factory=lambda: [
        "config/settings/base.py",
        "config/settings/prod.py",
        "apps/common/middleware.py",
        "apps/common/security_decorators.py",
        "apps/common/validators.py",
        "apps/common/encryption.py",
        "apps/common/credential_vault.py",
        "apps/users/mfa.py",
        "apps/users/views.py",
        "apps/audit/services.py",
    ])

    # Cache timeout for baselines (30 days)
    baseline_cache_timeout: int = 86400 * 30

    # Alert thresholds
    max_changes_before_alert: int = 10
    critical_change_immediate_alert: bool = True


# Cache key prefixes
BASELINE_CACHE_PREFIX: Final[str] = "fim_baseline:"
LAST_CHECK_CACHE_KEY: Final[str] = "fim_last_check"


class FileIntegrityMonitoringService:
    """
    Comprehensive File Integrity Monitoring service.

    Usage:
        service = FileIntegrityMonitoringService()

        # Establish baseline
        service.establish_baseline()

        # Check for changes
        changes = service.check_integrity()

        # Get report
        report = service.generate_report()
    """

    def __init__(self, config: FIMConfig | None = None) -> None:
        """Initialize FIM service."""
        self.config = config or FIMConfig()
        self.base_dir = Path(settings.BASE_DIR)

    def establish_baseline(self, force: bool = False) -> dict[str, Any]:
        """
        Establish baseline hashes for all monitored files.

        Args:
            force: Force re-establishment even if baseline exists

        Returns:
            Dictionary with baseline establishment results
        """
        results = {
            "established_at": timezone.now().isoformat(),
            "files_baselined": 0,
            "skipped_existing": 0,
            "errors": [],
        }

        for file_path in self._get_monitored_files():
            try:
                relative_path = str(file_path.relative_to(self.base_dir))
                cache_key = f"{BASELINE_CACHE_PREFIX}{relative_path}"

                # Check if baseline exists
                if not force and cache.get(cache_key):
                    results["skipped_existing"] += 1
                    continue

                # Create and store metadata
                metadata = FileMetadata.from_path(file_path)
                cache.set(
                    cache_key,
                    json.dumps(metadata.to_dict()),
                    self.config.baseline_cache_timeout,
                )
                results["files_baselined"] += 1

                logger.debug(f"[FIM] Baseline established: {relative_path}")

            except Exception as e:
                results["errors"].append({
                    "path": str(file_path),
                    "error": str(e),
                })
                logger.error(f"[FIM] Failed to baseline {file_path}: {e}")

        # Store last check time
        cache.set(LAST_CHECK_CACHE_KEY, timezone.now().isoformat())

        logger.info(
            f"[FIM] Baseline established: {results['files_baselined']} files, "
            f"{results['skipped_existing']} skipped"
        )

        return results

    def check_integrity(self) -> list[FileChange]:
        """
        Check file integrity against baseline.

        Returns:
            List of detected file changes
        """
        changes: list[FileChange] = []
        checked_files: set[str] = set()

        for file_path in self._get_monitored_files():
            try:
                relative_path = str(file_path.relative_to(self.base_dir))
                checked_files.add(relative_path)
                cache_key = f"{BASELINE_CACHE_PREFIX}{relative_path}"

                # Get baseline metadata
                baseline_json = cache.get(cache_key)

                if baseline_json is None:
                    # New file detected
                    metadata = FileMetadata.from_path(file_path)
                    severity = self._get_file_severity(relative_path)

                    changes.append(FileChange(
                        path=relative_path,
                        change_type=FileChangeType.CREATED,
                        severity=severity,
                        detected_at=timezone.now(),
                        current_metadata=metadata,
                        details={"note": "New file detected, not in baseline"},
                    ))

                    # Add to baseline
                    cache.set(
                        cache_key,
                        json.dumps(metadata.to_dict()),
                        self.config.baseline_cache_timeout,
                    )

                    logger.info(f"[FIM] New file detected: {relative_path}")
                    continue

                # Compare with baseline
                baseline_data = json.loads(baseline_json)
                current_metadata = FileMetadata.from_path(file_path)

                change = self._compare_metadata(
                    relative_path,
                    baseline_data,
                    current_metadata,
                )

                if change:
                    changes.append(change)

                    # Update baseline if content changed
                    if change.change_type == FileChangeType.MODIFIED:
                        cache.set(
                            cache_key,
                            json.dumps(current_metadata.to_dict()),
                            self.config.baseline_cache_timeout,
                        )

            except Exception as e:
                logger.error(f"[FIM] Error checking {file_path}: {e}")

        # Check for deleted files (files in baseline but not on disk)
        deleted_changes = self._check_deleted_files(checked_files)
        changes.extend(deleted_changes)

        # Store last check time
        cache.set(LAST_CHECK_CACHE_KEY, timezone.now().isoformat())

        # Log summary
        if changes:
            logger.warning(
                f"[FIM] Integrity check found {len(changes)} changes: "
                f"{[c.change_type.value for c in changes]}"
            )
        else:
            logger.info("[FIM] Integrity check completed: no changes detected")

        return changes

    def _get_monitored_files(self) -> list[Path]:
        """Get list of files to monitor based on configuration."""
        files: list[Path] = []

        # Add critical files first
        for critical_file in self.config.critical_files:
            file_path = self.base_dir / critical_file
            if file_path.exists() and file_path.is_file():
                files.append(file_path)

        # Add files from monitored paths
        for monitored_path in self.config.monitored_paths:
            path = self.base_dir / monitored_path
            if not path.exists():
                continue

            for include_pattern in self.config.include_patterns:
                for file_path in path.rglob(include_pattern):
                    if not file_path.is_file():
                        continue

                    # Check exclusions
                    relative = str(file_path.relative_to(self.base_dir))
                    if self._is_excluded(relative):
                        continue

                    if file_path not in files:
                        files.append(file_path)

        return files

    def _is_excluded(self, relative_path: str) -> bool:
        """Check if a path should be excluded."""
        from fnmatch import fnmatch

        for pattern in self.config.exclude_patterns:
            if fnmatch(relative_path, pattern):
                return True
        return False

    def _get_file_severity(self, relative_path: str) -> FileSeverity:
        """Determine severity level for a file."""
        if relative_path in self.config.critical_files:
            return FileSeverity.CRITICAL

        if "settings" in relative_path or "config" in relative_path:
            return FileSeverity.HIGH

        if relative_path.endswith(".py"):
            return FileSeverity.MEDIUM

        return FileSeverity.LOW

    def _compare_metadata(
        self,
        relative_path: str,
        baseline: dict[str, Any],
        current: FileMetadata,
    ) -> FileChange | None:
        """Compare current metadata with baseline."""
        severity = self._get_file_severity(relative_path)
        details: dict[str, Any] = {}

        # Check hash (content change)
        if baseline["hash"] != current.hash:
            return FileChange(
                path=relative_path,
                change_type=FileChangeType.MODIFIED,
                severity=severity,
                detected_at=timezone.now(),
                previous_metadata=None,  # We don't have full previous metadata
                current_metadata=current,
                details={
                    "previous_hash": baseline["hash"][:16] + "...",
                    "current_hash": current.hash[:16] + "...",
                    "size_change": current.size - baseline["size"],
                },
            )

        # Check permissions
        if baseline["mode"] != oct(current.mode):
            details["permission_change"] = {
                "previous": baseline["mode"],
                "current": oct(current.mode),
            }
            return FileChange(
                path=relative_path,
                change_type=FileChangeType.PERMISSIONS_CHANGED,
                severity=severity,
                detected_at=timezone.now(),
                current_metadata=current,
                details=details,
            )

        # Check ownership
        if baseline["uid"] != current.uid or baseline["gid"] != current.gid:
            details["ownership_change"] = {
                "previous_uid": baseline["uid"],
                "current_uid": current.uid,
                "previous_gid": baseline["gid"],
                "current_gid": current.gid,
            }
            return FileChange(
                path=relative_path,
                change_type=FileChangeType.OWNER_CHANGED,
                severity=severity,
                detected_at=timezone.now(),
                current_metadata=current,
                details=details,
            )

        return None

    def _check_deleted_files(self, checked_files: set[str]) -> list[FileChange]:
        """Check for files that exist in baseline but were deleted."""
        changes: list[FileChange] = []

        # Get all baseline keys from cache
        # Note: This is a simplified implementation. In production,
        # you might want to store the list of baselined files separately.
        for critical_file in self.config.critical_files:
            if critical_file not in checked_files:
                file_path = self.base_dir / critical_file
                if not file_path.exists():
                    cache_key = f"{BASELINE_CACHE_PREFIX}{critical_file}"
                    if cache.get(cache_key):
                        changes.append(FileChange(
                            path=critical_file,
                            change_type=FileChangeType.DELETED,
                            severity=FileSeverity.CRITICAL,
                            detected_at=timezone.now(),
                            details={"note": "Critical file has been deleted"},
                        ))
                        # Remove from baseline
                        cache.delete(cache_key)
                        logger.error(f"[FIM] Critical file deleted: {critical_file}")

        return changes

    def generate_report(self, period_days: int = 7) -> dict[str, Any]:
        """
        Generate FIM status report.

        Args:
            period_days: Number of days to include in report

        Returns:
            Dictionary with report data
        """
        last_check = cache.get(LAST_CHECK_CACHE_KEY)

        return {
            "generated_at": timezone.now().isoformat(),
            "period_days": period_days,
            "last_integrity_check": last_check,
            "monitored_paths": self.config.monitored_paths,
            "critical_files_count": len(self.config.critical_files),
            "total_monitored_files": len(self._get_monitored_files()),
            "configuration": {
                "include_patterns": self.config.include_patterns,
                "exclude_patterns": self.config.exclude_patterns,
                "baseline_timeout_days": self.config.baseline_cache_timeout // 86400,
            },
        }

    def verify_critical_files(self) -> dict[str, Any]:
        """
        Quick verification of critical files only.

        Returns:
            Dictionary with verification results
        """
        results = {
            "verified_at": timezone.now().isoformat(),
            "files_checked": 0,
            "files_ok": 0,
            "files_changed": 0,
            "files_missing": 0,
            "changes": [],
        }

        for critical_file in self.config.critical_files:
            file_path = self.base_dir / critical_file
            results["files_checked"] += 1

            if not file_path.exists():
                results["files_missing"] += 1
                results["changes"].append({
                    "path": critical_file,
                    "status": "missing",
                    "severity": "critical",
                })
                continue

            cache_key = f"{BASELINE_CACHE_PREFIX}{critical_file}"
            baseline_json = cache.get(cache_key)

            if not baseline_json:
                # No baseline, establish one
                metadata = FileMetadata.from_path(file_path)
                cache.set(
                    cache_key,
                    json.dumps(metadata.to_dict()),
                    self.config.baseline_cache_timeout,
                )
                results["files_ok"] += 1
                continue

            # Verify hash
            baseline = json.loads(baseline_json)
            current_hash = FileMetadata._calculate_hash(file_path)

            if baseline["hash"] == current_hash:
                results["files_ok"] += 1
            else:
                results["files_changed"] += 1
                results["changes"].append({
                    "path": critical_file,
                    "status": "modified",
                    "severity": "critical",
                    "previous_hash": baseline["hash"][:16] + "...",
                    "current_hash": current_hash[:16] + "...",
                })

        return results


# Global service instance
fim_service = FileIntegrityMonitoringService()
