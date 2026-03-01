"""
Tests for File Integrity Monitoring (FIM) service.

Tests cover:
- Baseline establishment
- Change detection (content, permissions, ownership)
- Deleted file detection
- Critical file verification
- Report generation
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.file_integrity_service import (
    BASELINE_CACHE_PREFIX,
    FileChange,
    FileChangeType,
    FileIntegrityMonitoringService,
    FileMetadata,
    FileSeverity,
    FIMConfig,
)
from config.settings.test import LOCMEM_TEST_CACHE


class FileMetadataTests(TestCase):
    """Tests for FileMetadata class."""

    def test_calculate_hash_returns_sha256(self) -> None:
        """Test that hash calculation returns valid SHA-256."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            f.flush()

            # Calculate expected hash
            expected = hashlib.sha256(b"test content").hexdigest()

            # Get hash from FileMetadata
            actual = FileMetadata._calculate_hash(Path(f.name))

            self.assertEqual(actual, expected)
            self.assertEqual(len(actual), 64)  # SHA-256 hex length

    def test_from_path_creates_metadata(self) -> None:
        """Test that from_path creates complete metadata."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content for metadata")
            f.flush()

            metadata = FileMetadata.from_path(Path(f.name))

            self.assertEqual(metadata.path, f.name)
            self.assertIsNotNone(metadata.hash)
            self.assertEqual(metadata.size, 25)  # Length of test content
            self.assertIsNotNone(metadata.mode)
            self.assertIsNotNone(metadata.mtime)

    def test_to_dict_serializes_correctly(self) -> None:
        """Test that to_dict produces valid dictionary."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            f.flush()

            metadata = FileMetadata.from_path(Path(f.name))
            data = metadata.to_dict()

            self.assertIn("path", data)
            self.assertIn("hash", data)
            self.assertIn("size", data)
            self.assertIn("mode", data)
            self.assertTrue(data["mode"].startswith("0o"))


class FileChangeTests(TestCase):
    """Tests for FileChange class."""

    def test_to_dict_serializes_change(self) -> None:
        """Test that FileChange serializes to dictionary."""
        change = FileChange(
            path="test/file.py",
            change_type=FileChangeType.MODIFIED,
            severity=FileSeverity.HIGH,
            detected_at=timezone.now(),
            details={"note": "test change"},
        )

        data = change.to_dict()

        self.assertEqual(data["path"], "test/file.py")
        self.assertEqual(data["change_type"], "modified")
        self.assertEqual(data["severity"], "high")
        self.assertIn("detected_at", data)
        self.assertEqual(data["details"]["note"], "test change")


class FIMConfigTests(TestCase):
    """Tests for FIMConfig defaults."""

    def test_default_config_has_critical_files(self) -> None:
        """Test that default config includes critical security files."""
        config = FIMConfig()

        self.assertIn("config/settings/base.py", config.critical_files)
        self.assertIn("apps/common/middleware.py", config.critical_files)
        self.assertIn("apps/users/mfa.py", config.critical_files)

    def test_default_config_excludes_pycache(self) -> None:
        """Test that default config excludes __pycache__."""
        config = FIMConfig()

        self.assertIn("__pycache__/*", config.exclude_patterns)
        self.assertIn("*.pyc", config.exclude_patterns)

    def test_custom_config_overrides_defaults(self) -> None:
        """Test that custom config overrides work."""
        config = FIMConfig(
            critical_files=["custom/file.py"],
            include_patterns=["*.txt"],
        )

        self.assertEqual(config.critical_files, ["custom/file.py"])
        self.assertEqual(config.include_patterns, ["*.txt"])


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class FileIntegrityMonitoringServiceTests(TestCase):
    """Tests for FileIntegrityMonitoringService."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = FIMConfig(
            monitored_paths=[],
            critical_files=[],
        )
        # Clear cache
        cache.clear()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        cache.clear()

    @patch("apps.audit.file_integrity_service.settings")
    def test_establish_baseline_creates_hashes(self, mock_settings: MagicMock) -> None:
        """Test that establish_baseline stores file hashes."""
        # Create test file
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('hello')")

        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=[],
            critical_files=["test.py"],
        )
        service = FileIntegrityMonitoringService(config)

        results = service.establish_baseline()

        self.assertEqual(results["files_baselined"], 1)
        self.assertEqual(len(results["errors"]), 0)

        # Verify baseline in cache
        cache_key = f"{BASELINE_CACHE_PREFIX}test.py"
        baseline = cache.get(cache_key)
        self.assertIsNotNone(baseline)

    @patch("apps.audit.file_integrity_service.settings")
    def test_check_integrity_detects_modification(self, mock_settings: MagicMock) -> None:
        """Test that check_integrity detects file modifications."""
        # Create test file
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("original content")

        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=[],
            critical_files=["test.py"],
        )
        service = FileIntegrityMonitoringService(config)

        # Establish baseline
        service.establish_baseline()

        # Modify file
        test_file.write_text("modified content")

        # Check integrity
        changes = service.check_integrity()

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, FileChangeType.MODIFIED)
        self.assertEqual(changes[0].path, "test.py")

    @patch("apps.audit.file_integrity_service.settings")
    def test_check_integrity_detects_new_file(self, mock_settings: MagicMock) -> None:
        """Test that check_integrity detects new files."""
        # Create test file after baseline
        test_file = Path(self.temp_dir) / "new_file.py"

        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=[],
            critical_files=["new_file.py"],
        )
        service = FileIntegrityMonitoringService(config)

        # Establish empty baseline
        service.establish_baseline()

        # Create new file
        test_file.write_text("new file content")

        # Check integrity - file exists now
        changes = service.check_integrity()

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, FileChangeType.CREATED)

    @patch("apps.audit.file_integrity_service.settings")
    def test_check_integrity_no_changes_returns_empty(
        self, mock_settings: MagicMock
    ) -> None:
        """Test that check_integrity returns empty list when no changes."""
        # Create test file
        test_file = Path(self.temp_dir) / "stable.py"
        test_file.write_text("stable content")

        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=[],
            critical_files=["stable.py"],
        )
        service = FileIntegrityMonitoringService(config)

        # Establish baseline
        service.establish_baseline()

        # Check integrity without changes
        changes = service.check_integrity()

        self.assertEqual(len(changes), 0)

    @patch("apps.audit.file_integrity_service.settings")
    def test_verify_critical_files_detects_missing(
        self, mock_settings: MagicMock
    ) -> None:
        """Test that verify_critical_files detects missing files."""
        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=[],
            critical_files=["nonexistent.py"],
        )
        service = FileIntegrityMonitoringService(config)

        results = service.verify_critical_files()

        self.assertEqual(results["files_missing"], 1)
        self.assertEqual(len(results["changes"]), 1)
        self.assertEqual(results["changes"][0]["status"], "missing")

    @patch("apps.audit.file_integrity_service.settings")
    def test_generate_report_includes_config(self, mock_settings: MagicMock) -> None:
        """Test that generate_report includes configuration."""
        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            monitored_paths=["apps"],
            critical_files=["test.py"],
        )
        service = FileIntegrityMonitoringService(config)

        report = service.generate_report()

        self.assertIn("monitored_paths", report)
        self.assertIn("critical_files_count", report)
        self.assertEqual(report["critical_files_count"], 1)

    @patch("apps.audit.file_integrity_service.settings")
    def test_get_file_severity_categorizes_correctly(
        self, mock_settings: MagicMock
    ) -> None:
        """Test that file severity is assigned correctly."""
        mock_settings.BASE_DIR = self.temp_dir

        config = FIMConfig(
            critical_files=["apps/users/mfa.py"],
        )
        service = FileIntegrityMonitoringService(config)

        # Critical file
        self.assertEqual(
            service._get_file_severity("apps/users/mfa.py"),
            FileSeverity.CRITICAL,
        )

        # Settings file
        self.assertEqual(
            service._get_file_severity("config/settings/base.py"),
            FileSeverity.HIGH,
        )

        # Regular Python file
        self.assertEqual(
            service._get_file_severity("apps/utils.py"),
            FileSeverity.MEDIUM,
        )

        # Other file
        self.assertEqual(
            service._get_file_severity("static/style.css"),
            FileSeverity.LOW,
        )

    @patch("apps.audit.file_integrity_service.settings")
    def test_is_excluded_filters_pycache(self, mock_settings: MagicMock) -> None:
        """Test that __pycache__ files are excluded."""
        mock_settings.BASE_DIR = self.temp_dir

        service = FileIntegrityMonitoringService()

        self.assertTrue(service._is_excluded("apps/__pycache__/module.cpython-311.pyc"))
        self.assertTrue(service._is_excluded("test.pyc"))
        self.assertFalse(service._is_excluded("apps/views.py"))


class IntegrityTasksTests(TestCase):
    """Tests for integrity monitoring tasks."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        cache.clear()

    def tearDown(self) -> None:
        """Clean up."""
        cache.clear()

    @patch("apps.audit.tasks.AuditIntegrityService.verify_audit_integrity")
    def test_run_integrity_check_calls_service(
        self, mock_verify: MagicMock
    ) -> None:
        """Test that task calls integrity service."""
        from apps.audit.models import AuditIntegrityCheck
        from apps.audit.tasks import run_integrity_check
        from apps.common.types import Ok

        # Mock successful check
        mock_check = MagicMock(spec=AuditIntegrityCheck)
        mock_check.status = "healthy"
        mock_check.records_checked = 100
        mock_check.issues_found = 0
        mock_check.id = "test-id"
        mock_verify.return_value = Ok(mock_check)

        results = run_integrity_check(
            check_type="hash_verification",
            period="1h",
            send_alerts=False,
        )

        self.assertEqual(results["status"], "healthy")
        self.assertEqual(len(results["checks"]), 1)
        mock_verify.assert_called_once()

    @patch("apps.audit.tasks.AuditIntegrityService.verify_audit_integrity")
    def test_run_integrity_check_all_runs_multiple(
        self, mock_verify: MagicMock
    ) -> None:
        """Test that 'all' check type runs multiple checks."""
        from apps.audit.models import AuditIntegrityCheck
        from apps.audit.tasks import run_integrity_check
        from apps.common.types import Ok

        mock_check = MagicMock(spec=AuditIntegrityCheck)
        mock_check.status = "healthy"
        mock_check.records_checked = 50
        mock_check.issues_found = 0
        mock_check.id = "test-id"
        mock_verify.return_value = Ok(mock_check)

        results = run_integrity_check(check_type="all", period="24h")

        # Should run 3 check types
        self.assertEqual(mock_verify.call_count, 3)
        self.assertEqual(len(results["checks"]), 3)

    def test_generate_integrity_report_structure(self) -> None:
        """Test that report has expected structure."""
        from apps.audit.tasks import generate_integrity_report

        report = generate_integrity_report(period_days=7)

        self.assertIn("period_days", report)
        self.assertIn("generated_at", report)
        self.assertIn("total_checks", report)
        self.assertIn("by_status", report)
        self.assertIn("by_type", report)
        self.assertIn("total_issues", report)
