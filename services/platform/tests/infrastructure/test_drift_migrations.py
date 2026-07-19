"""
Tests for the drift dedup data migration (0003).

The RunPython step is imported and exercised directly against the live app
registry — the survivor-selection policy (keep the report owning the most
advanced open request) guards real approval work and must not regress.
"""

from __future__ import annotations

import importlib

from django.apps import apps as django_apps
from django.db import IntegrityError, connection, transaction
from django.test import TestCase

from apps.infrastructure.models import (
    CloudProvider,
    DriftCheck,
    DriftRemediationRequest,
    DriftReport,
    NodeDeployment,
    NodeRegion,
    NodeSize,
    PanelType,
)

_migration = importlib.import_module(
    "apps.infrastructure.migrations.0003_driftremediationrequest_execution_claimed_at_and_more"
)


class _DriftDataTestBase(TestCase):
    """Shared fixtures for the migration-dedup and constraint tests."""

    def setUp(self) -> None:
        self.provider = CloudProvider.objects.create(
            name="Test Hetzner",
            provider_type="hetzner",
            code="het",
            credential_identifier="test-cred",
        )
        self.region = NodeRegion.objects.create(
            provider=self.provider,
            name="Falkenstein",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        self.size = NodeSize.objects.create(
            provider=self.provider,
            name="Small",
            display_name="2 vCPU / 4GB",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.0100",
            monthly_cost_eur="5.00",
        )
        self.panel = PanelType.objects.create(
            name="Virtualmin GPL",
            panel_type="virtualmin",
            ansible_playbook="virtualmin.yml",
        )
        self.deployment = NodeDeployment.objects.create(
            environment="prd",
            node_type="sha",
            provider=self.provider,
            node_size=self.size,
            region=self.region,
            panel_type=self.panel,
            hostname="prd-sha-het-de-fsn1-001",
            node_number=1,
            status="completed",
            external_node_id="12345",
            ipv4_address="1.2.3.4",
        )
        self.check = DriftCheck.objects.create(
            deployment=self.deployment,
            check_type="cloud",
            status="completed",
        )

    def _report(self, field_name: str = "ipv4_address", **kwargs) -> DriftReport:
        defaults = {
            "drift_check": self.check,
            "deployment": self.deployment,
            "severity": "critical",
            "category": "network",
            "field_name": field_name,
            "expected_value": "1.2.3.4",
            "actual_value": "5.6.7.8",
        }
        defaults.update(kwargs)
        return DriftReport.objects.create(**defaults)

    def _request(self, report: DriftReport, status: str, action_type: str = "apply_desired") -> DriftRemediationRequest:
        return DriftRemediationRequest.objects.create(
            report=report,
            deployment=self.deployment,
            action_type=action_type,
            action_details={
                "field_name": report.field_name,
                "expected_value": report.expected_value,
                "actual_value": report.actual_value,
            },
            status=status,
        )


class TestDedupDriftMigration(_DriftDataTestBase):
    """Exercise _dedup_drift_state survivor selection and normalization.

    The fixtures deliberately contain duplicates that can only exist BEFORE
    migration 0004's partial-unique constraints, so those constraints are
    dropped for this class (SQLite DDL is transactional — the test rollback
    restores them).
    """

    def setUp(self) -> None:
        super().setUp()
        # Partial unique constraints are implemented as partial unique indexes
        # on SQLite and PostgreSQL alike; DROP INDEX is transactional DDL, so
        # the test rollback restores them.
        with connection.cursor() as cursor:
            for model in (DriftReport, DriftRemediationRequest):
                for constraint in model._meta.constraints:
                    cursor.execute(f'DROP INDEX IF EXISTS "{constraint.name}"')

    def _run(self) -> None:
        _migration._dedup_drift_state(django_apps, None)

    def test_survivor_is_report_with_most_advanced_open_request(self):
        oldest = self._report()
        middle = self._report()
        newest = self._report()
        approved = self._request(middle, "approved")
        pending = self._request(newest, "pending_approval")

        self._run()

        middle.refresh_from_db()
        self.assertFalse(middle.resolved)
        for loser in (oldest, newest):
            loser.refresh_from_db()
            self.assertTrue(loser.resolved)
            self.assertEqual(loser.resolution_type, "superseded")
        pending.refresh_from_db()
        self.assertEqual(pending.status, "superseded")
        approved.refresh_from_db()
        self.assertEqual(approved.status, "approved")

    def test_duplicate_in_progress_requests_reduced_to_newest(self):
        report = self._report()
        older = self._request(report, "in_progress")
        newer = self._request(report, "in_progress")

        self._run()

        older.refresh_from_db()
        newer.refresh_from_db()
        self.assertEqual(older.status, "failed")
        self.assertIn("dedup migration", older.error_message)
        self.assertEqual(newer.status, "in_progress")

    def test_one_open_request_per_report_keeps_most_advanced(self):
        report = self._report()
        pending = self._request(report, "pending_approval")
        scheduled = self._request(report, "scheduled")

        self._run()

        pending.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertEqual(pending.status, "superseded")
        self.assertEqual(scheduled.status, "scheduled")

    def test_consecutive_network_reports_normalized_to_stable_name(self):
        report = self._report(field_name="network_unreachable_consecutive", severity="critical")

        self._run()

        report.refresh_from_db()
        self.assertEqual(report.field_name, "network_unreachable")
        self.assertEqual(report.severity, "critical")

    def test_unfixable_open_requests_become_manual_intervention(self):
        ip_report = self._report(field_name="ipv4_address")
        type_report = self._report(field_name="server_type")
        ip_request = self._request(ip_report, "pending_approval")
        type_request = self._request(type_report, "pending_approval")

        self._run()

        ip_request.refresh_from_db()
        type_request.refresh_from_db()
        self.assertEqual(ip_request.action_type, "manual_intervention")
        self.assertEqual(type_request.action_type, "apply_desired")

class TestDriftConstraints(_DriftDataTestBase):
    """The 0004 partial-unique constraints are live and enforce the invariants."""

    def test_open_report_uniqueness_enforced_by_database(self):
        """The partial unique constraint is the backstop against scan races."""
        self._report()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._report()

        # A resolved duplicate is fine — uniqueness covers open rows only
        DriftReport.objects.filter(deployment=self.deployment).update(resolved=True)
        self._report()

    def test_open_request_per_report_uniqueness_enforced(self):
        report = self._report()
        self._request(report, "pending_approval")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._request(report, "approved")

        # Closed requests do not collide
        DriftRemediationRequest.objects.filter(report=report).update(status="failed")
        self._request(report, "pending_approval")

    def test_single_in_progress_per_deployment_enforced(self):
        report_a = self._report(field_name="ipv4_address")
        report_b = self._report(field_name="server_type")
        self._request(report_a, "in_progress")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._request(report_b, "in_progress")
