"""
Tests for the drift-state uniqueness constraints.

The constraints guard real approval work and must hold at the database:
one open report per drifted field, one open remediation request per report,
and one in-progress remediation per deployment.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
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


class _DriftDataTestBase(TestCase):
    """Shared fixtures for the constraint tests."""

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

class TestDriftConstraints(_DriftDataTestBase):
    """The partial-unique constraints are live and enforce the invariants."""

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
