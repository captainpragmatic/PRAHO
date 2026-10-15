"""The legacy rebuild only plans: a real run is refused (ADR-0061 P0.7).

``rebuild_server_from_praho`` recreates *empty* domains on the target. Restoring only the account
records without the customer's files and databases reads as a recovery while losing the data, so
until a real recover-to-node service replaces it (ADR-0061 P2) a non-dry run is refused.
"""

from __future__ import annotations

from unittest.mock import patch

from apps.common.types import Ok
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class LegacyRebuildDryRunOnlyTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.account.status = "active"
        self.account.save(update_fields=["status", "updated_at"])

    def test_a_real_run_is_refused_and_touches_nothing(self) -> None:
        with patch.object(VirtualminProvisioningService, "reprovision_virtualmin_account") as reprovision:
            result = VirtualminDisasterRecoveryService().rebuild_server_from_praho(self.server, dry_run=False)

        self.assertTrue(result.is_err())
        self.assertIn("dry run", result.unwrap_err().lower())
        reprovision.assert_not_called()
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).status, "active")

    def test_a_real_run_is_refused_even_when_no_account_needs_rebuilding(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="terminated")

        result = VirtualminDisasterRecoveryService().rebuild_server_from_praho(self.server, dry_run=False)

        self.assertTrue(result.is_err())

    def test_the_default_and_an_explicit_dry_run_still_plan(self) -> None:
        service = VirtualminDisasterRecoveryService()
        for result in (
            service.rebuild_server_from_praho(self.server),
            service.rebuild_server_from_praho(self.server, dry_run=True),
        ):
            self.assertEqual(result.unwrap()["accounts_to_rebuild"], 1)
            self.assertTrue(result.unwrap()["dry_run"])

    def test_the_dry_run_never_points_operators_at_the_refused_real_run(self) -> None:
        message = VirtualminDisasterRecoveryService().rebuild_server_from_praho(self.server).unwrap()["message"]

        self.assertNotIn("dry_run=False", message)
        self.assertIn("not available", message.lower())

    def test_the_readiness_report_still_runs_its_dry_run(self) -> None:
        with patch.object(
            VirtualminDisasterRecoveryService, "rebuild_server_from_praho", return_value=Ok({"accounts_to_rebuild": 0, "rebuild_plan": []})
        ) as plan:
            VirtualminDisasterRecoveryService().test_recovery_capability(self.server)

        plan.assert_called_once_with(self.server, dry_run=True)
