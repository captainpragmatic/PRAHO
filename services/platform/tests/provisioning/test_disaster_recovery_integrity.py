"""DR readiness verifier checks the REAL rebuild input set (#431)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from apps.common.types import Err, Ok
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.provisioning import test_virtualmin_tasks as task_tests


class DataIntegrityVerifierTests(task_tests.VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.dr = VirtualminDisasterRecoveryService()
        # fsm-bypass: the shared fixture account starts in "error"; DR
        # readiness counts active/suspended accounts.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active")
        vault_patch = patch(
            "apps.common.credential_vault.get_credential_vault"
        )
        self.vault = vault_patch.start()
        self.addCleanup(vault_patch.stop)
        self.vault.return_value.get_credential.return_value = Err("not found")

    def _issues(self, report: dict[str, Any]) -> set[str]:
        return {issue["issue"] for issue in report["missing_data_issues"]}

    def test_healthy_fixture_is_ready(self) -> None:
        result = self.dr.verify_praho_data_integrity()
        self.assertTrue(result.is_ok(), result)
        report = result.unwrap()
        self.assertTrue(report["disaster_recovery_ready"], report)
        self.assertEqual(report["recoverable_accounts"], 1)
        # No deployment on the fixture server: transport warning, NOT a failure.
        warning_issues = {w["issue"] for w in report["transport_warnings"]}
        self.assertIn("servers_without_node_deployment", warning_issues)

    def test_missing_username_and_seed_ids_are_flagged(self) -> None:
        # fsm-bypass: strip the rebuild inputs directly.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            virtualmin_username="", praho_customer_id=None
        )
        report = self.dr.verify_praho_data_integrity().unwrap()
        issues = self._issues(report)
        self.assertIn("accounts_without_virtualmin_username", issues)
        self.assertIn("accounts_with_unusable_recovery_seed", issues)
        self.assertFalse(report["disaster_recovery_ready"])
        self.assertEqual(report["recoverable_accounts"], 0)

    def test_inconsistent_seed_is_flagged(self) -> None:
        # fsm-bypass: point the seed at a different service id.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(praho_service_id=999999)
        report = self.dr.verify_praho_data_integrity().unwrap()
        self.assertIn("accounts_with_inconsistent_recovery_seed", self._issues(report))

    def test_vault_credential_counts_as_usable(self) -> None:
        """A vault-managed server with an empty legacy field must NOT be flagged."""
        # fsm-bypass: emulate registration_service's deliberate empty field.
        self.server.encrypted_api_password = b""
        self.server.save(update_fields=["encrypted_api_password"])
        self.vault.return_value.get_credential.return_value = Ok(("vault-user", "vault-pass", None))
        report = self.dr.verify_praho_data_integrity().unwrap()
        self.assertNotIn("servers_without_usable_credentials", self._issues(report))

    def test_no_credential_anywhere_is_flagged(self) -> None:
        self.server.encrypted_api_password = b""
        self.server.save(update_fields=["encrypted_api_password"])
        report = self.dr.verify_praho_data_integrity().unwrap()
        self.assertIn("servers_without_usable_credentials", self._issues(report))
