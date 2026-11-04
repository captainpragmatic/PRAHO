"""Enrollment failure must never progress to interactive-access lockdown."""

from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.common.credential_vault import CredentialVault, EncryptedCredential
from apps.common.types import Err, Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning.virtualmin_gateway import VirtualminAuthError, VirtualminUnreachableError
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity, record_inspection
from apps.provisioning.virtualmin_security_apply import apply_hardening
from apps.provisioning.virtualmin_security_execution import claim_hardening
from apps.users.models import User
from tests.provisioning.test_node_security_policy import ADMIN_NETWORKS, node_policy_evidence


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class SecurityApplyTests(TestCase):
    def setUp(self):
        self.server = VirtualminServer.objects.create(hostname="apply.example.test", api_username="root")
        self.server.set_api_password("original-root-rescue-password")
        self.server.save()
        actor = User.objects.create_superuser(email="apply@example.test", password="test-password")
        evidence = node_policy_evidence()
        evidence["identity"] = connection_identity(self.server)
        evidence["proposed_changes"].append(
            "Firewall reload hook /etc/ufw/after.init: sha256=" + "b" * 64 + ", executable=True"
        )
        review = record_inspection(self.server, evidence)
        self.run = claim_hardening(review, evidence, actor, "Mail and DNS evacuated; accept interruption")
        store = CredentialVault.store_credential

        def checked_store(vault, credential):
            result = store(vault, credential)
            self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
            return result

        # These workflow tests use the real vault. Report a failed storage prerequisite
        # directly instead of mistaking it for the authentication/transport boundary.
        self.enterContext(patch.object(CredentialVault, "store_credential", autospec=True, side_effect=checked_store))

    def test_failed_durable_storage_precedes_any_remote_mutation(self):
        with (
            patch(
                "apps.provisioning.virtualmin_security_apply.AnsibleService.operator_public_keys", return_value=("key",)
            ),
            patch("apps.provisioning.virtualmin_security_apply.get_credential_vault") as vault,
            patch("apps.provisioning.virtualmin_security_apply._run") as remote,
        ):
            vault.return_value.store_credential.return_value = Err("storage unavailable")
            with self.assertRaises(ValidationError):
                apply_hardening(self.run)
        remote.assert_not_called()
        self.server.refresh_from_db()
        self.assertEqual(self.server.api_username, "root")
        self.assertEqual(self.server.get_api_password(), "original-root-rescue-password")

    def _api_failure_message(self, outcome):
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, self.run.pk)
        self.assertEqual(self.server.get_api_password(), "original-root-rescue-password")
        with (
            patch(
                "apps.provisioning.virtualmin_security_apply.AnsibleService.operator_public_keys", return_value=("key",)
            ),
            patch("apps.provisioning.virtualmin_security_apply._preserve_imported_trust"),
            patch(
                "apps.provisioning.virtualmin_security_apply._run", return_value="PRAHO_PANEL_CERT=" + "a" * 64
            ) as remote,
            patch("apps.provisioning.virtualmin_security_apply.VirtualminGateway.call", return_value=outcome) as call,
            self.assertRaises(ValidationError) as caught,
        ):
            apply_hardening(self.run)
        self.assertEqual(call.call_args.args, ("info",))
        self.assertEqual(remote.call_count, 1)
        self.assertEqual(remote.call_args.args[2], "virtualmin_security_enroll.yml")
        self.assertTrue(
            EncryptedCredential.objects.filter(service_identifier=f"security:{self.run.pk}", is_active=True).exists()
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.api_username, "root")
        self.assertEqual(self.server.security_operation, self.run.pk)
        return caught.exception.messages[0]

    def test_failed_api_authentication_prevents_ssh_and_webmin_lockdown(self):
        message = self._api_failure_message(Err(VirtualminAuthError("HTTP 401")))
        self.assertEqual(
            message,
            "Dedicated API authentication failed; interactive access has not been restricted.",
        )

    def test_refused_panel_check_prevents_ssh_and_webmin_lockdown(self):
        message = self._api_failure_message(
            Ok(
                SimpleNamespace(
                    success=False, data={"error": "ACL denies info"}, execution_time=0, server_hostname="node"
                )
            )
        )
        self.assertEqual(
            message,
            "The panel refused the API check (ACL denies info); interactive access has not been restricted",
        )

    def test_unreachable_panel_is_not_reported_as_bad_credentials(self):
        message = self._api_failure_message(Err(VirtualminUnreachableError("IPv6 connect timed out")))
        self.assertEqual(
            message,
            f"The panel at {self.server.hostname}:{self.server.api_port} could not be reached "
            "(IPv6 connect timed out); interactive access has not been restricted",
        )
        self.assertNotIn("authentication failed", message)

    def test_success_orders_durable_enrollment_api_proof_ssh_and_final_live_proof(self):
        calls = []

        def remote(server, playbook, variables, **kwargs):
            calls.append((playbook, set(variables)))
            self.assertEqual(kwargs["security_execution"], str(self.run.pk))
            if playbook == "virtualmin_security_enroll.yml":
                self.assertTrue(
                    EncryptedCredential.objects.filter(service_identifier=f"security:{self.run.pk}").exists()
                )
                return Ok(AnsibleResult(True, playbook, "PRAHO_PANEL_CERT=" + "a" * 64, "", 0))
            self.assertTrue(
                EncryptedCredential.objects.filter(service_identifier=server.hostname, is_active=True).exists()
            )
            self.assertNotIn("praho_api_password", variables)
            if playbook in {"virtualmin_firewall.yml", "virtualmin_harden.yml"}:
                self.assertEqual(variables["security_reviewed_firewall_hooks"], {"/etc/ufw/after.init": "b" * 64})
            if playbook == "ssh-hardening.yml":
                VirtualminServer.objects.filter(pk=server.pk).update(ssh_port=9876)
            return Ok(AnsibleResult(True, playbook, "", "", 0))

        def inspected(server):
            server.refresh_from_db()
            evidence = node_policy_evidence()
            evidence["identity"] = connection_identity(server)
            for principal in evidence["principals"]:
                if principal["name"] == "praho-api":
                    principal["name"] = server.api_username
            return evidence

        with (
            patch(
                "apps.provisioning.virtualmin_security_apply.AnsibleService.operator_public_keys", return_value=("key",)
            ),
            patch("apps.provisioning.virtualmin_security_apply._preserve_imported_trust"),
            patch("apps.provisioning.virtualmin_security_apply.AnsibleService.run_server_playbook", side_effect=remote),
            patch(
                "apps.provisioning.virtualmin_security_apply.VirtualminGateway.call",
                return_value=Ok(
                    SimpleNamespace(success=True, data={}, execution_time=0, server_hostname=self.server.hostname)
                ),
            ),
            patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", side_effect=inspected),
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=ADMIN_NETWORKS,
            ),
        ):
            verification = apply_hardening(self.run)
        self.assertEqual(
            [name for name, _ in calls],
            ["virtualmin_security_enroll.yml", "virtualmin_firewall.yml", "ssh-hardening.yml", "virtualmin_harden.yml"],
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_state, "verified_web")
        self.assertEqual(self.server.verified_security_review_id, verification.pk)
        self.assertIsNone(self.server.security_operation)
