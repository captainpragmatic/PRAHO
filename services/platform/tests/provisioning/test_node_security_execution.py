"""An approved preview authorizes one fenced attempt, never an automatic replay."""

import base64
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.common.types import Ok
from apps.infrastructure.node_teardown import close_node_admission
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity, record_inspection
from apps.provisioning.virtualmin_security_execution import (
    claim_hardening,
    complete_hardening,
    frozen_transport_policy,
    hardening_transport_scope,
    operator_key_fingerprints,
    owns_hardening,
    park_hardening,
    reviewed_transport_policy,
    transport_mutation_allowed,
)
from apps.provisioning.virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.users.models import User
from tests.provisioning.test_node_security_policy import ADMIN_NETWORKS, OPERATOR_FINGERPRINT, node_policy_evidence


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class SecurityExecutionTests(TestCase):
    def setUp(self):
        self.server = VirtualminServer.objects.create(hostname="apply.example.test", api_username="root")
        self.operator = User.objects.create_superuser(email="apply@example.test", password="test-password")
        self.evidence = {
            "schema": 1,
            "identity": connection_identity(self.server),
            "versions": {"webmin": "2.670", "virtualmin": "8.3.0"},
            "listeners": [],
            "principals": [{"name": "root", "access": "all"}],
            "services": [],
            "firewall": node_policy_evidence()["firewall"],
            "proposed_changes": [
                "Restrict root",
                "Administrative networks: " + ", ".join(sorted(ADMIN_NETWORKS)),
                "Approved operator SSH key: " + OPERATOR_FINGERPRINT,
            ],
        }
        self.review = record_inspection(self.server, self.evidence)

    def claim(self):
        return claim_hardening(self.review, self.evidence, self.operator, "Mail and DNS evacuated; accept interruption")

    def test_claim_binds_actor_review_and_owns_server_without_changing_health(self):
        run = self.claim()
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, run.pk)
        self.assertEqual(run.decision.review_id, self.review.pk)
        self.assertEqual(run.decision.action, "apply_hardening")
        self.assertEqual(run.decision.actor, self.operator)
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertEqual(self.server.status, "active")

    def test_retained_source_responsibility_refuses_before_creating_a_hardening_operation(self):
        with (
            patch(
                "apps.provisioning.component_migration_models.retained_source_refusal",
                return_value="Retained native mail/DNS responsibility",
            ),
            self.assertRaisesRegex(ValidationError, "Retained native mail/DNS"),
        ):
            self.claim()
        self.server.refresh_from_db()
        self.assertIsNone(self.server.security_operation)
        self.assertFalse(NodeSecurityExecution.objects.exists())
        self.assertFalse(NodeSecurityDecision.objects.exists())

    def test_drift_refuses_before_creating_decision_or_execution(self):
        self.evidence["listeners"] = ["tcp 0.0.0.0:25"]
        with self.assertRaises(ValidationError):
            self.claim()
        self.assertFalse(NodeSecurityDecision.objects.exists())
        self.assertFalse(NodeSecurityExecution.objects.exists())

    def test_running_attempt_cannot_be_replayed_or_superseded_by_inspection(self):
        run = self.claim()
        with self.assertRaises(ValidationError):
            self.claim()
        with self.assertRaises(ValidationError):
            record_inspection(self.server, self.evidence)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, run.pk)

    def test_uncertain_outcome_retains_exclusion_and_is_not_verified(self):
        run = self.claim()
        park_hardening(run.pk)
        run.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(run.status, "needs_review")
        self.assertEqual(self.server.security_operation, run.pk)
        self.assertEqual(self.server.security_state, "unreviewed")

    def test_wrong_token_cannot_park_another_attempt(self):
        run = self.claim()
        with self.assertRaises(ValidationError):
            park_hardening(uuid4())
        run.refresh_from_db()
        self.assertEqual(run.status, "running")

    def test_connection_change_revokes_authority_before_another_remote_step(self):
        run = self.claim()
        self.assertTrue(owns_hardening(self.server, str(run.pk)))
        VirtualminServer.objects.filter(pk=self.server.pk).update(ssh_port=22222)
        self.assertFalse(owns_hardening(self.server, str(run.pk)))

    def test_recursive_transport_scope_does_not_authorize_unrelated_work(self):
        run = self.claim()
        self.assertFalse(transport_mutation_allowed(self.server))
        with hardening_transport_scope(str(run.pk)):
            self.assertTrue(transport_mutation_allowed(self.server))
        self.assertFalse(transport_mutation_allowed(self.server))

    def test_transport_uses_the_reviewed_bundle_when_configuration_changes_inside_a_step(self):
        key = "ssh-ed25519 " + base64.b64encode(b"reviewed-test-public-key").decode()
        self.evidence["proposed_changes"] = [
            "Administrative networks: 192.0.2.1/32",
            *operator_key_fingerprints((key,)),
        ]
        self.review = record_inspection(self.server, self.evidence)
        run = self.claim()
        with (
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=["192.0.2.1/32"],
            ),
            patch("apps.infrastructure.ansible_service.AnsibleService.operator_public_keys", return_value=(key,)),
        ):
            policy = reviewed_transport_policy(self.server, str(run.pk))
        with (
            hardening_transport_scope(str(run.pk), policy),
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=["198.51.100.1/32"],
            ),
        ):
            self.assertEqual(frozen_transport_policy()["node_admin_allowed_cidrs"], ["192.0.2.1/32"])
            self.assertEqual(frozen_transport_policy()["ssh_operator_public_keys"], [key])
            with self.assertRaises(ValidationError):
                reviewed_transport_policy(self.server, str(run.pk))
        self.assertIsNone(frozen_transport_policy())

    def test_teardown_and_new_account_admission_respect_exclusion_even_with_force(self):
        run = self.claim()
        self.assertIn("hardening", close_node_admission(self.server.pk, force=True).unwrap_err())
        self.assertIn("hardening", VirtualminProvisioningService._lock_open_server(self.server).unwrap_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, run.pk)
        self.assertEqual(self.server.status, "active")

    def test_gateway_mutation_is_refused_before_credentials_or_network(self):
        self.claim()
        gateway = VirtualminGateway(VirtualminConfig(server=self.server))
        with (
            patch.object(gateway, "_get_credentials") as credentials,
            patch.object(gateway, "_make_request") as request,
        ):
            result = gateway.call("create-domain", {})
        self.assertIn("hardening", str(result.unwrap_err()))
        credentials.assert_not_called()
        request.assert_not_called()

    def test_draining_or_disabled_server_cannot_start_hardening(self):
        for changes in ({"is_draining": True}, {"status": "disabled"}):
            with self.subTest(changes=changes):
                VirtualminServer.objects.filter(pk=self.server.pk).update(**changes)
                with self.assertRaises(ValidationError):
                    self.claim()
                VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=False, status="active")

    def test_unqualified_native_version_requires_preparation(self):
        self.evidence["versions"]["webmin"] = "2.671"
        self.review = record_inspection(self.server, self.evidence)
        with self.assertRaises(ValidationError):
            self.claim()
        self.assertFalse(NodeSecurityExecution.objects.exists())

    def hardened_evidence(self):
        self.server.api_username = "praho-api"
        self.server.save(update_fields=["api_username"])
        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.server.hostname,
                username="praho-api",
                password="dedicated-test-api-password",
                reason="Final verification fixture",
            )
        )
        self.assertTrue(stored.is_ok())
        evidence = node_policy_evidence()
        evidence["identity"] = connection_identity(self.server)
        return evidence

    def test_completed_policy_and_real_api_proof_release_only_owned_execution(self):
        run = self.claim()
        evidence = self.hardened_evidence()
        with (
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=ADMIN_NETWORKS,
            ),
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
                return_value=Ok({"healthy": True}),
            ),
        ):
            review = complete_hardening(run.pk, evidence)
        run.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(run.status, "verified")
        self.assertEqual(run.verification_id, review.pk)
        self.assertEqual(self.server.verified_security_review_id, review.pk)
        self.assertIsNone(self.server.security_operation)
        self.assertEqual(self.server.security_state, "verified_web")

    def test_reconciled_verification_records_the_actual_reviewing_operator(self):
        run = self.claim()
        park_hardening(run.pk)
        reviewer = User.objects.create_superuser(email="recovery@example.test", password="test-password")
        evidence = self.hardened_evidence()
        with (
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=ADMIN_NETWORKS,
            ),
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
                return_value=Ok({"healthy": True}),
            ),
        ):
            review = complete_hardening(
                run.pk, evidence, actor=reviewer, reason="Remote commands stopped; recovered access and verified policy"
            )
        decision = NodeSecurityDecision.objects.get(review=review)
        self.assertEqual(decision.action, "verify_policy")
        self.assertEqual(decision.actor, reviewer)

    def test_failed_api_proof_does_not_release_exclusion_or_grant_verification(self):
        run = self.claim()
        evidence = self.hardened_evidence()
        with (
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=ADMIN_NETWORKS,
            ),
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
                return_value=Ok({"healthy": False}),
            ),
            self.assertRaises(ValidationError),
        ):
            complete_hardening(run.pk, evidence)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, run.pk)
        self.assertEqual(self.server.security_state, "unreviewed")

    def test_changed_identity_during_api_proof_cannot_attest_old_target(self):
        run = self.claim()
        evidence = self.hardened_evidence()

        def changed():
            VirtualminServer.objects.filter(pk=self.server.pk).update(api_port=10001)
            return Ok({"healthy": True})

        with (
            patch(
                "apps.provisioning.virtualmin_security_execution.node_admin_allowed_cidrs",
                return_value=ADMIN_NETWORKS,
            ),
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection", side_effect=changed),
            self.assertRaises(ValidationError),
        ):
            complete_hardening(run.pk, evidence)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, run.pk)
        self.assertIsNone(self.server.verified_security_review_id)
