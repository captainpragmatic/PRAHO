"""Security admission is independent of health and has an explicit legacy rollout."""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security import POLICY_VERSION, _evidence_digest, connection_identity
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from apps.settings.services import SettingsService
from tests.provisioning.test_node_security_policy import node_policy_evidence


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class NodeCapabilityTests(TestCase):
    def tearDown(self):
        cache.clear()

    def setUp(self):
        self.server = VirtualminServer.objects.create(
            hostname="target.example.test", api_username="praho-api", last_health_check=timezone.now()
        )

    def attest(self):
        evidence = node_policy_evidence()
        identity = connection_identity(self.server)
        evidence["identity"] = identity
        proof = NodeSecurityReview.objects.create(
            server=self.server,
            server_uuid=self.server.pk,
            policy_version=POLICY_VERSION,
            identity=identity,
            digest=_evidence_digest(evidence),
            evidence=evidence,
        )
        self.server.security_state = "verified_web"
        self.server.verified_security_review = proof
        self.server.save(update_fields=["security_state", "verified_security_review"])
        return proof

    def test_new_healthy_import_never_inherits_legacy_admission(self):
        self.assertFalse(self.server.legacy_security_admission)
        self.assertTrue(self.server.can_host_domain())
        self.assertIsNotNone(destination_refusal(self.server))

    def test_existing_unreviewed_node_retains_admission_until_rollout_is_enforced(self):
        self.server.legacy_security_admission = True
        self.server.save(update_fields=["legacy_security_admission"])
        self.assertTrue(SettingsService.update_setting("provisioning.enforce_verified_web_nodes", False).is_ok())
        self.assertIsNone(destination_refusal(self.server))
        self.assertTrue(SettingsService.update_setting("provisioning.enforce_verified_web_nodes", True).is_ok())
        self.assertIsNotNone(destination_refusal(self.server))

    def test_source_acknowledgment_is_never_a_destination_even_during_rollout(self):
        self.server.legacy_security_admission = True
        self.server.security_state = "acknowledged_source_only"
        self.server.save(update_fields=["legacy_security_admission", "security_state"])
        with patch(
            "apps.provisioning.virtualmin_node_capability.SettingsService.get_boolean_setting", return_value=False
        ):
            self.assertIsNotNone(destination_refusal(self.server))
        self.assertTrue(self.server.can_host_domain(), "security refusal must not falsify health/capacity")

    def test_verified_label_without_bound_evidence_is_not_enough(self):
        self.server.security_state = "verified_web"
        self.server.save(update_fields=["security_state"])
        self.assertIsNotNone(destination_refusal(self.server))

    def test_current_evidence_admits_and_credential_drift_withdraws_admission(self):
        self.attest()
        self.assertIsNone(destination_refusal(self.server))
        self.server.set_api_password("rotated-after-attestation")
        self.server.save(update_fields=["encrypted_api_password"])
        self.assertIsNotNone(destination_refusal(self.server))

    def test_verification_does_not_override_independent_health(self):
        self.attest()
        self.server.last_health_check = timezone.now() - timezone.timedelta(days=1)
        self.server.save(update_fields=["last_health_check"])
        self.assertFalse(self.server.can_host_domain())
        self.assertIsNone(destination_refusal(self.server))
