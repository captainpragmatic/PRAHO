"""Operator approval must describe the current node without changing its services."""

import secrets
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.credential_vault import EncryptedCredential
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import acknowledge_source, connection_identity, record_inspection
from apps.provisioning.virtualmin_security_models import NodeSecurityDecision, NodeSecurityReview
from apps.users.models import User


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class NodeSecurityReviewTests(TestCase):
    def setUp(self):
        self.server = VirtualminServer.objects.create(
            hostname="legacy.example.com", api_username="root", last_health_check=timezone.now()
        )
        self.operator = User.objects.create_superuser(email="operator@example.com", password=None)
        self.evidence = {
            "schema": 1,
            "identity": connection_identity(self.server),
            "versions": {"webmin": "2.670", "virtualmin": "8.3.0"},
            "listeners": ["tcp 0.0.0.0:25", "udp 0.0.0.0:53"],
            "principals": [{"name": "root", "access": "unrestricted"}],
            "services": ["postfix", "bind9"],
            "firewall": ["allow tcp 25"],
            "proposed_changes": ["Restrict root to loopback", "Close public mail and DNS ports"],
        }

    def inspect(self):
        return record_inspection(self.server, self.evidence)

    def test_reading_connection_identity_never_enrolls_legacy_host_trust(self):
        from tests.infrastructure.test_deployment_service_pipeline import _create_deployment  # noqa: PLC0415

        deployment = _create_deployment("completed")
        deployment.virtualmin_server = self.server
        deployment.ssh_host_keys = ""
        deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        self.server.refresh_from_db()
        with patch("apps.infrastructure.ssh_transport.resolve_node_host_keys", return_value="would-enroll") as enroll:
            identity = connection_identity(self.server)
        self.assertEqual(len(identity), 64)
        enroll.assert_not_called()
        deployment.refresh_from_db()
        self.assertEqual(deployment.ssh_host_keys, "")

    def test_managed_persisted_trust_is_not_revoked_by_an_unrelated_known_hosts_edit(self):
        from tests.infrastructure.test_deployment_service_pipeline import _create_deployment  # noqa: PLC0415
        from tests.provisioning.test_node_security_policy import OPERATOR_KEY  # noqa: PLC0415

        deployment = _create_deployment("completed")
        deployment.virtualmin_server = self.server
        deployment.ssh_host_keys = OPERATOR_KEY
        deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        self.server.refresh_from_db()
        with TemporaryDirectory() as directory:
            trust = Path(directory) / "known_hosts"
            trust.write_text("unrelated-node initial key\n")
            with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=str(trust)):
                original = connection_identity(self.server)
                trust.write_text("unrelated-node replacement key\n")
                self.assertEqual(connection_identity(self.server), original)

    def test_import_stays_active_and_unreviewed(self):
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertTrue(self.server.is_healthy)

    def test_inspection_preserves_services_and_does_not_grant_verification(self):
        review = self.inspect()
        self.server.refresh_from_db()
        self.assertEqual(review.evidence, self.evidence)
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertTrue(self.server.is_healthy)

    def test_acknowledgment_records_responsibility_without_hardening(self):
        review = self.inspect()
        decision = acknowledge_source(review, self.evidence, self.operator, "Mail stays here until migration")
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_state, "acknowledged_source_only")
        self.assertTrue(self.server.is_healthy)
        self.assertEqual(self.server.api_username, "root")
        self.assertEqual(decision.actor, self.operator)
        self.assertEqual(decision.review_id, review.pk)
        self.assertEqual(decision.reason, "Mail stays here until migration")
        self.assertEqual(decision.action, "acknowledge_source")
        self.assertEqual(NodeSecurityDecision.objects.count(), 1)

    def test_changed_findings_require_new_preview(self):
        review = self.inspect()
        changed = deepcopy(self.evidence)
        changed["principals"].append({"name": "new-admin", "access": "unrestricted"})
        with self.assertRaises(ValidationError):
            acknowledge_source(review, changed, self.operator, "Keep existing services")
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertFalse(NodeSecurityDecision.objects.exists())

    def test_old_preview_cannot_supersede_latest_inspection(self):
        review = self.inspect()
        self.inspect()
        with self.assertRaises(ValidationError):
            acknowledge_source(review, self.evidence, self.operator, "Keep existing services")

    def test_connection_change_invalidates_preview(self):
        review = self.inspect()
        self.server.ssh_port = 22222
        self.server.save(update_fields=["ssh_port"])
        with self.assertRaises(ValidationError):
            acknowledge_source(review, self.evidence, self.operator, "Keep existing services")

    def test_ordinary_staff_cannot_acknowledge(self):
        staff = User.objects.create_user(email="support@example.com", password=None, is_staff=True)
        with self.assertRaises(PermissionDenied):
            acknowledge_source(self.inspect(), self.evidence, staff, "Keep existing services")

    def test_reason_is_required(self):
        with self.assertRaises(ValidationError):
            acknowledge_source(self.inspect(), self.evidence, self.operator, "   ")

    def test_duplicate_acknowledgment_is_refused(self):
        review = self.inspect()
        acknowledge_source(review, self.evidence, self.operator, "Keep existing services")
        with self.assertRaises(ValidationError):
            acknowledge_source(review, self.evidence, self.operator, "Another decision")

    def test_preview_does_not_accept_secrets(self):
        self.evidence["api_password"] = secrets.token_urlsafe(16)
        with self.assertRaises(ValidationError):
            self.inspect()
        self.assertFalse(NodeSecurityReview.objects.exists())

    def test_evidence_and_decisions_cannot_be_overwritten(self):
        review = self.inspect()
        decision = acknowledge_source(review, self.evidence, self.operator, "Keep existing services")
        review.evidence = {}
        with self.assertRaises(ValidationError):
            review.save()
        with self.assertRaises(ValidationError):
            NodeSecurityReview.objects.filter(pk=review.pk).update(digest="0" * 64)
        with self.assertRaises(ValidationError):
            NodeSecurityDecision.objects.filter(pk=decision.pk).delete()

    def test_bounded_evidence_and_required_sections(self):
        self.evidence["listeners"] = ["x" * 140000]
        with self.assertRaises(ValidationError):
            self.inspect()
        self.evidence = deepcopy(self.evidence)
        self.evidence["listeners"] = []
        del self.evidence["identity"]
        with self.assertRaises(ValidationError):
            self.inspect()

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    def test_decision_is_audited_with_the_operator(self):
        review = self.inspect()
        inspection = AuditEvent.objects.get(object_id=str(review.pk), action="security_scan_detected")
        self.assertEqual(inspection.severity, "low", "Recording evidence is not a detected security incident")
        decision = acknowledge_source(review, self.evidence, self.operator, "Keep existing services")
        event = AuditEvent.objects.get(object_id=str(decision.pk), action="configuration_changed")
        self.assertEqual(event.user_id, self.operator.pk)
        self.assertEqual(event.new_values["review_id"], str(review.pk))

    def test_expired_preview_requires_reinspection(self):
        review = self.inspect()
        with (
            patch(
                "apps.provisioning.virtualmin_security.timezone.now",
                return_value=timezone.now() + timedelta(minutes=16),
            ),
            self.assertRaises(ValidationError),
        ):
            acknowledge_source(review, self.evidence, self.operator, "Keep existing services")

    def test_forged_instance_cannot_replace_history(self):
        review = self.inspect()
        forged = NodeSecurityReview(pk=review.pk, server=self.server, evidence={})
        with self.assertRaises(ValidationError):
            forged.save(force_update=True)

    def test_deleting_node_preserves_review_without_blocking_teardown(self):
        review = self.inspect()
        original_id = self.server.pk
        self.server.delete()
        review.refresh_from_db()
        self.assertIsNone(review.server_id)
        self.assertEqual(review.server_uuid, original_id)

    def test_same_size_schema_rejects_nested_credentials(self):
        self.evidence["principals"] = [{"name": "root", "access": "all", "password": secrets.token_urlsafe(16)}]
        with self.assertRaises(ValidationError):
            self.inspect()

    def test_vault_rotation_changes_review_identity(self):
        before = connection_identity(self.server)
        EncryptedCredential.objects.create(
            service_type="virtualmin",
            service_identifier=self.server.hostname,
            encrypted_username=b"opaque-username",
            encrypted_password=b"opaque-password",
            expires_at=timezone.now() + timedelta(days=30),
        )
        self.assertNotEqual(before, connection_identity(self.server))

    def test_imported_trust_rotation_changes_review_identity(self):
        with TemporaryDirectory() as directory:
            trust = Path(directory) / "known_hosts"
            trust.write_text("first enrolled trust")
            with self.settings(PRAHO_SSH_KNOWN_HOSTS_PATH=str(trust)):
                before = connection_identity(self.server)
                trust.write_text("different enrolled trust")
                self.assertNotEqual(before, connection_identity(self.server))
