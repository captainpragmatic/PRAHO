"""Import is observational; quota adoption and customer-mail handover are separate."""

from copy import deepcopy
from types import ModuleType
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.provisioning.hosting_node_execution import (
    claim_hosting_operation,
    complete_hosting_operation,
    hosting_transport_allowed,
    hosting_transport_scope,
    park_hosting_operation,
    record_hosting_inspection,
)
from apps.provisioning.hosting_node_policy import (
    NOTIFICATION_EMITTERS,
    managed_quota_refusal,
    platform_notifications_owned,
)
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy, NodeHostingReview
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from apps.users.models import User
from tests.provisioning.test_hosting_node_policy import quota_evidence


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class HostingNodeAdoptionTests(TestCase):
    def setUp(self):
        notifier = ModuleType("apps.provisioning.hosting_warning_delivery")
        notifier.HANDOVER_CAPABILITY_VERSION = "quota-warnings-v1"
        notifier.notification_handover_refusal = lambda server: None
        self.notifier = patch.dict("sys.modules", {notifier.__name__: notifier})
        self.notifier.start()
        self.addCleanup(self.notifier.stop)
        self.server = VirtualminServer.objects.create(hostname="adoption.example.test", api_username="praho-api")
        self.actor = User.objects.create_superuser(email="node-operator@example.test", password="test")
        self.identity = connection_identity(self.server)
        quota = quota_evidence()
        quota["identity"] = self.identity
        self.mail = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": self.identity,
            "installation": quota["installation"],
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        self.inventory = {"identity": self.identity, "quota": quota, "notifications": self.mail}

    def test_new_import_and_inspection_change_neither_caps_nor_notification_owner(self):
        self.assertIsNotNone(managed_quota_refusal(self.server))
        self.assertFalse(platform_notifications_owned(self.server))
        review = record_hosting_inspection(self.server, self.inventory)
        self.assertEqual(review.evidence, self.inventory)
        self.assertFalse(NodeHostingPolicy.objects.filter(server=self.server).exists())
        self.assertIsNotNone(managed_quota_refusal(self.server))
        self.assertFalse(platform_notifications_owned(self.server))

    def test_quota_adoption_never_implies_mail_handover_and_retarget_invalidates_proof(self):
        review = record_hosting_inspection(self.server, self.inventory)
        run = claim_hosting_operation(review, self.inventory, self.actor, "adopt_quota", "Verified native lab proof")
        self.assertIsNotNone(managed_quota_refusal(self.server))
        complete_hosting_operation(run.pk, {**self.inventory, "fenced_token": str(run.pk)})
        self.assertIsNone(managed_quota_refusal(self.server))
        self.assertFalse(platform_notifications_owned(self.server))
        VirtualminServer.objects.filter(pk=self.server.pk).update(api_port=10001)
        self.assertIsNotNone(managed_quota_refusal(self.server))

    def test_source_only_email_handover_does_not_require_supported_kernel_adoption(self):
        self.server.security_state = "acknowledged_source_only"
        self.server.save(update_fields=["security_state"])
        self.inventory["quota"] = {}
        review = record_hosting_inspection(self.server, self.inventory)
        run = claim_hosting_operation(
            review, self.inventory, self.actor, "handover_mail", "Platform owns customer notices"
        )
        with self.assertRaises(ValidationError):
            complete_hosting_operation(run.pk, self.inventory)
        park_hosting_operation(run.pk)
        self.assertFalse(platform_notifications_owned(self.server))
        complete_hosting_operation(run.pk, {**self.inventory, "fenced_token": str(run.pk)})
        self.assertTrue(platform_notifications_owned(self.server))
        self.assertIsNotNone(managed_quota_refusal(self.server))

    def test_changed_inventory_or_unfenced_uncertainty_cannot_release_exclusion(self):
        review = record_hosting_inspection(self.server, self.inventory)
        changed = deepcopy(self.inventory)
        changed["notifications"]["emitters"]["status_monitors"] = False
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, changed, self.actor, "handover_mail", "Reviewed")
        run = claim_hosting_operation(review, self.inventory, self.actor, "handover_mail", "Reviewed")
        park_hosting_operation(run.pk)
        with self.assertRaises(ValidationError):
            complete_hosting_operation(run.pk, self.inventory)
        self.assertEqual(NodeHostingPolicy.objects.get(server=self.server).operation, run.pk)
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, self.inventory, self.actor, "handover_mail", "Second run")

    def test_review_is_append_only_and_old_quota_proof_does_not_mask_missing_verification(self):
        review = record_hosting_inspection(self.server, self.inventory)
        with self.assertRaises(ValidationError):
            NodeHostingReview.objects.filter(pk=review.pk).update(evidence={})
        with self.assertRaises(ValidationError):
            NodeHostingReview(
                id=review.pk,
                server=self.server,
                server_uuid=self.server.pk,
                policy_version="hosting-node-v1",
                identity=self.identity,
                digest="a" * 64,
                evidence={},
            ).save()
        NodeHostingPolicy.objects.create(
            server=self.server,
            quota_adopted=True,
            connection_identity=self.identity,
            quota_evidence=self.inventory["quota"],
            notification_owner="platform",
            notification_evidence=self.mail,
            notifications_verified_at=timezone.now(),
        )
        self.assertTrue(platform_notifications_owned(self.server))
        self.assertIsNotNone(managed_quota_refusal(self.server))

    def test_missing_platform_notifier_refuses_handover_and_stale_owner_flags(self):
        review = record_hosting_inspection(self.server, self.inventory)
        with patch.dict("sys.modules", {"apps.provisioning.hosting_warning_delivery": None}):
            with self.assertRaises(ValidationError):
                claim_hosting_operation(review, self.inventory, self.actor, "handover_mail", "Not yet safe")
            self.assertFalse(NodeHostingPolicy.objects.filter(server=self.server).exists())
            NodeHostingPolicy.objects.create(
                server=self.server,
                notification_owner="platform",
                notification_evidence=self.mail,
                notifications_verified_at=timezone.now(),
            )
            self.assertFalse(platform_notifications_owned(self.server))

    def test_accepted_operator_authority_is_immutable_and_required_at_transport(self):
        review = record_hosting_inspection(self.server, self.inventory)
        run = claim_hosting_operation(
            review,
            self.inventory,
            self.actor,
            "handover_mail",
            "Approved operators",
            operator_emails=["Operator@example.test", "operator@example.test"],
        )
        self.assertEqual(run.authority, {"operator_emails": ["operator@example.test"]})
        variables = {
            "hosting_action": "handover",
            "hosting_request": {
                "identity": self.identity,
                "token": str(run.pk),
                "operator_emails": ["operator@example.test"],
            },
        }
        self.assertFalse(hosting_transport_allowed(self.server, variables))
        with hosting_transport_scope(run.pk):
            self.assertTrue(hosting_transport_allowed(self.server, variables))
            changed = deepcopy(variables)
            changed["hosting_request"]["operator_emails"] = ["customer@example.test"]
            self.assertFalse(hosting_transport_allowed(self.server, changed))
            self.assertFalse(hosting_transport_allowed(self.server))
        run.authority = {"operator_emails": ["customer@example.test"]}
        with self.assertRaises(ValidationError):
            run.save(update_fields=["authority"])
        with self.assertRaises(ValidationError):
            type(run).objects.filter(pk=run.pk).update(authority=run.authority)
        self.assertEqual(type(run).objects.get(pk=run.pk).authority, {"operator_emails": ["operator@example.test"]})

    def test_unadopted_draining_source_can_prepare_helpers_without_mail_or_kernel_handover(self):
        self.server.status, self.server.is_draining = "disabled", True
        self.server.save(update_fields=["status", "is_draining"])
        current = {"identity": connection_identity(self.server), "helper_bundle_digest": "a" * 64}
        review = record_hosting_inspection(self.server, current)
        run = claim_hosting_operation(review, current, self.actor, "prepare_helpers", "Prepare source inventory")
        with self.assertRaises(ValidationError):
            complete_hosting_operation(run.pk, {**current, "fenced_token": str(uuid4())})
        complete_hosting_operation(run.pk, {**current, "fenced_token": str(run.pk)})
        self.assertIsNotNone(managed_quota_refusal(self.server))
        self.assertFalse(platform_notifications_owned(self.server))

    def test_observed_new_boot_invalidates_stored_readiness_until_qualified_readoption(self):
        review = record_hosting_inspection(self.server, self.inventory)
        run = claim_hosting_operation(review, self.inventory, self.actor, "adopt_quota", "Initial acceptance")
        complete_hosting_operation(run.pk, {**self.inventory, "fenced_token": str(run.pk)})
        self.assertIsNone(managed_quota_refusal(self.server))
        current = deepcopy(self.inventory)
        current["quota"]["boot_id"] = str(uuid4())
        current["quota"]["requalification_required"] = True
        review = record_hosting_inspection(self.server, current)
        self.assertIsNotNone(managed_quota_refusal(self.server))
        run = claim_hosting_operation(review, current, self.actor, "adopt_quota", "Requalify same node after reboot")
        with self.assertRaises(ValidationError):
            complete_hosting_operation(run.pk, {**current, "fenced_token": str(run.pk)})
        current["quota"]["requalification_required"] = False
        current["quota"]["qualification_id"] = str(uuid4())
        complete_hosting_operation(run.pk, {**current, "fenced_token": str(run.pk)})
        policy = NodeHostingPolicy.objects.get(server=self.server)
        self.assertIsNone(managed_quota_refusal(self.server))
        self.assertEqual(policy.quota_evidence["boot_id"], current["quota"]["boot_id"])
        self.assertNotEqual(policy.quota_evidence["boot_id"], self.inventory["quota"]["boot_id"])

    def test_isolated_requalification_cannot_adopt_unknown_replaced_or_unchanged_nodes(self):
        changed = deepcopy(self.inventory)
        changed["quota"]["boot_id"] = str(uuid4())
        changed["quota"]["requalification_required"] = True
        review = record_hosting_inspection(self.server, changed)
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, changed, self.actor, "requalify_quota", "Unknown source")
        NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=self.identity,
            quota_adopted=True,
            quota_evidence=self.inventory["quota"],
            quota_verified_at=timezone.now(),
        )
        for field, value in (
            ("installation", str(uuid4())),
            ("filesystem_uuid", str(uuid4())),
            ("acceptance_id", str(uuid4())),
            ("requalification_required", False),
        ):
            invalid = deepcopy(changed)
            invalid["quota"][field] = value
            review = record_hosting_inspection(self.server, invalid)
            with self.subTest(field=field), self.assertRaises(ValidationError):
                claim_hosting_operation(review, invalid, self.actor, "requalify_quota", "Unsupported qualification")
        self.server.security_operation = uuid4()
        self.server.save(update_fields=["security_operation"])
        review = record_hosting_inspection(self.server, changed)
        with self.assertRaises(ValidationError):
            claim_hosting_operation(review, changed, self.actor, "requalify_quota", "Security work still owns node")
