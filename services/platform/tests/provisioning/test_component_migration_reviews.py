"""Explicit component scope and backup responsibility are bound to current source and target authority."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.provisioning.component_migration_service import approve_component_review, record_component_review
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import POLICY_VERSION, _evidence_digest, connection_identity
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from tests.provisioning.test_component_migration_manifest import component_manifest
from tests.provisioning.test_node_security_policy import node_policy_evidence
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class ComponentReviewTestBase(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.staff.is_staff = True
        self.staff.is_superuser = True
        self.staff.save(update_fields=["is_staff", "is_superuser"])
        self.server.security_state = "acknowledged_source_only"
        self.server.save(update_fields=["security_state"])
        self.target.security_state = "verified_web"
        self.target.api_username = "praho-api"
        self.target.save(update_fields=["api_username"])
        evidence = node_policy_evidence()
        evidence["identity"] = connection_identity(self.target)
        proof = NodeSecurityReview.objects.create(
            server=self.target,
            server_uuid=self.target.pk,
            policy_version=POLICY_VERSION,
            identity=evidence["identity"],
            digest=_evidence_digest(evidence),
            evidence=evidence,
        )
        self.target.verified_security_review = proof
        self.target.save(update_fields=["security_state", "verified_security_review"])
        self.facts = component_manifest()
        self.facts["source"].update(
            {
                "server_uuid": str(self.server.pk),
                "connection_identity": connection_identity(self.server),
                "domain": self.account.domain,
                "owner": self.account.virtualmin_username,
                "home": "/home/" + self.account.virtualmin_username,
            }
        )
        self.facts["routing"]["website_names"] = [self.account.domain, "www." + self.account.domain]

    def review(self):
        return record_component_review(self.account, self.target, self.facts, self.staff)

    def approve(self, review, facts=None, backup_handoff="Operations retains independent source mail/DNS backups."):
        return approve_component_review(
            review,
            self.facts if facts is None else facts,
            self.staff,
            "Move the selected website and database; retain source mail and DNS.",
            backup_handoff,
        )


class ComponentReviewTests(ComponentReviewTestBase):
    def test_approval_records_exact_scope_actor_and_separate_backup_responsibility(self):
        review = self.review()
        approval = self.approve(review)
        self.assertEqual(approval.review_id, review.pk)
        self.assertEqual(approval.actor, self.staff)
        self.assertIn("independent source", approval.backup_responsibility)
        self.assertEqual(review.manifest, self.facts)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertFalse(self.account.migrations.exists())
        with self.assertRaises(ValidationError):
            type(review).objects.filter(pk=review.pk).update(manifest={})
        with self.assertRaises(ValidationError):
            approval.delete()

    def test_live_bytes_and_children_are_requalified_within_the_same_selected_roots(self):
        review = self.review()
        fresh = deepcopy(self.facts)
        fresh["paths"][0]["bytes"] += 1000
        fresh["paths"][0]["tree_digest"] = "b" * 64
        self.assertEqual(self.approve(review, fresh).review_id, review.pk)

    def test_changed_root_grant_or_routing_needs_a_new_preview(self):
        review = self.review()
        for section in ("root", "grant", "route"):
            fresh = deepcopy(self.facts)
            if section == "root":
                fresh["paths"][0]["inode"] += 1
            elif section == "grant":
                fresh["databases"][0]["principals"][0]["grants_digest"] = "9" * 64
            else:
                fresh["routing"]["digest"] = "9" * 64
            with self.subTest(section=section), self.assertRaises(ValidationError):
                self.approve(review, fresh)
        self.assertFalse(apps.get_model("provisioning", "ComponentMigrationApproval").objects.exists())

    def test_backup_handoff_and_active_deployment_permission_are_required(self):
        review = self.review()
        with self.assertRaises(ValidationError):
            self.approve(review, backup_handoff="")
        self.staff.is_active = False
        with self.assertRaises(PermissionDenied):
            self.approve(review)

    def test_superseded_or_stale_preview_cannot_authorize_a_move(self):
        review = self.review()
        self.review()
        with self.assertRaises(ValidationError):
            self.approve(review)
        latest = self.review()
        with (
            patch(
                "apps.provisioning.component_migration_service.timezone.now",
                return_value=timezone.now() + timedelta(minutes=16),
            ),
            self.assertRaises(ValidationError),
        ):
            self.approve(latest)

    def test_target_credential_drift_revokes_component_approval(self):
        review = self.review()
        self.target.set_api_password("different credential after preview")
        self.target.save(update_fields=["encrypted_api_password"])
        with self.assertRaises(ValidationError):
            self.approve(review)

    def test_unresolved_dependencies_can_be_recorded_but_cannot_be_accepted_away(self):
        self.facts["preparation"] = ["MX points to the website apex; prepare an independent mail host."]
        review = self.review()
        self.assertEqual(review.manifest["preparation"], self.facts["preparation"])
        with self.assertRaises(ValidationError):
            self.approve(review)

    def test_source_only_is_required_and_a_bare_target_label_is_insufficient(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(security_state="unreviewed")
        with self.assertRaises(ValidationError):
            self.approve(self.review())

    def test_target_label_requires_a_bound_current_native_proof(self):
        review = self.review()
        VirtualminServer.objects.filter(pk=self.target.pk).update(verified_security_review=None)
        with self.assertRaises(ValidationError):
            self.approve(review)
