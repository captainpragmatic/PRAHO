"""Imported component admission reserves capacity and retains independent source obligations."""

from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from django.core.exceptions import ValidationError

from apps.infrastructure.models import NodeDeployment
from apps.provisioning.component_migration_models import SourceServiceObligation
from apps.provisioning.component_migration_service import start_component_migration
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_security import POLICY_VERSION, _evidence_digest, connection_identity
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from apps.users.models import User
from tests.provisioning.test_component_migration_reviews import ComponentReviewTestBase
from tests.provisioning.test_node_security_policy import OPERATOR_KEY, node_policy_evidence


class ComponentAdmissionTestBase(ComponentReviewTestBase):
    def setUp(self):
        super().setUp()
        NodeDeployment.objects.filter(virtualmin_server=self.server).update(virtualmin_server=None)
        NodeDeployment.objects.filter(virtualmin_server=self.target).update(ssh_host_keys=[OPERATOR_KEY])
        self.server.refresh_from_db()
        self.target.refresh_from_db()
        self.server.ipv4_address = "192.0.2.10"
        self.server.save(update_fields=["ipv4_address"])
        self.target.ipv4_address = "192.0.2.20"
        self.target.save(update_fields=["ipv4_address"])
        self.server.imported_ssh_host_keys = OPERATOR_KEY
        self.server.save(update_fields=["imported_ssh_host_keys"])
        key = Path(self.spool.name) / "imported-private-key"
        key.write_text("Fixture identity; remote SSH is an external test boundary.")
        key.chmod(0o600)
        self.enterContext(self.settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(key)))
        self.facts["source"]["connection_identity"] = connection_identity(self.server)
        native = self.source_gateway._domains[self.account.domain]
        native.domain_id = self.facts["source"]["domain_id"]
        native.features = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "mail", "dns"]
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
        self.target.save(update_fields=["verified_security_review"])

    def start(self, approval, facts=None, *, enqueue=False):
        return start_component_migration(approval, self.facts if facts is None else facts, self.staff, enqueue=enqueue)


class ComponentAdmissionTests(ComponentAdmissionTestBase):
    def test_imported_admission_consumes_approval_reserves_capacity_and_preserves_source(self):
        approval = self.approve(self.review())
        migration = self.start(approval)
        self.assertEqual(migration.contract, "imported_web")
        self.assertEqual(migration.component_approval_id, approval.pk)
        self.assertEqual(migration.status, "pending")
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)
        obligation = migration.component_source_obligation
        self.assertEqual(obligation.source_server_id, self.server.pk)
        self.assertEqual(obligation.source_domain_id, self.facts["source"]["domain_id"])
        self.assertEqual(obligation.retained_services, ["mail", "dns", "authentication"])
        self.assertEqual(obligation.backup_responsible_id, self.staff.pk)
        self.assertEqual(obligation.backup_responsibility, approval.backup_responsibility)
        self.assertIsNone(migration.lease_token)
        self.assertIsNone(migration.source_disabled_at)
        self.assertFalse(migration.restore_issued)
        self.assertTrue(self.source_gateway._domains[self.account.domain].enabled)
        self.assertEqual(set(self._programs("source")), {"list-domains"})
        self.assertEqual(set(self._programs("target")), {"list-domains"})
        self.ansible.return_value.run_playbook.assert_not_called()
        self.enqueue.assert_not_called()
        self.assertFalse(NodeDeployment.objects.filter(virtualmin_server=self.server).exists())

    def test_queue_dispatch_happens_only_after_obligation_and_reservation_commit(self):
        approval = self.approve(self.review())
        with self.captureOnCommitCallbacks(execute=True):
            migration = self.start(approval, enqueue=True)
            self.assertTrue(SourceServiceObligation.objects.filter(migration=migration).exists())
            self.enqueue.assert_not_called()
        self.enqueue.assert_called_once()

    def test_current_scope_drift_or_replaced_native_domain_refuses_before_reservation(self):
        approval = self.approve(self.review())
        changed = deepcopy(self.facts)
        changed["paths"][0]["inode"] += 1
        with self.assertRaises(ValidationError):
            self.start(approval, changed)
        self.source_gateway._domains[self.account.domain].domain_id = "987654321"
        with self.assertRaises(ValidationError):
            self.start(approval)
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_busy_account_full_target_or_missing_imported_trust_refuses_without_side_effects(self):
        approval = self.approve(self.review())
        self.target.max_domains = 0
        self.target.save(update_fields=["max_domains"])
        with self.assertRaises(ValidationError):
            self.start(approval)
        self.target.max_domains = 100
        self.target.save(update_fields=["max_domains"])
        self.enterContext(self.settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=""))
        with self.assertRaises(ValidationError):
            self.start(approval)
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_approval_is_single_use(self):
        approval = self.approve(self.review())
        self.start(approval)
        with self.assertRaises(ValidationError):
            self.start(approval)
        self.assertEqual(VirtualminMigration.objects.count(), 1)
        self.assertEqual(SourceServiceObligation.objects.count(), 1)

    def test_a_different_operator_must_accept_their_own_component_preview(self):
        approval = self.approve(self.review())
        other = User.objects.create_superuser(email="other-component-operator@example.test", password="fixture")
        with self.assertRaises(ValidationError):
            start_component_migration(approval, self.facts, other, enqueue=False)
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_an_existing_account_operation_cannot_be_bypassed_by_component_approval(self):
        approval = self.approve(self.review())
        existing = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, contract="legacy"
        )
        with self.assertRaises(ValidationError):
            self.start(approval)
        self.assertEqual(list(VirtualminMigration.objects.values_list("pk", flat=True)), [existing.pk])
        self.assertFalse(SourceServiceObligation.objects.exists())

    def test_a_new_approval_after_a_failed_attempt_reuses_the_retained_source_obligation(self):
        first = self.start(self.approve(self.review()))
        obligation = first.component_source_obligation
        token = uuid4()
        self.assertTrue(first.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(first.transition(token, "pending", "failed"))
        second = self.start(self.approve(self.review()))
        self.assertEqual(second.component_source_obligation_id, obligation.pk)
        self.assertEqual(SourceServiceObligation.objects.count(), 1)
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)

    def test_terminal_held_attempt_must_finish_private_artifact_cleanup_before_new_admission(self):
        first = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(first.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(
            first.transition(token, "pending", "quiescing", barrier_state={"component_source_hold_issued": True})
        )
        self.assertTrue(first.transition(token, "quiescing", "compensating"))
        self.assertTrue(first.transition(token, "compensating", "rolled_back"))
        approval = self.approve(self.review())
        for cleanup in ({}, {"done": False}, {"done": "true"}):
            # fsm-bypass: independently pending cleanup evidence on an already terminal row.
            VirtualminMigration.objects.filter(pk=first.pk).update(
                barrier_state={
                    "component_source_hold_issued": True,
                    "component_source_released": True,
                    "artifact_cleanup": cleanup,
                }
            )
            with self.subTest(cleanup=cleanup), self.assertRaisesRegex(ValidationError, "artifact|cleanup"):
                self.start(approval)
        self.assertEqual(VirtualminMigration.objects.count(), 1)
        self.assertEqual(SourceServiceObligation.objects.count(), 1)
        # fsm-bypass: the leased terminal cleanup independently verified all private locations.
        VirtualminMigration.objects.filter(pk=first.pk).update(
            barrier_state={
                "component_source_hold_issued": True,
                "component_source_released": True,
                "artifact_cleanup": {"done": True},
            }
        )
        second = self.start(approval)
        self.assertEqual(second.component_source_obligation_id, first.component_source_obligation_id)

    def test_unknown_prior_native_hold_evidence_cannot_be_treated_as_never_held(self):
        first = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(first.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(
            first.transition(token, "pending", "failed", barrier_state={"component_source_hold_issued": "unknown"})
        )
        with self.assertRaisesRegex(ValidationError, "artifact|cleanup|history"):
            self.start(self.approve(self.review()))

    def test_retained_hold_receipt_without_intent_marker_cannot_skip_cleanup(self):
        first = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(first.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(first.transition(token, "pending", "failed", barrier_state={"component_source_held": True}))
        with self.assertRaisesRegex(ValidationError, "artifact|cleanup|history"):
            self.start(self.approve(self.review()))

    def test_different_fresh_native_domain_identity_keeps_its_independent_obligation(self):
        first = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(first.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(
            first.transition(token, "pending", "failed", barrier_state={"component_source_hold_issued": True})
        )
        self.facts["source"]["domain_id"] = "987654321"
        self.source_gateway._domains[self.account.domain].domain_id = "987654321"
        second = self.start(self.approve(self.review()))
        self.assertNotEqual(second.component_source_obligation_id, first.component_source_obligation_id)
        self.assertEqual(SourceServiceObligation.objects.count(), 2)

    def test_remote_source_actions_require_current_consumed_approval_and_exact_worker_lease(self):
        from apps.provisioning.component_migration_transport import (  # noqa: PLC0415
            source_operation_refusal,
            source_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(migration.transition(token, "pending", "lowering_ttl"))
        self.assertTrue(migration.transition(token, "lowering_ttl", "quiescing"))
        migration.refresh_from_db()
        variables = source_operation_variables(migration, token, "source_hold")
        self.assertIsNone(source_operation_refusal(self.server, variables))
        variables["component_operation"]["worker_token"] = str(uuid4())
        self.assertIsNotNone(source_operation_refusal(self.server, variables))
        variables = source_operation_variables(migration, token, "source_hold")
        variables["component_request"]["paths"][0]["relative"] = "Maildir"
        self.assertIsNotNone(source_operation_refusal(self.server, variables))

    def test_source_compensation_is_forbidden_after_forward_commit(self):
        from django.utils import timezone  # noqa: PLC0415

        from apps.provisioning.component_migration_transport import (  # noqa: PLC0415
            source_operation_refusal,
            source_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(migration.transition(token, "pending", "lowering_ttl"))
        self.assertTrue(migration.transition(token, "lowering_ttl", "quiescing"))
        self.assertTrue(migration.transition(token, "quiescing", "compensating"))
        migration.refresh_from_db()
        variables = source_operation_variables(migration, token, "source_release")
        self.assertIsNone(source_operation_refusal(self.server, variables))
        # fsm-bypass: prove an independently committed row cannot reopen the source.
        VirtualminMigration.objects.filter(pk=migration.pk).update(cutover_committed_at=timezone.now())
        self.assertIsNotNone(source_operation_refusal(self.server, variables))

    def test_source_runner_accepts_only_one_exact_secret_free_native_receipt(self):
        import base64  # noqa: PLC0415
        import json  # noqa: PLC0415
        from types import SimpleNamespace  # noqa: PLC0415
        from unittest.mock import patch  # noqa: PLC0415

        from apps.common.types import Ok  # noqa: PLC0415
        from apps.provisioning.component_migration_transport import run_source_operation  # noqa: PLC0415

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        self.assertTrue(migration.transition(token, "pending", "lowering_ttl"))
        self.assertTrue(migration.transition(token, "lowering_ttl", "quiescing"))
        migration.refresh_from_db()
        receipt = {"operation_id": str(migration.pk), "action": "source_hold", "phase": "held"}
        encoded = "PRAHO_COMPONENT_RESULT=" + base64.b64encode(json.dumps(receipt).encode()).decode()
        with patch("apps.infrastructure.ansible_service.AnsibleService") as runner:
            runner.return_value.run_server_playbook.return_value = Ok(SimpleNamespace(success=True, stdout=encoded))
            self.assertEqual(run_source_operation(migration, token, "source_hold"), receipt)
            call = runner.return_value.run_server_playbook.call_args
            self.assertEqual(call.args[:2], (migration.source_server, "virtualmin_component.yml"))
            self.assertEqual(call.args[2]["component_operation"]["worker_token"], str(token))
            for evidence in (encoded + "\n" + encoded, "PRAHO_COMPONENT_RESULT=not-json"):
                runner.return_value.run_server_playbook.return_value = Ok(
                    SimpleNamespace(success=True, stdout=evidence)
                )
                with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                    run_source_operation(migration, token, "source_hold")
            receipt["operation_id"] = str(uuid4())
            wrong = "PRAHO_COMPONENT_RESULT=" + base64.b64encode(json.dumps(receipt).encode()).decode()
            runner.return_value.run_server_playbook.return_value = Ok(SimpleNamespace(success=True, stdout=wrong))
            with self.assertRaises(ValueError):
                run_source_operation(migration, token, "source_hold")

    def test_target_operations_require_exact_destination_lease_and_selected_archive(self):
        from apps.provisioning.component_target_transport import (  # noqa: PLC0415
            target_operation_refusal,
            target_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # fsm-bypass: a transfer completed independently before this worker resumed.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="restoring", archive_sha256="b" * 64)
        migration.refresh_from_db()
        variables = target_operation_variables(migration, token, "target_prepare")
        self.assertIsNone(target_operation_refusal(self.target, variables))
        self.assertIsNotNone(target_operation_refusal(self.server, variables))
        variables["component_operation"]["archive_sha256"] = "c" * 64
        self.assertIsNotNone(target_operation_refusal(self.target, variables))
        variables = target_operation_variables(migration, token, "target_prepare")
        variables["component_operation"]["worker_token"] = str(uuid4())
        self.assertIsNotNone(target_operation_refusal(self.target, variables))

    def test_target_activation_requires_forward_commit_and_current_held_receipt(self):
        from django.utils import timezone  # noqa: PLC0415

        from apps.provisioning.component_target_transport import (  # noqa: PLC0415
            target_operation_refusal,
            target_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # fsm-bypass: model a recovered activation phase on both sides of the cutover boundary.
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="activating",
            archive_sha256="b" * 64,
            barrier_state={
                "component_target_receipt_sha256": "c" * 64,
                "component_source_sealed": True,
                "component_target_sealed": True,
            },
        )
        migration.refresh_from_db()
        variables = target_operation_variables(migration, token, "target_activate", enabled=True)
        self.assertIsNotNone(target_operation_refusal(self.target, variables))
        VirtualminMigration.objects.filter(pk=migration.pk).update(cutover_committed_at=timezone.now())
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.assertIsNone(target_operation_refusal(self.target, variables))
        variables["component_operation"]["target_receipt_sha256"] = "d" * 64
        self.assertIsNotNone(target_operation_refusal(self.target, variables))

    def test_source_seal_intent_blocks_both_compensation_actions_even_before_database_commit(self):
        from apps.provisioning.component_migration_transport import (  # noqa: PLC0415
            source_operation_refusal,
            source_operation_variables,
        )
        from apps.provisioning.component_target_transport import (  # noqa: PLC0415
            target_operation_refusal,
            target_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # fsm-bypass: lost source-seal response followed by an independently resumed cancellation.
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="compensating",
            archive_sha256="b" * 64,
        )
        migration.refresh_from_db()
        source = source_operation_variables(migration, token, "source_release")
        target = target_operation_variables(migration, token, "target_remove")
        self.assertIsNone(source_operation_refusal(self.server, source))
        self.assertIsNone(target_operation_refusal(self.target, target))
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state={"component_source_seal_intent": True})
        self.assertIsNotNone(source_operation_refusal(self.server, source))
        self.assertIsNotNone(target_operation_refusal(self.target, target))

    def test_bridge_address_changes_require_new_scope_before_mutations_but_allow_owned_compensation(self):
        from apps.provisioning.component_migration_transport import (  # noqa: PLC0415
            source_operation_refusal,
            source_operation_variables,
        )
        from apps.provisioning.component_target_transport import (  # noqa: PLC0415
            target_operation_refusal,
            target_operation_variables,
        )

        migration = self.start(self.approve(self.review()))
        self.assertEqual(
            migration.pre_migration_snapshot["component_network"],
            {
                "source_ipv4": "192.0.2.10",
                "target_ipv4": "192.0.2.20",
                "source_ipv6": "",
                "target_ipv6": "",
            },
        )
        token = uuid4()
        self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
        # fsm-bypass: model a transfer completed before addresses drifted.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="restoring", archive_sha256="b" * 64)
        migration.refresh_from_db()
        variables = target_operation_variables(migration, token, "target_prepare")
        self.assertIsNone(target_operation_refusal(self.target, variables))
        self.target.ipv4_address = "192.0.2.99"
        self.target.save(update_fields=["ipv4_address"])
        self.assertIsNotNone(target_operation_refusal(self.target, variables))
        # fsm-bypass: compensate the uncommitted known target after the stale address was detected.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="compensating")
        migration.refresh_from_db()
        self.assertIsNone(
            target_operation_refusal(self.target, target_operation_variables(migration, token, "target_remove"))
        )
        self.assertIsNone(
            source_operation_refusal(self.server, source_operation_variables(migration, token, "source_release"))
        )
