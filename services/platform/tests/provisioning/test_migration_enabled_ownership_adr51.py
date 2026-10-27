"""ADR-0051: a hold added after admission must win before a writable target is exposed."""

import base64
import json
from copy import deepcopy
from datetime import timedelta
from unittest.mock import Mock, patch

from django.db import transaction
from django.utils import timezone

from apps.common.types import Ok
from apps.domains.models import TLD, Domain, Registrar
from apps.provisioning import migration_bridge_service as bridge
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.domain_veto import domain_disables_hosting
from apps.provisioning.relationship_models import ServiceDomain
from apps.provisioning.services import HostingAccountStaffActions, ServiceManagementService
from apps.provisioning.virtualmin_domain_state import domain_state_params
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import MigrationDeferredError, VirtualminMigrationService
from apps.provisioning.virtualmin_pair_restore import PairStepResult
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from apps.provisioning.virtualmin_tasks import reconcile_virtualmin_service_state, run_virtualmin_migration
from tests.provisioning.test_migration_bridge_service import BridgeServiceCase
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class EnabledOwnershipDuringRecoveryTests(MigrationTestBase):
    def _admit(self):
        name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        result = VirtualminRecoveryService().start_recovery(
            self.account,
            self.target,
            backup_ids=["b" * 32],
            source_fenced="provider confirms old node powered off",
            initiated_by=self.staff,
            enqueue=False,
        )
        self.assertTrue(result.is_ok(), result)
        migration = result.unwrap()
        self.assertEqual(migration.pre_migration_snapshot["status"], "active")
        # The dedicated account button intentionally refuses while a migration owns it.
        self.assertTrue(HostingAccountStaffActions.suspend(self.account).is_err())
        return migration, name

    def _checkpoint(self, migration, name):
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        # Resume a valid persisted boundary after restore/verification and ownership commit;
        # those stages have their own native tests. Admission and the public worker are real.
        domain_id = str(VirtualminRecoveryService()._domain(self.target, self.account.domain)["attributes"]["ID"])
        with transaction.atomic():
            self.account.server = self.target
            self.account.save(update_fields=["server", "updated_at"])
            name.target_server = self.target
            name.save(update_fields=["target_server", "updated_at"])
            VirtualminMigration.objects.filter(
                pk=migration.pk
            ).update(  # fsm-bypass: persisted CharField phase fixture.
                status="activating",
                cutover_committed_at=timezone.now(),
                barrier_state={
                    **migration.barrier_state,
                    "target_domain_id": domain_id,
                    "held_archives": [
                        {"archive_name": "virtualmin_backup_" + "b" * 32 + ".tar.gz", "checksum_sha256": "a" * 64}
                    ],
                },
            )

    def _node_edge(self, migration, action, *, enabled=None):
        intended = migration.pre_migration_snapshot["status"] == "active" if enabled is None else enabled
        self.native_calls.append((action, intended))
        if action == "reconcile_policy":
            command = "enable-domain" if intended else "disable-domain"
            self.target_gateway.call(command, domain_state_params(migration.account.domain))

    def _resume_committed_target(self, migration, name, *, cutover=False):
        self._checkpoint(migration, name)
        if cutover:
            VirtualminMigration.objects.filter(pk=migration.pk).update(contract="cutover")
            migration.refresh_from_db()
            self.source_gateway.domain_state_of(self.account.domain).enabled = False
        self.native_calls = []
        self.enterContext(
            patch("apps.provisioning.virtualmin_recovery_service.run_held_target_node", side_effect=self._node_edge)
        )
        self.enterContext(
            patch("apps.provisioning.migration_target_hold.run_held_target_node", side_effect=self._node_edge)
        )
        if cutover:
            self.enterContext(
                patch("apps.provisioning.migration_bridge_service.activate_target", return_value=Ok("activated"))
            )
            self.enterContext(
                patch(
                    "apps.provisioning.migration_bridge_service.enforce_target_policy",
                    side_effect=self._bridge_policy,
                )
            )
            self.enterContext(patch.object(VirtualminMigrationService, "_release_target_hold"))
            self.enterContext(
                patch.object(
                    VirtualminMigrationService,
                    "_bridge",
                    side_effect=lambda current, token: VirtualminMigrationService()._move(current, token, "repointing"),
                )
            )
        released = PairStepResult(outcome="released", reason="barrier_removed", ran=False, checkpoints=())
        self.events.clear()
        with (
            patch("apps.provisioning.virtualmin_recovery_service.run_pair_step", return_value=Ok(released)),
            patch.object(
                VirtualminMigrationService,
                "_converge_cutover",
                side_effect=MigrationDeferredError(
                    timezone.now() + timedelta(hours=4), "authoritative DNS temporarily unavailable"
                ),
            ),
        ):
            result = run_virtualmin_migration(str(migration.pk))
        self.assertTrue(result["success"], result)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "repointing", migration.error_detail)
        self.assertIsNotNone(migration.resume_after)
        if cutover:
            self.assertTrue(all(program == "list-domains" for program in self._programs("source")))
        else:
            self.assertEqual(self._programs("source"), [])
        activate = next(enabled for action, enabled in self.native_calls if action == "activate")
        return VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"], {
            "recovery_enabled": activate
        }

    def _bridge_policy(self, migration, enabled):
        self._node_edge(migration, "reconcile_policy", enabled=enabled)
        return Ok("reconciled")

    def test_billing_style_service_suspension_wins_before_target_activation(self):
        migration, name = self._admit()
        changed = ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue")
        self.assertTrue(changed.is_ok(), changed)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")
        self.assertEqual(reconcile_virtualmin_service_state(str(self.service.pk))["action"], "migration_locked")
        enabled, variables = self._resume_committed_target(migration, name)
        self.assertFalse(enabled, "A current suspended Service must not acquire a writable target while DNS waits")
        self.assertFalse(variables["recovery_enabled"])

    def test_bound_domain_expiry_wins_before_target_activation(self):
        registrar = Registrar.objects.create(name="gandi", display_name="Gandi", status="active")
        tld = TLD.objects.create(
            extension="com", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        domain = Domain.objects.create(
            name=self.account.domain, tld=tld, registrar=registrar, customer=self.customer, status="active"
        )
        ServiceDomain.objects.create(service=self.service, domain=domain)
        migration, name = self._admit()
        domain.expire()
        domain.save(update_fields=["status", "updated_at"])
        self.assertTrue(domain_disables_hosting(self.account))
        enabled, variables = self._resume_committed_target(migration, name)
        self.assertFalse(enabled, "A newly expired bound domain must hold the replacement account off")
        self.assertFalse(variables["recovery_enabled"])

    def test_an_unchanged_active_service_still_activates_its_replacement(self):
        migration, name = self._admit()
        enabled, variables = self._resume_committed_target(migration, name)
        self.assertTrue(enabled)
        self.assertTrue(variables["recovery_enabled"])

    def test_a_new_hold_and_its_release_converge_while_committed_dns_waits(self):
        migration, name = self._admit()
        self._resume_committed_target(migration, name)
        snapshot = dict(migration.pre_migration_snapshot)
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertNotEqual(result["action"], "migration_locked")
        self.assertFalse(VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"])
        self.assertTrue(ServiceManagementService.manage_service(str(self.service.pk), "resume").is_ok())
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertNotEqual(result["action"], "migration_locked")
        self.assertTrue(VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"])
        migration.refresh_from_db()
        self.assertEqual(migration.pre_migration_snapshot, snapshot)
        self.assertEqual(sum(action == "activate" for action, _enabled in self.native_calls), 1)

    def test_a_postactivation_review_hold_does_not_freeze_enabled_policy(self):
        migration, name = self._admit()
        self._resume_committed_target(migration, name)
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review", parked_phase="repointing")
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertNotEqual(result["action"], "migration_locked")
        self.assertFalse(VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"])
        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.parked_phase), ("needs_review", "repointing"))

    def test_an_unactivated_committed_target_remains_excluded_from_reconciliation(self):
        migration, name = self._admit()
        self._checkpoint(migration, name)
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review", parked_phase="repointing")
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        self.events.clear()
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(result["action"], "migration_locked")
        self.assertEqual(self.events, [])

    def test_cutover_also_uses_current_policy_and_converges_later_holds(self):
        migration, name = self._admit()
        snapshot = dict(migration.pre_migration_snapshot)
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        enabled, variables = self._resume_committed_target(migration, name, cutover=True)
        self.assertFalse(enabled)
        self.assertFalse(variables["recovery_enabled"])
        self.assertTrue(ServiceManagementService.manage_service(str(self.service.pk), "resume").is_ok())
        self.assertEqual(reconcile_virtualmin_service_state(str(self.service.pk))["action"], "migration_policy")
        self.assertTrue(VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"])
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        self.assertEqual(reconcile_virtualmin_service_state(str(self.service.pk))["action"], "migration_policy")
        self.assertFalse(VirtualminRecoveryService()._domain(self.target, self.account.domain)["enabled"])
        migration.refresh_from_db()
        self.assertEqual(migration.pre_migration_snapshot, snapshot)
        self.assertEqual(sum(action == "activate" for action, _enabled in self.native_calls), 1)

    def test_current_target_identity_drift_denies_the_policy_rpc(self):
        migration, name = self._admit()
        self._resume_committed_target(migration, name)
        self.target_gateway.seed_domain(self.account.domain, username="differentcustomer", enabled=True)
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        self.native_calls.clear()
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertFalse(result["success"])
        self.assertEqual(self.native_calls, [])

    def test_restore_hold_and_other_lifecycle_writers_remain_excluded_after_activation(self):
        migration, name = self._admit()
        self._resume_committed_target(migration, name)
        self.account.refresh_from_db()
        self.assertTrue(HostingAccountStaffActions.suspend(self.account).is_err())
        self.account.restore_hold = True
        self.account.save(update_fields=["restore_hold", "updated_at"])
        self.native_calls.clear()
        result = reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(result["action"], "operation_active")
        self.assertEqual(self.native_calls, [])

    def test_insufficient_reconciler_budget_refuses_before_any_native_or_gateway_call(self):
        migration, name = self._admit()
        self._resume_committed_target(migration, name)
        self.assertTrue(
            ServiceManagementService.manage_service(str(self.service.pk), "suspend", reason="payment_overdue").is_ok()
        )
        self.native_calls.clear()
        self.events.clear()
        result = reconcile_virtualmin_service_state(str(self.service.pk), task_budget_seconds=1)
        self.assertFalse(result["success"])
        self.assertEqual(result["action"], "migration_policy")
        self.assertIn("budget", result["error"])
        self.assertEqual(self.native_calls, [])
        self.assertEqual(self.events, [])


class BridgeEnabledPolicyProofTests(BridgeServiceCase):
    def test_activation_override_keeps_the_original_record_identical(self):
        self.migration.cutover_committed_at = timezone.now()
        original = deepcopy(self.migration.barrier_state)
        self.assertEqual(bridge.activate_target(self.migration, enabled=False), Ok("activated"))
        self.assertIs(self._variables()["bridge_enabled"], False)
        self.assertEqual(self.migration.barrier_state, original)
        self.assertEqual(self._variables()["bridge_barrier_record"], original["record"])

    def test_policy_transport_is_target_only_bounded_and_requires_exact_proof(self):
        self.migration.cutover_committed_at = timezone.now()
        self.migration.barrier_state["target_domain_id"] = "987654"
        proof = {"domain_id": "987654", "owner": self.account.virtualmin_username, "enabled": False}
        encoded = base64.b64encode(
            json.dumps({"identity": str(self.migration.pk), "action": "reconcile_policy", "payload": proof}).encode()
        ).decode()
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Ok(Mock(success=True, stdout=f"BRIDGE_RESULT={encoded}"))
        self.assertEqual(bridge.enforce_target_policy(self.migration, False), Ok("reconciled"))
        call = self.runner.run_playbook.call_args
        self.assertEqual(call.args[0], self.target.node_deployment)
        self.assertEqual(call.kwargs["timeout_seconds"], 300)
        self.assertNotIn("bridge_barrier_record", self._variables())

    def test_policy_refuses_uncertain_or_mismatched_native_identity(self):
        self.migration.cutover_committed_at = timezone.now()
        self.migration.barrier_state["target_domain_id"] = "987654"
        for proof in (
            {},
            {"domain_id": "other", "owner": self.account.virtualmin_username, "enabled": False},
            {"domain_id": "987654", "owner": "other", "enabled": False},
            {"domain_id": "987654", "owner": self.account.virtualmin_username, "enabled": True},
        ):
            with self.subTest(proof=proof), patch.object(bridge, "_step", return_value=Ok(proof)):
                self.assertTrue(bridge.enforce_target_policy(self.migration, False).is_err())

    def test_policy_refuses_before_commit_without_contacting_a_node(self):
        self.migration.barrier_state["target_domain_id"] = "987654"
        self.assertTrue(bridge.enforce_target_policy(self.migration, False).is_err())
        self.runner.run_playbook.assert_not_called()
