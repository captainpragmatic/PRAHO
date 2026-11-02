"""Imported component workers never fall through whole-domain migration callbacks."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.utils import timezone

from apps.infrastructure.dns_agreement import Agreement
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService, resolve_migration
from tests.provisioning.acme_fakes import issue_chain
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentWorkerTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        self.token = uuid4()
        self.assertTrue(self.migration.acquire_lease(self.token, timedelta(minutes=5)))
        self.events.clear()

    def phase(self, status, **fields):
        # fsm-bypass: establish the persisted checkpoint left by an independent prior worker.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(status=status, **fields)
        self.migration.refresh_from_db()

    def worker(self):
        from apps.provisioning.component_migration_worker import ComponentMigrationWorker  # noqa: PLC0415

        return ComponentMigrationWorker()

    def test_approved_imported_dispatch_runs_component_hold_and_checkpoints_before_backup(self):
        with (
            patch("apps.provisioning.component_migration_worker.run_source_operation") as native,
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake") as wake,
        ):
            result = VirtualminMigrationService().execute(self.migration, self.token)
        self.assertTrue(result.is_ok(), result)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "backing_up")
        self.assertTrue(self.migration.barrier_state["component_source_hold_issued"])
        self.assertEqual([call.args[2] for call in native.call_args_list], ["source_hold", "source_verify"])
        self.assertTrue(wake.called)
        self.assertEqual(self.events, [])
        self.assertFalse(self.migration.restore_issued)
        self.assertIsNone(self.migration.source_disabled_at)

    def test_component_backup_persists_only_the_published_selected_receipt(self):
        self.phase("backing_up", barrier_state={"component_source_hold_issued": True})
        exported = {
            "path": f"/var/lib/praho-transfer/components/{self.migration.pk}/{self.migration.archive_name}",
            "sha256": "a" * 64,
            "bytes": 1234,
            "files": 5,
            "databases": [],
        }
        with patch(
            "apps.provisioning.component_migration_worker.run_source_operation", return_value={"export": exported}
        ):
            self.worker()._backup(self.migration, self.token)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "fetching")
        self.assertEqual(self.migration.archive_sha256, "a" * 64)
        self.assertEqual(self.migration.barrier_state["component_export"], exported)
        self.assertIsNone(self.migration.source_disabled_at)
        self.assertEqual(self.events, [])

    def test_target_restore_records_native_identity_before_exact_restore(self):
        self.phase("restoring", archive_sha256="a" * 64)
        checkpoints = []

        def native(migration, _token, action):
            current = VirtualminMigration.objects.get(pk=migration.pk)
            self.assertTrue(current.restore_issued)
            checkpoints.append(action)
            if action == "target_restore":
                self.assertEqual(current.barrier_state["target_domain_id"], "987654321")
                return {"target_domain_id": "987654321", "target_receipt_sha256": "b" * 64}
            return {"target_domain_id": "987654321"}

        with patch("apps.provisioning.component_migration_worker.run_target_operation", side_effect=native):
            self.worker()._restore(self.migration, self.token)
        self.migration.refresh_from_db()
        self.assertEqual(checkpoints, ["target_prepare", "target_restore"])
        self.assertEqual(self.migration.status, "verifying")
        self.assertEqual(self.migration.barrier_state["component_target_receipt_sha256"], "b" * 64)
        self.assertEqual(self.events, [])

    def test_seal_intent_cancellation_resumes_forward_without_rechecking_precommit_holds(self):
        self.phase("verifying", cancel_requested=True, barrier_state={"component_source_seal_intent": True})
        with (
            patch("apps.provisioning.component_migration_worker.commit_component_cutover") as commit,
            patch("apps.provisioning.component_migration_worker.run_source_operation") as source,
            patch("apps.provisioning.component_migration_worker.run_target_operation") as target,
        ):
            self.worker()._verify(self.migration, self.token)
        self.assertEqual(commit.call_args.args[1:], (self.migration, self.token))
        self.assertEqual(commit.call_count, 1)
        source.assert_not_called()
        target.assert_not_called()

    def test_compensation_removes_prepared_bridge_then_target_then_source_holds(self):
        self.phase(
            "compensating",
            restore_issued=True,
            barrier_state={
                "component_source_hold_issued": True,
                "component_bridge_source_prepare_issued": True,
                "component_bridge_origin_issued": True,
                "target_domain_id": "987654321",
            },
        )
        actions = []
        with (
            patch(
                "apps.provisioning.component_migration_worker.run_bridge_operation",
                side_effect=lambda _m, _t, action: actions.append(action),
            ),
            patch(
                "apps.provisioning.component_migration_worker.run_target_operation",
                side_effect=lambda _m, _t, action: actions.append(action),
            ),
            patch(
                "apps.provisioning.component_migration_worker.run_source_operation",
                side_effect=lambda _m, _t, action: actions.append(action),
            ),
            patch("apps.provisioning.component_migration_worker.retire_removed_node_name") as retire,
        ):
            from apps.common.types import Ok  # noqa: PLC0415

            retire.return_value = Ok(None)
            self.worker()._compensate(self.migration, self.token)
        self.assertEqual(actions, ["remove", "origin_remove", "target_remove", "source_release"])
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "rolled_back")
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(self.events, [])

    def test_sealed_precommit_row_cannot_transition_to_compensation(self):
        self.phase("verifying", barrier_state={"component_source_seal_intent": True})
        self.assertFalse(self.migration.transition(self.token, "verifying", "compensating"))
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "verifying")

    def test_uncommitted_sealed_review_resolves_forward_and_never_marks_source_kept(self):
        self.phase(
            "needs_review",
            barrier_state={"component_source_seal_intent": True},
            parked_phase="verifying",
            lease_token=None,
            worker_lease_expires_at=None,
        )
        with self.captureOnCommitCallbacks(execute=True):
            result = resolve_migration(self.migration, resolved_by=self.staff, note="Review exact native receipts")
        self.assertTrue(result.is_ok(), result)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "verifying")
        self.assertEqual(self.migration.parked_phase, "")
        self.assertIsNone(self.migration.cutover_committed_at)
        self.enqueue.assert_called_once()

    def test_unknown_review_cannot_use_the_sealed_component_forward_edge(self):
        self.phase("needs_review", contract="unrecognised", barrier_state={"component_source_seal_intent": True})
        self.assertFalse(self.migration.transition(self.token, "needs_review", "verifying"))

    def test_unsealed_component_review_can_only_resolve_via_native_compensation(self):
        self.phase("needs_review", parked_phase="restoring", lease_token=None, worker_lease_expires_at=None)
        with self.captureOnCommitCallbacks(execute=True):
            result = resolve_migration(self.migration, resolved_by=self.staff, note="Keep the original source")
        self.assertTrue(result.is_ok(), result)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "compensating")
        self.assertEqual(self.migration.parked_phase, "")
        self.assertEqual(self.events, [])

    def test_activation_never_replays_original_policy_when_current_service_has_changed(self):
        self.phase(
            "activating",
            cutover_committed_at=timezone.now(),
            barrier_state={
                "target_domain_id": "987654321",
                "component_target_activation_enabled": True,
                "component_target_activation_issued": True,
                "component_source_sealed": True,
                "component_target_sealed": True,
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        # fsm-bypass: billing changed the independent Service while activation was interrupted.
        type(self.account.service).objects.filter(pk=self.account.service_id).update(status="suspended")
        self.migration.refresh_from_db()
        actions = []

        def native(_migration, _token, action, *, enabled=None):
            actions.append((action, enabled))
            return {"target_domain_id": "987654321", "phase": "active"}

        with patch("apps.provisioning.component_migration_worker.run_target_operation", side_effect=native):
            self.worker()._activate(self.migration, self.token)
        self.migration.refresh_from_db()
        self.assertEqual(actions, [("target_activate", True), ("target_policy", False)])
        self.assertEqual(self.migration.status, "bridging")
        self.assertTrue(self.migration.barrier_state["component_target_activation_complete"])
        self.assertFalse(self.migration.barrier_state["target_activation"]["enabled"])

    def test_completed_component_cleanup_dispatch_never_enters_whole_source_deletion(self):
        self.phase("completed", cutover_committed_at=timezone.now())
        bridge = MigrationBridge.objects.create(
            migration=self.migration, source_server=self.server, target_server=self.target, domain=self.account.domain
        )
        cleanup = MagicMock(return_value={"action": "torn_down"})
        with (
            patch("apps.provisioning.migration_bridge_cleanup._claim", return_value=(bridge, "claimed")),
            patch("apps.provisioning.migration_bridge_cleanup._guard") as whole_guard,
            patch("apps.provisioning.migration_bridge_cleanup._release"),
            patch.dict(
                "sys.modules",
                {"apps.provisioning.component_bridge_cleanup": SimpleNamespace(cleanup_component_bridge=cleanup)},
            ),
        ):
            from apps.provisioning.migration_bridge_cleanup import cleanup_bridge  # noqa: PLC0415

            self.assertEqual(cleanup_bridge(str(self.migration.pk)), {"action": "torn_down"})
        whole_guard.assert_not_called()
        self.assertEqual(cleanup.call_args.args[0], bridge)

    def committed(self, phase="activating"):
        self.phase(
            phase,
            archive_sha256="a" * 64,
            cutover_committed_at=timezone.now(),
            barrier_state={
                "target_domain_id": "987654321",
                "component_target_receipt_sha256": "b" * 64,
                "component_source_seal_intent": True,
                "component_source_sealed": True,
                "component_target_sealed": True,
                "component_bridge_origin_certificate": "public certificate fixture at native transport boundary",
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        return MigrationBridge.objects.create(
            migration=self.migration,
            source_server=self.server,
            target_server=self.target,
            domain=self.account.domain,
            evidence={"component_source_retained": True},
        )

    def test_committed_worker_activates_bridges_routes_and_completes_without_a_platform_hostname(self):
        bridge = self.committed()
        self.assertEqual(self.migration.pre_migration_snapshot["component_account_name"], "")
        route = {"operation_id": str(self.migration.pk), "action": "source_route", "phase": "routed"}
        frontend = {self.account.domain: {"agreed": True, "ttl": 0}}
        with (
            patch(
                "apps.provisioning.component_migration_worker.run_target_operation",
                return_value={"target_domain_id": "987654321", "phase": "active"},
            ) as target,
            patch("apps.provisioning.component_migration_worker.run_bridge_operation") as native_bridge,
            patch("apps.provisioning.component_migration_worker.run_source_operation", return_value=route) as source,
            patch("apps.provisioning.component_migration_worker.observe_frontends", return_value=(frontend, [])),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup") as schedule,
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.worker().execute(self.migration, self.token)
        self.assertTrue(result.is_ok(), result)
        self.migration.refresh_from_db()
        self.account.refresh_from_db()
        bridge.refresh_from_db()
        self.assertEqual(self.migration.status, "completed")
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(bridge.status, "active")
        self.assertEqual(bridge.evidence["routing"], frontend)
        self.assertEqual(self.migration.barrier_state["component_routing"], route)
        self.assertIsNotNone(self.migration.dns_converged_at)
        self.assertEqual(
            [call.args[2] for call in target.call_args_list],
            ["target_activate", "target_policy", "target_policy", "target_policy"],
        )
        self.assertEqual([call.args[2] for call in native_bridge.call_args_list], ["install", "verify"])
        self.assertEqual([call.args[2] for call in source.call_args_list], ["source_route"])
        schedule.assert_called_once_with(self.migration.pk)
        self.assertEqual(self.events, [])
        self.assertFalse(hasattr(self.migration.component_source_obligation, "release"))

    def test_bridge_verify_failure_keeps_target_and_parks_forward_without_compensation(self):
        self.committed("bridging")
        self.phase(
            "bridging", barrier_state={**self.migration.barrier_state, "component_target_activation_complete": True}
        )

        def native_bridge(_migration, _token, action, **_options):
            if action == "verify":
                raise TimeoutError("Lost public source bridge proof")

        with (
            patch("apps.provisioning.component_migration_worker.run_target_operation"),
            patch("apps.provisioning.component_migration_worker.run_bridge_operation", side_effect=native_bridge),
            patch("apps.provisioning.component_migration_worker.run_source_operation") as source,
        ):
            self.worker().execute(self.migration, self.token)
        self.migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(self.migration.status, "needs_review")
        self.assertEqual(self.migration.parked_phase, "bridging")
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertTrue(self.migration.barrier_state["component_source_sealed"])
        source.assert_not_called()
        self.assertEqual(self.events, [])

    def test_customer_dns_wait_keeps_active_bridge_and_durable_retry(self):
        bridge = self.committed("repointing")
        bridge.activate()
        bridge.save()
        with (
            patch("apps.provisioning.component_migration_worker.run_target_operation"),
            patch(
                "apps.provisioning.component_migration_worker.run_source_operation", return_value={"phase": "routed"}
            ),
            patch(
                "apps.provisioning.component_migration_worker.observe_frontends",
                return_value=(
                    {self.account.domain: {"agreed": False, "ttl": 300}},
                    ["Old customer DNS still reaches source"],
                ),
            ),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake") as wake,
        ):
            self.worker().execute(self.migration, self.token)
        self.migration.refresh_from_db()
        bridge.refresh_from_db()
        self.assertEqual(self.migration.status, "repointing")
        self.assertEqual(self.migration.parked_phase, "")
        self.assertIsNotNone(self.migration.resume_after)
        self.assertEqual(bridge.status, "active")
        self.assertFalse(bridge.evidence["routing"][self.account.domain]["agreed"])
        wake.assert_called_once()

    def test_lost_restore_response_parks_without_removing_target_or_reopening_source(self):
        self.phase("restoring", archive_sha256="a" * 64, barrier_state={"component_source_hold_issued": True})

        def target(_migration, _token, action):
            if action == "target_prepare":
                return {"target_domain_id": "987654321"}
            raise TimeoutError("Lost component restore response")

        with (
            patch("apps.provisioning.component_migration_worker.run_target_operation", side_effect=target) as native,
            patch("apps.provisioning.component_migration_worker.run_source_operation") as source,
        ):
            self.worker().execute(self.migration, self.token)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "needs_review")
        self.assertEqual(self.migration.parked_phase, "restoring")
        self.assertTrue(self.migration.restore_issued)
        self.assertEqual(self.migration.barrier_state["target_domain_id"], "987654321")
        self.assertEqual([call.args[2] for call in native.call_args_list], ["target_prepare", "target_restore"])
        source.assert_not_called()
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_bridge_preparation_preserves_public_receipts_and_frontend_cache_bounds_without_account_name(self):
        self.phase(
            "verifying",
            archive_sha256="a" * 64,
            barrier_state={"target_domain_id": "987654321", "component_target_receipt_sha256": "b" * 64},
        )
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.account.domain)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.account.domain)]), False)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )
        certificate = issue_chain(csr, 30)
        manifest = {
            "identity": str(self.migration.pk),
            "domain": self.account.domain,
            "source": "192.0.2.10",
            "target": "192.0.2.20",
            "account_name": "",
            "origin": "bridge-" + self.migration.pk.hex + ".invalid",
            "vhosts": [
                {
                    "name": self.account.domain,
                    "names": [self.account.domain, "www." + self.account.domain],
                    "port": 80,
                    "neutral": False,
                    "bindings": ["*"],
                    "verify_names": [self.account.domain, "www." + self.account.domain],
                }
            ],
        }
        actions = []

        def native(migration, _token, action, **options):
            current = VirtualminMigration.objects.get(pk=migration.pk)
            actions.append(action)
            self.assertTrue(current.barrier_state["component_bridge_source_prepare_issued"])
            if action == "prepare":
                return manifest
            self.assertTrue(current.barrier_state["component_bridge_origin_issued"])
            self.assertEqual(current.barrier_state["component_bridge_manifest"], manifest)
            if action == "origin_install":
                self.assertEqual(options["manifest"], manifest)
                return certificate
            self.assertEqual(options["origin_certificate"], certificate)
            self.assertEqual(current.barrier_state["component_bridge_origin_certificate"], certificate)
            return None

        with (
            patch("apps.provisioning.component_migration_worker.run_bridge_operation", side_effect=native),
            patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, ttl=600)),
        ):
            self.worker()._prepare_bridge(self.migration, self.token)
        self.migration.refresh_from_db()
        state = self.migration.barrier_state
        self.assertEqual(actions, ["prepare", "origin_install", "origin_verify"])
        self.assertTrue(state["component_bridge_verified"])
        self.assertEqual(state["component_bridge_origin_certificate"], certificate)
        self.assertEqual(state["dns_names"], sorted((self.account.domain, "www." + self.account.domain)))
        self.assertTrue(all(row["ttl"] == 600 for row in state["frontend_dns_before"].values()))
        self.assertNotIn("PRIVATE KEY", str(state))

    def test_changed_held_target_receipt_cannot_prepare_or_seal_bridge(self):
        self.phase("verifying", archive_sha256="a" * 64, barrier_state={"component_target_receipt_sha256": "b" * 64})
        with (
            patch("apps.provisioning.component_migration_worker.run_source_operation"),
            patch(
                "apps.provisioning.component_migration_worker.run_target_operation",
                return_value={"target_receipt_sha256": "c" * 64},
            ),
            patch("apps.provisioning.component_migration_worker.run_bridge_operation") as bridge,
            patch("apps.provisioning.component_migration_worker.commit_component_cutover") as commit,
            self.assertRaisesRegex(ValueError, "changed"),
        ):
            self.worker()._verify(self.migration, self.token)
        bridge.assert_not_called()
        commit.assert_not_called()
