"""Adversarial-review fixes: ambiguity boundaries, capacity truth, stranded recovery."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.models import NodeDeployment
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_forms import VirtualminMigrationForm
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import (
    NodeDrain,
    VirtualminMigration,
    account_has_active_migration,
)
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService, resolve_migration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class MigrationBoundaryTests(MigrationTestBase):
    def _ambiguous_response(self, program: str, side: str) -> Ok[VirtualminResponse]:
        return Ok(
            VirtualminResponse(
                success=False,
                data={"error": "Empty response"},
                raw_response="",
                http_status=200,
                execution_time=0.1,
                program=program,
                server_hostname=self.gateways[side].server_hostname,
            )
        )

    def test_ambiguous_restore_parks_review_without_deletion(self) -> None:
        """An empty 200 body proves nothing; it must never authorize compensation."""
        self.effects[("target", "restore-domain")] = self._ambiguous_response("restore-domain", "target")
        migration = self._start()
        self._run(migration)
        self.assertEqual(migration.status, "needs_review")
        self.assertNotIn("delete-domain", self._programs("target"))
        # The quiesced source must not have been touched by compensation either.
        self.assertNotIn("enable-domain", self._programs("source"))

    def test_external_reenable_before_repoint_parks_review(self) -> None:
        """A writer re-enabling the quiesced source must block completion (split-brain)."""

        def external_writer() -> object:
            response = self.original_calls["target"]("enable-domain", {"domain": self.account.domain})
            self.original_calls["source"]("enable-domain", {"domain": self.account.domain})
            return response

        self.effects[("target", "enable-domain")] = external_writer
        migration = self._start()
        self._run(migration)
        self.assertEqual(migration.status, "needs_review")
        self.assertIn("external writer", migration.error_detail)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_can_host_domain_counts_reservations(self) -> None:
        """Every admission path must see in-flight migrations as occupied capacity."""
        VirtualminServer.objects.filter(pk=self.target.pk).update(max_domains=1, current_domains=0)
        self.target.refresh_from_db()
        self.assertTrue(self.target.can_host_domain())
        VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, reason="manual"
        )
        self.target.refresh_from_db()
        self.assertFalse(self.target.can_host_domain())

    def test_janitor_requeues_stalled_migration_only(self) -> None:
        """A lease-expired non-terminal migration is requeued; needs_review is not."""
        stalled = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, reason="drain"
        )
        # fsm-bypass: fabricate a worker that died mid-fetch with an expired lease.
        VirtualminMigration.objects.filter(pk=stalled.pk).update(
            status="fetching",
            worker_lease_expires_at=timezone.now() - timedelta(minutes=5),
            updated_at=timezone.now() - timedelta(hours=1),
        )
        self.enqueue.reset_mock()
        counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        self.assertEqual(counts["migrations_requeued"], 1)
        self.assertEqual(self.enqueue.call_args.args[1], str(stalled.pk))

        # fsm-bypass: a reviewed row is an operator's queue, not the janitor's.
        VirtualminMigration.objects.filter(pk=stalled.pk).update(status="needs_review")
        self.enqueue.reset_mock()
        counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        self.assertEqual(counts["migrations_requeued"], 0)
        self.enqueue.assert_not_called()

    def test_janitor_redispatches_stale_pending_drain(self) -> None:
        """A drain whose enqueue died between commit and dispatch is re-dispatched."""
        drain = NodeDrain.objects.create(server=self.server)
        NodeDrain.objects.filter(pk=drain.pk).update(updated_at=timezone.now() - timedelta(hours=1))
        with patch.object(NodeDrainService, "_enqueue") as redispatch:
            counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        self.assertEqual(counts["drains_requeued"], 1)
        redispatch.assert_called_once_with(drain.pk, drain.task_token)

    def test_cancel_refused_while_migration_inflight_then_resolves(self) -> None:
        """cancel_drain must not re-admit the server while its account is mid-migration."""
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, reason="drain"
        )
        # fsm-bypass: a drain paused mid-account with the migration parked for review.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review")
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        drain = NodeDrain.objects.create(server=self.server, status="paused_needs_review")
        NodeDrain.objects.filter(pk=drain.pk).update(current_migration=migration)
        drain.refresh_from_db()

        refused = NodeDrainService.cancel_drain(drain)
        self.assertTrue(refused.is_err())
        self.assertIn("in-flight migration", refused.unwrap_err())
        self.server.refresh_from_db()
        self.assertTrue(self.server.is_draining)

        migration.refresh_from_db()
        resolved = resolve_migration(migration, resolved_by=self.staff, note="source re-enabled by hand")
        self.assertTrue(resolved.is_ok(), resolved)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "failed")
        self.assertIn("Manually resolved", migration.error_detail)
        self.assertFalse(account_has_active_migration(self.account))

        cancelled = NodeDrainService.cancel_drain(drain)
        self.assertTrue(cancelled.is_ok(), cancelled)
        self.server.refresh_from_db()
        self.assertFalse(self.server.is_draining)

    def test_auto_health_drain_proceeds_past_its_own_trigger(self) -> None:
        """An auto_health drain exists because the source is unhealthy; it must not pause on that."""
        # fsm-bypass: the health failure that triggered the drain is still live.
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            health_check_error="probe timeout", is_draining=True
        )

        def fake_migrate(drain_row: NodeDrain, account: VirtualminAccount) -> str:
            VirtualminAccount.objects.filter(pk=account.pk).update(server=self.target)
            return ""

        for reason, expect_attempt in (("manual", False), ("auto_health", True)):
            with self.subTest(reason=reason):
                drain = NodeDrain.objects.create(server=self.server, reason=reason, accounts_total=1)
                with patch.object(NodeDrainService, "_migrate", side_effect=fake_migrate) as attempt:
                    result = NodeDrainService.run(drain.pk)
                drain.refresh_from_db()
                status, attempts = drain.status, attempt.call_count
                # fsm-bypass: detach this drain so the next subTest can admit one.
                NodeDrain.objects.filter(pk=drain.pk).update(status="cancelled")
                self.assertTrue(result.is_ok(), result)
                if expect_attempt:
                    self.assertGreater(attempts, 0)
                    self.assertEqual(status, "completed")
                else:
                    self.assertEqual(attempts, 0)
                    self.assertEqual(status, "paused_needs_review")

    def test_explicit_target_respects_placement_tag_policy(self) -> None:
        """Passing a target_server directly must not bypass the tag hard filters."""
        self.settings_values["provisioning.placement_excluded_tags"] = ["decommissioning"]
        VirtualminServer.objects.filter(pk=self.target.pk).update(tags=["decommissioning"])
        self.target.refresh_from_db()
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff
        )
        self.assertTrue(result.is_err(), result)
        self.assertIn("placement tag policy", result.unwrap_err())
        self.assertFalse(VirtualminMigration.objects.exclude(status="failed").exists())

    def test_migration_form_preserves_policy_order(self) -> None:
        """The dropdown must present targets in placement order, not database order."""
        heavy = VirtualminServer.objects.create(
            name="heavyweight",
            hostname="heavyweight.example.com",
            api_username="praho-acl",
            last_health_check=timezone.now(),
            current_domains=5,
            weight=200,
        )
        heavy.set_api_password("heavy-test-password")
        heavy.save()
        template = self.target.node_deployment
        NodeDeployment.objects.create(
            provider=template.provider,
            node_size=template.node_size,
            region=template.region,
            panel_type=template.panel_type,
            hostname="prd-sha-het-de-fsn1-003",
            node_number=3,
            ipv4_address="203.0.113.3",
            virtualmin_server=heavy,
        )
        form = VirtualminMigrationForm(account=self.account)
        ordered = list(form.fields["target_server"].queryset)
        # Strict weight priority: the heavier server leads despite higher load.
        self.assertEqual([server.pk for server in ordered], [heavy.pk, self.target.pk])

    def test_resolve_rejects_non_review_states_and_view_flow(self) -> None:
        """Only needs_review resolves; the staff view drives the same contract."""
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target, reason="manual"
        )
        rejected = resolve_migration(migration, resolved_by=self.staff, note="")
        self.assertTrue(rejected.is_err())
        migration.refresh_from_db()
        self.assertEqual(migration.status, "pending")

        # fsm-bypass: park it for review, then resolve through the staff endpoint.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review")
        self.client.force_login(self.staff)
        url = reverse("provisioning:virtualmin_migration_resolve", args=[self.account.pk])
        response = self.client.post(url, {"note": "target removed manually"})
        self.assertEqual(response.status_code, 302)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "failed")
        self.assertIn(self.staff.email, migration.error_detail)
