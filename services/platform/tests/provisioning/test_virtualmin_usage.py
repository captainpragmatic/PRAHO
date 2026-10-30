"""Usage publication is scoped to the owner and the node collection interval."""

import base64
import importlib.util
import json
from datetime import timedelta
from pathlib import Path
from time import monotonic
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService
from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.service_models import Service
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_usage_models import AccountUsageState, NodeUsageSyncState, UsageInterval, UsageReading
from apps.provisioning.virtualmin_usage_tasks import dispatch_usage_sync, sync_node_usage, transport_identity
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class UsagePublicationTests(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.usage = usage
        self.settings_values["provisioning.usage_sync_enabled"] = True
        self.state = usage.current_state(self.account)

    def payload(self):
        now = timezone.now()
        return {
            "version": 1,
            "installation": str(uuid4()),
            "observed_at": now.isoformat(),
            "records": [
                {
                    "domain": self.account.domain,
                    "username": self.account.virtualmin_username,
                    "domain_id": "12345",
                    "scan_started_at": now.isoformat(),
                    "scan_finished_at": now.isoformat(),
                    "disk_files_bytes": 300 * 1024**2,
                    "disk_db_bytes": 20 * 1024**2,
                    "databases": 1,
                    "mailboxes": 0,
                    "segments": [],
                }
            ],
        }

    def test_reading_updates_account_and_service_together_without_metering(self):
        payload = self.payload()
        with patch("apps.billing.metering_service.MeteringService.record_event") as meter:
            self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.account.refresh_from_db()
        self.account.service.refresh_from_db()
        self.assertEqual(self.account.current_disk_usage_mb, 320)
        self.assertEqual(self.account.service.disk_usage_mb, 320)
        self.assertEqual(self.account.service.databases_used, 1)
        meter.assert_not_called()
        public = self.usage.public_usage(self.account.service)
        self.assertEqual(public["disk_usage_gb"], 0.31)
        self.assertIsNone(public["bandwidth_usage_gb"])

    def test_restore_finished_before_poll_rejects_cached_gauge(self):
        payload = self.payload()
        self.state.gauge_not_before = timezone.now() + timedelta(seconds=1)
        self.state.save(update_fields=["gauge_not_before"])
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.assertIsNone(self.usage.public_usage(self.account.service)["disk_usage_gb"])

    def test_invalid_record_never_becomes_zero(self):
        payload = self.payload()
        payload["records"][0]["disk_files_bytes"] = True
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.assertIsNone(self.usage.public_usage(self.account.service)["disk_usage_gb"])

    def test_failed_poll_preserves_last_good_source_time(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        before = self.usage.public_usage(self.account.service)
        self.usage.record_failure(self.server.pk, "unavailable")
        after = self.usage.public_usage(self.account.service)
        self.assertEqual(after["disk_usage_gb"], before["disk_usage_gb"])
        self.assertEqual(after["usage_as_of"], before["usage_as_of"])
        self.assertEqual(after["usage_state"], "stale")

    def test_old_poll_cannot_publish_after_new_owner_scope(self):
        captured = self.usage.capture(self.server)
        self.usage.reset_owner_scope(self.account.pk)
        self.usage.publish_snapshot(self.server.pk, self.payload(), captured)
        self.assertIsNone(self.usage.public_usage(self.account.service)["disk_usage_gb"])

    def test_real_failed_restore_terminal_write_invalidates_cached_scan(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="restore_domain", status="running"
        )
        job.mark_failed("Restore failed after writing files")
        self.state.refresh_from_db()
        self.assertGreater(self.state.gauge_not_before, usage.timestamp(payload["records"][0]["scan_started_at"]))
        self.assertIsNone(self.state.disk_reading_id)
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.assertIsNone(self.usage.public_usage(self.account.service)["disk_usage_gb"])

    def test_verified_recreation_on_same_node_accepts_new_native_id_once(self):
        first = self.payload()
        self.usage.publish_snapshot(self.server.pk, first, self.usage.capture(self.server))
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="create_domain", status="running"
        )
        job.mark_completed({"success": True})
        self.state.refresh_from_db()
        self.assertEqual(self.state.domain_id, "")
        new_payload = self.payload()
        new_payload["installation"] = first["installation"]
        new_payload["records"][0]["domain_id"] = "67890"
        # The node retains the old identity for final source intervals.
        new_payload["records"].append({**first["records"][0], "present": False})
        self.assertEqual(self.usage.publish_snapshot(self.server.pk, new_payload, self.usage.capture(self.server)), 1)
        current_interval = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
        job.mark_completed({"success": True})
        self.assertEqual(UsageInterval.objects.get(account=self.account, ended_at__isnull=True).pk, current_interval.pk)

    def test_cached_old_identity_cannot_rebind_between_recreation_and_fresh_scan(self):
        old = self.payload()
        self.usage.publish_snapshot(self.server.pk, old, self.usage.capture(self.server))
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="create_domain", status="running"
        )
        job.mark_completed({"success": True})
        stale = {**old, "observed_at": timezone.now().isoformat()}
        stale["records"][0]["identity_observed_at"] = old["records"][0]["scan_started_at"]
        self.usage.publish_snapshot(self.server.pk, stale, self.usage.capture(self.server))
        self.state.refresh_from_db()
        self.assertEqual(self.state.domain_id, "")
        fresh = self.payload()
        fresh["installation"] = old["installation"]
        fresh["records"][0]["domain_id"] = "67890"
        self.assertEqual(self.usage.publish_snapshot(self.server.pk, fresh, self.usage.capture(self.server)), 1)
        self.state.refresh_from_db()
        self.assertEqual(self.state.domain_id, "67890")

    def bandwidth_payload(self, installation, *, known_owner=True):
        if known_owner:
            self.state.owner_start_known = True
            self.state.save(update_fields=["owner_start_known"])
        payload = self.payload()
        payload["installation"] = installation
        interval = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
        payload["records"][0]["segments"] = [
            {
                "id": str(interval.pk),
                "start": interval.started_at.isoformat(),
                "end": payload["observed_at"],
                "bytes": 123456789,
                "complete": True,
            }
        ]
        return payload

    def test_expired_poll_cannot_publish_bandwidth(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        claim = NodeUsageSyncState.objects.create(
            server=self.server, token=uuid4(), lease_until=timezone.now() - timedelta(seconds=1)
        )
        self.usage.publish_snapshot(
            self.server.pk,
            self.bandwidth_payload(payload["installation"]),
            self.usage.capture(self.server),
            token=claim.token,
        )
        self.state.refresh_from_db()
        self.assertIsNone(self.state.bandwidth_reading_id)
        self.assertEqual(UsageInterval.objects.get(account=self.account).totals, {})

    def test_bandwidth_is_independent_of_disk_scan_validity(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        bandwidth = self.bandwidth_payload(payload["installation"])
        bandwidth["records"][0]["disk_files_bytes"] = None
        self.state.disk_reading = None
        self.state.save(update_fields=["disk_reading"])
        self.usage.publish_snapshot(self.server.pk, bandwidth, self.usage.capture(self.server))
        public = self.usage.public_usage(self.account.service)
        self.assertIsNone(public["disk_usage_gb"])
        self.assertEqual(public["bandwidth_usage_gb"], round(123456789 / 1024**3, 2))
        self.assertTrue(public["bandwidth_complete"])

    def test_wrong_installation_cannot_add_source_bytes(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.usage.publish_snapshot(
            self.server.pk, self.bandwidth_payload(str(uuid4())), self.usage.capture(self.server)
        )
        self.assertIsNone(self.usage.public_usage(self.account.service)["bandwidth_usage_gb"])

    def test_existing_account_first_month_remains_partial(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.usage.publish_snapshot(
            self.server.pk,
            self.bandwidth_payload(payload["installation"], known_owner=False),
            self.usage.capture(self.server),
        )
        self.assertFalse(self.usage.public_usage(self.service)["bandwidth_complete"])
        self.assertIsNone(self.usage.public_usage(self.service)["bandwidth_usage_gb"])

    def test_transfer_before_first_poll_records_the_actual_new_owner_boundary(self):
        UsageInterval.objects.filter(account=self.account).delete()
        self.state.delete()
        other = Customer.objects.create(name="New before polling", primary_email="new-before-poll@example.net")
        Service.objects.filter(pk=self.service.pk).update(customer=other)
        state = self.usage.current_state(self.account)
        self.assertTrue(state.owner_start_known)
        self.assertEqual(state.customer_id_snapshot, other.pk)
        self.assertEqual(
            UsageInterval.objects.get(account=self.account, ended_at__isnull=True).started_at, state.owner_started_at
        )

    def test_transfer_then_move_without_poll_retains_new_owners_source_interval(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        other = Customer.objects.create(name="Transfer before move", primary_email="transfer-move@example.net")
        Service.objects.filter(pk=self.service.pk).update(customer=other)
        self.state.refresh_from_db()
        transfer_start = self.state.owner_started_at
        self.usage.move_interval(self.account.pk, self.target.pk)
        parts = list(
            UsageInterval.objects.filter(account=self.account, owner_scope=self.state.owner_scope).order_by(
                "started_at"
            )
        )
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0].started_at, transfer_start)
        self.assertEqual(parts[0].ended_at, parts[1].started_at)
        self.assertEqual(parts[0].server_id, self.server.pk)
        self.assertEqual(parts[0].domain_id, "12345")

    def test_move_preserves_prefix_but_missing_final_source_is_partial(self):
        payload = self.payload()
        self.usage.publish_snapshot(self.server.pk, payload, self.usage.capture(self.server))
        self.usage.publish_snapshot(
            self.server.pk, self.bandwidth_payload(payload["installation"]), self.usage.capture(self.server)
        )
        self.assertTrue(self.usage.public_usage(self.service)["bandwidth_complete"])
        self.usage.move_interval(self.account.pk, self.target.pk)
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.state.refresh_from_db()
        self.assertIsNotNone(self.state.bandwidth_reading_id)
        public = self.usage.public_usage(self.service)
        self.assertFalse(public["bandwidth_complete"])
        self.assertEqual(public["bandwidth_state"], "partial")

    def test_duplicate_worker_delivery_performs_one_export(self):
        token = uuid4()
        NodeUsageSyncState.objects.create(
            server=self.server,
            token=token,
            lease_until=timezone.now() + timedelta(seconds=330),
            input_identity=transport_identity(self.server),
        )
        with patch(
            "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook",
            return_value=Err("Node is offline"),
        ) as export:
            self.assertEqual(sync_node_usage(str(self.server.pk), str(token))["state"], "unavailable")
            self.assertEqual(sync_node_usage(str(self.server.pk), str(token))["state"], "superseded")
        export.assert_called_once()

    def test_200_account_batch_publication_stays_under_30_seconds(self):
        for number in range(199):
            service = Service.objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.currency,
                service_name=f"Usage {number}",
                domain=f"usage{number}.example.net",
                username=f"usage{number}",
                price=self.service.price,
                status="active",
            )
            type(self.account).objects.create(
                service=service,
                server=self.server,
                domain=service.domain,
                virtualmin_username=service.username,
                status="active",
            )
        before = monotonic()
        captures = self.usage.capture(self.server)
        payload = self.payload()
        template = payload["records"][0]
        payload["records"] = [
            {**template, "domain": account.domain, "username": account.virtualmin_username, "domain_id": str(index + 1)}
            for index, account in enumerate(type(self.account).objects.filter(server=self.server))
        ]
        count = self.usage.publish_snapshot(self.server.pk, payload, captures)
        self.assertEqual(count, 200)
        self.assertEqual(UsageReading.objects.count(), 200)
        self.assertLess(monotonic() - before, 30)

    def test_terminal_migration_rejects_scan_collected_before_completion(self):
        migration = self._start()
        payload = self.payload()
        completed = self._run(migration)
        self.assertEqual(completed.status, "completed")
        self.state.refresh_from_db()
        self.assertGreater(self.state.gauge_not_before, usage.timestamp(payload["records"][0]["scan_started_at"]))
        self.assertIsNone(self.state.disk_reading_id)

    def test_hourly_task_accepts_cached_export_clipped_to_its_real_source_time(self):
        source = Path(__file__).resolve().parents[2] / "infrastructure/ansible/playbooks/files/praho_usage.py"
        spec = importlib.util.spec_from_file_location("usage_task_fixture", source)
        node = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(node)
        ledger = node.Ledger(Path(self.spool.name) / "task-ledger.sqlite3")
        self.addCleanup(ledger.close)
        observed = timezone.now() - timedelta(minutes=10)
        start = observed - timedelta(minutes=10)
        self.state.owner_started_at, self.state.gauge_not_before = start, start
        self.state.owner_start_known = True
        self.state.save()
        UsageInterval.objects.filter(account=self.account).update(started_at=start)
        installation = str(uuid4())
        node.STATE_ROOT = Path(self.spool.name)
        (node.STATE_ROOT / "bindings.json").write_text(
            json.dumps(
                {
                    "installation": installation,
                    "accounts": {"12345": {"verified": True, "started_at": start.isoformat()}},
                }
            )
        )
        payload = self.payload()
        row = payload["records"][0]
        row.update(
            scan_started_at=observed.isoformat(),
            scan_finished_at=observed.isoformat(),
            binding_verified=True,
            binding_started_at=start.isoformat(),
        )
        with ledger.connection:
            ledger.store("observed_at", observed.isoformat())
            ledger.store("coverage_start", start.isoformat())
            ledger.store("caught_up", "1")
            ledger.store("inventory_epoch", str(node.epoch_us(observed.isoformat())))
            ledger.connection.execute(
                "INSERT INTO inventory VALUES (?,?)", (row["domain_id"], node.epoch_us(observed.isoformat()))
            )
            ledger.connection.execute("INSERT INTO gauges VALUES (?,?)", (row["domain_id"], json.dumps(row)))
            ledger.connection.execute(
                "INSERT INTO traffic VALUES (?,?,?,?)",
                (installation, row["domain_id"], node.epoch_us((observed - timedelta(seconds=1)).isoformat()), 9876543),
            )

        def export(server, playbook, variables, **kwargs):
            self.assertEqual(playbook, "virtualmin_usage_read.yml")
            snapshot = node.export_snapshot(ledger, installation, variables["usage_request"])
            encoded = base64.b64encode(json.dumps(snapshot).encode()).decode()
            return Ok(AnsibleResult(True, playbook, "PRAHO_USAGE_SNAPSHOT=" + encoded, "", 0))

        token = uuid4()
        NodeUsageSyncState.objects.create(
            server=self.server,
            token=token,
            lease_until=timezone.now() + timedelta(seconds=330),
            input_identity=transport_identity(self.server),
        )
        with patch(
            "apps.infrastructure.ansible_service.AnsibleService.run_server_playbook", side_effect=export
        ) as transport:
            result = sync_node_usage(str(self.server.pk), str(token))
        self.assertEqual(result["state"], "ok")
        transport.assert_called_once()
        public = usage.public_usage(self.service)
        self.assertEqual(public["usage_as_of"], observed.isoformat())
        self.assertEqual(public["bandwidth_as_of"], observed.isoformat())
        self.assertEqual(public["bandwidth_usage_gb"], round(9876543 / 1024**3, 2))

    def test_history_does_not_cross_owner_scopes(self):
        self.usage.publish_snapshot(self.server.pk, self.payload(), self.usage.capture(self.server))
        self.assertEqual(len(self.usage.usage_history(self.account.service)["disk_usage_trend"]), 1)
        self.usage.reset_owner_scope(self.account.pk)
        self.assertEqual(self.usage.usage_history(self.account.service)["disk_usage_trend"], [])
        self.assertEqual(UsageReading.objects.filter(account=self.account).count(), 1)

    def test_duplicate_attempt_is_idempotent(self):
        payload, token = self.payload(), uuid4()
        NodeUsageSyncState.objects.create(
            server=self.server,
            token=token,
            lease_until=timezone.now() + timedelta(seconds=330),
            input_identity=transport_identity(self.server),
        )
        captured = self.usage.capture(self.server)
        self.assertEqual(self.usage.publish_snapshot(self.server.pk, payload, captured, token=token), 1)
        self.assertEqual(self.usage.publish_snapshot(self.server.pk, payload, captured, token=token), 0)
        self.assertEqual(UsageReading.objects.filter(account=self.account).count(), 1)

    def test_transfer_committed_while_waiting_for_the_account_lock_resets_the_owner_once(self):
        # On PostgreSQL a waited FOR UPDATE OF self re-reads only the account row: columns joined in
        # the same statement keep their pre-wait values. Commit the transfer right after that
        # statement, as a transfer holding the lock would, so anything it read with it is stale.
        other = Customer.objects.create(name="Owner during wait", primary_email="owner-during-wait@example.net")
        after_transfer = {}

        def transfer_after_lock(execute, sql, params, many, context):
            result = execute(sql, params, many, context)
            if not after_transfer and 'FROM "provisioning_virtualmin_accounts"' in sql:
                after_transfer["scope"] = None
                Service.objects.filter(pk=self.service.pk).update(customer=other)
                after_transfer["scope"] = AccountUsageState.objects.get(account=self.account).owner_scope
            return result

        with connection.execute_wrapper(transfer_after_lock):
            state = self.usage.current_state(self.account)
        self.assertIsNotNone(after_transfer["scope"])
        self.assertEqual(state.owner_scope, after_transfer["scope"])
        self.assertEqual(state.customer_id_snapshot, other.pk)
        self.assertEqual(UsageInterval.objects.filter(account=self.account, owner_scope=state.owner_scope).count(), 1)

    def test_capture_of_a_transfer_after_the_candidate_query_is_consistent(self):
        # The transfer commits after capture() listed its accounts and before it locked this one: the
        # capture must describe the locked state, owner included, or publication silently skips it.
        other = Customer.objects.create(name="Owner after listing", primary_email="owner-after-listing@example.net")
        moved = []

        def transfer_after_listing(execute, sql, params, many, context):
            result = execute(sql, params, many, context)
            if not moved and 'FROM "provisioning_virtualmin_accounts"' in sql and '"provisioning_usage_interval"' in sql:
                moved.append(sql)
                Service.objects.filter(pk=self.service.pk).update(customer=other)
            return result

        with connection.execute_wrapper(transfer_after_listing):
            captured = self.usage.capture(self.server)
        self.assertTrue(moved)
        state = AccountUsageState.objects.get(account=self.account)
        self.assertEqual(
            captured[self.account.pk],
            usage.AccountCapture(state.owner_scope, self.service.pk, other.pk, self.account.chain_epoch),
        )

    def test_customer_a_b_a_never_resurrects_original_history_through_bulk_writers(self):
        self.usage.publish_snapshot(self.server.pk, self.payload(), self.usage.capture(self.server))
        original_scope = self.state.owner_scope
        other = Customer.objects.create(name="Other owner", primary_email="other-usage@example.net")
        Service.objects.filter(pk=self.service.pk).update(customer=other)
        self.state.refresh_from_db()
        middle_scope = self.state.owner_scope
        self.assertNotEqual(original_scope, middle_scope)
        self.service.refresh_from_db()
        self.service.customer = self.customer
        Service.objects.bulk_update([self.service], ["customer"])
        self.state.refresh_from_db()
        self.assertNotIn(self.state.owner_scope, (original_scope, middle_scope))
        self.assertEqual(self.usage.usage_history(self.service)["disk_usage_trend"], [])
        self.assertIsNone(self.usage.public_usage(self.service)["disk_usage_gb"])

    def test_move_closes_canonical_interval_and_invalidates_source_binding(self):
        self.usage.publish_snapshot(self.server.pk, self.payload(), self.usage.capture(self.server))
        source = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
        self.usage.move_interval(self.account.pk, self.target.pk)
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.state.refresh_from_db()
        source.refresh_from_db()
        target = UsageInterval.objects.get(account=self.account, ended_at__isnull=True)
        self.assertEqual(source.ended_at, target.started_at)
        self.assertEqual(source.server_id, self.server.pk)
        self.assertEqual(target.server_id, self.target.pk)
        self.assertEqual(source.domain_id, "12345")
        self.assertEqual(self.state.domain_id, "")
        self.assertIsNone(self.state.disk_reading_id)


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class UsageApiTests(HMACTestMixin, MigrationTestBase):
    payload = UsagePublicationTests.payload

    def setUp(self):
        super().setUp()
        self.usage = usage
        self.settings_values["provisioning.usage_sync_enabled"] = True
        self.user = User.objects.create_user(email="usage-owner@example.net", password="usage-owner-test")
        CustomerMembership.objects.create(customer=self.customer, user=self.user, role="owner")
        usage.current_state(self.account)
        self.path = f"/api/services/{self.service.pk}/usage/"
        self.identity = {"user_id": self.user.pk, "customer_id": self.customer.pk, "action": "get_usage_stats"}

    def test_signed_portal_usage_is_unknown_before_first_reading_and_never_fakes_uptime(self):
        response = self.portal_post(self.path, self.identity)
        self.assertEqual(response.status_code, 200, response.content)
        value = response.json()["data"]["usage"]
        self.assertIsNone(value["current_usage"]["disk_usage_gb"])
        self.assertEqual(value["current_usage"]["usage_state"], "unknown")
        self.assertIsNone(value["historical_usage"]["uptime_percentage"])

    def test_real_reading_fires_existing_80_percent_warning_and_has_source_time_and_history(self):
        self.plan.disk_space_gb = 1
        self.plan.save(update_fields=["disk_space_gb"])
        payload = self.payload()
        payload["records"][0].update(disk_files_bytes=850 * 1024**2, disk_db_bytes=21 * 1024**2)
        usage.publish_snapshot(self.server.pk, payload, usage.capture(self.server))
        response = self.portal_post(self.path, self.identity)
        self.assertEqual(response.status_code, 200, response.content)
        value = response.json()["data"]["usage"]
        self.assertGreater(value["current_usage"]["disk_usage_percentage"], 85)
        self.assertEqual(value["current_usage"]["usage_as_of"], payload["records"][0]["scan_finished_at"])
        self.assertEqual([alert["resource"] for alert in value["alerts"]], ["disk"])
        self.assertEqual(len(value["historical_usage"]["disk_usage_trend"]), 1)
        self.assertNotIn("installation", str(value))

    def test_signed_request_cannot_read_another_owners_history(self):
        other = Customer.objects.create(name="Foreign owner")
        response = self.portal_post(self.path, {**self.identity, "customer_id": other.pk})
        self.assertEqual(response.status_code, 403, response.content)

    def test_other_provider_keeps_its_usage_and_warning_when_virtualmin_is_enabled(self):
        self.plan.disk_space_gb = 1
        self.plan.save(update_fields=["disk_space_gb"])
        other = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="External",
            domain="external.example.net",
            username="external",
            price=self.service.price,
            status="active",
            disk_usage_mb=871,
            bandwidth_usage_mb=456,
        )
        response = self.portal_post(f"/api/services/{other.pk}/usage/", self.identity)
        self.assertEqual(response.status_code, 200, response.content)
        value = response.json()["data"]["usage"]
        self.assertEqual(value["current_usage"]["disk_usage_gb"], round(871 / 1024, 2))
        self.assertEqual([item["resource"] for item in value["alerts"]], ["disk"])
        from apps.api.services.serializers import ServiceListSerializer  # noqa: PLC0415

        self.assertEqual(ServiceListSerializer(other).data["bandwidth_usage_gb"], round(456 / 1024, 2))


class UsageEnablementTests(TestCase):
    def test_setting_gates_real_dispatch_without_discarding_existing_readings(self):
        VirtualminServer.objects.create(name="Usage gate", hostname="usage-gate.example.net", status="active")
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("provisioning.usage_sync_enabled", False).is_ok())
        with patch("apps.provisioning.virtualmin_usage_tasks.async_task") as queue:
            self.assertFalse(usage.enabled())
            self.assertEqual(dispatch_usage_sync(), {"queued": 0})
            queue.assert_not_called()
            with self.captureOnCommitCallbacks(execute=True):
                self.assertTrue(SettingsService.update_setting("provisioning.usage_sync_enabled", True).is_ok())
            self.assertTrue(usage.enabled())
            self.assertEqual(dispatch_usage_sync(), {"queued": 1})
            queue.assert_called_once()


class UsageTransportPolicyTests(SimpleTestCase):
    def test_cached_read_is_allowed_but_never_runs_as_a_deployment_step(self):
        transport = AnsibleService.__new__(AnsibleService)
        transport.timeout = 30
        transport._ssh_manager = Mock()
        transport._ssh_manager.get_private_key_file.return_value = Err("Key deliberately unavailable")
        result = transport.run_playbook(
            SimpleNamespace(ipv4_address="192.0.2.10", ssh_host_keys="enrolled"), "virtualmin_usage_read.yml"
        )
        self.assertTrue(result.is_err())
        self.assertIn("enrolled authentication key", result.unwrap_err())
        transport._ssh_manager.get_private_key_file.assert_called_once()
        self.assertNotIn("virtualmin_usage_read.yml", AnsibleService.PANEL_PLAYBOOKS["virtualmin"])

    def test_usage_read_never_bootstraps_trust_or_recovers_a_different_port(self):
        transport = AnsibleService.__new__(AnsibleService)
        transport.timeout = 30
        transport._ssh_manager = Mock()
        deployment = SimpleNamespace(ipv4_address="192.0.2.10", ssh_host_keys=None, ssh_port=20322)
        self.assertIn(
            "enrolled SSH host trust", transport.run_playbook(deployment, "virtualmin_usage_read.yml").unwrap_err()
        )
        transport._ssh_manager.get_private_key_file.assert_not_called()
        deployment.ssh_host_keys = "enrolled"
        transport._ssh_manager.get_private_key_file.return_value = Ok(Path("/private/tmp/usage-test-key"))
        transport._wait_for_ssh = Mock(return_value=Err("Node is offline"))
        transport._scan_host_key = Mock()
        with (
            patch(
                "apps.infrastructure.ansible_service.trusted_node_known_hosts",
                return_value=Path("/private/tmp/usage-test-trust"),
            ),
            patch("apps.infrastructure.ansible_service.recover_connection_port") as recover,
        ):
            self.assertEqual(
                transport.run_playbook(deployment, "virtualmin_usage_read.yml").unwrap_err(), "Node is offline"
            )
        recover.assert_not_called()
        transport._wait_for_ssh.assert_called_once_with(deployment.ipv4_address, port=20322, timeout=10)
        transport._scan_host_key.assert_not_called()
