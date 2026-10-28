"""Provider outcomes are recoverable checkpoints; uncertainty never exposes a nameserver switch."""

import time
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

from django.db import transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

import apps.domains.dns_zone_tasks as tasks
from apps.common.types import Err, Ok, Retriability
from apps.domains import dns_zone_deletion as deletion
from apps.domains import dns_zone_services as zones
from apps.domains.dns_zone_models import HostedZone, HostedZoneOperation
from apps.domains.models import TLD, Domain, Registrar
from apps.infrastructure.dns_zone_gateway import (
    DnssecStatus,
    ProviderZoneRecord,
    ZoneBinding,
    ZoneIdentity,
    ZoneInventory,
)
from apps.settings.services import SettingsService
from tests.domains.test_dns_zone_import_service import UPLOAD, hosting_fixture


class Provider:
    def __init__(self):
        self.identity = ZoneIdentity(
            ZoneBinding("cloudflare", "a" * 32, "b" * 32, "customer.example.net"),
            "pending",
            ("ns.cloudflare.example", "ns2.cloudflare.example"),
        )
        self.records = {}
        self.calls = []
        self.preexisting = False
        self.ambiguous_zone = False
        self.ambiguous_record = False
        self.apply_ambiguous_record = True
        self.next_identifier = 1
        self.ambiguous_delete = False
        self.rejected_record = False

    def list_zones(self, account_id, name):
        self.calls.append("list_zones")
        return Ok((self.identity,) if self.preexisting else ())

    def create_zone(self, account_id, name):
        self.calls.append("create_zone")
        if self.ambiguous_zone:
            return Err("lost create response", retriability=Retriability.UNKNOWN)
        return Ok(self.identity)

    def read_zone(self, binding):
        self.calls.append("read_zone")
        assert binding == self.identity.binding
        return Ok(self.identity)

    def list_records(self, binding):
        self.calls.append("list_records")
        return Ok(ZoneInventory(self.identity, tuple(self.records.values())))

    def create_record(self, binding, spec):
        self.calls.append(("create_record", spec.local_id))
        if self.rejected_record:
            self.rejected_record = False
            return Err("definite refusal", retriability=Retriability.NOT_RETRIABLE)
        value = ProviderZoneRecord(f"{self.next_identifier:032x}", spec)
        self.next_identifier += 1
        if self.ambiguous_record:
            self.ambiguous_record = False
            if self.apply_ambiguous_record:
                self.records[value.id] = value
            return Err("lost record response", retriability=Retriability.UNKNOWN)
        self.records[value.id] = value
        return Ok(value)

    def update_record(self, binding, identifier, spec):
        self.calls.append(("update_record", identifier))
        value = ProviderZoneRecord(identifier, spec)
        self.records[identifier] = value
        return Ok(value)

    def delete_record(self, binding, identifier, *, expected_owner_tag):
        self.calls.append(("delete_record", identifier))
        if identifier in self.records:
            assert self.records[identifier].spec.owner_tag == expected_owner_tag
            del self.records[identifier]
        return Ok(None)

    def trigger_activation(self, binding):
        self.calls.append("trigger_activation")
        return Ok(None)

    def get_dnssec(self, binding):
        self.calls.append("get_dnssec")
        return Ok(DnssecStatus("disabled"))

    def delete_zone(self, binding, *, expected_records=None):
        self.calls.append("delete_zone")
        if expected_records is not None and set(expected_records) != {row.spec for row in self.records.values()}:
            return Err("record inventory drift", retriability=Retriability.NOT_RETRIABLE)
        if self.ambiguous_delete:
            self.ambiguous_delete = False
            return Err("lost delete response", retriability=Retriability.UNKNOWN)
        self.records.clear()
        return Ok(None)


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneWorkerTests(TransactionTestCase):
    def setUp(self):
        self.account, self.hostname, self.actor = hosting_fixture()
        SettingsService.update_setting("dns.cloudflare_account_id", "a" * 32).unwrap()
        self.provider = Provider()
        patch.object(zones, "_audit").start()
        patch.object(tasks, "_enqueue").start()
        patch.object(tasks, "get_zone_gateway", return_value=self.provider).start()
        patch(
            "apps.domains.dns_zone_checks.probe_provider_batch",
            return_value={"ok": True, "complete": True, "cursor": 100},
        ).start()
        self.handover = patch(
            "apps.domains.dns_zone_checks.handover_snapshot",
            return_value={
                "state": "verified",
                "nameservers": ["ns.old.example"],
                "ds": [],
                "ds_ttl": 0,
                "ns_ttl": 300,
                "checked_at": timezone.now().isoformat(),
            },
        ).start()
        self.addCleanup(patch.stopall)
        self.revision = zones.preview_zone_import(self.account, UPLOAD, actor=self.actor).unwrap()
        self.revision.crosscheck = {"complete": True, "ok": True, "checked_at": timezone.now().isoformat(), "ds_ttl": 0}
        self.revision.save(update_fields=["crosscheck"])
        self.zone = zones.confirm_import(
            self.revision.zone, self.revision.number, self.revision.manifest_digest, actor=self.actor
        ).unwrap()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone)

    def tick(self):
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(next_attempt_at=timezone.now())
        return tasks.advance_zone_operation(str(self.operation.pk))

    def finish_apply(self):
        for _ in range(100):
            outcome = self.tick()
            self.operation.refresh_from_db()
            if self.operation.status in {"completed", "parked", "failed"}:
                return outcome
        raise AssertionError("A small confirmed inventory failed to reach a bounded checkpoint")

    def test_complete_import_is_read_back_and_proven_before_nameservers_are_available(self):
        result = self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual(self.operation.status, "completed", result)
        self.assertEqual(self.zone.status, "awaiting_ns")
        self.assertEqual(
            zones.cached_zone_status(self.zone)["nameservers"], ["ns.cloudflare.example", "ns2.cloudflare.example"]
        )
        self.assertEqual(len(self.provider.records), len(self.revision.manifest))
        self.assertEqual(self.provider.calls.count("create_zone"), 1)
        self.assertGreaterEqual(self.provider.calls.count("list_records"), 2)

    def test_provider_account_setting_excludes_unconfigured_work_and_selects_the_actual_account(self):
        SettingsService.update_setting("dns.cloudflare_account_id", "").unwrap()
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(self.operation.last_error, "zone_provider_not_configured")
        self.assertEqual(self.provider.calls, [])

        SettingsService.update_setting("dns.cloudflare_account_id", "c" * 32).unwrap()
        zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        token = tasks._claim(self.operation.pk)
        self.assertIsNotNone(token)
        with patch.object(self.provider, "list_zones", wraps=self.provider.list_zones) as listed:
            self.assertEqual(tasks._preflight(self.operation.pk, token), 0)
        listed.assert_called_once_with("c" * 32, self.zone.name)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "create_zone")
        self.assertEqual(self.operation.evidence["provider_account_id"], "c" * 32)

    def test_preexisting_zone_is_not_adopted_or_mutated(self):
        self.provider.preexisting = True
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertNotIn("create_zone", self.provider.calls)
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])

    def test_expired_source_proof_is_refreshed_before_any_provider_creation(self):
        self.revision.crosscheck["checked_at"] = (timezone.now() - timedelta(hours=2)).isoformat()
        self.revision.save(update_fields=["crosscheck"])
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "refresh_source")
        self.assertEqual(self.provider.calls, [])
        with patch(
            "apps.domains.dns_zone_checks.probe_import_batch",
            return_value={
                "ok": True,
                "complete": True,
                "cursor": 100,
                "checked_at": timezone.now().isoformat(),
                "observations": {},
                "ds_ttl": 0,
            },
        ) as refresh:
            self.tick()
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.args[1], self.revision.inventory)
        self.assertEqual(self.finish_apply()["action"], "completed")

    def test_source_drift_discovered_after_provider_publish_parks_without_nameserver_instructions(self):
        for _ in range(100):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.phase == "handover":
                break
        self.revision.crosscheck["checked_at"] = (timezone.now() - timedelta(hours=2)).isoformat()
        self.revision.save(update_fields=["crosscheck"])
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "refresh_source")
        with patch(
            "apps.domains.dns_zone_checks.probe_import_batch",
            return_value={
                "ok": False,
                "complete": False,
                "cursor": 0,
                "checked_at": timezone.now().isoformat(),
                "error": "source_record_missing_from_inventory",
            },
        ):
            self.tick()
        self.operation.refresh_from_db()
        self.revision.refresh_from_db()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])
        self.assertEqual(self.revision.raw_upload, UPLOAD)

    def test_ambiguous_zone_creation_parks_without_a_second_post_or_adoption(self):
        self.provider.ambiguous_zone = True
        self.finish_apply()
        self.tick()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(self.provider.calls.count("create_zone"), 1)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.provider_zone_id, "")

    def test_lost_record_response_is_recovered_only_from_its_positive_uuid_ownership(self):
        self.provider.ambiguous_record = True
        result = self.finish_apply()
        self.assertEqual(self.operation.status, "completed", result)
        creates = [call for call in self.provider.calls if isinstance(call, tuple) and call[0] == "create_record"]
        self.assertEqual(len({call[1] for call in creates}), len(creates))

    def test_absent_ambiguous_record_is_parked_without_a_blind_retry(self):
        self.provider.ambiguous_record = True
        self.provider.apply_ambiguous_record = False
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(len([call for call in self.provider.calls if isinstance(call, tuple)]), 1)

    def test_explicit_retry_of_a_definitively_rejected_record_uses_the_known_safe_phase(self):
        self.provider.rejected_record = True
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(self.operation.phase, "inventory")
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        self.assertEqual(self.finish_apply()["action"], "completed")

    def test_a_completed_apply_retry_clears_the_parked_zone_error(self):
        self.provider.rejected_record = True
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual((self.zone.status, self.zone.last_error), ("failed", "record_create_unconfirmed"))
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        self.assertEqual(self.finish_apply()["action"], "completed")
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "awaiting_ns")
        self.assertEqual(self.zone.last_error, "")

    def park_activation(self):
        """Apply, then park the follow-up activation poll on a definite provider refusal."""
        self.finish_apply()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="waiting")
        refused = Err("definite refusal", retriability=Retriability.NOT_RETRIABLE)
        with patch.object(self.provider, "read_zone", return_value=refused):
            self.tick()
        self.operation.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual((self.zone.status, self.zone.last_error), ("failed", "activation_status_unproven"))
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()

    def poll_activation(self):
        for _ in range(30):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.status != "waiting":
                break
        self.zone.refresh_from_db()

    def test_a_successful_activation_retry_activates_the_failed_zone_and_clears_its_error(self):
        self.park_activation()
        self.provider.identity = replace(self.provider.identity, status="active")
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }
        self.poll_activation()
        self.assertEqual(self.operation.status, "completed")
        self.assertEqual(self.zone.status, "active")
        self.assertEqual(self.zone.last_error, "")
        self.assertTrue(self.zone.activation["activated_at"])

    def test_an_activation_retry_reads_the_inventory_again_before_activating(self):
        self.finish_apply()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="waiting")
        self.provider.identity = replace(self.provider.identity, status="active")
        refused = Err("definite refusal", retriability=Retriability.NOT_RETRIABLE)
        with patch.object(self.provider, "get_dnssec", return_value=refused):
            self.poll_activation()
        self.assertEqual((self.operation.status, self.operation.phase), ("parked", "activation_dnssec"))
        key = next(iter(self.provider.records))
        row = self.provider.records[key]
        self.provider.records[key] = replace(row, spec=replace(row.spec, ttl=row.spec.ttl + 60))
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }
        self.poll_activation()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual((self.zone.status, self.zone.last_error), ("failed", "provider_inventory_mismatch"))

    def test_a_retry_after_the_poll_deadline_gets_a_fresh_deadline(self):
        self.finish_apply()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="waiting")
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(created_at=timezone.now() - timedelta(days=8))
        self.tick()
        self.operation.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual((self.operation.status, self.zone.last_error), ("parked", "activation_deadline"))
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        self.provider.identity = replace(self.provider.identity, status="active")
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }
        self.poll_activation()
        self.assertEqual(self.operation.status, "completed")
        self.assertEqual((self.zone.status, self.zone.last_error), ("active", ""))

    def test_an_activation_retry_that_reproves_readiness_offers_the_nameservers_again(self):
        self.park_activation()
        for _ in range(8):
            self.tick()
        self.operation.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual(self.operation.status, "waiting")
        self.assertEqual(self.zone.status, "awaiting_ns")
        self.assertEqual(self.zone.last_error, "")
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], list(self.zone.assigned_nameservers))

    def terminate_hosting_of_active_zone(self):
        """Termination withdraws the managed web records and retires the name; the zone keeps its account link."""
        from apps.provisioning.account_hostname_service import lock_for_publication  # noqa: PLC0415
        from apps.provisioning.managed_dns_service import withdraw_managed_locked  # noqa: PLC0415

        self.finish_apply()
        HostedZoneOperation.objects.filter(zone=self.zone, kind="activate").update(status="completed")
        self.zone.refresh_from_db()
        self.zone.provider_status = "active"
        self.zone.activation = {
            "revision": self.zone.current_revision,
            "parent_ns_verified": True,
            "inventory_verified": True,
        }
        self.zone.activate()
        self.zone.save()
        type(self.account).objects.filter(pk=self.account.pk).update(status="terminated")
        type(self.account.service).objects.filter(pk=self.account.service_id).update(status="terminated")
        with (
            patch("apps.provisioning.managed_dns_service.get_zone_gateway", return_value=self.provider),
            transaction.atomic(),
        ):
            withdraw_managed_locked(lock_for_publication(self.hostname.pk)).unwrap()
        type(self.hostname).objects.filter(pk=self.hostname.pk).update(
            retired_at=timezone.now(), records={}, target_server=None
        )
        self.zone.refresh_from_db()
        self.assertEqual((self.zone.status, self.zone.account_id), ("active", self.account.pk))
        self.assertFalse(self.zone.records.filter(managed_by="praho", desired_deleted=False).exists())
        aged = {**self.zone.readiness, "checked_at": (timezone.now() - timedelta(hours=1)).isoformat()}
        HostedZone.objects.filter(pk=self.zone.pk).update(readiness=aged)
        tasks._seed_activation_checks(timezone.now())
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="pending")
        self.provider.identity = replace(self.provider.identity, status="active")
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }

    def test_terminated_hosting_does_not_break_monitoring_of_the_customers_active_zone(self):
        self.terminate_hosting_of_active_zone()
        self.poll_activation()
        self.assertEqual(self.operation.status, "completed")
        self.assertEqual((self.zone.status, self.zone.last_error), ("active", ""))

    def test_monitoring_after_termination_still_parks_on_a_changed_provider_identity(self):
        self.terminate_hosting_of_active_zone()
        self.provider.identity = replace(self.provider.identity, nameservers=("ns.elsewhere.example",))
        self.poll_activation()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual((self.zone.status, self.zone.last_error), ("failed", "assigned_nameservers_changed"))

    def test_unowned_record_drift_blocks_whole_inventory_readback(self):
        for _ in range(100):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.phase == "verify_inventory":
                break
        first = next(iter(self.provider.records.values()))
        self.provider.records["c" * 32] = ProviderZoneRecord(
            "c" * 32, replace(first.spec, local_id="", owner_tag="", rdata="95.217.0.77")
        )
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")

    def test_provider_drift_after_assigned_checks_is_read_again_before_nameserver_instructions(self):
        for _ in range(100):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.phase == "handover":
                break
        else:
            self.fail("Import did not reach the parent proof boundary")
        selected = next(iter(self.provider.records))
        row = self.provider.records[selected]
        self.provider.records[selected] = replace(row, spec=replace(row.spec, ttl=row.spec.ttl + 60))
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])

    def test_old_ds_and_its_cache_ttl_block_the_switch_without_losing_applied_progress(self):
        self.revision.crosscheck["ds_ttl"] = 86400
        self.revision.save(update_fields=["crosscheck"])
        for _ in range(100):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.phase == "handover":
                break
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "waiting")
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])
        self.assertTrue(self.provider.records)

    def test_ds_reappearance_resets_the_absence_clock_and_uses_its_new_observed_ttl(self):
        for _ in range(100):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.phase == "handover":
                break
        self.operation.evidence["ds_absent_since"] = (timezone.now() - timedelta(days=2)).isoformat()
        self.operation.save(update_fields=["evidence"])
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.old.example"],
            "ds": ["new DS"],
            "ds_ttl": 86400,
        }
        self.tick()
        self.operation.refresh_from_db()
        self.assertNotIn("ds_absent_since", self.operation.evidence)
        self.assertEqual(self.operation.evidence["old_ds_ttl"], 86400)
        self.handover.return_value = {"state": "verified", "nameservers": ["ns.old.example"], "ds": [], "ds_ttl": 0}
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "waiting")
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])

    def test_expired_readiness_never_exposes_nameservers_from_an_old_ds_or_inventory_check(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        self.zone.readiness["checked_at"] = (timezone.now() - timedelta(hours=2)).isoformat()
        self.zone.save(update_fields=["readiness"])
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])

    def test_a_live_claim_or_stale_delivery_never_dispatches_a_provider_mutation(self):
        token = uuid4()
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(
            lease_token=token, lease_until=timezone.now() + timedelta(minutes=3), worker_started_at=timezone.now()
        )
        self.assertEqual(self.tick()["action"], "busy")
        self.assertEqual(
            tasks.advance_zone_operation(str(self.operation.pk), lease_token=str(uuid4()))["action"], "busy"
        )
        self.assertEqual(self.provider.calls, [])

    def test_worker_refuses_an_enclosing_transaction_before_claim_or_provider_io(self):
        with transaction.atomic():
            self.assertEqual(self.tick()["action"], "transaction_required")
        self.assertEqual(self.provider.calls, [])
        self.operation.refresh_from_db()
        self.assertIsNone(self.operation.lease_token)

    def test_completed_apply_automatically_seeds_bounded_activation_work_without_inline_dns(self):
        self.finish_apply()
        following = HostedZoneOperation.objects.filter(zone=self.zone, kind="activate", status="waiting").get()
        self.assertGreater(following.next_attempt_at, timezone.now())
        self.assertLessEqual(following.next_attempt_at, timezone.now() + timedelta(minutes=5))

    def test_dispatch_rechecks_an_active_zone_after_its_cached_proof_ages_without_network_inline(self):
        self.finish_apply()
        HostedZoneOperation.objects.filter(zone=self.zone, kind="activate").update(status="completed")
        self.zone.refresh_from_db()
        self.zone.provider_status = "active"
        self.zone.activation = {
            "revision": self.zone.current_revision,
            "parent_ns_verified": True,
            "inventory_verified": True,
        }
        self.zone.activate()
        self.zone.readiness["checked_at"] = (timezone.now() - timedelta(minutes=40)).isoformat()
        self.zone.save()
        before = list(self.provider.calls)
        with patch.object(tasks, "_enqueue") as enqueue:
            result = tasks.dispatch_zone_operations()
        self.assertEqual(result["queued"], 1)
        enqueue.assert_called_once()
        self.assertEqual(self.provider.calls, before)

    def test_delete_requires_real_export_and_waits_for_parent_move_away_and_cache(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertTrue(
            zones.request_zone_delete(self.zone, self.zone.current_revision, "0" * 64, actor=self.actor).is_err()
        )
        zones.export_zone_file(self.zone, actor=self.actor).unwrap()
        digest = zones.cached_zone_status(self.zone)["export_digest"]
        self.operation = zones.request_zone_delete(
            self.zone, self.zone.current_revision, digest, actor=self.actor
        ).unwrap()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 600,
        }
        self.tick()
        self.tick()
        self.assertNotIn("delete_zone", self.provider.calls)
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.other.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 600,
        }
        self.tick()
        self.assertNotIn("delete_zone", self.provider.calls)
        self.operation.refresh_from_db()
        self.operation.evidence["parent_moved_since"] = (timezone.now() - timedelta(seconds=601)).isoformat()
        self.operation.evidence["ds_absent_since"] = (timezone.now() - timedelta(seconds=601)).isoformat()
        self.operation.save(update_fields=["evidence"])
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "deleted")
        self.assertEqual(self.provider.calls.count("delete_zone"), 1)

    def begin_ready_delete(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        zones.export_zone_file(self.zone, actor=self.actor).unwrap()
        self.operation = zones.request_zone_delete(
            self.zone,
            self.zone.current_revision,
            zones.cached_zone_status(self.zone)["export_digest"],
            actor=self.actor,
        ).unwrap()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.other.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 0,
        }
        self.tick()
        self.tick()
        self.operation.refresh_from_db()
        self.operation.evidence["parent_moved_since"] = (timezone.now() - timedelta(hours=1)).isoformat()
        self.operation.evidence["ds_absent_since"] = (timezone.now() - timedelta(hours=1)).isoformat()
        self.operation.save(update_fields=["evidence"])
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "delete_provider_inflight")

    def test_final_delete_revalidates_the_exported_whole_inventory_after_the_cache_wait(self):
        self.begin_ready_delete()
        key = next(iter(self.provider.records))
        row = self.provider.records[key]
        self.provider.records[key] = replace(row, spec=replace(row.spec, ttl=row.spec.ttl + 60))
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertTrue(self.provider.records)

    def test_a_retried_delete_clears_the_parked_zone_error(self):
        self.begin_ready_delete()
        key = next(iter(self.provider.records))
        row = self.provider.records[key]
        self.provider.records[key] = replace(row, spec=replace(row.spec, ttl=row.spec.ttl + 60))
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual((self.zone.status, self.zone.last_error), ("failed", "zone_delete_refused"))
        self.provider.records[key] = row
        self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual(self.operation.status, "completed")
        self.assertEqual((self.zone.status, self.zone.last_error), ("deleted", ""))

    def test_unknown_delete_rechecks_delegation_before_a_retry_can_remove_the_zone(self):
        self.begin_ready_delete()
        self.provider.ambiguous_delete = True
        self.tick()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }
        self.tick()
        self.assertEqual(self.provider.calls.count("delete_zone"), 1)
        self.assertTrue(self.provider.records)

    def test_a_resumed_delete_does_not_remove_a_zone_whose_delegation_was_restored(self):
        # The worker committed the in-flight phase and stopped; the customer then delegated back to us.
        self.begin_ready_delete()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 300,
        }
        self.tick()
        self.assertNotIn("delete_zone", self.provider.calls)
        self.assertTrue(self.provider.records)
        self.operation.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual(self.operation.phase, "delete_parent")
        self.assertEqual(self.operation.last_error, "move_away_proof_required")
        self.assertNotIn("parent_moved_since", self.operation.evidence)
        self.assertEqual(self.zone.status, "deleting")
        self.assertFalse(self.zone.deletion["parent_moved_away"])

    def test_an_observation_that_aged_while_waiting_for_locks_never_authorizes_the_delete(self):
        self.begin_ready_delete()
        with patch.object(deletion, "PROOF_MAX_AGE", timedelta(0), create=True):
            self.tick()
        self.operation.refresh_from_db()
        self.assertNotIn("delete_zone", self.provider.calls)
        self.assertEqual(self.operation.phase, "delete_provider_inflight")
        self.assertEqual(self.operation.last_error, "move_away_proof_stale")
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "deleted")
        self.assertEqual(self.provider.calls.count("delete_zone"), 1)

    def test_a_slow_parent_observation_counts_toward_the_proof_age(self):
        self.begin_ready_delete()
        moved = dict(self.handover.return_value)

        def slow_snapshot(name):
            time.sleep(0.5)
            return moved

        self.handover.side_effect = slow_snapshot
        with patch.object(deletion, "PROOF_MAX_AGE", timedelta(milliseconds=250)):
            self.tick()
        self.handover.side_effect = None
        self.operation.refresh_from_db()
        self.assertNotIn("delete_zone", self.provider.calls)
        self.assertEqual(self.operation.last_error, "move_away_proof_stale")

    def test_a_resumed_delete_restarts_the_cache_wait_when_the_delegation_changed(self):
        self.begin_ready_delete()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.third.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 900,
        }
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "delete_parent")
        self.tick()
        self.operation.refresh_from_db()
        restarted = parse_datetime(self.operation.evidence["parent_moved_since"])
        self.assertGreater(restarted, timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.operation.evidence["old_ns_ttl"], 900)
        self.assertNotIn("delete_zone", self.provider.calls)
        aged = (timezone.now() - timedelta(seconds=901)).isoformat()
        self.operation.evidence.update(parent_moved_since=aged, ds_absent_since=aged)
        self.operation.save(update_fields=["evidence"])
        self.finish_apply()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "deleted")
        self.assertEqual(self.provider.calls.count("delete_zone"), 1)

    def test_a_delegation_change_during_the_cache_wait_restarts_it(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        zones.export_zone_file(self.zone, actor=self.actor).unwrap()
        self.operation = zones.request_zone_delete(
            self.zone, self.zone.current_revision, zones.cached_zone_status(self.zone)["export_digest"], actor=self.actor
        ).unwrap()
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.other.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 0,
        }
        self.tick()
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "delete_parent")
        aged = (timezone.now() - timedelta(hours=1)).isoformat()
        self.operation.evidence.update(parent_moved_since=aged, ds_absent_since=aged)
        self.operation.save(update_fields=["evidence"])
        self.handover.return_value = {**self.handover.return_value, "nameservers": ["ns.third.example"]}
        self.tick()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.phase, "delete_parent")
        self.assertGreater(
            parse_datetime(self.operation.evidence["parent_moved_since"]), timezone.now() - timedelta(minutes=1)
        )
        self.assertNotIn("delete_zone", self.provider.calls)

    def test_provider_active_does_not_activate_without_parent_delegation_and_fresh_inventory(self):
        self.finish_apply()
        self.operation = zones.request_nameserver_switch(
            self.zone, self.zone.current_revision, actor=self.actor
        ).unwrap()
        self.provider.identity = replace(self.provider.identity, status="active")
        for _ in range(8):
            self.tick()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "awaiting_ns")
        self.handover.return_value = {
            "state": "verified",
            "nameservers": ["ns.cloudflare.example", "ns2.cloudflare.example"],
            "ds": [],
            "ds_ttl": 0,
            "ns_ttl": 86400,
        }
        for _ in range(30):
            self.tick()
            self.operation.refresh_from_db()
            if self.operation.status == "completed":
                break
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "active")
        self.assertTrue(self.zone.activation["activated_at"])

    def test_free_activation_trigger_is_not_replayed_more_than_once_per_hour(self):
        self.finish_apply()
        self.operation = zones.request_nameserver_switch(
            self.zone, self.zone.current_revision, actor=self.actor
        ).unwrap()
        for _ in range(20):
            self.tick()
        self.assertEqual(self.provider.calls.count("trigger_activation"), 1)

    def test_replacing_readonly_poll_work_preserves_the_free_plan_activation_limit_for_the_zone(self):
        self.finish_apply()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="waiting")
        for _ in range(8):
            self.tick()
        self.assertEqual(self.provider.calls.count("trigger_activation"), 1)
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(status="completed")
        self.operation = HostedZoneOperation.objects.create(
            zone=self.zone, revision=self.revision, kind="activate", phase="activation_identity"
        )
        for _ in range(8):
            self.tick()
        self.assertEqual(self.provider.calls.count("trigger_activation"), 1)

    def test_readonly_activation_defers_intentional_cutover_ttl_without_parking(self):
        self.finish_apply()
        self.operation = HostedZoneOperation.objects.get(zone=self.zone, kind="activate", status="waiting")
        type(self.hostname).objects.filter(pk=self.hostname.pk).update(previous_ttl=900)
        calls = list(self.provider.calls)
        result = self.tick()
        self.assertEqual(result["action"], "waiting")
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, "awaiting_ns")
        self.assertEqual(self.provider.calls, calls)

    def test_pending_customer_edit_refreshes_the_original_source_inventory(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        revision = zones.request_record_change(
            self.zone,
            self.zone.current_revision,
            actor=self.actor,
            name="_verify." + self.zone.name,
            record_type="TXT",
            rdata='"new-value"',
        ).unwrap()
        revision.crosscheck["checked_at"] = (timezone.now() - timedelta(hours=2)).isoformat()
        revision.save(update_fields=["crosscheck"])
        self.operation = HostedZoneOperation.objects.get(revision=revision)
        self.tick()
        with patch(
            "apps.domains.dns_zone_checks.probe_import_batch",
            return_value={
                "ok": True,
                "complete": True,
                "cursor": 100,
                "checked_at": timezone.now().isoformat(),
                "observations": {},
                "ds_ttl": 0,
            },
        ) as refresh:
            self.tick()
        self.assertEqual(refresh.call_args.args[1], self.revision.inventory)
        self.assertEqual(self.finish_apply()["action"], "completed")

    def test_registrar_switch_prepares_offline_and_rechecks_parent_ds_before_the_single_submission(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        registrar = Registrar.objects.create(name="gandi", display_name="Gandi", status="active")
        tld = TLD.objects.create(
            extension="net", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        self.zone.domain = Domain.objects.create(
            name=self.zone.name,
            customer=self.zone.customer,
            registrar=registrar,
            tld=tld,
            status="active",
            nameservers=["ns.old.example"],
        )
        self.zone.save(update_fields=["domain"])
        gateway = Mock()
        gateway.update_nameservers.return_value = Ok(Mock(pending=False))
        with (
            patch.object(zones, "can_switch_registrar", return_value=True),
            patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gateway),
        ):
            self.operation = zones.request_nameserver_switch(
                self.zone, self.zone.current_revision, actor=self.actor
            ).unwrap()
            self.assertIsNotNone(self.operation.registrar_operation_id)
            gateway.update_nameservers.assert_not_called()
            self.handover.return_value = {
                "state": "verified",
                "nameservers": ["ns.old.example"],
                "ds": ["12345 13 2 " + "AB" * 32],
                "ds_ttl": 600,
            }
            for _ in range(12):
                self.tick()
            gateway.update_nameservers.assert_not_called()
            self.handover.return_value = {"state": "verified", "nameservers": ["ns.old.example"], "ds": [], "ds_ttl": 0}
            for _ in range(4):
                self.tick()
            gateway.update_nameservers.assert_not_called()
            self.operation.refresh_from_db()
            self.operation.evidence["ds_absent_since"] = (timezone.now() - timedelta(seconds=601)).isoformat()
            self.operation.save(update_fields=["evidence"])
            for _ in range(24):
                self.tick()
            gateway.update_nameservers.assert_called_once()

    def test_registrar_switch_reads_the_whole_inventory_again_after_its_dns_checks(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        registrar = Registrar.objects.create(name="gandi", display_name="Gandi", status="active")
        tld = TLD.objects.create(
            extension="net", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        self.zone.domain = Domain.objects.create(
            name=self.zone.name,
            customer=self.zone.customer,
            registrar=registrar,
            tld=tld,
            status="active",
            nameservers=["ns.old.example"],
        )
        self.zone.save(update_fields=["domain"])
        gateway = Mock()
        gateway.update_nameservers.return_value = Ok(Mock(pending=False))
        with (
            patch.object(zones, "can_switch_registrar", return_value=True),
            patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gateway),
        ):
            self.operation = zones.request_nameserver_switch(
                self.zone, self.zone.current_revision, actor=self.actor
            ).unwrap()
            for _ in range(10):
                self.tick()
                self.operation.refresh_from_db()
                if self.operation.phase == "switch_parent":
                    break
            self.assertEqual(self.operation.phase, "switch_parent")
            key = next(iter(self.provider.records))
            row = self.provider.records[key]
            self.provider.records[key] = replace(row, spec=replace(row.spec, ttl=row.spec.ttl + 60))
            for _ in range(10):
                self.tick()
            gateway.update_nameservers.assert_not_called()
            self.operation.refresh_from_db()
            self.assertEqual(self.operation.status, "parked")

    def test_explicit_registrar_retry_stores_a_fresh_attempt_and_preserves_the_failed_uuid(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        registrar = Registrar.objects.create(name="gandi", display_name="Gandi", status="active")
        tld = TLD.objects.create(
            extension="net", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        self.zone.domain = Domain.objects.create(
            name=self.zone.name,
            customer=self.zone.customer,
            registrar=registrar,
            tld=tld,
            status="active",
            nameservers=["ns.old.example"],
        )
        self.zone.save(update_fields=["domain"])
        gateway = Mock()
        gateway.update_nameservers.return_value = Err(
            Mock(code=Mock(value="forbidden")), retriability=Retriability.NOT_RETRIABLE
        )
        with (
            patch.object(zones, "can_switch_registrar", return_value=True),
            patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=gateway),
        ):
            self.operation = zones.request_nameserver_switch(
                self.zone, self.zone.current_revision, actor=self.actor
            ).unwrap()
            self.finish_apply()
            self.assertEqual(self.operation.status, "parked")
            failed_id = self.operation.registrar_operation_id
            self.operation = zones.request_operation_retry(self.zone, actor=self.actor).unwrap()
            self.assertNotEqual(self.operation.registrar_operation_id, failed_id)
            self.assertEqual(self.operation.registrar_operation.parameters["retry_of"], str(failed_id))
            self.assertEqual(self.operation.evidence["registrar_previous_attempt"], str(failed_id))
            gateway.update_nameservers.return_value = Ok(Mock(pending=False))
            for _ in range(30):
                self.tick()
            self.assertEqual(gateway.update_nameservers.call_count, 2)

    def test_independent_orphan_zone_edit_applies_customer_data_without_recreating_managed_routes(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        self.zone.provider_status = "active"
        self.zone.activation = {
            "revision": self.zone.current_revision,
            "parent_ns_verified": True,
            "inventory_verified": True,
        }
        self.zone.activate()
        self.zone.save()
        managed = list(self.zone.records.filter(managed_by="praho"))
        for record in managed:
            self.provider.records.pop(record.provider_record_id, None)
        self.zone.records.filter(managed_by="praho").update(desired_deleted=True)
        self.account.delete()
        self.zone.refresh_from_db()
        revision = zones.request_record_change(
            self.zone,
            self.zone.current_revision,
            actor=self.actor,
            name="_dmarc." + self.zone.name,
            record_type="TXT",
            rdata='"v=DMARC1; p=reject"',
            ttl=300,
        ).unwrap()
        self.operation = HostedZoneOperation.objects.get(revision=revision)
        result = self.finish_apply()
        self.assertEqual(self.operation.status, "completed", result)
        self.assertTrue(any(row.spec.name.startswith("_dmarc.") for row in self.provider.records.values()))
        self.assertFalse(
            any(
                row.spec.name in {self.zone.name, "www." + self.zone.name}
                and row.spec.record_type in {"A", "AAAA", "CNAME"}
                for row in self.provider.records.values()
            )
        )

    def test_unrelated_provider_drift_is_not_silently_overwritten_by_a_customer_edit(self):
        self.finish_apply()
        self.zone.refresh_from_db()
        changed = next(row for row in self.zone.records.filter(managed_by="imported") if row.record_type == "TXT")
        remote = self.provider.records[changed.provider_record_id]
        self.provider.records[remote.id] = replace(remote, spec=replace(remote.spec, ttl=remote.spec.ttl + 60))
        revision = zones.request_record_change(
            self.zone,
            self.zone.current_revision,
            actor=self.actor,
            name="_verify." + self.zone.name,
            record_type="TXT",
            rdata='"new"',
        ).unwrap()
        self.operation = HostedZoneOperation.objects.get(revision=revision)
        before = list(self.provider.calls)
        self.finish_apply()
        self.assertEqual(self.operation.status, "parked")
        self.assertFalse(any(isinstance(call, tuple) for call in self.provider.calls[len(before) :]))
