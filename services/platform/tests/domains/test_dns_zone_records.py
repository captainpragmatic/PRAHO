"""Explicit record intents preserve managed owners and remain usable after hosting removal."""

import hashlib
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.domains import dns_zone_services as zones
from apps.domains.dns_zone_import import parse_zone_file
from apps.domains.dns_zone_models import HostedZoneOperation
from apps.provisioning.service_models import Service
from apps.users.models import CustomerMembership, User
from tests.domains.test_dns_zone_import_service import UPLOAD, hosting_fixture


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneRecordIntentTests(TestCase):
    def setUp(self):
        self.account, self.hostname, self.actor = hosting_fixture()
        patch.object(zones, "_audit").start()
        self.addCleanup(patch.stopall)
        revision = zones.preview_zone_import(self.account, UPLOAD, actor=self.actor).unwrap()
        revision.crosscheck = {"ok": True, "complete": True, "checked_at": timezone.now().isoformat()}
        revision.save(update_fields=["crosscheck"])
        self.zone = zones.confirm_import(
            revision.zone, revision.number, revision.manifest_digest, actor=self.actor
        ).unwrap()
        HostedZoneOperation.objects.filter(zone=self.zone).update(status="completed")
        self.zone.provider_account_id = "a" * 32
        self.zone.provider_zone_id = "b" * 32
        self.zone.applied_revision = self.zone.current_revision
        self.zone.readiness = {
            "revision": self.zone.current_revision,
            "complete": True,
            "ds_safe": True,
            "checked_at": timezone.now().isoformat(),
        }
        self.zone.provider_status = "active"
        self.zone.assigned_nameservers = ["ns.cloudflare.example", "ns2.cloudflare.example"]
        self.zone.await_nameservers()
        self.zone.activation = {
            "revision": self.zone.current_revision,
            "parent_ns_verified": True,
            "inventory_verified": True,
        }
        self.zone.activate()
        self.zone.save()

    def test_customer_cannot_edit_delete_or_shadow_a_managed_owner(self):
        managed = self.zone.records.filter(managed_by="praho").first()
        for kwargs in (
            {"record_id": managed.pk, "delete": True},
            {"name": self.zone.name, "record_type": "AAAA", "rdata": "2a01:4f9:c010::77"},
            {"name": "www." + self.zone.name, "record_type": "TXT", "rdata": '"shadow"'},
        ):
            result = zones.request_record_change(self.zone, self.zone.current_revision, actor=self.actor, **kwargs)
            self.assertTrue(result.is_err(), result)
        self.assertFalse(HostedZoneOperation.objects.filter(status="pending").exists())

    def test_explicit_unrelated_record_edit_is_a_new_revision_and_durable_job_without_provider_io(self):
        with patch(
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway", side_effect=AssertionError("request provider call")
        ):
            result = zones.request_record_change(
                self.zone,
                self.zone.current_revision,
                actor=self.actor,
                name="_verify." + self.zone.name,
                record_type="TXT",
                rdata='"new-token"',
                ttl=300,
            )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().number, self.zone.current_revision + 1)
        self.assertEqual(HostedZoneOperation.objects.get(status="pending").kind, "edit")

    def _suspend_customer(self):
        Customer.objects.filter(pk=self.zone.customer_id).update(status="suspended")
        self.assertEqual(Customer.objects.get(pk=self.zone.customer_id).status, "suspended")

    def _record_change(self, actor):
        return zones.request_record_change(
            self.zone,
            self.zone.current_revision,
            actor=actor,
            name="_verify." + self.zone.name,
            record_type="TXT",
            rdata='"held"',
            ttl=300,
        )

    def test_a_suspended_customer_publishes_nothing_but_still_reads_and_exports(self):
        from apps.domains.dns_zone_lifecycle import request_nameserver_switch  # noqa: PLC0415

        self._suspend_customer()
        self.assertEqual(self._record_change(self.actor).unwrap_err(), "customer_suspended")
        self.assertEqual(
            request_nameserver_switch(self.zone, self.zone.current_revision, actor=self.actor).unwrap_err(),
            "customer_suspended",
        )
        revision = self.zone.revisions.get(number=self.zone.current_revision)
        self.assertEqual(
            zones.confirm_import(
                self.zone, revision.number, revision.manifest_digest, actor=self.actor
            ).unwrap_err(),
            "customer_suspended",
        )
        self.assertFalse(HostedZoneOperation.objects.filter(status="pending").exists())
        self.assertTrue(zones.export_zone_file(self.zone, actor=self.actor).is_ok())

    def test_staff_may_still_publish_for_a_suspended_customer(self):
        self._suspend_customer()
        staff = User.objects.create_user(email="dns-staff@example.test", password="x", staff_role="admin")
        self.assertTrue(self._record_change(staff).is_ok())

    def test_publishing_queued_before_the_suspension_waits_for_its_end(self):
        from apps.domains import dns_zone_tasks  # noqa: PLC0415

        self.assertTrue(self._record_change(self.actor).is_ok())
        operation = HostedZoneOperation.objects.get(status="pending", kind="edit")
        self._suspend_customer()
        with patch.object(dns_zone_tasks, "_guard", side_effect=AssertionError("held work must not run")):
            self.assertEqual(dns_zone_tasks._step(operation.pk, operation.pk), dns_zone_tasks.SUSPENDED_HOLD_SECONDS)

    def test_export_receipt_is_bound_to_real_bytes_revision_and_current_manifest(self):
        exported = zones.export_zone_file(self.zone, actor=self.actor).unwrap()
        parsed = parse_zone_file(exported, self.zone.name)
        self.assertTrue(any(row.record_type == "TXT" for row in parsed.records))
        self.assertEqual(zones.cached_zone_status(self.zone)["export_digest"], hashlib.sha256(exported).hexdigest())

    def test_runtime_managed_record_change_hides_an_export_receipt_even_without_a_revision_change(self):
        zones.export_zone_file(self.zone, actor=self.actor).unwrap()
        self.zone.records.filter(managed_by="praho").update(ttl=600)
        self.assertEqual(zones.cached_zone_status(self.zone)["export_digest"], "")

    def test_a_deletion_rests_on_the_requesting_members_own_export(self):
        colleague = User.objects.create_user(email="zone-tech@example.net", password="test-password")
        CustomerMembership.objects.create(customer=self.zone.customer, user=colleague, role="tech")
        digest = hashlib.sha256(zones.export_zone_file(self.zone, actor=self.actor).unwrap()).hexdigest()
        self.assertEqual(zones.cached_zone_status(self.zone, actor=self.actor)["export_digest"], digest)
        self.assertEqual(zones.cached_zone_status(self.zone, actor=colleague)["export_digest"], "")
        refused = zones.request_zone_delete(self.zone, self.zone.current_revision, digest, actor=colleague)
        self.assertTrue(refused.is_err(), refused)
        self.assertEqual(refused.unwrap_err(), "current_export_required")
        self.assertFalse(HostedZoneOperation.objects.filter(kind="delete").exists())
        zones.export_zone_file(self.zone, actor=colleague).unwrap()
        self.assertEqual(zones.cached_zone_status(self.zone, actor=colleague)["export_digest"], digest)
        self.assertEqual(zones.cached_zone_status(self.zone, actor=self.actor)["export_digest"], "")
        accepted = zones.request_zone_delete(self.zone, self.zone.current_revision, digest, actor=colleague)
        self.assertTrue(accepted.is_ok(), accepted)
        self.assertEqual(accepted.unwrap().kind, "delete")

    def test_viewer_can_neither_export_a_deletion_receipt_nor_request_a_record_change(self):
        CustomerMembership.objects.filter(user=self.actor).update(role="viewer")
        exported = zones.export_zone_file(self.zone, actor=self.actor)
        self.assertTrue(exported.is_err(), exported)
        self.assertEqual(exported.unwrap_err(), "zone_access_denied")
        self.zone.refresh_from_db()
        self.assertNotIn("export_digest", self.zone.deletion)
        self.assertTrue(
            zones.request_record_change(
                self.zone,
                self.zone.current_revision,
                actor=self.actor,
                name="_verify." + self.zone.name,
                record_type="TXT",
                rdata='"no-write"',
            ).is_err()
        )

    def test_orphaned_hosting_does_not_make_independent_customer_dns_uneditable_or_unexportable(self):
        self.zone.records.filter(managed_by="praho").update(desired_deleted=True)
        self.account.delete()
        self.zone.refresh_from_db()
        self.assertIsNone(self.zone.account_id)
        changed = zones.request_record_change(
            self.zone,
            self.zone.current_revision,
            actor=self.actor,
            name="_dmarc." + self.zone.name,
            record_type="TXT",
            rdata='"v=DMARC1; p=reject"',
            ttl=300,
        )
        self.assertTrue(changed.is_ok(), changed)
        self.assertFalse(self.zone.records.filter(managed_by="praho", desired_deleted=False).exists())
        self.assertTrue(zones.export_zone_file(self.zone, actor=self.actor).is_ok())

    def test_hosting_customer_transfer_does_not_transfer_the_independent_zone_or_block_its_owner(self):
        other = Customer.objects.create(name="New hosting owner", primary_email="new@example.net")
        Service.objects.filter(pk=self.account.service_id).update(customer=other)
        original_managed = list(self.zone.records.filter(managed_by="praho").values("id", "rdata", "ttl"))
        self.assertTrue(zones.export_zone_file(self.zone, actor=self.actor).is_ok())
        self.assertTrue(
            zones.request_record_change(
                self.zone,
                self.zone.current_revision,
                actor=self.actor,
                name="_dmarc." + self.zone.name,
                record_type="TXT",
                rdata='"v=DMARC1; p=reject"',
            ).is_ok()
        )
        self.zone.refresh_from_db()
        self.assertNotEqual(self.zone.customer_id, other.pk)
        self.assertEqual(
            list(self.zone.records.filter(managed_by="praho", desired_deleted=False).values("id", "rdata", "ttl")),
            original_managed,
        )
        self.assertEqual(zones.cached_zone_status(self.zone)["nameservers"], [])
