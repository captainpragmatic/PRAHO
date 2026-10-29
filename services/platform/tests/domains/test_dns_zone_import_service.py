"""Request paths stage and confirm exact tenant/target-bound revisions without network calls."""

import json
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.common.types import Err
from apps.customers.models import Customer
from apps.domains import dns_zone_services as zones
from apps.domains.dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.domains.test_dns_zone_import import HEADER
from tests.helpers.fsm_helpers import force_status

UPLOAD = (
    HEADER
    + '@ A 95.217.0.99\nwww CNAME old.example.org.\n@ MX 10 mail.external.example.org.\nodd-selector._domainkey TXT "preserve-me"\n'
).encode()


def hosting_fixture():
    customer = Customer.objects.create(name="Zone owner", primary_email="owner@example.net")
    user = User.objects.create_user(email="zone-owner@example.net", password="test-password")
    CustomerMembership.objects.create(customer=customer, user=user, role="owner")
    Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
    service = Service.objects.create(
        customer=customer,
        service_plan=ServicePlan.objects.create(name="DNS plan", price_monthly="10.00"),
        currency_id="RON",
        service_name="DNS hosting",
        domain="customer.example.net",
        username="zoneuser",
        price="10.00",
        status="active",
    )
    server = VirtualminServer.objects.create(
        name="zone-target", hostname="target.example.org", ipv4_address="95.217.0.20"
    )
    account = VirtualminAccount.objects.create(
        service=service, server=server, domain=service.domain, virtualmin_username="zoneuser", status="active"
    )
    hostname = AccountHostname.objects.create(
        account=account,
        target_server=server,
        label="a1b2c3d4",
        zone="accounts.example.org",
        records={"A": {"intended": server.ipv4_address, "applied": server.ipv4_address}},
    )
    return account, hostname, user


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class ZoneImportServiceTests(TestCase):
    def setUp(self):
        self.account, self.hostname, self.actor = hosting_fixture()
        SettingsService.update_setting("dns.cloudflare_account_id", "a" * 32).unwrap()
        self.audit = patch.object(zones, "_audit").start()
        self.addCleanup(patch.stopall)

    def stage(self, raw=UPLOAD):
        result = zones.preview_zone_import(self.account, raw, actor=self.actor)
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def checked(self):
        revision = self.stage()
        revision.crosscheck = {"complete": True, "ok": True, "checked_at": timezone.now().isoformat(), "ds_ttl": 300}
        revision.save(update_fields=["crosscheck"])
        return revision

    def test_preview_and_confirmation_never_run_dns_or_provider_calls_inline(self):
        with patch(
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway", side_effect=AssertionError("request provider call")
        ):
            revision = self.checked()
            result = zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor)
        self.assertTrue(result.is_ok(), result)
        operation = HostedZoneOperation.objects.get(zone=revision.zone)
        self.assertEqual(operation.kind, "apply")
        self.assertIsNone(operation.lease_token)

    def test_managed_web_changes_are_explicit_and_unrelated_mail_and_dkim_are_kept(self):
        revision = self.stage()
        self.assertTrue(revision.valid)
        self.assertTrue(revision.normalizations)
        values = {(row["name"], row["record_type"]): row for row in revision.manifest}
        self.assertEqual(values[(self.account.domain, "A")]["rdata"]["text"], "95.217.0.20")
        self.assertEqual(values[(f"www.{self.account.domain}", "CNAME")]["rdata"]["text"], self.hostname.fqdn + ".")
        self.assertEqual(values[(self.account.domain, "MX")]["managed_by"], "imported")
        self.assertIn((f"odd-selector._domainkey.{self.account.domain}", "TXT"), values)

    def test_unsupported_record_refuses_entire_revision_but_keeps_rejected_inventory(self):
        revision = self.stage(UPLOAD + b"unknown TYPE65400 \\# 3 010203\n")
        self.assertFalse(revision.valid)
        self.assertEqual(revision.errors[0]["code"], "unsupported_records")
        self.assertTrue(any(row["record_type"] == "TYPE65400" for row in revision.inventory))
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        self.assertFalse(HostedZoneOperation.objects.exists())

    def test_confirmation_requires_exact_revision_digest_and_complete_successful_crosscheck(self):
        revision = self.stage()
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        revision.crosscheck = {"complete": True, "ok": False}
        revision.save(update_fields=["crosscheck"])
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        revision.crosscheck = {"complete": True, "ok": True, "checked_at": timezone.now().isoformat()}
        revision.save(update_fields=["crosscheck"])
        self.assertTrue(
            zones.confirm_import(
                revision.zone, revision.number + 1, revision.manifest_digest, actor=self.actor
            ).is_err()
        )
        self.assertTrue(zones.confirm_import(revision.zone, revision.number, "0" * 64, actor=self.actor).is_err())

    def test_target_change_after_preview_requires_new_confirmation_and_hides_instructions(self):
        revision = self.checked()
        VirtualminServer.objects.filter(pk=self.account.server_id).update(ipv4_address="95.217.0.21")
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        self.assertEqual(zones.cached_zone_status(revision.zone)["nameservers"], [])

    def test_crosscheck_progress_and_confirmation_advance_the_revision_updated_at(self):
        revision = self.stage()
        earlier = timezone.now() - timedelta(days=1)
        rows = HostedZoneImportRevision.objects.filter(pk=revision.pk)
        rows.update(updated_at=earlier)
        revision.save(update_fields=[])
        self.assertEqual(rows.get().updated_at, earlier)
        revision.crosscheck = {"complete": True, "ok": True, "checked_at": timezone.now().isoformat(), "ds_ttl": 300}
        revision.save(update_fields=["crosscheck"])
        self.assertGreater(rows.get().updated_at, earlier)
        rows.update(updated_at=earlier)
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_ok()
        )
        confirmed = rows.get()
        self.assertIsNotNone(confirmed.confirmed_at)
        self.assertGreater(confirmed.updated_at, earlier)

    def test_customer_transfer_or_same_tenant_service_relink_invalidates_the_binding(self):
        revision = self.checked()
        other = Customer.objects.create(name="New owner")
        Service.objects.filter(pk=self.account.service_id).update(customer=other)
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        self.assertEqual(zones.cached_zone_status(revision.zone)["nameservers"], [])

    def test_viewer_and_foreign_customer_members_cannot_stage_or_confirm(self):
        CustomerMembership.objects.filter(user=self.actor).update(role="viewer")
        self.assertTrue(zones.preview_zone_import(self.account, UPLOAD, actor=self.actor).is_err())

    def test_active_operation_or_lowered_ttl_blocks_enrollment_reservation(self):
        revision = self.checked()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(previous_ttl=86400)
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )

    def test_an_allocated_unpublished_account_name_cannot_be_confirmed_until_dns_sync_proves_it(self):
        revision = self.checked()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records={})
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        self.assertFalse(HostedZoneOperation.objects.exists())
        AccountHostname.objects.filter(pk=self.hostname.pk).update(
            records={"A": {"intended": "95.217.0.20", "applied": "95.217.0.20"}}
        )
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_ok()
        )

    def test_terminated_hosting_and_disagreement_between_account_and_name_target_refuse_confirmation(self):
        revision = self.checked()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="terminated")
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active")
        other = VirtualminServer.objects.create(
            name="different-target", hostname="different.example.org", ipv4_address="95.217.0.21"
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=other)
        self.assertTrue(
            zones.confirm_import(revision.zone, revision.number, revision.manifest_digest, actor=self.actor).is_err()
        )

    def test_new_preview_does_not_mutate_the_old_immutable_confirmation(self):
        first = self.checked()
        second = self.stage(UPLOAD.replace(b"preserve-me", b"new-record-value"))
        first.refresh_from_db()
        self.assertEqual(second.number, first.number + 1)
        self.assertNotEqual(first.manifest_digest, second.manifest_digest)
        self.assertIsNone(first.confirmed_at)

    def test_crosscheck_request_is_a_durable_bounded_job_not_inline_work(self):
        revision = self.stage()
        result = zones.request_crosscheck(revision.zone, revision.number, actor=self.actor)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(HostedZoneOperation.objects.get().kind, "crosscheck")

    def test_a_zone_past_its_import_refuses_the_source_crosscheck_and_keeps_its_state(self):
        """Live DNS of an applied zone serves the managed records, not the upload: a mismatch would fail it."""
        revision = self.stage()
        zone = revision.zone
        for status, activated in (("active", True), ("awaiting_ns", False), ("failed", False)):
            with self.subTest(status=status):
                HostedZone.objects.filter(pk=zone.pk).update(
                    applied_revision=revision.number,
                    activation={"activated_at": timezone.now().isoformat()} if activated else {},
                )
                zone.refresh_from_db()
                force_status(zone, status)
                result = zones.request_crosscheck(zone, revision.number, actor=self.actor)
                self.assertEqual(result, Err("zone_crosscheck_not_applicable"))
                zone.refresh_from_db()
                self.assertEqual(zone.status, status)
                self.assertFalse(zone.operations.exists())
                self.assertFalse(zones.cached_zone_status(zone)["crosscheck_available"])

    def test_a_zone_past_its_import_refuses_a_new_upload_and_keeps_its_revision(self):
        """A new upload would move the revision and clear readiness, with no check left to confirm it."""
        revision = self.stage()
        zone = revision.zone
        HostedZone.objects.filter(pk=zone.pk).update(
            applied_revision=revision.number, readiness={"revision": revision.number, "complete": True}
        )
        zone.refresh_from_db()
        force_status(zone, "active")
        result = zones.preview_zone_import(self.account, UPLOAD.replace(b"preserve-me", b"new-value"), actor=self.actor)
        self.assertEqual(result, Err("zone_import_not_applicable"))
        zone.refresh_from_db()
        self.assertEqual(
            (zone.status, zone.current_revision, zone.readiness["revision"]), ("active", revision.number, 1)
        )
        self.assertEqual(zone.revisions.count(), 1)

    def test_an_importing_zone_still_offers_and_accepts_the_source_crosscheck(self):
        revision = self.stage()
        self.assertTrue(zones.cached_zone_status(revision.zone)["crosscheck_available"])
        self.assertTrue(zones.request_crosscheck(revision.zone, revision.number, actor=self.actor).is_ok())

    def test_status_is_paginated_and_never_copies_private_wire_inventory_into_the_public_payload(self):
        revision = self.stage((HEADER + "".join(f'token{index} TXT "value{index}"\n' for index in range(150))).encode())
        first = zones.cached_zone_status(revision.zone, page=1, page_size=100)
        second = zones.cached_zone_status(revision.zone, page=2, page_size=100)
        self.assertEqual(first["inventory_total"], 152)
        self.assertEqual(first["pages"], 2)
        self.assertEqual(len(first["inventory"]), 100)
        self.assertEqual(len(second["inventory"]), 52)
        self.assertEqual(len(first["inventory"] + second["inventory"]), len(revision.inventory))
        self.assertNotIn('"wire"', json.dumps(first))
        self.assertEqual(first["nameservers"], [])

    def test_nested_managed_diff_can_be_fully_inspected_on_later_pages(self):
        rows = "".join(f"@ A 95.217.1.{index}\n@ AAAA 2a01:4f9:c010::{index:x}\n" for index in range(1, 76))
        revision = self.stage((HEADER + rows).encode())
        first = zones.cached_zone_status(revision.zone, page=1)
        second = zones.cached_zone_status(revision.zone, page=2)
        before_first = next(row for row in first["normalizations"] if row["kind"] == "managed_frontend")["before"]
        before_second = next(row for row in second["normalizations"] if row["kind"] == "managed_frontend")["before"]
        self.assertEqual(len(before_first + before_second), 150)
        self.assertEqual(first["version"], 1)

    def test_normalization_groups_and_duplicate_rows_are_all_reachable_within_one_hundred_items_per_page(self):
        revision = self.stage((HEADER + '@ TXT "duplicate"\n' * 200).encode())
        statuses = [zones.cached_zone_status(revision.zone, page=page) for page in range(1, 4)]
        self.assertTrue(all(len(status["normalizations"]) <= 100 for status in statuses))
        duplicates = [
            row for status in statuses for row in status["normalizations"] if row["kind"] == "duplicate_collapsed"
        ]
        self.assertEqual(len(duplicates), 199)

    def test_provider_canonicalization_is_applied_to_manifest_data_before_ownership_digest(self):
        revision = self.stage((HEADER + '@ CAA 0 ISSUE "letsencrypt.org"\n').encode())
        caa = next(row for row in revision.manifest if row["record_type"] == "CAA")
        self.assertIn("issue", caa["rdata"]["text"])
        self.assertNotIn("ISSUE", caa["rdata"]["text"])

    def test_an_rrset_larger_than_the_bounded_authoritative_proof_is_refused_before_any_provider_intent(self):
        self.assertTrue(
            self.stage((HEADER + "".join(f'large TXT "value-{index}"\n' for index in range(128))).encode()).valid
        )
        revision = self.stage((HEADER + "".join(f'large TXT "value-{index}"\n' for index in range(129))).encode())
        self.assertFalse(revision.valid)
        self.assertFalse(HostedZoneOperation.objects.exists())
        self.assertEqual(revision.errors[0]["code"], "rrset_record_limit")
