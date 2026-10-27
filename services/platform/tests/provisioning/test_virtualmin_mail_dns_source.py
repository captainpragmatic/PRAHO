"""Managed mail proposals observe a complete provider inventory with a fresh private resource binding."""

from dataclasses import replace
from unittest.mock import patch

from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.domains.dns_zone_models import HostedZone
from apps.domains.dns_zone_services import capture_enrollment_binding
from apps.infrastructure.dns_zone_gateway import (
    ProviderZoneRecord,
    ZoneBinding,
    ZoneIdentity,
    ZoneInventory,
    ZoneRecordSpec,
)
from apps.provisioning import virtualmin_mail_dns_source as source
from apps.provisioning.service_models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.users.models import CustomerMembership
from tests.domains.test_dns_zone_import_service import hosting_fixture


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class MailDnsSourceTests(TransactionTestCase):
    def setUp(self):
        self.account, self.name, self.owner = hosting_fixture()
        self.zone = HostedZone.objects.create(
            customer=self.account.service.customer,
            service=self.account.service,
            account=self.account,
            account_hostname=self.name,
            name=self.account.domain,
            provider_account_id="a" * 32,
            provider_zone_id="b" * 32,
            current_revision=1,
            confirmed_revision=1,
            applied_revision=1,
            status="active",
            activation={"activated_at": timezone.now().isoformat()},
            enrollment_binding=capture_enrollment_binding(self.account, self.name),
        )
        self.binding = ZoneBinding("cloudflare", "a" * 32, "b" * 32, self.zone.name)
        self.rows = (
            self.record("c" * 32, self.zone.name, "MX", "10 mail.external.example.org."),
            self.record("d" * 32, "_dmarc." + self.zone.name, "TXT", '"v=DMARC1; p=reject"'),
            self.record("e" * 32, "old._domainkey." + self.zone.name, "TXT", '"external-key"'),
            self.record("f" * 32, "verification." + self.zone.name, "TXT", '"keep-me"', ttl=1800),
        )
        self.inventory = ZoneInventory(ZoneIdentity(self.binding, "active", ()), self.rows)
        self.gateway = self.enterContext(patch.object(source, "get_zone_gateway")).return_value
        self.gateway.list_records.return_value = Ok(self.inventory)

    @staticmethod
    def record(identifier, name, kind, rdata, *, ttl=300):
        return ProviderZoneRecord(identifier, ZoneRecordSpec(identifier, name, kind, ttl, rdata, ""))

    def observe(self):
        return source.observe_managed_mail_dns_source(self.account, actor=self.owner, intent="enable")

    def test_complete_provider_inventory_includes_unregistered_external_records(self):
        result = self.observe()
        self.assertTrue(result.is_ok(), result)
        observed = result.unwrap()
        self.assertEqual(observed.snapshot.zone_name, self.zone.name)
        self.assertEqual(observed.snapshot.scope, "zone")
        self.assertEqual(len(observed.snapshot.records), 4)
        self.assertIn('"keep-me"', {row.rdata for row in observed.snapshot.records})
        self.assertEqual(observed.binding.provider, self.binding)
        self.assertEqual(observed.binding.account_id, self.account.pk)
        self.assertEqual(observed.binding.service_id, self.account.service_id)
        self.assertEqual(observed.binding.zone_id, self.zone.pk)
        self.assertEqual(self.zone.records.count(), 0, "Provider observation must not adopt or write records")
        self.gateway.list_records.assert_called_once_with(self.binding)
        self.gateway.create_record.assert_not_called()
        self.gateway.update_record.assert_not_called()

    def test_same_public_records_recreated_with_new_provider_ids_invalidate_resource_binding(self):
        before = self.observe()
        self.assertTrue(before.is_ok(), before)
        changed = replace(self.rows[0], id="0" * 32)
        self.gateway.list_records.return_value = Ok(replace(self.inventory, records=(changed, *self.rows[1:])))
        after = self.observe()
        self.assertTrue(after.is_ok(), after)
        self.assertEqual(before.unwrap().snapshot.digest, after.unwrap().snapshot.digest)
        self.assertNotEqual(before.unwrap().binding.resource_digest, after.unwrap().binding.resource_digest)

    def test_foreign_provider_identity_is_refused(self):
        foreign = replace(self.binding, account_id="0" * 32)
        self.gateway.list_records.return_value = Ok(
            replace(self.inventory, identity=replace(self.inventory.identity, binding=foreign))
        )
        self.assertEqual(self.observe(), Err("mail_dns_source_identity_changed"))

    def test_provider_errors_are_bounded_and_never_return_raw_material(self):
        self.gateway.list_records.return_value = Err("provider-private-token=canary-must-not-escape")
        result = self.observe()
        self.assertEqual(result.unwrap_err(), "mail_dns_source_unavailable")
        self.assertNotIn("canary", repr(result))

    def test_ownership_revoked_during_inventory_discards_the_observation(self):
        def revoke(_binding):
            CustomerMembership.objects.filter(customer=self.zone.customer, user=self.owner).update(is_active=False)
            return Ok(self.inventory)

        self.gateway.list_records.side_effect = revoke
        self.assertEqual(self.observe(), Err("mail_forbidden"))

    def test_revision_changed_during_inventory_discards_the_observation(self):
        def advance(_binding):
            HostedZone.objects.filter(pk=self.zone.pk).update(current_revision=2)
            return Ok(self.inventory)

        self.gateway.list_records.side_effect = advance
        self.assertEqual(self.observe(), Err("mail_dns_source_changed"))

    def test_stale_account_instance_cannot_restore_or_use_an_old_binding(self):
        original = self.account.domain
        VirtualminAccount.objects.filter(pk=self.account.pk).update(domain="changed.example.net")
        self.assertEqual(self.account.domain, original)
        self.assertEqual(self.observe(), Err("mail_dns_source_unavailable"))
        self.gateway.list_records.assert_not_called()

    def test_duplicate_and_outside_zone_records_refuse_the_complete_snapshot(self):
        outside = self.record("1" * 32, "foreign.example.org", "TXT", '"foreign"')
        for records in ((self.rows[0], self.rows[0]), (*self.rows, outside)):
            with self.subTest(records=len(records)):
                self.gateway.list_records.return_value = Ok(replace(self.inventory, records=records))
                self.assertEqual(self.observe(), Err("mail_dns_source_invalid"))

    def test_no_new_transaction_is_held_across_provider_io(self):
        depth = len(connection.atomic_blocks)

        def inventory(_binding):
            self.assertEqual(len(connection.atomic_blocks), depth)
            return Ok(self.inventory)

        self.gateway.list_records.side_effect = inventory
        result = self.observe()
        self.assertTrue(result.is_ok(), result)

    def test_nested_transaction_refuses_before_provider_io(self):
        with transaction.atomic():
            self.assertEqual(self.observe(), Err("mail_dns_source_requires_worker"))
        self.gateway.list_records.assert_not_called()

    def test_hosting_transfer_does_not_grant_the_new_customer_authority_over_the_old_zone(self):
        customer = Customer.objects.create(name="Next hosting owner")
        CustomerMembership.objects.create(customer=customer, user=self.owner, role="owner")
        Service.objects.filter(pk=self.account.service_id).update(customer=customer)
        self.assertEqual(self.observe(), Err("mail_dns_source_unavailable"))
        self.gateway.list_records.assert_not_called()
        self.zone.refresh_from_db()
        self.assertNotEqual(self.zone.customer_id, customer.pk)

    def test_unrelated_proxied_records_and_owner_tags_are_preserved(self):
        original = self.record("1" * 32, "unrelated." + self.zone.name, "A", "203.0.113.25")
        original = replace(original, spec=replace(original.spec, proxied=True, owner_tag="external-owner"))
        self.gateway.list_records.return_value = Ok(replace(self.inventory, records=(*self.rows, original)))
        result = self.observe()
        self.assertTrue(result.is_ok(), result)
        row = next(record for record in result.unwrap().snapshot.records if record.name == original.spec.name)
        self.assertTrue(row.proxied)
        self.assertEqual(row.owner_tag, "external-owner")

    def test_inventory_record_limit_accepts_below_and_at_limit_and_refuses_above(self):
        for count in (1999, 2000, 2001):
            with self.subTest(records=count):
                records = tuple(
                    self.record(format(index, "032x"), f"r{index}.{self.zone.name}", "TXT", '"keep"')
                    for index in range(count)
                )
                self.gateway.list_records.return_value = Ok(replace(self.inventory, records=records))
                result = self.observe()
                if count <= 2000:
                    self.assertTrue(result.is_ok(), result)
                    self.assertEqual(len(result.unwrap().snapshot.records), count)
                else:
                    self.assertEqual(result, Err("mail_dns_source_invalid"))

    def test_malformed_inventory_values_refuse_without_raw_provider_details(self):
        for label, row in (
            ("identifier", replace(self.rows[0], id=True)),
            ("ttl", replace(self.rows[0], spec=replace(self.rows[0].spec, ttl=True))),
            (
                "record type",
                replace(self.rows[0], spec=replace(self.rows[0].spec, record_type="unknown-private-canary")),
            ),
            (
                "TXT syntax",
                replace(self.rows[1], spec=replace(self.rows[1].spec, rdata='"unterminated-private-canary')),
            ),
            ("owner syntax", replace(self.rows[0], spec=replace(self.rows[0].spec, name="bad.." + self.zone.name))),
        ):
            with self.subTest(field=label):
                self.gateway.list_records.return_value = Ok(replace(self.inventory, records=(row,)))
                result = self.observe()
                self.assertEqual(result, Err("mail_dns_source_invalid"))
                self.assertNotIn("private-canary", repr(result))
