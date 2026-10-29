"""Zone identity and durable record slots do not depend on a registrar or provider record lifetime."""

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.domains.dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneRecord


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class HostedZoneModelTests(TestCase):
    def setUp(self):
        self.customer = Customer.objects.create(name="Zone owner", primary_email="owner@example.net")

    def test_canonical_zone_identity_is_unique_across_customers_including_bulk_writes(self):
        first = HostedZone.objects.create(customer=self.customer, name="BÜCHER.EXAMPLE.NET.")
        self.assertEqual(first.name, "xn--bcher-kva.example.net")
        other = Customer.objects.create(name="Other owner", primary_email="other@example.net")
        with self.assertRaises(IntegrityError), transaction.atomic():
            HostedZone.objects.bulk_create([HostedZone(customer=other, name="xn--bcher-kva.example.net")])

    def test_external_registered_domain_requires_no_registered_domain_or_hosting_fk(self):
        zone = HostedZone.objects.create(customer=self.customer, name="external.example.net")
        self.assertIsNone(zone.domain_id)
        self.assertIsNone(zone.service_id)
        self.assertIsNone(zone.account_id)

    def test_partial_refresh_preserves_the_protected_lifecycle_state(self):
        zone = HostedZone.objects.create(customer=self.customer, name="customer.example.net")
        zone.refresh_from_db(fields=["readiness"])
        self.assertEqual(zone.status, "pending_import")

    def test_provider_binding_and_customer_cannot_be_replaced_after_creation(self):
        zone = HostedZone.objects.create(
            customer=self.customer, name="customer.example.net", provider_account_id="a" * 32, provider_zone_id="b" * 32
        )
        zone.provider_zone_id = "c" * 32
        with self.assertRaises(ValidationError):
            zone.save()
        with self.assertRaises(ValidationError):
            HostedZone.objects.filter(pk=zone.pk).update(name="victim.example.net")

    def test_multiple_mx_txt_and_address_values_have_distinct_record_identity(self):
        zone = HostedZone.objects.create(customer=self.customer, name="customer.example.net")
        for digest in ("a" * 64, "b" * 64):
            HostedZoneRecord.objects.create(
                zone=zone, name=zone.name, record_type="MX", rdata={"text": digest}, rdata_digest=digest, ttl=3600
            )
        self.assertEqual(zone.records.count(), 2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            HostedZoneRecord.objects.create(
                zone=zone, name=zone.name, record_type="MX", rdata_digest="a" * 64, ttl=3600
            )

    def test_managed_slot_tombstone_retains_provenance_and_allows_a_new_family_record(self):
        zone = HostedZone.objects.create(customer=self.customer, name="customer.example.net")
        old = HostedZoneRecord.objects.create(
            zone=zone,
            name=zone.name,
            record_type="AAAA",
            rdata_digest="a" * 64,
            managed_by="praho",
            managed_slot="apex:AAAA",
            ttl=3600,
            provider_record_id="old",
            evidence={"previous_ttl": 86400},
        )
        old.desired_deleted = True
        old.save(update_fields=["desired_deleted"])
        new = HostedZoneRecord.objects.create(
            zone=zone,
            name=zone.name,
            record_type="AAAA",
            rdata_digest="b" * 64,
            managed_by="praho",
            managed_slot="apex:AAAA",
            ttl=300,
        )
        old.refresh_from_db()
        self.assertNotEqual(old.pk, new.pk)
        self.assertEqual(old.evidence["previous_ttl"], 86400)
        self.assertEqual(old.provider_record_id, "old")

    def test_customer_alias_and_revision_evidence_cannot_bypass_immutable_identity(self):
        zone = HostedZone.objects.create(customer=self.customer, name="customer.example.net")
        other = Customer.objects.create(name="Other", primary_email="other@example.net")
        with self.assertRaises(ValidationError):
            HostedZone.objects.filter(pk=zone.pk).update(customer=other)
        revision = HostedZoneImportRevision.objects.create(
            zone=zone, number=1, raw_upload=b"original", manifest=[{"value": "original"}]
        )
        revision.manifest = [{"value": "changed"}]
        with self.assertRaises(ValidationError):
            revision.save(update_fields=["manifest"])
        with self.assertRaises(ValidationError):
            HostedZoneImportRevision.objects.filter(pk=revision.pk).update(binding={"target": "changed"})
        revision.refresh_from_db()
        revision.crosscheck = {"complete": True, "ok": True}
        revision.save(update_fields=["crosscheck"])
