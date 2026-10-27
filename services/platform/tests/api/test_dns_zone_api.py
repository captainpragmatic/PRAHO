"""Customer-zone intents cross the real signed, tenant-scoped Portal boundary."""

import base64
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.domains.dns_zone_import import MAX_UPLOAD_BYTES, make_record_data
from apps.domains.dns_zone_models import HostedZone, HostedZoneRecord
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "zone-api-tests"}}
UPLOAD = b'$ORIGIN customer.example.\n$TTL 900\n@ IN A 95.217.0.10\nselector-q._domainkey IN TXT "must-survive"\n'


@override_settings(CACHES=CACHE, PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class DnsZoneApiTests(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        self.customer = Customer.objects.create(
            name="Zone owner", primary_email="zone-owner@example.net", status="active"
        )
        self.user = User.objects.create_user(email="zone-owner@example.net")
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Zone hosting", price_monthly=Decimal("10.00"))
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency_id="RON",
            domain="customer.example",
            service_name="Hosting",
            username="zoneowner",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="Node", hostname="private-node.example.net", ipv4_address="95.217.0.10"
        )
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            server=self.server,
            domain="customer.example",
            virtualmin_username="zoneowner",
            status="active",
        )
        self.hostname = AccountHostname.objects.create(
            account=self.account,
            target_server=self.server,
            label="abc12345",
            zone="accounts.example.net",
            records={"A": {"intended": "95.217.0.10", "applied": "95.217.0.10", "ttl": 900, "applied_ttl": 900}},
        )
        self.path = "/api/dns/zones/"

    def identity(self, **values):
        return {"customer_id": self.customer.pk, "user_id": self.user.pk, **values}

    def stage(self):
        response = self.portal_post(
            self.path + "import/",
            self.identity(service_id=self.service.pk, zone_file=base64.b64encode(UPLOAD).decode()),
        )
        self.assertEqual(response.status_code, 201, response.content)
        return HostedZone.objects.get(account=self.account)

    def test_unsigned_and_forged_requests_are_refused(self):
        self.assertEqual(self.client.post(self.path, b"{}", content_type="application/json").status_code, 401)
        self.assertEqual(self.portal_post(self.path, self.identity(), HTTP_X_SIGNATURE="0" * 64).status_code, 401)

    def test_upload_stages_complete_inventory_without_provider_calls(self):
        with patch(
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway", side_effect=AssertionError("request network")
        ):
            zone = self.stage()
        receipt = self.portal_post(f"{self.path}{zone.pk}/", self.identity())
        self.assertEqual(receipt.status_code, 200, receipt.content)
        self.assertContains(receipt, "selector-q._domainkey.customer.example")
        self.assertIn("no-store", receipt.headers.get("Cache-Control", ""))
        self.assertNotContains(receipt, "private-node.example.net")

    def test_viewer_and_billing_can_read_but_cannot_upload(self):
        for role in ("viewer", "billing"):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save(update_fields=["role"])
                self.assertEqual(self.portal_post(self.path, self.identity()).status_code, 200)
                self.assertEqual(
                    self.portal_post(
                        self.path + "import/",
                        self.identity(service_id=self.service.pk, zone_file=base64.b64encode(UPLOAD).decode()),
                    ).status_code,
                    403,
                )
        self.assertFalse(HostedZone.objects.exists())

    def test_technical_contact_can_stage_and_revocation_is_immediate(self):
        self.membership.role = "tech"
        self.membership.save(update_fields=["role"])
        zone = self.stage()
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        self.assertEqual(
            self.portal_post(f"{self.path}{zone.pk}/crosscheck/", self.identity(expected_revision=1)).status_code, 403
        )

    def test_foreign_customer_zone_and_absent_zone_are_uniform_404(self):
        zone = self.stage()
        other = Customer.objects.create(name="Other", status="active")
        CustomerMembership.objects.create(user=self.user, customer=other, role="owner")
        for identifier in (zone.pk, uuid4()):
            for suffix in ("", "confirm/"):
                response = self.portal_post(
                    f"{self.path}{identifier}/{suffix}",
                    self.identity(customer_id=other.pk, expected_revision=1, manifest_digest="x"),
                )
                self.assertEqual(response.status_code, 404, response.content)

    def test_posted_zone_name_and_provider_identity_do_not_override_hosting_scope(self):
        zone = self.stage()
        response = self.portal_post(
            f"{self.path}{zone.pk}/", self.identity(provider_zone_id="other", name="victim.example")
        )
        self.assertEqual(response.status_code, 200)
        zone.refresh_from_db()
        self.assertEqual(zone.name, self.account.domain)
        self.assertEqual(zone.provider_zone_id, "")

    def test_bad_base64_oversized_and_nonhosting_imports_are_rejected(self):
        oversized = "A" * (4 * ((MAX_UPLOAD_BYTES + 2) // 3) + 4)
        for upload in ("not!base64", oversized, [], None):
            with self.subTest(upload_type=type(upload).__name__):
                response = self.portal_post(
                    self.path + "import/", self.identity(service_id=self.service.pk, zone_file=upload)
                )
                self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(HostedZone.objects.exists())

    def test_stale_or_boolean_revision_is_not_authority_to_confirm(self):
        zone = self.stage()
        for revision, expected in ((99, 409), (True, 400), (0, 400)):
            response = self.portal_post(
                f"{self.path}{zone.pk}/confirm/", self.identity(expected_revision=revision, manifest_digest="a" * 64)
            )
            self.assertEqual(response.status_code, expected, response.content)
        zone.refresh_from_db()
        self.assertIsNone(zone.confirmed_revision)

    def test_missing_canonical_http_actor_never_becomes_internal_system_authority(self):
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = self.portal_post(
                self.path + "import/",
                self.identity(service_id=self.service.pk, zone_file=base64.b64encode(UPLOAD).decode()),
            )
        self.assertEqual(response.status_code, 403, response.content)

    def test_an_old_zone_list_page_clamps_to_the_available_page(self):
        self.stage()
        response = self.portal_post(self.path, self.identity(page=999))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["page"], 1)
        self.assertEqual(len(response.json()["data"]["zones"]), 1)

    def test_record_reads_are_tenant_scoped_and_managed_updates_are_refused(self):
        zone = self.stage()
        row = HostedZoneRecord.objects.create(
            zone=zone,
            name=zone.name,
            record_type="A",
            rdata=make_record_data("A", "95.217.0.10"),
            rdata_digest="d" * 64,
            ttl=300,
            managed_by="praho",
            managed_slot="apex:A",
        )
        path = f"{self.path}{zone.pk}/records/{row.pk}/"
        response = self.portal_post(path + "detail/", self.identity())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["data"]["record"]["managed"])
        self.assertEqual(self.portal_post(path, self.identity(expected_revision=1, delete=True)).status_code, 409)
        self.assertEqual(
            self.portal_post(f"{self.path}{zone.pk}/records/{uuid4()}/detail/", self.identity()).status_code, 404
        )
