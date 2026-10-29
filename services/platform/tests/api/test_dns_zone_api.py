"""Customer-zone intents cross the real signed, tenant-scoped Portal boundary."""

import base64
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains import dns_zone_services as zones
from apps.domains.dns_zone_import import MAX_UPLOAD_BYTES, make_record_data
from apps.domains.dns_zone_models import HostedZone, HostedZoneRecord
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin, bound_fields, fresh_session

CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "zone-api-tests"}}
UPLOAD = b'$ORIGIN customer.example.\n$TTL 900\n@ IN A 95.217.0.10\nselector-q._domainkey IN TXT "must-survive"\n'
APEX = b"@ IN SOA ns.old.example. hostmaster.customer.example. (1 3600 600 86400 300)\n@ IN NS ns.old.example.\n"
EXPORTABLE = UPLOAD.replace(b"$TTL 900\n", b"$TTL 900\n" + APEX)


@override_settings(CACHES=CACHE, PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class DnsZoneApiTests(BoundSessionMixin, HMACTestMixin, TestCase):
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

    def stage(self, raw=UPLOAD):
        response = self.portal_post(
            self.path + "import/",
            self.identity(service_id=self.service.pk, zone_file=base64.b64encode(raw).decode()),
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

    def test_zone_export_records_a_deletion_receipt_so_only_technical_roles_may_export(self):
        zone = self.stage(EXPORTABLE)
        self.assertTrue(zone.revisions.get(number=zone.current_revision).valid)
        path = f"{self.path}{zone.pk}/export/"
        for role in ("viewer", "billing"):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save(update_fields=["role"])
                self.assertEqual(self.portal_post(f"{self.path}{zone.pk}/", self.identity()).status_code, 200)
                self.assertEqual(self.portal_post(path, self.identity()).status_code, 403)
        zone.refresh_from_db()
        self.assertNotIn("export_digest", zone.deletion)
        self.membership.role = "tech"
        self.membership.save(update_fields=["role"])
        response = self.portal_post(path, self.identity())
        self.assertEqual(response.status_code, 200, response.content)
        exported = base64.b64decode(response.json()["data"]["zone_file"])
        self.assertIn(b"selector-q._domainkey", exported)
        zone.refresh_from_db()
        self.assertEqual(zone.deletion["exported_by"], str(self.user.pk))
        digest = zone.deletion["export_digest"]
        detail = self.portal_post(f"{self.path}{zone.pk}/", self.identity())
        self.assertEqual(detail.json()["data"]["zone"]["export_digest"], digest)
        # Another technical member neither sees that receipt nor deletes on it.
        colleague = User.objects.create_user(email="zone-tech@example.net")
        CustomerMembership.objects.create(user=colleague, customer=self.customer, role="tech")
        detail = self.portal_post(f"{self.path}{zone.pk}/", self.identity(user_id=colleague.pk))
        self.assertEqual(detail.status_code, 200, detail.content)
        self.assertEqual(detail.json()["data"]["zone"]["export_digest"], "")
        refused = self.portal_post(
            f"{self.path}{zone.pk}/delete/",
            self.identity(user_id=colleague.pk, expected_revision=zone.current_revision, export_digest=digest),
        )
        self.assertEqual((refused.status_code, refused.json()["error"]), (409, "current_export_required"))
        self.assertFalse(zone.operations.filter(kind="delete").exists())

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

    def test_malformed_record_values_are_the_fixed_refusal_not_a_server_error(self):
        zone = self.stage()
        # Only a zone bound to its provider zone is editable, so the value reaches the record parser.
        HostedZone.objects.filter(pk=zone.pk).update(provider_account_id="a" * 32, provider_zone_id="b" * 32)
        self.client.raise_request_exception = False
        cases = (
            ("A", "not-an-ip"),
            ("AAAA", "not-an-ip"),
            ("CNAME", "bad..name."),
            ("MX", "ten mail.example."),
            ("TXT", '"unterminated'),
            ("SRV", "1 2 not-a-port target.example."),
            ("CAA", "0 issue"),
            ("BOGUS", "95.217.0.10"),
            ("", "95.217.0.10"),
        )
        for record_type, rdata in cases:
            with self.subTest(record_type=record_type, rdata=rdata):
                response = self.portal_post(
                    f"{self.path}{zone.pk}/records/",
                    self.identity(
                        expected_revision=1, name="new." + zone.name, record_type=record_type, rdata=rdata, ttl=300
                    ),
                )
                self.assertEqual(response.status_code, 409, response.content)
                self.assertEqual(response.json()["error"], "invalid_record")
        zone.refresh_from_db()
        self.assertEqual((zone.current_revision, zone.revisions.count()), (1, 1))

    def test_a_malformed_value_in_an_upload_is_staged_invalid_not_a_server_error(self):
        self.client.raise_request_exception = False
        upload = b"$ORIGIN customer.example.\n$TTL 900\n@ IN A not-an-ip\n"
        response = self.portal_post(
            self.path + "import/",
            self.identity(service_id=self.service.pk, zone_file=base64.b64encode(upload).decode()),
        )
        self.assertEqual(response.status_code, 201, response.content)
        staged = response.json()["data"]["zone"]
        self.assertFalse(staged["valid"])
        self.assertEqual([error["code"] for error in staged["errors"]], ["invalid_zone_file"])

    def test_publishing_needs_a_recent_identity_check_and_a_crosscheck_does_not(self):
        zone = self.stage()
        record = HostedZoneRecord.objects.create(
            zone=zone,
            name="www." + zone.name,
            record_type="A",
            rdata=make_record_data("A", "95.217.0.10"),
            rdata_digest="e" * 64,
            ttl=300,
        )
        session = fresh_session(self.user)
        cases = {
            "confirm": ("confirm_import", "confirm/", {"manifest_digest": "a" * 64}),
            "switch": ("request_nameserver_switch", "switch/", {}),
            "delete": ("request_zone_delete", "delete/", {"export_digest": "b" * 64}),
            "add a record": (
                "request_record_change",
                "records/",
                {"name": "mail." + zone.name, "record_type": "A", "rdata": "95.217.0.11"},
            ),
            "change a record": ("request_record_change", f"records/{record.pk}/", {"delete": True}),
            "crosscheck": ("request_crosscheck", "crosscheck/", {}),
        }
        for name, (service, suffix, data) in cases.items():
            for checked, seconds_ago in (("stale", 301), ("fresh", 0)):
                PortalSession.objects.filter(pk=session.pk).update(
                    reauth_at=timezone.now() - timedelta(seconds=seconds_ago)
                )
                body = self.identity(**bound_fields(session), expected_revision=zone.current_revision, **data)
                with self.subTest(action=name, session=checked), patch.object(zones, service, return_value=Ok(None)) as call:
                    response = self.portal_post(f"{self.path}{zone.pk}/{suffix}", body)
                    if checked == "stale" and name != "crosscheck":
                        self.assertEqual(response.status_code, 403, response.content)
                        self.assertEqual(response.json(), {"success": False, "code": "reauth_required"})
                        call.assert_not_called()  # refused before anything is asked of the provider
                    else:
                        self.assertEqual(response.status_code, 202, response.content)
                        call.assert_called_once()

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
