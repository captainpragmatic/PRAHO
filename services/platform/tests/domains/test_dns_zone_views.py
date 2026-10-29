"""Staff diagnostics are bounded database reads, with explicit background intents."""

from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains.dns_zone_models import HostedZone, HostedZoneImportRevision, HostedZoneOperation
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status


class HostedZoneStaffViewsTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_superuser(email="zone-staff@example.net")
        self.customer = Customer.objects.create(name="DNS customer", status="active")
        self.zone = HostedZone.objects.create(name="customer.example", customer=self.customer)
        self.revision = HostedZoneImportRevision.objects.create(
            zone=self.zone,
            number=1,
            raw_upload=b"@ TXT test",
            raw_digest="a" * 64,
            inventory_digest="b" * 64,
            manifest_digest="c" * 64,
        )
        self.operation = HostedZoneOperation.objects.create(
            zone=self.zone,
            revision=self.revision,
            kind="crosscheck",
            evidence={"detail": "<script>bad()</script>" + "x" * 20000},
        )
        self.client.force_login(self.staff)
        self.enterContext(
            patch(
                "apps.infrastructure.dns_zone_gateway.get_zone_gateway", side_effect=AssertionError("request provider")
            )
        )

    def test_staff_zone_list_shows_the_customer_and_recorded_state(self):
        response = self.client.get("/domains/admin/zones/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.zone.name)
        self.assertContains(response, "DNS customer")

    def test_staff_detail_reads_escaped_bounded_operation_evidence(self):
        response = self.client.get(f"/domains/admin/zones/{self.zone.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "crosscheck")
        self.assertNotContains(response, "<script>bad()")
        self.assertNotContains(response, "x" * 14000)

    def test_staff_detail_offers_the_source_check_only_during_the_import(self):
        path = f"/domains/admin/zones/{self.zone.pk}/"
        action = reverse("domains:zone_crosscheck", args=[self.zone.pk])
        self.assertContains(self.client.get(path), action)
        HostedZone.objects.filter(pk=self.zone.pk).update(applied_revision=1)
        self.zone.refresh_from_db()
        force_status(self.zone, "active")
        self.assertNotContains(self.client.get(path), action)

    def test_customer_user_cannot_read_staff_operation_evidence(self):
        self.client.force_login(User.objects.create_user(email="zone-viewer@example.net"))
        for path in ("/domains/admin/zones/", f"/domains/admin/zones/{self.zone.pk}/"):
            response = self.client.get(path)
            self.assertIn(response.status_code, (302, 403))
            self.assertNotIn(self.zone.name, response.content.decode())

    def test_staff_crosscheck_is_post_only_and_passes_the_canonical_actor(self):
        path = f"/domains/admin/zones/{self.zone.pk}/crosscheck/"
        with patch("apps.domains.dns_zone_views.request_crosscheck", return_value=Ok(self.operation)) as check:
            self.assertEqual(self.client.get(path).status_code, 405)
            response = self.client.post(path, {"expected_revision": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(check.call_args.kwargs["actor"], self.staff)
        self.assertEqual(check.call_args.args[1], 1)

    def test_zone_pages_are_linked_from_staff_domain_management(self):
        self.assertEqual(reverse("domains:zone_list"), "/domains/admin/zones/")
        self.assertContains(self.client.get(reverse("domains:admin_list")), "Hosted DNS zones")

    def test_staff_retry_persists_background_intent_with_the_canonical_actor(self):
        HostedZone.objects.filter(pk=self.zone.pk).update(current_revision=1)
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(status="parked")
        path = f"/domains/admin/zones/{self.zone.pk}/retry/"
        self.assertEqual(self.client.get(path).status_code, 405)
        with patch("apps.domains.dns_zone_services._audit") as audit:
            response = self.client.post(path)
        self.assertEqual(response.status_code, 302)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "waiting")
        self.assertEqual(audit.call_args.kwargs["actor"], self.staff)
        self.assertEqual(audit.call_args.args[1], "dns_zone_retry_requested")

    def test_staff_retry_preserves_an_ambiguous_zone_create_for_manual_reconciliation(self):
        HostedZone.objects.filter(pk=self.zone.pk).update(current_revision=1)
        HostedZoneOperation.objects.filter(pk=self.operation.pk).update(
            status="parked", kind="apply", phase="create_zone_inflight"
        )
        response = self.client.post(f"/domains/admin/zones/{self.zone.pk}/retry/")
        self.assertEqual(response.status_code, 302)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "parked")
