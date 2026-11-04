"""Only fully authenticated, signed browser addresses become short-lived customer history."""

from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.db import DatabaseError
from django.db.models import QuerySet
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.customers.models import Customer
from apps.security.customer_ips import record_recent_customer_ip
from apps.security.models import CustomerIPObservation
from apps.security.tasks import prune_security_history
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=True,
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class CustomerIPObservationTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.password = "Fixture-password-123!"
        self.user = User.objects.create_user(email="customer-ip@example.test", password=self.password)
        self.customers = [
            Customer.objects.create(name=f"Customer {index}", customer_type="company", status="active")
            for index in range(3)
        ]
        for index, customer in enumerate(self.customers):
            CustomerMembership.objects.create(user=self.user, customer=customer, role="owner", is_active=index < 2)

    def login(self, **data):
        return self.portal_post("/api/users/login/", {"email": self.user.email, "password": self.password, **data})

    def test_complete_login_records_every_active_membership_with_canonical_bytes(self) -> None:

        result = self.login(client_ip="::ffff:198.51.100.29")
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result.json()["security_observation"], {"enabled": True, "recorded": True, "degraded": False})
        rows = list(CustomerIPObservation.objects.filter(user=self.user).order_by("customer_id"))
        self.assertEqual([row.customer_id for row in rows], [customer.pk for customer in self.customers[:2]])
        self.assertEqual({row.address_family for row in rows}, {4})
        self.assertEqual({bytes(row.address) for row in rows}, {b"\0" * 12 + bytes((198, 51, 100, 29))})
        self.assertEqual({row.ip_address for row in rows}, {"198.51.100.29"})

    def test_failed_password_or_missing_second_factor_never_records_an_ip(self) -> None:

        failed = self.login(password="wrong", client_ip="198.51.100.29")
        self.assertEqual(failed.status_code, 401)
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = pyotp.random_base32()
        self.user.save(update_fields=["two_factor_enabled", "_two_factor_secret"])
        factor = self.login(client_ip="198.51.100.29")
        self.assertEqual(factor.status_code, 401)
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_unsigned_forwarding_headers_cannot_supply_an_observation(self) -> None:

        result = self.portal_post(
            "/api/users/login/",
            {"email": self.user.email, "password": self.password},
            HTTP_X_FORWARDED_FOR="198.51.100.29",
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["security_observation"], {"enabled": True, "recorded": False, "degraded": True})
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_observation_storage_failure_preserves_the_successful_platform_session(self) -> None:

        with patch(
            "apps.security.customer_ips._write_observations",
            side_effect=DatabaseError("fixture observation unavailable"),
        ):
            result = self.login(client_ip="198.51.100.29")
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result.json()["security_observation"], {"enabled": True, "recorded": False, "degraded": True})
        self.assertTrue(PortalSession.objects.filter(pk=result.json()["session_id"], user=self.user).exists())

    def test_observations_are_exported_and_erased_without_repopulation(self) -> None:

        self.assertEqual(self.login(client_ip="198.51.100.29").status_code, 200)
        exported = GDPRExportService._collect_user_data(
            self.user,
            {
                "include_profile": False,
                "include_customers": False,
                "include_billing": False,
                "include_tickets": False,
                "include_emails": False,
                "include_audit_logs": True,
            },
        )
        self.assertEqual(len(exported["recent_customer_ip_observations"]), 2)
        self.assertEqual(
            GDPRExportService._count_records(exported), 3 + len(exported["audit_summary"]["recent_activities"])
        )
        self.assertEqual({row["ip_address"] for row in exported["recent_customer_ip_observations"]}, {"198.51.100.29"})
        result = GDPRDeletionService._anonymize_user_data(self.user)
        self.assertTrue(result.is_ok(), result)
        self.assertFalse(CustomerIPObservation.objects.filter(user=self.user).exists())
        self.assertTrue(record_recent_customer_ip(user_id=self.user.pk, ip="198.51.100.29").healthy)
        self.assertFalse(CustomerIPObservation.objects.filter(user=self.user).exists())

    def test_retention_removes_only_observations_older_than_seven_days(self) -> None:

        self.assertEqual(self.login(client_ip="198.51.100.29").status_code, 200)
        rows = list(CustomerIPObservation.objects.order_by("customer_id"))
        CustomerIPObservation.objects.filter(pk=rows[0].pk).update(last_seen_at=timezone.now() - timedelta(days=8))
        CustomerIPObservation.objects.filter(pk=rows[1].pk).update(last_seen_at=timezone.now() - timedelta(days=6))
        pruned = prune_security_history()
        self.assertEqual(pruned["observations"], 1)
        self.assertEqual(list(CustomerIPObservation.objects.values_list("pk", flat=True)), [rows[1].pk])

    def test_repeated_success_refreshes_last_seen_without_creating_duplicates(self) -> None:

        self.assertEqual(self.login(client_ip="198.51.100.29").status_code, 200)
        original = timezone.now() - timedelta(days=4)
        CustomerIPObservation.objects.update(created_at=original, last_seen_at=original)
        self.assertEqual(self.login(client_ip="198.51.100.29").status_code, 200)
        rows = list(CustomerIPObservation.objects.all())
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.created_at == original and row.last_seen_at > original for row in rows))

    @override_settings(CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=False)
    def test_disabled_collection_does_not_write_or_claim_recording(self) -> None:
        with patch("apps.security.customer_ips._write_observations") as writer:
            response = self.login(client_ip="198.51.100.29")
        self.assertEqual(response.status_code, 200)
        writer.assert_not_called()
        self.assertEqual(
            response.json()["security_observation"], {"enabled": False, "recorded": False, "degraded": False}
        )

    def test_retention_keeps_a_successful_login_refreshed_after_candidate_selection(self) -> None:
        self.assertEqual(self.login(client_ip="198.51.100.29").status_code, 200)
        CustomerIPObservation.objects.update(last_seen_at=timezone.now() - timedelta(days=8))
        original_delete = QuerySet.delete
        refreshed = []

        def refresh_after_selection(queryset):
            if queryset.model is CustomerIPObservation and queryset.exists():
                recorded = record_recent_customer_ip(user_id=self.user.pk, ip="198.51.100.29")
                self.assertTrue(recorded.healthy)
                self.assertEqual(recorded.customer_count, 2)
                refreshed.append(True)
            return original_delete(queryset)

        with patch.object(QuerySet, "delete", refresh_after_selection):
            pruned = prune_security_history()
        self.assertEqual(refreshed, [True])
        self.assertEqual(CustomerIPObservation.objects.count(), 2)
        self.assertEqual(pruned["observations"], 0)
