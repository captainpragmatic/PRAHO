"""Retained source dependencies cross the real signed current-customer boundary."""

import json
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.infrastructure.maintenance_retained_fixtures import RetainedMaintenanceFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "retained-api"}},
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    PORTAL_HMAC_CREDENTIALS=None,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    Q_CLUSTER={"name": "retained-api", "orm": "default", "retry": 100000},
)
class RetainedMaintenanceAPITests(RetainedMaintenanceFixture, HMACTestMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.reader = User.objects.create_user(email="retained-reader@example.test", password=None)
        CustomerMembership.objects.create(customer=self.customer, user=self.reader, role="owner")

    def read(self, customer, *, detail: bool = False):
        path = f"/api/maintenance/services/{self.account.service_id}/" if detail else "/api/maintenance/summary/"
        return self.portal_post(path, {"customer_id": customer.pk, "user_id": self.reader.pk})

    def test_signed_source_summary_and_detail_find_retained_services_without_native_metadata(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source()

        for detail in (False, True):
            with self.subTest(detail=detail):
                response = self.read(self.customer, detail=detail)
                self.assertEqual(response.status_code, 200, response.content)
                windows = response.json()["data"]["maintenance"]["windows"]
                self.assertEqual([row["id"] for row in windows], [str(window.pk)])
                self.assertEqual(windows[0]["service_ids"], [self.account.service_id])
                serialized = json.dumps(windows)
                for secret_identity in (str(self.node.pk), self.node.hostname, self.account.virtualmin_username):
                    self.assertNotIn(secret_identity, serialized)

    def test_retained_source_scope_tracks_current_customer_and_rechecks_membership(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source()
        current_owner = Customer.objects.create(
            name="Current retained owner", primary_email="current-owner@example.test"
        )
        # Deliberate persisted ownership transfer; no historical snapshot grants access.
        self.account.service.customer = current_owner
        self.account.service.save(update_fields=["customer", "updated_at"])

        self.assertEqual(self.read(self.customer).json()["data"]["maintenance"]["windows"], [])
        self.assertEqual(self.read(self.customer, detail=True).status_code, 404)
        self.assertEqual(self.read(current_owner).status_code, 403)
        membership = CustomerMembership.objects.create(customer=current_owner, user=self.reader, role="owner")
        response = self.read(current_owner)
        self.assertEqual([row["id"] for row in response.json()["data"]["maintenance"]["windows"]], [str(window.pk)])
        membership.is_active = False
        membership.save(update_fields=["is_active"])
        self.assertEqual(self.read(current_owner).status_code, 403)

    def test_next_signed_refresh_clears_only_released_source_and_preserves_target_window(self) -> None:
        self.publish_retained_website()
        self.assertEqual(self.read(self.customer).json()["data"]["maintenance"]["windows"], [])
        source = self.schedule_source()
        target = create_window(
            self.target.pk,
            actor=self.actor,
            kind="panel_update",
            execution_mode="manual",
            starts_at=source.starts_at,
            ends_at=source.ends_at,
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="Website server maintenance.",
        )
        self.assertEqual(
            {row["id"] for row in self.read(self.customer).json()["data"]["maintenance"]["windows"]},
            {str(source.pk), str(target.pk)},
        )

        self.release_retained_source()

        response = self.read(self.customer)
        self.assertEqual([row["id"] for row in response.json()["data"]["maintenance"]["windows"]], [str(target.pk)])

    def test_executed_outcome_keeps_frozen_services_after_release_and_excludes_later_arrivals(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source(due=True)
        change_window(window.pk, actor=self.actor, revision=1, action="start", reason="Perform source checks")
        self.release_retained_source()
        change_window(
            window.pk,
            actor=self.actor,
            revision=1,
            action="finish",
            reason="Record source outcome",
            outcome="failed",
            public_outcome="Mail checks need follow-up.",
            attestation=True,
        )
        later = self.account_on_node("late-execution-retained.example.test")

        result = self.read(self.customer).json()["data"]["maintenance"]

        self.assertEqual(result["windows"], [])
        self.assertEqual(result["last_completed"]["service_ids"], [self.account.service_id])
        self.assertNotIn(later.service_id, result["last_completed"]["service_ids"])
        later_response = self.portal_post(
            f"/api/maintenance/services/{later.service_id}/",
            {"customer_id": self.customer.pk, "user_id": self.reader.pk},
        )
        self.assertIsNone(later_response.json()["data"]["maintenance"]["last_completed"])

    def test_not_run_signed_receipt_does_not_expand_after_source_release_and_later_arrival(self) -> None:
        self.publish_retained_website()
        window = self.schedule_source(due=True)
        with patch(
            "apps.infrastructure.node_maintenance_tasks.timezone.now",
            return_value=window.start_by + timedelta(seconds=1),
        ):
            tick_node_maintenance(window_ids=[str(window.pk)])
            self.release_retained_source()
            later = self.account_on_node("late-notrun-retained.example.test")

            result = self.read(self.customer).json()["data"]["maintenance"]
            later_response = self.portal_post(
                f"/api/maintenance/services/{later.service_id}/",
                {"customer_id": self.customer.pk, "user_id": self.reader.pk},
            )
            self.assertIsNone(later_response.json()["data"]["maintenance"]["last_completed"])

        self.assertEqual(result["last_completed"]["service_ids"], [self.account.service_id])
        self.assertNotIn(later.service_id, result["last_completed"]["service_ids"])
        window.refresh_from_db()
        self.assertIsNone(window.started_at)
        self.assertFalse(window.executions.exists())
