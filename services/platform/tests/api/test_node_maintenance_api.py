"""Maintenance reads cross the real signed customer boundary without native work."""

import json
import time
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.apps import apps
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

SUMMARY_PATH = "/api/maintenance/summary/"
EMPTY_MAINTENANCE = {"windows": [], "last_completed": None}
CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "maintenance-api"}}


@override_settings(
    CACHES=CACHE,
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    PORTAL_HMAC_CREDENTIALS=None,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
)
class _MaintenanceAPIFixture(HMACTestMixin, TestCase):
    staff_client: Client

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="Maintenance customer", primary_email="maintenance@example.test")
        self.user = User.objects.create(email="maintenance@example.test", is_active=True)
        self.membership = CustomerMembership.objects.create(customer=self.customer, user=self.user, role="owner")
        self.other_customer = Customer.objects.create(name="Other maintenance customer")
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(name="Maintenance hosting", price_monthly=Decimal("10.00"))
        self.service = self._service(self.customer, "maintenance-api.example.test")
        self.foreign_service = self._service(self.other_customer, "foreign-maintenance.example.test")
        self.node = VirtualminServer.objects.create(
            name="Private maintenance node", hostname="private-maintenance-node.example.test", status="active"
        )
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            server=self.node,
            domain=self.service.domain,
            virtualmin_username="maintenanceapi",
            status="active",
        )
        self.service_path = self._service_path(self.service.pk)

    def _service(self, customer: Customer, domain: str) -> Service:
        return Service.objects.create(
            customer=customer,
            service_plan=self.plan,
            currency_id="RON",
            service_name="Hosting",
            username=f"maintenance{customer.pk}-{domain.partition('.')[0]}",
            domain=domain,
            price=Decimal("10.00"),
            status="active",
        )

    @staticmethod
    def _service_path(service_id: int) -> str:
        return f"/api/maintenance/services/{service_id}/"

    def _identity(self, **overrides: int) -> dict[str, int]:
        return {"customer_id": self.customer.pk, "user_id": self.user.pk, **overrides}

    def _schedule(
        self, node: VirtualminServer, note: str, *, starts_at: datetime | None = None, duration_minutes: int = 30
    ) -> str:
        zone = ZoneInfo("Europe/Bucharest")
        if starts_at is None:
            starts_at = (timezone.localtime(timezone.now(), zone) + timedelta(days=3)).replace(
                hour=12, minute=0, second=0, microsecond=0
            )
        ends_at = starts_at + timedelta(minutes=duration_minutes)
        policy = self.staff_client.post(
            f"/infrastructure/maintenance/servers/{node.pk}/policy/",
            {
                "timezone": "Europe/Bucharest",
                "weekdays": [str(day) for day in range(7)],
                "starts_time": (starts_at.astimezone(zone) - timedelta(minutes=5)).strftime("%H:%M"),
                "ends_time": (ends_at.astimezone(zone) + timedelta(minutes=5)).strftime("%H:%M"),
                "max_defer_minutes": "30",
            },
        )
        self.assertEqual(policy.status_code, 302, policy.content)
        response = self.staff_client.post(
            f"/infrastructure/maintenance/servers/{node.pk}/create/",
            {
                "kind": "panel_update",
                "execution_mode": "manual",
                "starts_at": starts_at.isoformat(),
                "ends_at": ends_at.isoformat(),
                "expects_downtime": "on",
                "expected_downtime_minutes": "10",
                "customer_note": note,
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        window = apps.get_model("infrastructure", "NodeMaintenanceWindow").objects.get(node_id=node.pk)
        return str(window.pk)

    def _action(self, window_id: str, action: str, **fields: object) -> None:
        window = apps.get_model("infrastructure", "NodeMaintenanceWindow").objects.get(pk=window_id)
        response = self.staff_client.post(
            f"/infrastructure/maintenance/windows/{window_id}/{action}/",
            {
                "revision": window.revision,
                "reason": "Record the actual maintenance test action.",
                "confirmation": "on",
                **fields,
            },
        )
        self.assertEqual(response.status_code, 302, response.content)


class NodeMaintenanceAPIBoundaryTests(_MaintenanceAPIFixture):
    def test_signed_summary_returns_an_explicit_empty_result_without_a_window(self) -> None:
        response = self.portal_post(SUMMARY_PATH, self._identity())

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json(), {"success": True, "data": {"maintenance": EMPTY_MAINTENANCE}})
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_signed_service_read_returns_an_explicit_empty_result_without_a_window(self) -> None:
        response = self.portal_post(self.service_path, self._identity())

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json(), {"success": True, "data": {"maintenance": EMPTY_MAINTENANCE}})
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_all_active_membership_roles_can_read_their_maintenance(self) -> None:
        for role in ("owner", "tech", "billing", "viewer"):
            self.membership.role = role
            self.membership.save(update_fields=["role"])
            for path in (SUMMARY_PATH, self.service_path):
                with self.subTest(role=role, path=path):
                    response = self.portal_post(path, self._identity())
                    self.assertEqual(response.status_code, 200, response.content)

    def test_an_inactive_membership_is_refused_by_both_reads(self) -> None:
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                self.assertEqual(self.portal_post(path, self._identity()).status_code, 403)

    def test_a_revoked_membership_is_refused_by_both_reads(self) -> None:
        self.membership.delete()

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                self.assertEqual(self.portal_post(path, self._identity()).status_code, 403)

    def test_an_inactive_user_is_refused_by_both_reads(self) -> None:
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                self.assertEqual(self.portal_post(path, self._identity()).status_code, 401)

    def test_a_valid_signature_does_not_grant_foreign_customer_membership(self) -> None:
        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_post(path, self._identity(customer_id=self.other_customer.pk))
                self.assertEqual(response.status_code, 403, response.content)

    def test_foreign_and_absent_services_have_the_same_refusal(self) -> None:
        foreign = self.portal_post(self._service_path(self.foreign_service.pk), self._identity())
        missing = self.portal_post(self._service_path(999999999), self._identity())

        self.assertEqual(foreign.status_code, 404, foreign.content)
        self.assertEqual(missing.status_code, 404, missing.content)
        self.assertEqual(foreign.json(), missing.json())

    def test_unsigned_and_forged_requests_are_refused(self) -> None:
        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                unsigned = self.client.post(path, b"{}", content_type="application/json")
                forged = self.portal_post(path, self._identity(), HTTP_X_SIGNATURE="0" * 64)
                self.assertEqual(unsigned.status_code, 401, unsigned.content)
                self.assertEqual(forged.status_code, 401, forged.content)

    def test_a_replayed_signed_summary_is_refused_after_the_first_success(self) -> None:
        body = json.dumps({**self._identity(), "timestamp": time.time()}).encode()
        headers = hmac_headers("POST", SUMMARY_PATH, body, nonce="maintenance-api-replay-" + "a" * 32)

        first = self.client.post(SUMMARY_PATH, body, content_type="application/json", **headers)
        second = self.client.post(SUMMARY_PATH, body, content_type="application/json", **headers)

        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(second.status_code, 401, second.content)

    def test_signed_get_bodies_do_not_introduce_a_second_identity_contract(self) -> None:
        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_get(path, self._identity())
                self.assertEqual(response.status_code, 405, response.content)

    def test_customer_identity_cannot_be_changed_after_signing(self) -> None:
        payload = {**self._identity(), "timestamp": time.time()}
        body = json.dumps(payload).encode()
        headers = hmac_headers("POST", SUMMARY_PATH, body)
        substituted = json.dumps({**payload, "customer_id": self.other_customer.pk}).encode()

        response = self.client.post(SUMMARY_PATH, substituted, content_type="application/json", **headers)

        self.assertEqual(response.status_code, 401, response.content)

    def test_reads_do_not_probe_a_node_or_enqueue_work(self) -> None:
        with (
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.call") as native,
            patch("django_q.tasks.async_task") as enqueue,
        ):
            for path in (SUMMARY_PATH, self.service_path):
                with self.subTest(path=path):
                    response = self.portal_post(path, self._identity())
                    self.assertEqual(response.status_code, 200, response.content)
            native.assert_not_called()
            enqueue.assert_not_called()


class NodeMaintenanceAPIAudienceTests(_MaintenanceAPIFixture):
    """Nonempty real windows distinguish ownership filtering from always-empty output."""

    def setUp(self) -> None:
        super().setUp()
        self.second_node = VirtualminServer.objects.create(
            name="Private second node",
            hostname="private-second-maintenance.example.test",
            ipv4_address="192.0.2.32",
            status="active",
        )
        self.foreign_node = VirtualminServer.objects.create(
            name="Private foreign node",
            hostname="private-foreign-maintenance.example.test",
            ipv4_address="192.0.2.33",
            status="active",
        )
        self.second_service = self._service(self.customer, "second-maintenance.example.test")
        self.foreign_shared_service = self._service(self.other_customer, "shared-maintenance.example.test")
        for service, node, username in (
            (self.second_service, self.second_node, "maintenancesecond"),
            (self.foreign_service, self.foreign_node, "maintenanceforeign"),
            (self.foreign_shared_service, self.node, "maintenanceshared"),
        ):
            VirtualminAccount.objects.create(
                service=service, server=node, domain=service.domain, virtualmin_username=username, status="active"
            )
        self.other_user = User.objects.create(email="foreign-maintenance@example.test", is_active=True)
        CustomerMembership.objects.create(customer=self.other_customer, user=self.other_user, role="owner")
        self.staff = User.objects.create_superuser(email="maintenance-staff@example.test", password=None)
        self.staff_client = Client()
        self.staff_client.force_login(self.staff)
        self.first_window = self._schedule(self.node, "Public first maintenance window")
        self.second_window = self._schedule(self.second_node, "Public second maintenance window")
        self.foreign_window = self._schedule(self.foreign_node, "Foreign customer's maintenance window")

    def test_summary_contains_only_windows_for_currently_owned_services(self) -> None:
        response = self.portal_post(SUMMARY_PATH, self._identity())

        self.assertEqual(response.status_code, 200, response.content)
        maintenance = response.json()["data"]["maintenance"]
        windows = {window["id"]: window for window in maintenance["windows"]}
        self.assertEqual(set(windows), {self.first_window, self.second_window})
        self.assertEqual(windows[self.first_window]["service_ids"], [self.service.pk])
        self.assertEqual(windows[self.second_window]["service_ids"], [self.second_service.pk])
        self.assertIsNone(maintenance["last_completed"])
        self.assertNotIn("Foreign customer's maintenance window", response.content.decode())

    def test_a_service_lookup_contains_only_that_services_window(self) -> None:
        for service, expected in ((self.service, self.first_window), (self.second_service, self.second_window)):
            with self.subTest(service=service.pk):
                response = self.portal_post(self._service_path(service.pk), self._identity())
                self.assertEqual(response.status_code, 200, response.content)
                windows = response.json()["data"]["maintenance"]["windows"]
                self.assertEqual([window["id"] for window in windows], [expected])
                self.assertEqual(windows[0]["service_ids"], [service.pk])

    def test_a_shared_node_does_not_leak_the_other_customers_service_ids(self) -> None:
        response = self.portal_post(
            SUMMARY_PATH, {"customer_id": self.other_customer.pk, "user_id": self.other_user.pk}
        )

        self.assertEqual(response.status_code, 200, response.content)
        windows = {window["id"]: window for window in response.json()["data"]["maintenance"]["windows"]}
        self.assertEqual(set(windows), {self.first_window, self.foreign_window})
        self.assertEqual(windows[self.first_window]["service_ids"], [self.foreign_shared_service.pk])
        self.assertEqual(windows[self.foreign_window]["service_ids"], [self.foreign_service.pk])

    def test_nonempty_windows_expose_only_the_public_contract(self) -> None:
        response = self.portal_post(SUMMARY_PATH, self._identity())

        self.assertEqual(response.status_code, 200, response.content)
        windows = response.json()["data"]["maintenance"]["windows"]
        self.assertEqual(len(windows), 2)
        expected_fields = {
            "id",
            "kind",
            "status",
            "starts_at",
            "ends_at",
            "started_at",
            "finished_at",
            "expects_downtime",
            "expected_downtime_minutes",
            "customer_note",
            "public_outcome",
            "completion_source",
            "was_overrun",
            "service_ids",
        }
        for window in windows:
            with self.subTest(window=window["id"]):
                self.assertEqual(set(window), expected_fields)
                self.assertEqual(window["status"], "scheduled")
                self.assertTrue(window["expects_downtime"])
                self.assertEqual(window["expected_downtime_minutes"], 10)
                self.assertEqual(window["public_outcome"], "")
                self.assertEqual(window["completion_source"], "")
        for node in (self.node, self.second_node, self.foreign_node):
            for private in (str(node.pk), node.name, node.hostname):
                self.assertNotIn(private, response.content.decode())
        self.assertNotIn("192.0.2.32", response.content.decode())
        self.assertNotIn("192.0.2.33", response.content.decode())


class NodeMaintenanceAPICompletionTests(_MaintenanceAPIFixture):
    public_outcome = "Maintenance completed; hosting checked."

    def setUp(self) -> None:
        super().setUp()
        staff = User.objects.create_superuser(email="maintenance-completion@example.test", password=None)
        self.staff_client = Client()
        self.staff_client.force_login(staff)
        self.window_id = self._schedule(
            self.node,
            "Current manual maintenance",
            starts_at=timezone.now() - timedelta(seconds=30),
            duration_minutes=60,
        )

    def _finish(self) -> datetime:
        self._action(self.window_id, "start")
        self._action(
            self.window_id, "finish", outcome="completed", public_outcome=self.public_outcome, attestation="on"
        )
        window = apps.get_model("infrastructure", "NodeMaintenanceWindow").objects.get(pk=self.window_id)
        self.assertEqual(window.status, "completed")
        self.assertIsInstance(window.finished_at, datetime)
        return window.finished_at

    def test_actual_manual_completion_returns_only_its_safe_public_outcome(self) -> None:
        self._finish()
        private = "private-provider-failure-must-stay-in-platform"
        model = apps.get_model("infrastructure", "NodeMaintenanceWindow")
        model.objects.filter(pk=self.window_id).update(internal_outcome={"provider_error": private})
        self.assertEqual(model.objects.get(pk=self.window_id).internal_outcome, {"provider_error": private})

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_post(path, self._identity())
                self.assertEqual(response.status_code, 200, response.content)
                maintenance = response.json()["data"]["maintenance"]
                self.assertEqual(maintenance["windows"], [])
                completed = maintenance["last_completed"]
                self.assertEqual(completed["id"], self.window_id)
                self.assertEqual(completed["status"], "completed")
                self.assertEqual(completed["completion_source"], "operator")
                self.assertEqual(completed["public_outcome"], self.public_outcome)
                self.assertNotIn(private, response.content.decode())

    def test_completion_visibility_starts_at_finish_and_expires_at_exactly_twenty_four_hours(self) -> None:
        finished_at = self._finish()
        cases = (
            (timedelta(seconds=-1), False),
            (timedelta(0), True),
            (timedelta(hours=24, seconds=-1), True),
            (timedelta(hours=24), False),
            (timedelta(hours=24, seconds=1), False),
        )
        for age, visible in cases:
            with patch("django.utils.timezone.now", return_value=finished_at + age):
                for path in (SUMMARY_PATH, self.service_path):
                    with self.subTest(age=age, path=path):
                        response = self.portal_post(path, self._identity())
                        self.assertEqual(response.status_code, 200, response.content)
                        completed = response.json()["data"]["maintenance"]["last_completed"]
                        self.assertEqual(completed is not None, visible)
                        if visible:
                            self.assertEqual(completed["id"], self.window_id)

    def test_a_completed_service_keeps_its_note_after_placement_changes(self) -> None:
        self._finish()
        destination = VirtualminServer.objects.create(
            name="Moved maintenance account", hostname="moved-maintenance.example.test", status="active"
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=destination)
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).server_id, destination.pk)

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_post(path, self._identity())
                self.assertEqual(response.status_code, 200, response.content)
                completed = response.json()["data"]["maintenance"]["last_completed"]
                self.assertEqual(completed["id"], self.window_id)
                self.assertEqual(completed["service_ids"], [self.service.pk])

    def test_completion_follows_current_ownership_after_a_service_transfer(self) -> None:
        self._finish()
        other_user = User.objects.create(email="new-maintenance-owner@example.test", is_active=True)
        CustomerMembership.objects.create(customer=self.other_customer, user=other_user, role="owner")
        Service.objects.filter(pk=self.service.pk).update(customer=self.other_customer)
        self.assertEqual(Service.objects.get(pk=self.service.pk).customer_id, self.other_customer.pk)

        previous = self.portal_post(SUMMARY_PATH, self._identity())
        self.assertEqual(previous.status_code, 200, previous.content)
        self.assertEqual(previous.json()["data"]["maintenance"], EMPTY_MAINTENANCE)
        self.assertEqual(self.portal_post(self.service_path, self._identity()).status_code, 404)

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_post(path, {"customer_id": self.other_customer.pk, "user_id": other_user.pk})
                self.assertEqual(response.status_code, 200, response.content)
                completed = response.json()["data"]["maintenance"]["last_completed"]
                self.assertEqual(completed["id"], self.window_id)
                self.assertEqual(completed["service_ids"], [self.service.pk])

    def test_a_cancelled_window_has_neither_active_attention_nor_a_completion_note(self) -> None:
        self._action(self.window_id, "cancel")
        window = apps.get_model("infrastructure", "NodeMaintenanceWindow").objects.get(pk=self.window_id)
        self.assertEqual(window.status, "cancelled")

        for path in (SUMMARY_PATH, self.service_path):
            with self.subTest(path=path):
                response = self.portal_post(path, self._identity())
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(response.json()["data"]["maintenance"], EMPTY_MAINTENANCE)

    def test_an_overrun_precedes_an_earlier_started_window_that_is_still_in_progress(self) -> None:
        self._action(self.window_id, "start")
        second_node = VirtualminServer.objects.create(
            name="Overrun priority node", hostname="overrun-priority.example.test", status="active"
        )
        second_service = self._service(self.customer, "overrun-priority.example.test")
        VirtualminAccount.objects.create(
            service=second_service,
            server=second_node,
            domain=second_service.domain,
            virtualmin_username="maintenancepriority",
            status="active",
        )
        second_id = self._schedule(
            second_node, "Overrunning hosting update", starts_at=timezone.now() - timedelta(seconds=10)
        )
        self._action(second_id, "start")
        model = apps.get_model("infrastructure", "NodeMaintenanceWindow")
        second = model.objects.get(pk=second_id)
        first = model.objects.get(pk=self.window_id)
        read_at = second.ends_at + timedelta(seconds=1)
        self.assertLess(first.starts_at, second.starts_at)
        self.assertLess(second.ends_at, read_at)
        self.assertGreater(first.ends_at, read_at)

        with patch("django.utils.timezone.now", return_value=read_at):
            # Prepare this read fixture with the real overdue FSM transition.
            second.mark_overrun()
            second.save(update_fields=["status", "was_overrun", "updated_at"])
            response = self.portal_post(SUMMARY_PATH, self._identity())

        self.assertEqual(response.status_code, 200, response.content)
        windows = response.json()["data"]["maintenance"]["windows"]
        self.assertEqual([window["id"] for window in windows], [second_id, self.window_id])
        self.assertEqual([window["status"] for window in windows], ["overran", "running"])
