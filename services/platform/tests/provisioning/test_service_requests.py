"""Customer submissions become tickets with private, staff-controlled review."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.service_request_models import ServiceRequest
from apps.provisioning.service_request_service import review_service_request
from apps.tickets.models import Ticket
from apps.tickets.services import TicketStatusService
from apps.tickets.tasks import auto_close_inactive_tickets
from apps.users.models import CustomerMembership, User, UserProfile
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class ServiceRequestTests(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        self.customer = Customer.objects.create(name="Requests SRL", status="active")
        self.user = User.objects.create_user(email="requester@example.test", password="Customer-test123!")
        self.staff = User.objects.create_user(
            email="reviewer@example.test", password="Staff-test123!", is_staff=True, staff_role="support"
        )
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Hosting", plan_type="shared_hosting", price_monthly="20.00")
        self.service = Service.objects.create(
            customer=self.customer, service_plan=plan, currency=currency, service_name="Customer hosting",
            username="requests", domain="requests.example.test", price="20.00", status="active",
        )
        self.path = f"/api/services/{self.service.pk}/actions/"

    def payload(self, action="upgrade_request", **overrides):
        return {
            "customer_id": self.customer.pk, "user_id": self.user.pk,
            "action": action, "reason": "Please review this change.",
            "submission_id": str(uuid4()), **overrides,
        }

    def submit(self, payload=None):
        response = self.portal_post(self.path, payload or self.payload())
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()["data"]

    def test_all_four_submissions_create_owned_tickets_without_changing_the_service(self):
        for action in ("upgrade_request", "downgrade_request", "suspend_request", "cancel_request"):
            with self.subTest(action=action):
                receipt = self.submit(self.payload(action))
                self.assertEqual(set(receipt), {"request_id", "ticket_id", "ticket_number"})
                ticket = Ticket.objects.get(pk=receipt["ticket_id"])
                self.assertEqual(ticket.customer_id, self.customer.pk)
                self.assertEqual(ticket.related_service_id, self.service.pk)
                self.assertEqual(ticket.created_by_id, self.user.pk)
                self.assertEqual(ticket.ticket_number, receipt["ticket_number"])
                self.assertIn("Please review this change.", ticket.description)
                self.assertEqual(ticket.status, "open")
                event = AuditEvent.objects.get(
                    content_type__app_label="provisioning", content_type__model="servicerequest",
                    object_id=receipt["request_id"], action="support_ticket_created",
                )
                self.assertEqual(event.user_id, self.user.pk)
                self.assertEqual(event.metadata["ticket_id"], ticket.pk)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertEqual(Ticket.objects.count(), 4)

    def test_unauthorized_and_invalid_requests_create_nothing(self):
        response = self.client.post(self.path, self.payload(), content_type="application/json")
        self.assertIn(response.status_code, (401, 403))
        for role in ("viewer",):
            self.membership.role = role
            self.membership.save()
            self.assertEqual(self.portal_post(self.path, self.payload()).status_code, 403)
        self.membership.role = "owner"
        self.membership.save()
        for values in (
            {"action": "terminate"}, {"action": "cancel_request", "reason": " "},
            {"reason": "x" * 4001}, {"submission_id": "not-a-uuid"},
        ):
            self.assertEqual(self.portal_post(self.path, self.payload(**values)).status_code, 400)
        other = Customer.objects.create(name="Other SRL", status="active")
        self.service.customer = other
        self.service.save(update_fields=["customer"])
        self.assertEqual(self.portal_post(self.path, self.payload()).status_code, 404)
        self.assertEqual(Ticket.objects.count(), 0)

    def test_duplicate_receipt_is_stable_after_private_rejection(self):
        payload = self.payload()
        receipt = self.submit(payload)
        self.client.force_login(self.staff)
        decision = f"/tickets/{receipt['ticket_id']}/service-request/decision/"
        response = self.client.post(decision, {
            "decision": "reject", "note": "Internal rejection only", "expected_status": "pending",
        })
        self.assertEqual(response.status_code, 302, response.content)
        duplicate = self.portal_post(self.path, payload)
        self.assertEqual(duplicate.status_code, 200, duplicate.content)
        self.assertEqual(duplicate.json()["data"], receipt)
        conflict = self.portal_post(self.path, {**payload, "reason": "Different request"})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(Ticket.objects.count(), 1)
        self.assertNotIn("rejected", duplicate.content.decode())

    def test_private_review_completion_and_customer_visibility(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        decision = f"/tickets/{ticket.pk}/service-request/decision/"
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(decision, {"decision": "approve"}).status_code, 403)
        self.client.force_login(self.staff)
        page = self.client.get(f"/tickets/{ticket.pk}/")
        self.assertContains(page, "Approve")
        self.assertContains(page, f"/provisioning/services/{self.service.pk}/")
        for _ in range(2):
            self.assertEqual(self.client.post(decision, {"decision": "approve", "expected_status": "pending"}).status_code, 302)
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "in_progress")
        self.assertEqual(ticket.comments.count(), 1)
        note = ticket.comments.get()
        self.assertFalse(note.is_public)
        self.assertEqual(note.comment_type, "internal")
        response = self.portal_post(f"/api/tickets/{ticket.pk}/", {
            "user_id": self.user.pk, "customer_id": self.customer.pk,
        })
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotIn("approved", response.content.decode().lower())
        self.assertNotIn("service_request", response.json()["data"]["ticket"])
        self.assertEqual(response.json()["data"]["ticket"]["comments"], [])
        self.assertEqual(self.client.post(decision, {"decision": "complete", "note": ""}).status_code, 400)
        self.assertEqual(self.client.post(decision, {
            "decision": "complete", "note": "Applied manually and verified hosting and billing", "expected_status": "approved",
        }).status_code, 302)
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "closed")
        self.assertEqual(ticket.comments.count(), 2)
        self.assertFalse(ticket.comments.filter(is_public=True).exists())
        decisions = AuditEvent.objects.filter(
            content_type__app_label="provisioning", content_type__model="servicerequest",
            object_id=receipt["request_id"], action="support_ticket_updated",
        )
        self.assertEqual(decisions.count(), 2)
        self.assertEqual(set(decisions.values_list("user_id", flat=True)), {self.staff.pk})
        self.assertCountEqual([event.new_values["status"] for event in decisions], ["approved", "completed"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")

    def test_pending_request_cannot_be_closed_through_other_ticket_paths(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        with self.assertRaises(ValueError):
            TicketStatusService.close_ticket(ticket, "fixed")
        with self.assertRaises(ValueError):
            TicketStatusService.handle_agent_reply(ticket, self.staff, "close_with_resolution", "fixed")
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "open")

    def test_private_review_dates_follow_staff_preferences_across_midnight(self):
        receipt = self.submit()
        ticket_id = receipt["ticket_id"]
        review_service_request(ticket_id=ticket_id, staff=self.staff, decision="approve", expected_status="pending")
        review_service_request(
            ticket_id=ticket_id, staff=self.staff, decision="complete", expected_status="approved", note="Verified",
        )
        instant = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)
        ServiceRequest.objects.filter(ticket_id=ticket_id).update(
            reviewed_at=instant, completed_at=instant + timedelta(hours=1, minutes=15),
        )
        profile, _ = UserProfile.objects.get_or_create(user=self.staff)
        self.client.force_login(self.staff)
        for zone, pattern, reviewed, completed in (
            ("Europe/Bucharest", "%Y-%m-%d", "2026-01-01 00:30", "2026-01-01 01:45"),
            ("America/New_York", "%m/%d/%Y", "12/31/2025 17:30", "12/31/2025 18:45"),
        ):
            with self.subTest(zone=zone), timezone.override("UTC"):
                profile.timezone, profile.date_format = zone, pattern
                profile.save(update_fields=["timezone", "date_format"])
                response = self.client.get(f"/tickets/{ticket_id}/")
                self.assertContains(response, reviewed, count=1)
                self.assertContains(response, completed, count=1)
                self.assertEqual(timezone.get_current_timezone_name(), "UTC")

    def test_review_uses_original_service_after_ticket_reassignment(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        ticket.related_service = None
        ticket.save(update_fields=["related_service"])
        self.client.force_login(self.staff)
        page = self.client.get(f"/tickets/{ticket.pk}/")
        self.assertContains(page, f"/provisioning/services/{self.service.pk}/")

    def test_conflicting_staff_notes_and_stale_decisions_are_not_acknowledged(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        decision = f"/tickets/{ticket.pk}/service-request/decision/"
        self.client.force_login(self.staff)
        payload = {"decision": "reject", "note": "First private reason", "expected_status": "pending"}
        self.assertEqual(self.client.post(decision, payload).status_code, 302)
        self.assertEqual(self.client.post(decision, payload).status_code, 302)
        self.assertEqual(self.client.post(decision, {**payload, "note": "Changed reason"}).status_code, 409)
        self.assertEqual(self.client.post(decision, {"decision": "approve", "expected_status": "pending"}).status_code, 409)
        self.assertEqual(ticket.comments.count(), 1)
        self.assertIn("First private reason", ticket.comments.get().content)

    def test_close_and_reply_http_paths_roll_back_for_pending_and_approved_requests(self):
        for approved in (False, True):
            with self.subTest(approved=approved):
                receipt = self.submit()
                ticket = Ticket.objects.get(pk=receipt["ticket_id"])
                self.client.force_login(self.staff)
                if approved:
                    self.client.post(f"/tickets/{ticket.pk}/service-request/decision/", {
                        "decision": "approve", "expected_status": "pending",
                    })
                before_count = ticket.comments.count()
                response = self.client.post(f"/tickets/{ticket.pk}/close/", {"resolution_code": "fixed"})
                self.assertEqual(response.status_code, 302)
                self.client.post(f"/tickets/{ticket.pk}/reply/", {
                    "reply": "This reply must not falsely close the request",
                    "reply_action": "close_with_resolution", "resolution_code": "fixed",
                })
                ticket.refresh_from_db()
                self.assertNotEqual(ticket.status, "closed")
                self.assertEqual(ticket.comments.count(), before_count)

    def test_inactivity_worker_leaves_unresolved_requests_open(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        ticket.wait_on_customer()
        ticket.save()
        Ticket.objects.filter(pk=ticket.pk).update(updated_at=timezone.now() - timedelta(days=4))
        with patch("apps.tickets.tasks.SettingsService.get_integer_setting", return_value=24):
            result = auto_close_inactive_tickets()
        self.assertEqual(result["closed"], 0)
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "waiting_on_customer")

    def test_inactive_membership_and_missing_identity_cannot_submit(self):
        self.membership.is_active = False
        self.membership.save()
        self.assertEqual(self.portal_post(self.path, self.payload()).status_code, 403)
        payload = self.payload()
        del payload["user_id"]
        self.assertIn(self.portal_post(self.path, payload).status_code, (400, 403))
        self.assertEqual(Ticket.objects.count(), 0)

    def test_customer_ticket_page_and_counts_exclude_internal_decisions(self):
        receipt = self.submit()
        ticket = Ticket.objects.get(pk=receipt["ticket_id"])
        self.client.force_login(self.staff)
        self.client.post(f"/tickets/{ticket.pk}/service-request/decision/", {
            "decision": "approve", "expected_status": "pending", "note": "Staff only confidential decision",
        })
        self.client.force_login(self.user)
        page = self.client.get(f"/tickets/{ticket.pk}/")
        self.assertNotContains(page, "data-testid=\"staff-service-request\"")
        self.assertNotContains(page, "Staff only confidential decision")
        response = self.portal_post("/api/tickets/", {"customer_id": self.customer.pk, "user_id": self.user.pk})
        self.assertEqual(response.status_code, 200, response.content)
        listing = next(row for row in response.json()["data"]["tickets"] if row["id"] == ticket.pk)
        self.assertEqual(listing["comments_count"], 0)
