"""Real signed requests preserve customer, role and current session boundaries."""

from datetime import timedelta
from uuid import uuid4

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.provisioning.models import Service
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, PortalSession
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin, bound_fields, fresh_session


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class ServicePlanChangeAPITests(BoundSessionMixin, HMACTestMixin, _PlanChangeSettlementFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", False).is_ok())
        self.membership = CustomerMembership.objects.create(
            user=self.actor,
            customer=self.customer,
            role="owner",
            is_active=True,
        )
        self.accepted, _, _, _ = self.payable_change()
        self.path = f"/api/services/{self.service.pk}/plan-changes/{self.accepted.pk}/status/"
        self.body = {"user_id": self.actor.pk, "customer_id": self.customer.pk}

    def test_accepted_change_remains_visible_when_new_acceptance_is_disabled(self) -> None:
        response = self.portal_post(self.path, self.body)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()["data"]
        self.assertEqual(
            (data["id"], data["status"], data["net_cents"], data["total_cents"], data["currency"]),
            (str(self.accepted.pk), "awaiting_payment", 6000, 6000, "RON"),
        )
        self.assertEqual(data["proposed_limits"]["disk_mib"], 20480)
        self.assertEqual(data["next_recurring_net_cents"], 20000)
        self.assertNotIn("quote_snapshot", data)
        self.assertNotIn("client_secret", data)
        self.assertIn("no-store", response["Cache-Control"])

    def test_non_billing_role_cannot_inspect_a_plan_payment(self) -> None:
        self.membership.role = "tech"
        self.membership.save(update_fields=["role"])
        self.assertEqual(self.portal_post(self.path, self.body).status_code, 403)

    def test_change_id_cannot_be_rebound_to_another_service_even_for_same_customer(self) -> None:
        other = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Other service",
            username="otherapi",
            price=80,
        )
        wrong = f"/api/services/{other.pk}/plan-changes/{self.accepted.pk}/status/"
        missing = f"/api/services/{self.service.pk}/plan-changes/{uuid4()}/status/"
        self.assertEqual(self.portal_post(wrong, self.body).status_code, 404)
        self.assertEqual(self.portal_post(missing, self.body).json(), self.portal_post(wrong, self.body).json())

    def test_an_old_identity_check_cannot_inspect_the_sensitive_checkout(self) -> None:
        session = fresh_session(self.actor)
        PortalSession.objects.filter(pk=session.pk).update(reauth_at=timezone.now() - timedelta(seconds=301))
        response = self.portal_post(self.path, {**self.body, **bound_fields(session)})
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(response.json()["code"], "reauth_required")
        PortalSession.objects.filter(pk=session.pk).update(reauth_at=timezone.now())
        fresh = self.portal_post(self.path, {**self.body, **bound_fields(session)})
        self.assertEqual(fresh.status_code, 200, fresh.content)
        self.assertEqual(fresh.json()["data"]["id"], str(self.accepted.pk))

    def test_signed_caller_amount_cannot_change_authoritative_status_values(self) -> None:
        response = self.portal_post(self.path, {**self.body, "net_cents": 1, "total_cents": 1, "is_staff": True})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["data"]["total_cents"], 6000)
        self.accepted.refresh_from_db()
        self.assertEqual(self.accepted.total_cents, 6000)

    def test_service_detail_keeps_accepted_checkout_reachable_with_new_acceptance_disabled(self) -> None:
        response = self.portal_post(f"/api/services/{self.service.pk}/", self.body)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()["data"]["service"]
        self.assertEqual(data.get("plan_change"), {"id": str(self.accepted.pk), "status": "awaiting_payment"})
        self.assertIs(data.get("plan_changes_enabled"), False)
