"""Live checkout consumers reflect operator settings without losing accepted work."""

from unittest.mock import patch

from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from rest_framework.parsers import JSONParser
from rest_framework.request import Request

from apps.api.services.plan_change_views import _payment_response
from apps.api.services.views import customer_service_detail_api
from apps.billing.models import Payment
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.provisioning.plan_change_proposal_views import service_plan_change_proposal
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.api import test_service_plan_checkout as checkout_cases
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.helpers.portal_session import BoundSessionMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class HostingCheckoutSettingsTests(
    BoundSessionMixin, HMACTestMixin, VerifiedPlanChangeCheckoutFixture, TransactionTestCase
):
    payment_checkout = checkout_cases.ServicePlanCheckoutAPITests.payment_checkout

    def setUp(self) -> None:
        super().setUp()
        self.base = f"/api/services/{self.service.pk}/plan-changes/"
        self.body = {"user_id": self.actor.pk, "customer_id": self.customer.pk}

    def test_service_detail_flag_changes_new_acceptance_but_retains_the_accepted_checkout(self) -> None:
        change = self.confirm(self.quote())
        signed = self.portal_post(f"/api/services/{self.service.pk}/", self.body)
        self.assertEqual(signed.status_code, 200, signed.content)
        # Reuse the actual HMAC/session-authenticated request. Calling the real
        # decorated view also makes this consumer visible to the settings guard.
        for enabled in (False, True, False):
            with self.subTest(enabled=enabled):
                self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", enabled).is_ok())
                response = customer_service_detail_api(signed.wsgi_request, service_id=self.service.pk)
                self.assertEqual(response.status_code, 200, response.data)
                service = response.data["data"]["service"]
                self.assertIs(service["plan_changes_enabled"], enabled)
                self.assertEqual(service["plan_change"], {"id": str(change.pk), "status": "awaiting_payment"})

    def test_staff_proposal_flag_controls_rendered_links_without_creating_a_checkout(self) -> None:
        staff = User.objects.create_user(email="checkout-settings-staff@example.test", staff_role="billing")
        self.assertTrue(SettingsService.update_setting("portal.public_base_url", "https://portal.example.test").is_ok())
        self.client.force_login(staff)
        path = reverse("provisioning:service_detail", args=[self.service.pk]) + "plan-change/"
        signed_in = self.client.get(path)
        self.assertEqual(signed_in.status_code, 200, signed_in.content)
        for enabled in (False, True, False):
            with self.subTest(enabled=enabled):
                self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", enabled).is_ok())
                response = service_plan_change_proposal(signed_in.wsgi_request, pk=self.service.pk)
                self.assertEqual(response.status_code, 200, response.content)
                if enabled:
                    self.assertContains(response, str(self.target.pk))
                else:
                    self.assertNotContains(response, str(self.target.pk))
                self.assertFalse(self.subscription.plan_changes.exists())

    def test_public_key_controls_checkout_admission_and_ready_replay_uses_the_current_key(self) -> None:
        change, gateway, sdk, evidence = self.payment_checkout()
        signed = self.portal_post(
            self.base + str(change.pk) + "/status/",
            {**self.body, "quote_fingerprint": change.request_fingerprint},
        )
        self.assertEqual(signed.status_code, 200, signed.content)
        request = Request(signed.wsgi_request, parsers=[JSONParser()])
        scope = {
            "customer_id": self.customer.pk,
            "actor_id": self.actor.pk,
            "service_id": self.service.pk,
            "change_id": change.pk,
        }
        self.assertTrue(SettingsService.update_setting("integrations.stripe_publishable_key", "").is_ok())
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            refused = _payment_response(request, **scope)
            self.assertEqual(refused.status_code, 503, refused.data)
            self.assertFalse(PlanChangePaymentAttempt.objects.exists())
            self.assertFalse(Payment.objects.filter(meta__source="hosting_plan_change").exists())
            sdk.PaymentIntent.create.assert_not_called()
            for public_key in ("pk_test_current", "pk_test_rotated"):
                self.assertTrue(
                    SettingsService.update_setting("integrations.stripe_publishable_key", public_key).is_ok()
                )
                response = _payment_response(request, **scope)
                self.assertEqual(response.status_code, 200, response.data)
                self.assertEqual(response.data["data"]["publishable_key"], public_key)
                self.assertEqual(response.data["data"]["state"], "ready")
                self.assertEqual(response.data["data"]["client_secret"], "opaque-api-secret")
        self.assertEqual(PlanChangePaymentAttempt.objects.count(), 1)
        sdk.PaymentIntent.create.assert_called_once()
        self.assertEqual(evidence, [(False, "submitting", 1, True, 7260)])
