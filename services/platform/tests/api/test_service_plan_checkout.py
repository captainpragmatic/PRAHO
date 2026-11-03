"""Actual signed plan checkout uses native qualification and server-derived money."""

import logging
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import stripe
from django.db import connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import Payment, ProformaInvoice
from apps.billing.plan_change_models import PlanChange
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.proforma_service import ProformaPaymentService
from apps.provisioning.models import VirtualminProvisioningJob
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture
from tests.helpers.portal_session import BoundSessionMixin, bound_fields, fresh_session


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class ServicePlanCheckoutAPITests(
    BoundSessionMixin, HMACTestMixin, VerifiedPlanChangeCheckoutFixture, TransactionTestCase
):
    def setUp(self) -> None:
        super().setUp()
        self.base = f"/api/services/{self.service.pk}/plan-changes/"
        self.body = {"user_id": self.actor.pk, "customer_id": self.customer.pk}

    def test_real_signed_options_quote_confirm_creates_one_exact_standalone_proforma(self) -> None:
        options = self.portal_post(self.base + "options/", self.body)
        self.assertEqual(options.status_code, 200, options.content)
        target = next(item for item in options.json()["data"] if item["product_id"] == str(self.target.pk))
        self.assertTrue(target["available"])
        self.assertEqual(target["period_price_cents"], 20000)
        submission = str(uuid4())
        payload = {
            **self.body,
            "target_product_id": str(self.target.pk),
            "submission_id": submission,
            "expected_limit_revision": 2,
            "total_cents": 1,
            "is_staff": True,
        }
        quoted = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(quoted.status_code, 201, quoted.content)
        data = quoted.json()["data"]
        self.assertEqual((data["net_cents"], data["tax_cents"], data["total_cents"]), (6000, 1260, 7260))
        self.assertEqual(data["next_recurring_total_cents"], 24200)
        self.assertFalse(ProformaInvoice.objects.exists())
        replay = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json()["data"]["id"], data["id"])
        self.assertEqual(PlanChange.objects.count(), 1)
        confirmed_path = self.base + data["id"] + "/confirm/"
        confirmation = {**self.body, "quote_fingerprint": data["quote_fingerprint"]}
        confirmed = self.portal_post(confirmed_path, confirmation)
        self.assertEqual(confirmed.status_code, 200, confirmed.content)
        self.assertEqual(confirmed.json()["data"]["status"], "awaiting_payment")
        self.assertEqual(self.portal_post(confirmed_path, confirmation).status_code, 200)
        document = ProformaInvoice.objects.get()
        self.assertEqual((document.subtotal_cents, document.tax_cents, document.total_cents), (6000, 1260, 7260))
        line = document.lines.get()
        self.assertEqual((line.billing_cycle_id, line.quantity, line.unit_price_cents), (None, 1, 6000))
        self.assertEqual(self.service.customer_id, document.customer_id)

    def payment_checkout(self):
        change = self.confirm(self.quote())
        self.assertTrue(
            SettingsService.update_setting("integrations.stripe_publishable_key", "pk_test_fixture").is_ok()
        )
        sdk = MagicMock()
        sdk.error = stripe.error
        evidence = []

        def create(**kwargs):
            attempt = PlanChangePaymentAttempt.objects.get()
            evidence.append(
                (
                    connection.in_atomic_block,
                    attempt.state,
                    attempt.submission_count,
                    kwargs["idempotency_key"] == attempt.idempotency_key,
                    Payment.objects.get(pk=attempt.payment_id).amount_cents,
                )
            )
            return SimpleNamespace(id="pi_api_checkout", client_secret="opaque-api-secret")

        sdk.PaymentIntent.create.side_effect = create
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.api-checkout")
        return change, gateway, sdk, evidence

    def test_signed_checkout_issues_one_durable_on_session_intent_and_replays_the_same_secret(self) -> None:
        change, gateway, sdk, evidence = self.payment_checkout()
        path = self.base + str(change.pk) + "/payment-intent/"
        payload = {**self.body, "quote_fingerprint": change.request_fingerprint, "amount_cents": 1}
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            response = self.portal_post(path, payload)
            self.assertEqual(response.status_code, 200, response.content)
            replay = self.portal_post(path, payload)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(response.json()["data"], replay.json()["data"])
        self.assertEqual(response.json()["data"]["client_secret"], "opaque-api-secret")
        self.assertEqual(response.json()["data"]["publishable_key"], "pk_test_fixture")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(
            (
                Payment.objects.filter(meta__source="hosting_plan_change").count(),
                PlanChangePaymentAttempt.objects.count(),
            ),
            (1, 1),
        )
        sdk.PaymentIntent.create.assert_called_once()
        self.assertEqual(evidence, [(False, "submitting", 1, True, 7260)])
        status = self.portal_post(self.base + str(change.pk) + "/status/", self.body)
        self.assertEqual(status.json()["data"]["payment_state"], "ready")
        self.assertIs(status.json()["data"]["viewer_can_pay"], True)

    def test_safe_status_keeps_real_unknown_then_review_attempt_states_without_provider_details(self) -> None:
        change, gateway, sdk, _evidence = self.payment_checkout()
        sdk.PaymentIntent.create.side_effect = stripe.error.APIConnectionError("private provider diagnostic")
        path = self.base + str(change.pk) + "/payment-intent/"
        payload = {**self.body, "quote_fingerprint": change.request_fingerprint}
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            unknown = self.portal_post(path, payload)
            self.assertEqual(unknown.status_code, 200, unknown.content)
            self.assertEqual(unknown.json()["data"]["state"], "unknown")
            status = self.portal_post(self.base + str(change.pk) + "/status/", self.body)
            self.assertEqual(status.json()["data"].get("payment_state"), "unknown")
            self.assertIs(status.json()["data"].get("viewer_can_pay"), False)
            attempt = PlanChangePaymentAttempt.objects.get(change=change)
            attempt.replay_until = timezone.now() - timedelta(seconds=1)
            attempt.save(update_fields=["replay_until"])
            reviewed = self.portal_post(path, payload)
            self.assertEqual(reviewed.json()["data"]["state"], "review")
        final = self.portal_post(self.base + str(change.pk) + "/status/", self.body)
        self.assertEqual(final.json()["data"].get("payment_state"), "review")
        self.assertIs(final.json()["data"].get("viewer_can_pay"), False)
        self.assertNotIn("private provider diagnostic", final.content.decode())
        self.assertNotIn("client_secret", final.json()["data"])
        sdk.PaymentIntent.create.assert_called_once()

    def test_other_billing_member_can_read_and_cancel_but_never_pay_the_requesters_change(self) -> None:
        change, gateway, sdk, _evidence = self.payment_checkout()
        other = User.objects.create_user(email="second-plan-billing@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=other, role="billing", is_active=True)
        route = self.base + str(change.pk)
        owner = self.portal_post(route + "/status/", self.body)
        self.assertIs(owner.json()["data"].get("viewer_can_pay"), True)
        viewer_body = {**self.body, "user_id": other.pk}
        viewed = self.portal_post(route + "/status/", viewer_body)
        self.assertEqual(viewed.status_code, 200, viewed.content)
        self.assertIs(viewed.json()["data"].get("viewer_can_pay"), False)
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            refused = self.portal_post(
                route + "/payment-intent/",
                {
                    **viewer_body,
                    "quote_fingerprint": change.request_fingerprint,
                },
            )
        self.assertEqual(refused.status_code, 400, refused.content)
        self.assertFalse(PlanChangePaymentAttempt.objects.filter(change=change).exists())
        sdk.PaymentIntent.create.assert_not_called()
        cancelled = self.portal_post(
            route + "/cancel/",
            {
                **viewer_body,
                "quote_fingerprint": change.request_fingerprint,
            },
        )
        self.assertEqual(cancelled.status_code, 200, cancelled.content)
        self.assertEqual(cancelled.json()["data"]["status"], "cancelled")

    def test_only_the_original_requester_is_offered_quote_confirmation(self) -> None:
        change = self.quote()
        other = User.objects.create_user(email="another-plan-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=other, role="owner", is_active=True)
        route = self.base + str(change.pk)
        owner = self.portal_post(route + "/status/", self.body)
        self.assertIs(owner.json()["data"].get("viewer_can_accept"), True)
        viewed = self.portal_post(route + "/status/", {**self.body, "user_id": other.pk})
        self.assertIs(viewed.json()["data"].get("viewer_can_accept"), False)
        refused = self.portal_post(
            route + "/confirm/",
            {
                **self.body,
                "user_id": other.pk,
                "quote_fingerprint": change.request_fingerprint,
            },
        )
        self.assertEqual(refused.status_code, 400, refused.content)
        self.assertFalse(ProformaInvoice.objects.exists())

    def test_each_checkout_step_requires_a_recent_identity_check(self) -> None:
        change, gateway, sdk, _ = self.payment_checkout()
        session = fresh_session(self.actor)
        steps = [
            ("options/", {}),
            ("safety-refresh/", {}),
            (
                "quote/",
                {
                    "target_product_id": str(self.target.pk),
                    "submission_id": str(change.submission_id),
                    "expected_limit_revision": 2,
                },
            ),
            (str(change.pk) + "/confirm/", {"quote_fingerprint": change.request_fingerprint}),
            (str(change.pk) + "/payment-intent/", {"quote_fingerprint": change.request_fingerprint}),
        ]
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            for suffix, values in steps:
                with self.subTest(step=suffix):
                    session.reauth_at = timezone.now() - timedelta(seconds=301)
                    session.save(update_fields=["reauth_at"])
                    refused = self.portal_post(self.base + suffix, {**self.body, **values, **bound_fields(session)})
                    self.assertEqual(refused.status_code, 403, refused.content)
                    self.assertEqual(refused.json()["code"], "reauth_required")
                    session.reauth_at = timezone.now()
                    session.save(update_fields=["reauth_at"])
                    accepted = self.portal_post(self.base + suffix, {**self.body, **values, **bound_fields(session)})
                    self.assertEqual(
                        accepted.status_code, 202 if suffix == "safety-refresh/" else 200, accepted.content
                    )
        sdk.PaymentIntent.create.assert_called_once()
        values = sdk.PaymentIntent.create.call_args.kwargs
        self.assertEqual((values["amount"], values["currency"], values["confirm"]), (7260, "ron", False))
        self.assertNotIn("off_session", values)
        self.assertNotIn("setup_future_usage", values)

    def test_membership_revoked_during_gateway_io_never_receives_the_card_secret(self) -> None:
        change, gateway, sdk, evidence = self.payment_checkout()
        create = sdk.PaymentIntent.create.side_effect

        def revoke(**kwargs):
            result = create(**kwargs)
            CustomerMembership.objects.filter(customer=self.customer, user=self.actor).update(is_active=False)
            return result

        sdk.PaymentIntent.create.side_effect = revoke
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            response = self.portal_post(
                self.base + str(change.pk) + "/payment-intent/",
                {**self.body, "quote_fingerprint": change.request_fingerprint},
            )
        self.assertEqual(response.status_code, 403, response.content)
        self.assertNotIn("opaque-api-secret", response.content.decode())
        self.assertEqual(PlanChangePaymentAttempt.objects.get().state, "ready")
        self.assertEqual(evidence, [(False, "submitting", 1, True, 7260)])

    def test_changed_payload_for_same_submission_returns_conflict(self) -> None:
        payload = {
            **self.body,
            "target_product_id": str(self.target.pk),
            "submission_id": str(uuid4()),
            "expected_limit_revision": 2,
        }
        first = self.portal_post(self.base + "quote/", payload)
        self.assertEqual(first.status_code, 201, first.content)
        second = self.portal_post(self.base + "quote/", {**payload, "expected_limit_revision": 3})
        self.assertEqual(second.status_code, 409, second.content)
        self.assertEqual(PlanChange.objects.count(), 1)

    def test_signed_cancel_keeps_financial_document_for_actual_late_money_review(self) -> None:
        change = self.confirm(self.quote())
        response = self.portal_post(
            self.base + str(change.pk) + "/cancel/", {**self.body, "quote_fingerprint": change.request_fingerprint}
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["data"]["status"], "cancelled")
        document = ProformaInvoice.objects.get(pk=change.proforma_id)
        self.assertEqual(document.status, "accepted")
        result = ProformaPaymentService.record_payment_and_convert(str(document.pk), 7260, "bank")
        self.assertTrue(result.is_ok(), result)
        change.refresh_from_db()
        self.assertEqual(change.status, "paid_review")
        self.assertIsNotNone(change.invoice_id)
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, self.plan.pk)

    def test_cancellation_requires_a_recent_identity_check(self) -> None:
        change = self.confirm(self.quote())
        path = self.base + str(change.pk) + "/cancel/"
        session = fresh_session(self.actor)
        session.reauth_at = timezone.now() - timedelta(seconds=301)
        session.save(update_fields=["reauth_at"])
        data = {**self.body, "quote_fingerprint": change.request_fingerprint}
        stale = self.portal_post(path, {**data, **bound_fields(session)})
        self.assertEqual(stale.status_code, 403, stale.content)
        self.assertEqual(stale.json()["code"], "reauth_required")
        session.reauth_at = timezone.now()
        session.save(update_fields=["reauth_at"])
        accepted = self.portal_post(path, {**data, **bound_fields(session)})
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(accepted.json()["data"]["status"], "cancelled")

    def test_usage_refresh_is_a_deduplicated_read_without_card_or_quota_authority(self) -> None:
        path = self.base + "safety-refresh/"
        first = self.portal_post(path, self.body)
        self.assertEqual(first.status_code, 202, first.content)
        second = self.portal_post(path, self.body)
        self.assertEqual(second.status_code, 202, second.content)
        job = VirtualminProvisioningJob.objects.get(operation="observe_hosting_limits")
        self.assertEqual((job.status, job.result, job.hosting_limit_application_id), ("pending", {}, None))
        self.assertEqual(first.json()["data"], {"state": "pending"})
        self.assertEqual(second.json()["data"], first.json()["data"])
        self.assertFalse(PlanChangePaymentAttempt.objects.exists())
