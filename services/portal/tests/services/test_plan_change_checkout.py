"""Customer plan checkout forwards session authority and renders Platform money."""

import time
from unittest.mock import Mock, patch

from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError

CHANGE = "550e8400-e29b-41d4-a716-446655440099"
TARGET = "550e8400-e29b-41d4-a716-446655440077"
BASE = "/services/5/change-plan/"
DETAIL = BASE + CHANGE + "/"


def accepted_change(**changes):
    return {
        "id": CHANGE,
        "status": "quoted",
        "direction": "upgrade",
        "net_cents": 6000,
        "tax_cents": 1260,
        "total_cents": 7260,
        "currency": "RON",
        "quote_fingerprint": "a" * 64,
        "quote_revision": 2,
        "expires_at": "2026-11-10T12:15:00Z",
        "authority_expires_at": "2026-11-10T12:30:00Z",
        "effective_at": "2026-11-10T12:00:00Z",
        "next_recurring_net_cents": 20000,
        "next_recurring_total_cents": 24200,
        "proposed_limits": {"disk_mib": 20480, "bandwidth_mib": 102400},
        "periods": [
            {
                "start": "2026-11-01T00:00:00Z",
                "end": "2026-12-01T00:00:00Z",
                "slice_start": "2026-11-10T12:00:00Z",
                "net_cents": 6000,
                "current": True,
            }
        ],
        "payment_received": False,
        "limits_pending": False,
        "requires_review": False,
        "payment_state": None,
        "viewer_can_pay": True,
        "viewer_can_accept": True,
        **changes,
    }


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class PlanChangePortalTests(SimpleTestCase):
    def setUp(self) -> None:
        self.api = Mock()
        self.calls = []
        self.change = accepted_change()
        self.error = None
        self.api.post.side_effect = self.platform
        self.enterContext(patch("apps.services.plan_changes.PlatformAPIClient", return_value=self.api))
        self.login()

    def login(self, role="owner", client=None):
        session = (client or self.client).session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": role}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def platform(self, endpoint, data=None, **kwargs):
        self.calls.append((endpoint, dict(data or {})))
        if self.error is not None:
            raise self.error
        if endpoint.endswith("options/"):
            return {
                "success": True,
                "data": [
                    {
                        "product_id": TARGET,
                        "name": "Larger hosting",
                        "available": True,
                        "direction": "upgrade",
                        "period_price_cents": 20000,
                        "next_recurring_total_cents": 24200,
                        "currency": "RON",
                        "expected_limit_revision": 2,
                        "effective_at": "2026-11-10T12:00:00Z",
                        "allowances": {"disk_allowance_mib": 20480, "bandwidth_allowance_mib": 102400},
                    }
                ],
            }
        if endpoint.endswith("payment-intent/"):
            self.change["payment_state"] = "ready"
            return {
                "success": True,
                "data": {
                    "state": "ready",
                    "attempt_id": TARGET,
                    "client_secret": "pi_fixture_secret",
                    "publishable_key": "pk_test_fixture",
                },
            }
        return {"success": True, "data": self.change}

    def test_options_quote_and_confirmation_forward_only_session_identity_and_quote_fields(self) -> None:
        response = self.client.get(BASE)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Larger hosting")
        form = response.context["options"][0]["form"]
        payload = {
            "target_product_id": TARGET,
            "submission_id": str(form["submission_id"].value()),
            "expected_limit_revision": 2,
            "customer_id": 999,
            "user_id": 888,
            "total_cents": 1,
        }
        quoted = self.client.post(BASE, payload)
        self.assertRedirects(quoted, DETAIL, fetch_redirect_response=False)
        sent = self.calls[-1][1]
        self.assertEqual((sent["customer_id"], sent["user_id"]), (42, 7))
        self.assertEqual(sent["target_product_id"], TARGET)
        self.assertNotIn("total_cents", sent)
        review = self.client.get(DETAIL)
        self.assertContains(review, "72,60")
        self.assertContains(review, "12,60")
        self.assertContains(review, "242,00")
        self.assertContains(review, "Current paid period")
        self.change = accepted_change(status="awaiting_payment")
        confirmed = self.client.post(DETAIL + "confirm/", {"quote_fingerprint": "a" * 64})
        self.assertEqual(confirmed.status_code, 200)
        self.assertContains(confirmed, "Pay by card")
        self.assertEqual(self.calls[-2][1]["accept_zero_due"], False)

    def test_stripe_hosted_fields_only_render_for_explicit_payment_post(self) -> None:
        self.change = accepted_change(status="payment_in_flight")
        before = self.client.get(DETAIL)
        self.assertNotContains(before, "pi_fixture_secret")
        paying = self.client.post(DETAIL + "payment-intent/", {"quote_fingerprint": "a" * 64})
        self.assertEqual(paying.status_code, 200)
        self.assertContains(paying, "pi_fixture_secret")
        self.assertContains(paying, "hosting-plan-payment-element")
        self.assertNotContains(paying, 'name="card_number"')
        self.assertIn("no-store", paying["Cache-Control"])
        self.assertNotIn("pi_fixture_secret", str(dict(self.client.session)))

    def test_paid_pending_and_review_states_do_not_offer_another_payment(self) -> None:
        for state in ("applying_limits", "limits_attention", "completed", "paid_review", "cancelled", "expired"):
            with self.subTest(state=state):
                self.change = accepted_change(
                    status=state,
                    payment_received=state in {"applying_limits", "limits_attention", "completed", "paid_review"},
                )
                response = self.client.get(DETAIL)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "Pay by card")
                if state in {"applying_limits", "limits_attention"}:
                    self.assertContains(response, "Payment received")
                    self.assertContains(response, "limits")

    def test_zero_due_or_scheduled_resource_work_never_claims_a_payment_was_received(self) -> None:
        for state in ("applying_limits", "limits_attention", "paid_review"):
            with self.subTest(state=state):
                self.change = accepted_change(
                    status=state,
                    net_cents=0,
                    tax_cents=0,
                    total_cents=0,
                    payment_received=False,
                )
                response = self.client.get(DETAIL)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "Payment received")

    def test_uncertain_or_stopped_payment_attempts_never_render_a_repeat_pay_loop(self) -> None:
        for state in ("unknown", "submitting", "review", "refused"):
            with self.subTest(state=state):
                self.change = accepted_change(status="payment_in_flight", payment_state=state)
                original = self.platform

                def outcome(endpoint, data=None, *, _state=state, _original=original, **kwargs):
                    if endpoint.endswith("payment-intent/"):
                        return {"success": True, "data": {"state": _state, "client_secret": None}}
                    return _original(endpoint, data=data, **kwargs)

                self.api.post.side_effect = outcome
                posted = self.client.post(DETAIL + "payment-intent/", {"quote_fingerprint": "a" * 64})
                self.assertEqual(posted.status_code, 200)
                self.assertNotContains(posted, "Pay by card")
                self.assertContains(posted, "Refresh status")
                refreshed = self.client.get(DETAIL)
                self.assertNotContains(refreshed, "Pay by card")

    def test_another_authorized_billing_viewer_cannot_accept_or_pay_the_original_requesters_quote(self) -> None:
        self.change = accepted_change(viewer_can_accept=False, viewer_can_pay=False)
        quoted = self.client.get(DETAIL)
        self.assertEqual(quoted.status_code, 200)
        self.assertNotContains(quoted, "Accept quoted terms")
        self.assertContains(quoted, "Cancel this change")
        self.change = accepted_change(status="awaiting_payment", viewer_can_accept=False, viewer_can_pay=False)
        confirmed = self.client.get(DETAIL)
        self.assertNotContains(confirmed, "Pay by card")
        self.assertContains(confirmed, "Cancel this change")

    def test_expired_ready_attempt_does_not_offer_an_unavailable_card_secret(self) -> None:
        self.change = accepted_change(
            status="payment_in_flight",
            payment_state="ready",
            authority_expires_at="2000-01-01T00:00:00Z",
        )
        response = self.client.get(DETAIL)
        self.assertNotContains(response, "Pay by card")

    def test_requesters_reserved_and_ready_attempts_keep_explicit_resume_without_a_secret_on_get(self) -> None:
        for state in ("reserved", "ready"):
            with self.subTest(state=state):
                self.change = accepted_change(status="payment_in_flight", payment_state=state)
                response = self.client.get(DETAIL)
                self.assertContains(response, "Pay by card")
                self.assertNotContains(response, "pi_fixture_secret")

    def test_billing_role_csrf_and_platform_conflict_remain_enforced(self) -> None:
        self.login("tech")
        self.assertEqual(self.client.get(BASE).status_code, 403)
        self.assertEqual(self.calls, [])
        csrf = Client(enforce_csrf_checks=True)
        self.login(client=csrf)
        self.assertEqual(csrf.post(BASE, {}).status_code, 403)
        self.login()
        self.error = PlatformAPIError("Changed", status_code=409)
        response = self.client.get(DETAIL)
        self.assertEqual(response.status_code, 409)
        self.assertNotContains(response, "Pay by card", status_code=409)
