"""Gift purchases use signed identity, confirmed currency, and explicit payment/reveal actions."""

import json
import time
from unittest.mock import Mock, patch

from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError

PURCHASE_ID = "550e8400-e29b-41d4-a716-446655440099"
INDEX = "/billing/gift-cards/"
DETAIL = f"{INDEX}{PURCHASE_ID}/"


def catalog(currency="EUR", revision=2, *, enabled=True):
    return {
        "success": True, "sales_enabled": enabled, "selling_currency": currency,
        "currency_revision": revision, "denominations": [2500, 5000], "payment_methods": ["stripe", "bank"],
    }


def purchase(**overrides):
    return {
        "id": PURCHASE_ID, "created_at": "2026-09-29T10:00:00Z", "status": "pending",
        "currency_code": "EUR", "amount_cents": 2500, "payment_method": "stripe",
        "recipient_email": "buyer@example.test", "recipient_name": "Buyer", "is_gift": False,
        "delivery_status": "pending", "current_balance_cents": 0, "can_reveal": False, "can_resend": False,
        "available_balance_cents": 0, "reserved_cents": 0, "refund_held_cents": 0, "spending_frozen": False,
        "can_pay": overrides.get("status", "pending") == "pending", "can_refresh": False,
        "payment_closed": False, "funding_needs_review": False, "funding_status": "pending",
        "delivery_queued": False, "deliveries": [], "resend_available_at": None,
        **overrides,
    }


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class GiftPurchaseViewsTests(SimpleTestCase):
    def setUp(self) -> None:
        self.api = Mock()
        self.current_catalog = catalog()
        self.current_purchase = purchase()
        self.create_error = None
        self.action_errors = {}
        self.history_has_next = False
        self.funding_status = "requires_payment_method"
        self.bank_details = {"bank_name": "Currency bank", "iban": "EUR-IBAN", "currency": "EUR", "beneficiary": "Example SRL"}
        self.calls = []
        self.api.post.side_effect = self.platform
        self.api.get_billing.return_value = {"success": True, "config": {"publishable_key": "pk_test_gifts"}}
        self.enterContext(patch("apps.billing.services.PlatformAPIClient", return_value=self.api))
        self.login("owner")

    def login(self, role, client=None):
        session = (client or self.client).session
        session.update({
            "customer_id": 42, "user_id": 7, "email": "buyer@example.test",
            "user_memberships": [{"customer_id": 42, "role": role}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def platform(self, endpoint, data=None, **kwargs):  # noqa: PLR0911 - API fixture dispatches independent actions
        self.calls.append((endpoint, dict(data or {})))
        action = endpoint.strip("/").split("/")[-1]
        if action in self.action_errors:
            raise self.action_errors[action]
        if action == "catalog":
            return self.current_catalog
        if action == "purchases":
            return {"success": True, "purchases": [self.current_purchase], "page": data.get("page", 1), "has_next": self.history_has_next}
        if action == "create":
            if self.create_error:
                raise self.create_error
            return {"success": True, "purchase": self.current_purchase}
        if action in {"detail", "refresh"}:
            return {
                "success": True, "purchase": self.current_purchase,
                "bank_details": self.bank_details,
            }
        if action == "funding":
            return {"success": True, "payment_intent_id": "pi_gift", "client_secret": "pi_gift_secret", "status": self.funding_status}
        if action == "reveal":
            return {"success": True, "code": "PRIVATE-GIFT-CODE"}
        if action == "resend":
            return {"success": True}
        raise AssertionError(f"Unexpected API endpoint {endpoint}")

    def form_payload(self):
        response = self.client.get(INDEX)
        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        return {
            "idempotency_key": str(form["idempotency_key"].value()),
            "currency": form["currency"].value(), "currency_revision": form["currency_revision"].value(),
            "amount_cents": "2500", "payment_method": "stripe", "delivery": "for_me",
        }

    def test_catalog_uses_each_currency_and_has_billing_navigation(self):
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                self.current_catalog = catalog(code)
                response = self.client.get(INDEX)
                self.assertContains(response, f"25,00 {code}")
                self.assertContains(response, "Anyone with the code")
                self.assertContains(response, "Send as a gift")
                self.assertContains(response, "/billing/automatic-payments/")

    def test_create_uses_session_identity_and_only_supported_tender(self):
        data = self.form_payload()
        data.update(customer_id=999, user_id=888, coupon_codes="DISCOUNT", gift_code="FREE")
        response = self.client.post(f"{INDEX}create/", data)
        self.assertRedirects(response, DETAIL, fetch_redirect_response=False)
        sent = next(data for endpoint, data in self.calls if endpoint.endswith("create/"))
        self.assertEqual((sent["customer_id"], sent["user_id"]), (42, 7))
        self.assertEqual((sent["currency"], sent["currency_revision"], sent["amount_cents"]), ("EUR", 2, 2500))
        self.assertFalse(sent["is_gift"])
        self.assertEqual(sent["recipient"]["email"], "")
        self.assertNotIn("coupon_codes", sent)
        self.assertNotIn("gift_code", sent)

    def test_for_me_ignores_recipient_fields_left_from_an_unfinished_gift(self):
        data = self.form_payload()
        data.update(recipient_email="unfinished@", recipient_name="Alice", recipient_message="Unused")
        response = self.client.post(f"{INDEX}create/", data)
        self.assertRedirects(response, DETAIL, fetch_redirect_response=False)
        sent = next(data for endpoint, data in self.calls if endpoint.endswith("create/"))
        self.assertEqual(sent["recipient"], {"email": "", "name": "", "message": ""})

    def test_gift_requires_recipient_email_and_keeps_optional_message(self):
        data = self.form_payload()
        data.update(delivery="gift", recipient_email="", recipient_name="Alice", recipient_message="A gift for you")
        response = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(any(endpoint.endswith("create/") for endpoint, _ in self.calls))
        data["recipient_email"] = "alice@example.test"
        response = self.client.post(f"{INDEX}create/", data)
        self.assertRedirects(response, DETAIL, fetch_redirect_response=False)
        sent = self.calls[-1][1]
        self.assertTrue(sent["is_gift"])
        self.assertEqual(sent["recipient"], {"email": "alice@example.test", "name": "Alice", "message": "A gift for you"})

    def test_unoffered_amount_or_payment_method_never_creates_purchase(self):
        for field, value in (("amount_cents", "1"), ("payment_method", "gift_card"), ("currency", "USD")):
            with self.subTest(field=field):
                data = self.form_payload()
                data[field] = value
                response = self.client.post(f"{INDEX}create/", data)
                self.assertEqual(response.status_code, 400)
        self.assertFalse(any(endpoint.endswith("create/") for endpoint, _ in self.calls))

    def test_changed_currency_renders_new_offer_and_requires_new_submit(self):
        data = self.form_payload()
        self.current_catalog = catalog("USD", 3)
        self.create_error = PlatformAPIError("Changed", status_code=409, response_data={"code": "currency_changed"})
        response = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(response.status_code, 409)
        self.assertContains(response, "25,00 USD", status_code=409)
        self.assertContains(response, "Review", status_code=409)
        self.assertNotEqual(str(response.context["form"]["idempotency_key"].value()), data["idempotency_key"])
        self.assertEqual(sum(endpoint.endswith("create/") for endpoint, _ in self.calls), 1)

    def test_uncertain_retry_keeps_original_currency_key_and_recipient(self):
        data = self.form_payload()
        self.create_error = PlatformAPIError("Unavailable", status_code=503)
        first = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(first.status_code, 503)
        self.current_catalog = catalog("USD", 3)
        self.create_error = None
        retry = self.client.post(f"{INDEX}create/", data)
        self.assertRedirects(retry, DETAIL, fetch_redirect_response=False)
        sent = [payload for endpoint, payload in self.calls if endpoint.endswith("create/")]
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(sent[1]["currency"], "EUR")

    def test_uncertain_retry_cannot_change_original_purchase_amount(self):
        data = self.form_payload()
        self.create_error = PlatformAPIError("Unavailable", status_code=503)
        self.client.post(f"{INDEX}create/", data)
        data["amount_cents"] = "5000"
        response = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(sum(endpoint.endswith("create/") for endpoint, _ in self.calls), 1)

    def test_sales_disabled_hides_buy_form_but_keeps_history_and_reveal(self):
        self.current_catalog = catalog(enabled=False)
        self.current_purchase = purchase(status="funded", can_reveal=True)
        response = self.client.get(INDEX)
        self.assertNotContains(response, 'name="amount_cents"')
        self.assertContains(response, DETAIL)
        self.calls.clear()
        response = self.client.post(f"{DETAIL}reveal/")
        self.assertContains(response, "PRIVATE-GIFT-CODE")
        self.assertFalse(any(endpoint.endswith("catalog/") for endpoint, _ in self.calls))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn("PRIVATE-GIFT-CODE", json.dumps(dict(self.client.session)))

    def test_funding_and_refresh_use_saved_purchase_without_new_sale_policy(self):
        self.current_catalog = catalog("USD", 3)
        response = self.client.post(f"{DETAIL}funding/")
        self.assertContains(response, "25,00 EUR")
        self.assertContains(response, "pi_gift_secret")
        self.assertContains(response, "pk_test_gifts")
        self.current_purchase = purchase(status="funded", current_balance_cents=2500, can_reveal=True)
        response = self.client.post(f"{DETAIL}refresh/")
        self.assertContains(response, "Funded")
        self.assertNotContains(response, "PRIVATE-GIFT-CODE")
        self.assertFalse(any(endpoint.endswith("catalog/") for endpoint, _ in self.calls))

    def test_processing_or_completed_card_payment_does_not_offer_confirmation_again(self):
        for status in ("processing", "succeeded"):
            with self.subTest(status=status):
                self.funding_status = status
                self.current_purchase = purchase(status="funded" if status == "succeeded" else "pending")
                response = self.client.post(f"{DETAIL}funding/")
                self.assertNotContains(response, "Confirm payment")
                self.assertNotContains(response, "pi_gift_secret")

    def test_bank_purchase_shows_original_currency_account(self):
        self.current_purchase = purchase(payment_method="bank")
        response = self.client.get(DETAIL)
        self.assertContains(response, "EUR-IBAN")
        self.assertContains(response, "25,00 EUR")
        self.assertContains(response, "Example SRL")

    def test_partially_refunded_purchase_shows_remaining_usable_balance(self):
        self.current_purchase = purchase(status="partially_refunded", current_balance_cents=1500,
                                        available_balance_cents=1500, can_reveal=True)
        response = self.client.get(DETAIL)
        self.assertContains(response, "15,00 EUR")
        self.assertNotContains(response, "becomes usable after payment")

    def test_held_and_frozen_value_is_not_presented_as_available(self):
        self.current_purchase = purchase(status="funded", current_balance_cents=2500, available_balance_cents=1000,
                                        reserved_cents=500, refund_held_cents=1000)
        response = self.client.get(DETAIL)
        self.assertContains(response, "Available balance: 10,00 EUR")
        self.assertContains(response, "Held for refunds: 10,00 EUR")
        self.assertContains(response, "Reserved for orders: 5,00 EUR")
        self.current_purchase.update(status="disputed", available_balance_cents=0, spending_frozen=True)
        response = self.client.get(DETAIL)
        self.assertContains(response, "Available balance: 0,00 EUR")
        self.assertContains(response, "Spending is frozen")

    def test_closed_payment_offers_new_purchase_and_review_does_not_offer_another_charge(self):
        self.current_purchase = purchase(funding_status="canceled", payment_closed=True, can_pay=False)
        response = self.client.get(DETAIL)
        self.assertNotContains(response, "Pay by card")
        self.assertContains(response, "Start a new purchase")
        self.current_purchase.update(payment_closed=False, funding_status="needs_review", funding_needs_review=True)
        response = self.client.get(DETAIL)
        self.assertContains(response, "needs review")
        self.assertNotContains(response, "Start a new purchase")
        self.assertNotContains(response, "Pay by card")

    def test_queued_delivery_and_cooldown_explain_missing_resend_button(self):
        self.current_purchase = purchase(status="funded", can_reveal=True, delivery_queued=True)
        response = self.client.get(DETAIL)
        self.assertContains(response, "Delivery is queued")
        self.assertNotContains(response, "Send code again")
        self.current_purchase.update(delivery_queued=False, resend_available_at="2026-09-29T10:05:00Z")
        response = self.client.get(DETAIL)
        self.assertContains(response, "Sending again is available after")

    def test_resend_validation_and_rate_limit_errors_are_controlled(self):
        for status in (400, 429):
            with self.subTest(status=status):
                self.action_errors["resend"] = PlatformAPIError(
                    "Do not expose raw provider exception", status_code=status, retry_after=60 if status == 429 else None,
                    response_data={"error": "Please wait a few minutes before sending this gift card again."},
                )
                response = self.client.post(f"{DETAIL}resend/")
                self.assertEqual(response.status_code, status)
                self.assertContains(response, "Wait", status_code=status)
                self.assertNotContains(response, "raw provider", status_code=status)
                if status == 429:
                    self.assertEqual(response["Retry-After"], "60")

    def test_refunded_or_disputed_purchase_does_not_ask_for_payment(self):
        for status in ("refunded", "disputed"):
            with self.subTest(status=status):
                self.current_purchase = purchase(status=status)
                response = self.client.get(DETAIL)
                self.assertNotContains(response, "becomes usable after payment")
                self.assertNotContains(response, "Check payment status")

    def test_bank_purchase_never_shows_an_account_in_another_currency(self):
        self.current_purchase = purchase(payment_method="bank")
        self.bank_details = {"currency": "USD", "iban": "USD-ACCOUNT", "bank_name": "Other currency"}
        response = self.client.get(DETAIL)
        self.assertNotContains(response, "USD-ACCOUNT")
        self.assertContains(response, "Contact support")

    def test_catalog_outage_keeps_history_without_a_fallback_buy_offer(self):
        self.action_errors["catalog"] = PlatformAPIError("Unavailable", status_code=503)
        response = self.client.get(INDEX)
        self.assertContains(response, "temporarily unavailable")
        self.assertContains(response, DETAIL)
        self.assertNotContains(response, 'name="amount_cents"')

    def test_incomplete_catalog_disables_buying(self):
        self.current_catalog.pop("currency_revision")
        response = self.client.get(INDEX)
        self.assertNotContains(response, 'name="amount_cents"')
        self.assertContains(response, "temporarily unavailable")

    def test_history_failure_is_not_reported_as_no_purchases(self):
        self.action_errors["purchases"] = PlatformAPIError("Unavailable", status_code=503)
        response = self.client.get(INDEX)
        self.assertContains(response, "history is temporarily unavailable")
        self.assertNotContains(response, "no gift card purchases yet")
        self.assertContains(response, 'name="amount_cents"')

    def test_same_currency_new_revision_requires_new_form_and_submit(self):
        data = self.form_payload()
        self.current_catalog = catalog("EUR", 4)
        self.create_error = PlatformAPIError("Changed", status_code=409, response_data={"code": "currency_changed"})
        response = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.context["form"]["currency_revision"].value(), 4)
        self.assertNotEqual(str(response.context["form"]["idempotency_key"].value()), data["idempotency_key"])
        self.assertEqual(sum(endpoint.endswith("create/") for endpoint, _ in self.calls), 1)

    def test_form_from_another_customer_never_reaches_create(self):
        data = self.form_payload()
        session = self.client.session
        session.update({"customer_id": 99, "user_memberships": [{"customer_id": 99, "role": "owner"}]})
        session.save()
        response = self.client.post(f"{INDEX}create/", data)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(any(endpoint.endswith("create/") for endpoint, _ in self.calls))

    def test_known_rejection_is_distinct_from_an_uncertain_network_result(self):
        data = self.form_payload()
        self.create_error = PlatformAPIError("Invalid amount", status_code=400)
        response = self.client.post(f"{INDEX}create/", data)
        self.assertContains(response, "purchase was not accepted", status_code=400)
        self.assertNotContains(response, "could not confirm", status_code=400)

    def test_platform_denies_another_customers_detail_and_actions(self):
        for action in ("detail", "funding", "refresh", "reveal", "resend"):
            with self.subTest(action=action):
                self.action_errors[action] = PlatformAPIError("Forbidden", status_code=403)
                response = self.client.get(DETAIL) if action == "detail" else self.client.post(f"{DETAIL}{action}/")
                self.assertEqual(response.status_code, 404)
                self.assertNotContains(response, "buyer@example.test", status_code=404)
                self.action_errors.clear()

    def test_reveal_code_is_escaped_and_not_returned_by_get(self):
        self.current_purchase = purchase(status="funded", can_reveal=True)
        response = self.client.get(DETAIL)
        self.assertNotContains(response, "PRIVATE-GIFT-CODE")
        original_platform = self.platform
        self.api.post.side_effect = lambda endpoint, data=None: (
            {"success": True, "code": "<script>private</script>"}
            if endpoint.endswith("reveal/") else original_platform(endpoint, data)
        )
        response = self.client.post(f"{DETAIL}reveal/")
        self.assertContains(response, "&lt;script&gt;private&lt;/script&gt;")
        self.assertNotContains(response, "<script>private</script>")

    def test_history_pages_keep_all_owned_purchases_accessible(self):
        self.history_has_next = True
        response = self.client.get(f"{INDEX}?page=2")
        sent = next(data for endpoint, data in self.calls if endpoint.endswith("purchases/"))
        self.assertEqual(sent["page"], 2)
        self.assertContains(response, '?page=1')
        self.assertContains(response, '?page=3')

    def test_uncertain_retry_cannot_change_delivery_or_recipient(self):
        for changed in ({"delivery": "for_me"}, {"recipient_email": "other@example.test"}, {"recipient_message": "Changed"}):
            with self.subTest(changed=changed):
                self.calls.clear()
                data = self.form_payload()
                data.update(delivery="gift", recipient_email="alice@example.test", recipient_name="Alice", recipient_message="Original")
                self.create_error = PlatformAPIError("Unavailable", status_code=503)
                self.client.post(f"{INDEX}create/", data)
                response = self.client.post(f"{INDEX}create/", {**data, **changed})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(sum(endpoint.endswith("create/") for endpoint, _ in self.calls), 1)

    def test_reveal_and_delivery_are_explicit_post_actions(self):
        for action in ("funding", "refresh", "reveal", "resend"):
            with self.subTest(action=action):
                self.assertEqual(self.client.get(f"{DETAIL}{action}/").status_code, 405)
        response = self.client.post(f"{DETAIL}resend/")
        self.assertRedirects(response, DETAIL, fetch_redirect_response=False)
        self.assertEqual(self.calls[-1][1]["purchase_id"], PURCHASE_ID)

    def test_owner_and_billing_allowed_while_technical_and_viewer_denied(self):
        for role, status in (("owner", 200), ("billing", 200), ("tech", 403), ("viewer", 403)):
            with self.subTest(role=role):
                self.login(role)
                self.assertEqual(self.client.get(INDEX).status_code, status)

    def test_csrf_is_required_for_purchase_and_sensitive_actions(self):
        csrf_client = Client(enforce_csrf_checks=True)
        self.login("owner", csrf_client)
        for path in (f"{INDEX}create/", f"{DETAIL}funding/", f"{DETAIL}reveal/", f"{DETAIL}resend/"):
            with self.subTest(path=path):
                self.assertEqual(csrf_client.post(path).status_code, 403)
        self.api.post.assert_not_called()
