"""
Regression tests for PR #112 order flow bug fixes.

Tests two platform-side fixes:
1. Preflight rejects unsupported currencies
2. Confirmation without a generic server retains the canonical linked Service

Portal quantity validation tests are in services/portal/tests/.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from django.test import RequestFactory, TestCase, override_settings

from apps.billing.models import Currency
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Server, Service
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin
from tests.helpers.task_queue import quiet_task_queue
from tests.orders import test_confirm_order_service_identity as identity
from tests.orders._hosting_workflow_case import HostingWorkflowCase

# ---------------------------------------------------------------------------
# 1. Preflight currency validation
# ---------------------------------------------------------------------------


def _call_preflight(customer: Customer, cart_items: list[dict], currency: str | None = "RON") -> tuple[int, dict]:
    """Call preflight_order with optional currency. Returns (status_code, response_data)."""
    from apps.api.orders.views import preflight_order  # noqa: PLC0415

    body_data: dict = {"items": cart_items, "currency_revision": 1}
    if currency is not None:
        body_data["currency"] = currency
    body = json.dumps(body_data, default=str).encode()
    factory = RequestFactory()
    raw_request = factory.post(
        "/api/orders/preflight/",
        data=body,
        content_type="application/json",
    )

    with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
        response = preflight_order(raw_request)

    return response.status_code, response.data  # type: ignore[union-attr]  # DRF Response always has .data


class PreflightCurrencyValidationTests(TestCase):
    """Verify preflight rejects unsupported and malformed currencies."""

    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Currency Test SRL",
            company_name="Currency Test SRL",
            customer_type="company",
            primary_email="currency@example.ro",
            status="active",
        )
        product = Product.objects.create(
            slug="test-product",
            name="Test Product",
            product_type="shared_hosting",
            is_active=True,
            is_public=True,
        )
        ProductPrice.objects.create(
            product=product,
            currency=Currency.objects.get(code="RON"),
            monthly_price_cents=2500,
            is_active=True,
        )
        self.cart_items = [{"product_slug": "test-product", "quantity": 1, "billing_period": "monthly"}]

    def test_missing_currency_requires_a_fresh_cart(self) -> None:
        """A legacy cart cannot silently inherit a changed selling currency."""
        status_code, data = _call_preflight(self.customer, self.cart_items, currency=None)
        self.assertEqual(status_code, 400)
        self.assertIn("currency", data["details"])

    def test_unsupported_currency_rejected(self) -> None:
        """GBP is not in CurrencyCode enum."""
        status_code, data = _call_preflight(self.customer, self.cart_items, currency="GBP")
        self.assertEqual(status_code, 400)
        self.assertFalse(data["success"])
        self.assertTrue(any("currency" in e.lower() for e in data["errors"]))

    def test_empty_string_currency_rejected(self) -> None:
        status_code, _data = _call_preflight(self.customer, self.cart_items, currency="")
        self.assertEqual(status_code, 400)

    def test_non_string_currency_rejected(self) -> None:
        """Numeric currency code should be rejected."""
        status_code, data = _call_preflight(self.customer, self.cart_items, currency=123)
        self.assertEqual(status_code, 400)
        self.assertTrue(any("currency" in e.lower() for e in data["errors"]))

    def test_missing_db_record_distinct_error(self) -> None:
        """Currency passes enum but has no DB row — should say 'not configured', not 'unsupported'."""
        Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        # Delete EUR from DB to simulate missing record
        Currency.objects.filter(code="EUR").delete()
        status_code, data = _call_preflight(self.customer, self.cart_items, currency="EUR")
        self.assertEqual(status_code, 400)
        self.assertTrue(any("not configured" in e.lower() for e in data["errors"]))

    def test_non_vat_payer_eu_business_uses_profile_for_preview(self) -> None:
        """Preflight must not quote reverse charge when the tax profile disables it."""
        address = CustomerAddress.objects.create(
            customer=self.customer,
            is_billing=True,
            address_line1="Teststrasse 1",
            city="Berlin",
            county="Berlin",
            postal_code="10115",
            country="DE",
        )
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_number="DE123456789",
            is_vat_payer=False,
        )

        for country in ("DE", "Germany", "Germania"):
            with self.subTest(country=country):
                address.country = country
                address.save(update_fields=["country"])
                status_code, data = _call_preflight(self.customer, self.cart_items)

                self.assertEqual(status_code, 200)
                self.assertEqual(data["preview"]["subtotal_cents"], 2500)
                self.assertEqual(data["preview"]["vat_cents"], 475)
                self.assertEqual(data["preview"]["total_cents"], 2975)


# ---------------------------------------------------------------------------
# 2. Confirmation without a generic provisioning server
# ---------------------------------------------------------------------------


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class NullServerGuardTests(BoundSessionMixin, HMACTestMixin, HostingWorkflowCase):
    def test_no_server_confirms_only_the_linked_service(self) -> None:
        quiet_task_queue(self)
        self.assertFalse(Server.objects.exists())
        self.owner = User.objects.create_user(email="no-server-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        order = self.create_order()
        service_id = order.items.get().service_id
        identity.ConfirmOrderServiceIdentityTests.prepare_payment(self, order)
        with self.captureOnCommitCallbacks(execute=True):
            response = identity.ConfirmOrderServiceIdentityTests.request_confirmation(self, order)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["provisioning"], [])
        self.assertEqual(list(Service.objects.values_list("pk", flat=True)), [service_id])
        self.assertEqual(order.items.get().service_id, service_id)
