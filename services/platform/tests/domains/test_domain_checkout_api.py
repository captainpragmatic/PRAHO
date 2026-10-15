"""Signed availability and registrar identity requirements on the actual order paths."""
from __future__ import annotations

import uuid
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import resolve

from apps.billing.currency_policy import currency_switch_blockers, get_selling_currency_policy
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import TLDRegistrarAssignment
from apps.domains.services import DomainOrderService
from apps.orders.models import Order
from apps.orders.preflight import OrderPreflightValidationService
from apps.orders.services import OrderCreateData, OrderService
from apps.users.models import CustomerMembership, User
from tests.helpers.checkout import checkout_consents
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

from .test_domain_order_flow import DomainOrderLineFixture, _domain_line

PATH = "/api/orders/domains/availability/"
CNP = "1850101123451"


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class DomainCheckoutAPITests(HMACTestMixin, DomainOrderLineFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        Customer.objects.filter(pk=self.customer.pk).update(status="active", customer_type="individual", company_name="")
        self.customer = Customer.objects.get(pk=self.customer.pk)
        CustomerTaxProfile.objects.filter(customer=self.customer).delete()
        self.owner = User.objects.create_user(email="domain-checkout-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_active=True)
        self.gateway = ROTLDGateway(self.ro_registrar)
        self.enterContext(patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=self.gateway))

    def identity(self) -> dict[str, object]:
        return {"customer_id": self.customer.pk, "user_id": self.owner.pk}

    def request_items(self, mode: str = "register") -> dict[str, object]:
        return {
            **self.identity(), "auto_pending": True, "idempotency_key": str(uuid.uuid4()), "currency": "RON", "currency_revision": get_selling_currency_policy().revision,
            "items": [{"product_slug": self.domain_product.slug, "quantity": 1, "billing_period": "annual", "domain_name": "checkout.ro", "config": {"domain_mode": mode}}],
            **checkout_consents(),
        }

    def test_signed_availability_returns_prices_requirements_and_canonical_name(self) -> None:
        payload = {**self.identity(), "domain_name": "  CHECKOUT.RO  ", "domain_mode": "register", "client_ip": "192.0.2.44"}
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, True)) as check:
            denied = self.client.post(PATH, payload, content_type="application/json")
            self.assertEqual(denied.status_code, 401)
            response = self.portal_post(PATH, payload)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertTrue(data["available"])
        self.assertTrue(data["orderable"])
        self.assertEqual(data["domain_name"], "checkout.ro")
        self.assertEqual(data["register_price_cents"], 1000)
        self.assertEqual(data["transfer_price_cents"], 800)
        self.assertEqual(data["requires"], ["cnp"])
        check.assert_called_once_with(self.ro_registrar, "checkout.ro")
        throttles = {throttle.scope for throttle in resolve(PATH).func.cls.throttle_classes}
        self.assertTrue({"public_lookup_ip", "portal_hmac", "portal_hmac_burst"}.issubset(throttles))
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(True, False)):
            response = self.portal_post(PATH, {**payload, "domain_mode": "transfer"})
        self.assertFalse(response.json()["available"])
        self.assertEqual(response.json()["requires"], [])

    def test_unknown_availability_and_unorderable_tld_never_claim_available(self) -> None:
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability", return_value=(False, True)):
            response = self.portal_post(PATH, {**self.identity(), "domain_name": "checkout.ro"})
        self.assertFalse(response.json().get("available", False))
        self.assertFalse(response.json()["success"])
        self.assertTrue(response.json()["orderable"])
        self.assertEqual(response.json()["register_price_cents"], 1000)
        self.assertEqual(response.json()["transfer_price_cents"], 800)
        self.assertEqual(response.json()["requires"], ["cnp"])
        self.assertIn("error", response.json())
        TLDRegistrarAssignment.objects.filter(tld=self.ro).update(is_active=False)
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability") as check:
            response = self.portal_post(PATH, {"domain_name": "checkout.ro"})
        self.assertFalse(response.json()["orderable"])
        self.assertFalse(response.json().get("available", False))
        check.assert_not_called()
        response = self.portal_post(PATH, {"domain_name": "<script>.ro"})
        self.assertFalse(response.json()["success"])

    def test_availability_customer_requirements_are_scoped_to_active_membership(self) -> None:
        outsider = User.objects.create_user(email="domain-checkout-outsider@example.test")
        with patch("apps.domains.services.DomainRegistrarGateway.check_domain_availability") as check:
            response = self.portal_post(PATH, {**self.identity(), "user_id": outsider.pk, "domain_name": "checkout.ro"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("error", response.json())
        check.assert_not_called()

    def test_missing_cnp_blocks_preflight_and_create_then_the_form_save_unblocks(self) -> None:
        payload = self.request_items()
        before = Order.objects.count()
        preflight = self.portal_post("/api/orders/preflight/", payload)
        self.assertEqual(preflight.status_code, 200, preflight.content)
        self.assertFalse(preflight.json()["success"])
        self.assertEqual(preflight.json()["checkout"]["registrant_requires"], ["cnp"])
        self.assertTrue(preflight.json()["errors"])
        refused = self.portal_post("/api/orders/create/", payload)
        self.assertEqual(refused.status_code, 400, refused.content)
        self.assertEqual(Order.objects.count(), before)
        saved = self.portal_post("/api/customers/tax-profile/", {**self.identity(), "cnp": CNP})
        self.assertTrue(saved.json()["success"])
        accepted = self.portal_post("/api/orders/preflight/", self.request_items())
        self.assertTrue(accepted.json()["success"], accepted.content)
        self.assertEqual(accepted.json()["checkout"]["registrant_requires"], [])
        created = self.portal_post("/api/orders/create/", self.request_items())
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(Order.objects.count(), before + 1)
        self.assertNotIn(CNP, created.content.decode() + accepted.content.decode())

    def test_direct_order_service_and_existing_order_preflight_enforce_requirements(self) -> None:
        quoted = DomainOrderService.quote_order_line("direct.ro", "register", "RON").unwrap()
        result = OrderService.create_order(OrderCreateData(customer=self.customer, currency="RON", billing_address=self._billing(), items=[_domain_line(self.domain_product, "direct.ro", quoted.total_cents)]))
        self.assertTrue(result.is_err())
        self.assertFalse(Order.objects.filter(items__domain_name="direct.ro").exists())
        CustomerTaxProfile.objects.create(customer=self.customer, cnp=CNP)
        self.customer = Customer.objects.get(pk=self.customer.pk)
        order, _line = self._domain_order("existing.ro")
        CustomerTaxProfile.objects.filter(customer=self.customer).delete()
        order = Order.objects.get(pk=order.pk)
        errors, _warnings = OrderPreflightValidationService.validate(order)
        self.assertTrue(any("registrant" in str(error).lower() for error in errors), errors)
        Customer.objects.filter(pk=self.customer.pk).update(customer_type="company")
        CustomerTaxProfile.objects.create(customer=self.customer, cui="14399840")
        self.customer = Customer.objects.get(pk=self.customer.pk)
        result = OrderService.create_order(OrderCreateData(customer=self.customer, currency="RON", billing_address=self._billing(), items=[_domain_line(self.domain_product, "company.ro", quoted.total_cents)]))
        self.assertTrue(result.is_err())
        self.assertFalse(Order.objects.filter(items__domain_name="company.ro").exists())

    def test_transfer_does_not_require_cnp_and_response_never_returns_a_code(self) -> None:
        response = self.portal_post("/api/orders/create/", self.request_items("transfer"))
        self.assertEqual(response.status_code, 201, response.content)
        order = Order.objects.order_by("created_at").last()
        assert order is not None
        item = order.items.get()
        details = self.portal_post(f"/api/orders/{order.pk}/", self.identity()).json()
        self.assertTrue(details["items"][0]["can_submit_transfer_code"])
        item.domain_order_item.set_encrypted_epp_code("SECRET-TRANSFER")
        item.domain_order_item.save(update_fields=["epp_code"])
        response = self.portal_post(f"/api/orders/{order.pk}/", self.identity())
        self.assertNotIn("SECRET-TRANSFER", response.content.decode())

    def test_domain_catalog_product_uses_tld_prices_when_checking_a_currency_switch(self) -> None:
        blockers = currency_switch_blockers("RON")
        self.assertFalse(any(self.domain_product.name in blocker for blocker in blockers), blockers)

    def test_public_catalog_and_detail_include_domain_products_without_catalog_prices(self) -> None:
        response = self.client.get("/api/orders/products/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(str(self.domain_product.pk), [product["id"] for product in response.json()["results"]])
        response = self.client.get(f"/api/orders/products/{self.domain_product.slug}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["product_type"], "domain")
        self.assertEqual(response.json()["prices"], [])
