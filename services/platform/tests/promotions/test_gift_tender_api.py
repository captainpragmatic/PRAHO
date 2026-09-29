"""Existing-card spending retains HMAC, membership, and billing-role checks."""

from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.price_sealing import create_sealed_price_for_product_price
from apps.products.models import Product, ProductPrice
from apps.promotions.models import Coupon, GiftCard
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    PRICE_SEALING_SECRET="checkout-test-secret-with-at-least-32-characters",
)
class GiftTenderAPITests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        self.customer = Customer.objects.create(
            name="Gift tender customer", customer_type="individual", status="active"
        )
        self.owner = User.objects.create_user(email="gift-tender-owner@example.test")
        self.membership = CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner")
        self.card = GiftCard.objects.create(
            code="API-BALANCE",
            currency=currency,
            initial_value_cents=500,
            current_balance_cents=500,
            status="active",
            ledger_version=2,
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=currency,
            number="INV-GIFT-API",
            subtotal_cents=1000,
            tax_cents=210,
            total_cents=1210,
        )
        self.invoice.issue()
        self.invoice.save()
        self.payload = {
            "customer_id": self.customer.pk,
            "user_id": self.owner.pk,
            "action": "gift_card_payment",
            "document_type": "invoice",
            "document_number": self.invoice.number,
            "code": self.card.code,
            "operation_key": "6430c172-230b-48b1-bf94-6c50e8be5ff8",
        }

    def test_billing_owner_can_spend_existing_card_once(self) -> None:
        for _ in range(2):
            response = self.portal_post("/api/billing/gift-card-payment/", self.payload)
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(response.json()["cash_due_cents"], 710)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 0)
        self.assertEqual(self.invoice.payments.filter(payment_method="gift_card").count(), 1)
        hold = self.invoice.gift_card_reservations.get()
        self.assertEqual(AuditEvent.objects.filter(
            content_type__model="giftcardreservation", object_id=str(hold.pk),
            user=self.owner, action="create",
        ).count(), 1)

    def test_viewer_and_cross_customer_document_cannot_spend_balance(self) -> None:
        self.membership.role = "viewer"
        self.membership.save()
        response = self.portal_post("/api/billing/gift-card-payment/", self.payload)
        self.assertEqual(response.status_code, 403)
        self.membership.role = "owner"
        self.membership.save()
        other = Customer.objects.create(name="Other customer", customer_type="individual", status="active")
        Invoice.objects.create(
            customer=other, currency=self.invoice.currency, number="INV-OTHER-TENDER", total_cents=1210
        )
        self.payload["document_number"] = "INV-OTHER-TENDER"
        response = self.portal_post("/api/billing/gift-card-payment/", self.payload)
        self.assertEqual(response.status_code, 404)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 500)

    def checkout_payload(self):

        product = Product.objects.create(name="Quoted hosting", slug="quoted-hosting", product_type="shared_hosting")
        price = ProductPrice.objects.create(product=product, currency=self.invoice.currency, monthly_price_cents=1000)
        return {
            "customer_id": self.customer.pk,
            "user_id": self.owner.pk,
            "currency": "RON",
            "currency_revision": 1,
            "items": [
                {
                    "product_id": str(product.pk),
                    "quantity": 1,
                    "billing_period": "monthly",
                    "sealed_price_token": create_sealed_price_for_product_price(
                        price, client_ip="127.0.0.1", billing_period="monthly"
                    ),
                }
            ],
        }

    def test_stale_signed_quote_returns_conflict_and_creates_no_order(self):

        SettingsService.update_setting("promotions.new_offers_enabled", True, reason="API quote regression")
        self.addCleanup(SettingsService._clear_setting_cache, "promotions.new_offers_enabled")
        coupon = Coupon.objects.create(
            code="APIQUOTE", name="Quoted offer", discount_type="percent", discount_percent=10
        )
        payload = {**self.checkout_payload(), "coupon_codes": [coupon.code]}
        calculated = self.portal_post("/api/orders/calculate/", payload)
        self.assertEqual(calculated.status_code, 200, calculated.content)
        coupon.discount_percent = 20
        coupon.save(update_fields=["discount_percent"])
        response = self.portal_post(
            "/api/orders/create/",
            {
                **payload,
                "promotion_quote": calculated.json()["promotion_quote"],
                "idempotency_key": "stale-quote-request",
            },
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["code"], "PROMOTION_QUOTE_CHANGED")
        self.assertFalse(Order.objects.filter(customer=self.customer).exists())
        coupon.refresh_from_db()
        self.assertEqual(coupon.total_uses, 0)

    def test_checkout_reserves_exact_quoted_gift_tender_through_hmac(self):

        payload = {**self.checkout_payload(), "gift_code": self.card.code}
        calculated = self.portal_post("/api/orders/calculate/", payload)
        self.assertEqual(calculated.status_code, 200, calculated.content)
        quote = calculated.json()
        self.assertEqual((quote["gift_applied_cents"], quote["cash_due_cents"]), (500, 710))
        response = self.portal_post(
            "/api/orders/create/",
            {
                **payload,
                "promotion_quote": quote["promotion_quote"],
                "idempotency_key": "gift-checkout-request",
            },
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["order"]["cash_due_cents"], 710)
        order = Order.objects.get(pk=response.json()["order"]["id"])
        self.assertEqual(order.proforma.gift_card_reservations.get().amount_cents, 500)
        self.assertEqual((order.total_cents, order.tax_cents, order.discount_cents), (1210, 210, 0))
