"""Public registration and purchase contracts used by the real Portal."""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api.core.throttling import AuthThrottle
from apps.api.orders.serializers import OrderDetailSerializer
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.services import OrderService, StatusChangeData
from apps.products.models import Product, ProductPrice
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class PurchaseIdentityContracts(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()

    def registration(self, email="purchase@example.com", phone="+40722123456"):
        return {
            "user_data": {
                "email": email,
                "password": "Registration-pass123!",
                "first_name": "Ana",
                "last_name": "Pop",
                "phone": phone,
            },
            "customer_data": {
                "customer_type": "company",
                "company_name": "Știință SRL",
                "vat_number": "RO14399847",
                "address_line1": "Str. Victoriei nr. 10",
                "city": "București",
                "county": "București",
                "postal_code": "010061",
                "country": "România",
                "data_processing_consent": True,
            },
        }

    def register(self):
        response = self.portal_post("/api/customers/register/", self.registration())
        self.assertEqual(response.status_code, 201, response.content)
        user = User.objects.get(email="purchase@example.com")
        customer = CustomerMembership.objects.get(user=user, role="owner", is_primary=True).customer
        return user, customer

    def test_company_identity_consent_and_billing_address_survive_registration(self):
        user, customer = self.register()
        self.assertEqual(customer.name, "Știință SRL")
        self.assertEqual(customer.primary_email, user.email)
        self.assertEqual(customer.primary_phone, "+40722123456")
        self.assertTrue(customer.data_processing_consent)
        self.assertIsNotNone(user.gdpr_consent_date)
        self.assertFalse(user.is_staff)
        self.assertTrue(user.check_password("Registration-pass123!"))
        self.assertEqual(customer.tax_profile.vat_number, "RO14399847")
        address = OrderService.build_billing_address_from_customer(customer)
        self.assertEqual(address["address_line1"], "Str. Victoriei nr. 10")
        self.assertEqual(address["city"], "București")
        self.assertEqual(address["postal_code"], "010061")

    def test_romanian_phones_are_normalized_and_invalid_lengths_rejected(self):
        for index, phone in enumerate(("+40.722.123.456", "0722 123 456")):
            response = self.portal_post(
                "/api/customers/register/",
                {
                    **self.registration(f"phone{index}@example.com", phone),
                    "customer_data": {**self.registration()["customer_data"], "company_name": f"Phone Company {index}"},
                },
            )
            self.assertEqual(response.status_code, 201, response.content)
            user = User.objects.get(email=f"phone{index}@example.com")
            self.assertEqual(user.phone, phone.replace(".", "").replace(" ", ""))
        for phone in ("+4072212345", "+407221234567", "+40722123456junk"):
            response = self.portal_post("/api/customers/register/", self.registration(phone=phone))
            self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(User.objects.count(), 2)

    def test_invalid_registration_is_atomic(self):
        for field, value in (("address_line1", ""), ("data_processing_consent", False)):
            data = self.registration()
            data["customer_data"][field] = value
            response = self.portal_post("/api/customers/register/", data)
            self.assertEqual(response.status_code, 400, response.content)
            self.assertFalse(Customer.objects.exists())
            self.assertFalse(User.objects.exists())

    def test_order_retains_selected_method_domain_type_term_and_recorded_vat(self):
        user, customer = self.register()
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        product = Product.objects.create(
            name="VPS", slug="purchase-vps", product_type="vps", requires_domain=False, domain_required_at_signup=True
        )
        ProductPrice.objects.create(product=product, currency=currency, monthly_price_cents=10000)
        response = self.portal_post(
            "/api/orders/create/",
            {
                "customer_id": customer.pk,
                "user_id": user.pk,
                "idempotency_key": "bank-order-contract",
                "currency": "RON",
                "payment_method": "bank_transfer",
                "items": [
                    {
                        "product_slug": product.slug,
                        "quantity": 1,
                        "billing_period": "annual",
                        "domain_name": "vps.example",
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 201, response.content)
        order = Order.objects.get(pk=response.json()["order"]["id"])
        self.assertEqual(order.payment_method, "bank_transfer")
        item = order.items.get()
        self.assertEqual((item.product_type, item.domain_name, item.billing_period), ("vps", "vps.example", "annual"))
        self.assertEqual(item.unit_price_cents, 120000)
        data = OrderDetailSerializer(order).data
        self.assertEqual(data["items"][0]["billing_period"], "annual")
        self.assertEqual(data["vat_rate_percent"], "21")
        # A flag on a product that needs no domain must not block submission.
        item.domain_name = ""
        item.save(update_fields=["domain_name"])
        result = OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment"))
        self.assertTrue(result.is_ok(), str(result))
        order.refresh_from_db()
        self.assertIsNotNone(order.proforma_id)
        self.assertEqual(order.payment_method, "bank_transfer")
        self.assertIsNone(order.invoice_id)

    def test_unknown_payment_method_cannot_create_an_order(self):
        user, customer = self.register()
        response = self.portal_post(
            "/api/orders/create/",
            {
                "customer_id": customer.pk,
                "user_id": user.pk,
                "idempotency_key": "invalid-method-contract",
                "currency": "RON",
                "payment_method": "cash",
                "items": [],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Order.objects.exists())

    @override_settings(
        RATE_LIMITING_ENABLED=True,
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    )
    def test_registration_really_throttles_and_duplicate_attempt_keeps_original_account(self):

        with patch.object(AuthThrottle, "rate", "2/min", create=True):
            user, customer = self.register()
            duplicate = self.registration()
            duplicate["customer_data"]["company_name"] = "Replacement name"
            response = self.portal_post("/api/customers/register/", duplicate)
            self.assertEqual(response.status_code, 400, response.content)
            response = self.portal_post("/api/customers/register/", self.registration("new@example.com"))
            self.assertEqual(response.status_code, 429, response.content)
            self.assertIn("Retry-After", response)
            customer.refresh_from_db()
            self.assertEqual(customer.name, "Știință SRL")
            self.assertEqual(User.objects.filter(email=user.email).count(), 1)
            self.assertFalse(User.objects.filter(email="new@example.com").exists())
