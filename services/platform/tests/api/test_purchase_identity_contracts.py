"""Public registration and purchase contracts used by the real Portal."""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api.orders.serializers import OrderDetailSerializer
from apps.billing.models import Currency
from apps.common.performance.rate_limiting import RegistrationClientIPThrottle
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.services import OrderService, StatusChangeData
from apps.products.models import Product, ProductPrice
from apps.settings.models import SystemSetting
from apps.users.models import CustomerMembership, User
from apps.users.pending_registration import PendingRegistration
from apps.users.services import SecureUserRegistrationService
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.task_queue import run_queued

CHOSEN = "Registration-pass123!"
DELIVER = "apps.users.tasks.deliver_registration"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class PurchaseIdentityContracts(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        SystemSetting.objects.update_or_create(
            key="portal.public_base_url",
            defaults={
                "name": "Portal URL",
                "category": "platform",
                "data_type": "string",
                "value": "https://customers.example.test",
                "default_value": "",
            },
        )

    def registration(self, email="purchase@example.com", phone="+40722123456"):
        return {
            "user_data": {
                "email": email,
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

    def submit(self, data):
        with self.captureOnCommitCallbacks(execute=True):
            return self.portal_post("/api/customers/register/", data)

    def confirm(self, email, password=CHOSEN):
        self.assertEqual(run_queued(DELIVER), [{"sent": True, "kind": "confirm"}])
        row = PendingRegistration.objects.get(email=email)
        return self.portal_post(
            "/api/users/register/confirm/",
            {
                "registration_id": str(row.pk),
                "token": row.token(),
                "password": password,
                "password_confirm": password,
                "data_processing_consent": True,
            },
        )

    def register(self, data=None, password=CHOSEN):
        data = data or self.registration()
        submitted = self.submit(data)
        self.assertEqual(submitted.status_code, 202, submitted.content)
        email = data["user_data"]["email"]
        confirmed = self.confirm(email, password)
        self.assertEqual(confirmed.status_code, 201, confirmed.content)
        user = User.objects.get(email=email)
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
        self.assertTrue(user.check_password(CHOSEN))
        self.assertEqual(customer.tax_profile.vat_number, "RO14399847")
        address = OrderService.build_billing_address_from_customer(customer)
        self.assertEqual(address["address_line1"], "Str. Victoriei nr. 10")
        self.assertEqual(address["city"], "București")
        self.assertEqual(address["postal_code"], "010061")

    def test_registration_and_login_preserve_leading_and_trailing_password_spaces(self):
        for index, password in enumerate((" Leading-pass123!", "Trailing-pass123! ", " Both-pass123! ")):
            with self.subTest(password_position=index):
                cache.clear()
                data = self.registration(email=f"password-spaces-{index}@example.test")
                data["customer_data"]["company_name"] = f"Password Spaces {index} SRL"
                user, _customer = self.register(data, password)
                login = self.portal_post(
                    "/api/users/login/",
                    {
                        "email": data["user_data"]["email"],
                        "password": password,
                    },
                )
                self.assertEqual(login.status_code, 200, login.content)
                self.assertTrue(login.json()["success"])
                self.assertTrue(user.check_password(password))
                self.assertFalse(user.check_password(password.strip()))
                trimmed = self.portal_post(
                    "/api/users/login/",
                    {
                        "email": user.email,
                        "password": password.strip(),
                    },
                )
                self.assertEqual(trimmed.status_code, 401, trimmed.content)

    def test_confirmation_retains_password_length_validation(self):
        self.assertEqual(self.submit(self.registration()).status_code, 202)
        self.assertEqual(run_queued(DELIVER), [{"sent": True, "kind": "confirm"}])
        row = PendingRegistration.objects.get(email="purchase@example.com")
        for password in ("", "short", " short "):
            with self.subTest(password_length=len(password)):
                cache.clear()
                response = self.portal_post(
                    "/api/users/register/confirm/",
                    {
                        "registration_id": str(row.pk),
                        "token": row.token(),
                        "password": password,
                        "password_confirm": password,
                        "data_processing_consent": True,
                    },
                )
                self.assertEqual(response.status_code, 400, response.content)
                self.assertIn("password", response.json()["errors"])
                self.assertFalse(User.objects.exists())
                self.assertFalse(Customer.objects.exists())

    def test_onboarding_checkbox_consent_is_preserved_without_a_user_timestamp(self):
        data = self.registration()
        result = SecureUserRegistrationService.register_new_customer_owner(
            **{**data, "user_data": {**data["user_data"], "password": CHOSEN}}
        )
        self.assertTrue(result.is_ok(), str(result))
        user, customer = result.unwrap()
        user.refresh_from_db()
        customer.refresh_from_db()
        self.assertIsNotNone(user.gdpr_consent_date)
        self.assertTrue(customer.data_processing_consent)

    def test_absent_or_negative_checkbox_cannot_fabricate_consent(self):
        for index, consent in enumerate((False, None, "false", "true")):
            data = self.registration(email=f"consent{index}@example.com")
            data["customer_data"].update(company_name=f"Consent Company {index}", data_processing_consent=consent)
            result = SecureUserRegistrationService.register_new_customer_owner(
                **{**data, "user_data": {**data["user_data"], "password": CHOSEN}}
            )
            self.assertTrue(result.is_ok(), str(result))
            user, customer = result.unwrap()
            self.assertIsNone(user.gdpr_consent_date)
            self.assertFalse(customer.data_processing_consent)

    def test_romanian_phones_are_normalized_and_invalid_lengths_rejected(self):
        for index, phone in enumerate(("+40.722.123.456", "0722 123 456")):
            user, _customer = self.register(
                {
                    **self.registration(f"phone{index}@example.com", phone),
                    "customer_data": {**self.registration()["customer_data"], "company_name": f"Phone Company {index}"},
                }
            )
            self.assertEqual(user.phone, phone.replace(".", "").replace(" ", ""))
        for phone in ("+4072212345", "+407221234567", "+40722123456junk"):
            response = self.submit(self.registration(phone=phone))
            self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(PendingRegistration.objects.filter(consumed_at__isnull=True).count(), 0)

    def test_invalid_registration_is_atomic(self):
        for field, value in (("address_line1", ""), ("data_processing_consent", False)):
            data = self.registration()
            data["customer_data"][field] = value
            response = self.submit(data)
            self.assertEqual(response.status_code, 400, response.content)
            self.assertFalse(PendingRegistration.objects.exists())
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
                "currency_revision": 1,
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
        client = {"client_ip": "203.0.113.9"}
        with patch.object(RegistrationClientIPThrottle, "rate", "2/min", create=True):
            user, customer = self.register({**self.registration(), **client})
            duplicate = {**self.registration(), **client}
            duplicate["customer_data"]["company_name"] = "Replacement name"
            response = self.submit(duplicate)
            # The same answer as for a new address: the request never says the address is taken.
            self.assertEqual(response.status_code, 202, response.content)
            response = self.submit({**self.registration("new@example.com"), **client})
            self.assertEqual(response.status_code, 429, response.content)
            self.assertIn("Retry-After", response)
            run_queued(DELIVER)
            customer.refresh_from_db()
            self.assertEqual(customer.name, "Știință SRL")
            self.assertEqual(User.objects.filter(email=user.email).count(), 1)
            self.assertFalse(PendingRegistration.objects.filter(email="new@example.com").exists())
