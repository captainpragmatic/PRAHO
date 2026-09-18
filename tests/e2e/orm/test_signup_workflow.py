"""Registration and onboarding through public APIs/services, with persisted outcomes."""

import json

import pytest
from django.conf import settings
from django.test import TestCase

from apps.customers.contact_service import AddressData, ContactService
from apps.customers.models import Customer
from apps.orders.services import OrderService
from apps.users.models import CustomerMembership, User
from services.platform.tests.helpers.hmac import hmac_headers

pytestmark = pytest.mark.e2e


class RegistrationCase(TestCase):
    def post_registration(self, payload):
        path = "/api/customers/register/"
        body = json.dumps(payload).encode()
        headers = hmac_headers("POST", path, body, secret=settings.PLATFORM_API_SECRET)
        return self.client.post(path, body, content_type="application/json", **headers)

    def payload(self, *, individual=False):
        return {
            "user_data": {
                "email": "owner@e2e.test",
                "password": "Registration-pass123!",
                "first_name": "Ana",
                "last_name": "Pop",
                "phone": "+40722123456",
            },
            "customer_data": {
                "customer_type": "individual" if individual else "company",
                "company_name": "Ana Pop" if individual else "E2E Registration SRL",
                "vat_number": "" if individual else "RO14399847",
                "address_line1": "Str. Victoriei nr. 10",
                "city": "București",
                "county": "București",
                "postal_code": "010061",
                "country": "România",
                "data_processing_consent": True,
            },
        }

    def register(self, *, individual=False):
        response = self.post_registration(self.payload(individual=individual))
        self.assertEqual(response.status_code, 201, response.content)
        user = User.objects.get(email="owner@e2e.test")
        customer = CustomerMembership.objects.get(user=user, role="owner", is_primary=True).customer
        self.assertTrue(user.check_password("Registration-pass123!"))
        self.assertFalse(user.is_staff)
        self.assertTrue(customer.data_processing_consent)
        self.assertIsNotNone(user.gdpr_consent_date)
        return user, customer


class TestSignupWorkflow(RegistrationCase):
    def test_complete_company_signup_flow(self):
        user, customer = self.register()
        self.assertEqual(customer.company_name, "E2E Registration SRL")
        self.assertEqual(customer.primary_email, user.email)
        self.assertEqual(customer.tax_profile.vat_number, "RO14399847")
        self.assertEqual(customer.billing_profile.preferred_currency, "RON")
        address = customer.addresses.get(is_current=True, is_billing=True)
        self.assertEqual(
            (address.address_line1, address.city, address.postal_code), ("Str. Victoriei nr. 10", "București", "010061")
        )

    def test_complete_individual_signup_flow(self):
        _, customer = self.register(individual=True)
        self.assertEqual(customer.customer_type, "individual")
        self.assertEqual(customer.billing_profile.preferred_currency, "RON")
        self.assertTrue(customer.addresses.get().is_billing)

    def test_signup_requires_gdpr_consent(self):
        payload = self.payload()
        payload["customer_data"]["data_processing_consent"] = False
        response = self.post_registration(payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("data_processing_consent", response.content.decode())
        self.assertFalse(User.objects.exists())
        self.assertFalse(Customer.objects.exists())

    def test_signup_with_multiple_addresses(self):
        user, customer = self.register()
        original = customer.addresses.get()
        address = ContactService.create_address(
            customer,
            user,
            AddressData(
                address_line1="Str. Noua 20", city="Cluj-Napoca", county="Cluj", postal_code="400001", is_billing=True
            ),
        )
        original.refresh_from_db()
        self.assertFalse(original.is_current)
        self.assertEqual(customer.addresses.filter(is_current=True, is_billing=True).get().pk, address.pk)
        self.assertGreater(address.version, original.version)


class TestUserRegistrationFlow(TestCase):
    def test_login_page_accessible(self):
        response = self.client.get("/auth/login/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="password"')

    def test_successful_login(self):
        user = User.objects.create_user(
            email="login@e2e.test", password="Login-pass123!", is_staff=True, staff_role="admin"
        )
        response = self.client.post("/auth/login/", {"email": user.email, "password": "Login-pass123!"})
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))

    def test_invalid_login_rejected(self):
        response = self.client.post("/auth/login/", {"email": "missing@e2e.test", "password": "wrongpassword"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertContains(response, "Invalid")

    def test_logout_workflow(self):
        user = User.objects.create_user(
            email="logout@e2e.test", password="Logout-pass123!", is_staff=True, staff_role="admin"
        )
        self.client.force_login(user)
        response = self.client.post("/auth/logout/")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertRedirects(
            self.client.get("/dashboard/"), "/auth/login/?next=/dashboard/", fetch_redirect_response=False
        )


class TestCustomerOnboardingFlow(RegistrationCase):
    def test_new_customer_onboarding_steps(self):
        user, customer = self.register()

        address = OrderService.build_billing_address_from_customer(customer)
        self.assertEqual(address["company_name"], customer.company_name)
        self.assertEqual(address["email"], user.email)
        self.assertEqual(address["address_line1"], "Str. Victoriei nr. 10")
        self.assertEqual(address["vat_number"], "RO14399847")

    def test_registration_rejects_incomplete_billing_profile(self):
        """Incomplete registration is rejected before any account or profile is persisted."""
        payload = self.payload()
        payload["customer_data"]["address_line1"] = ""
        response = self.post_registration(payload)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.exists())
        self.assertFalse(Customer.objects.exists())
