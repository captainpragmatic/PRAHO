from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.domains.forms import RegistrarForm
from apps.domains.models import Registrar, TLD, Domain
from apps.domains.services import DomainLifecycleService


User = get_user_model()


class RegistrarFormSecurityTests(TestCase):
    def setUp(self) -> None:
        self.registrar = Registrar.objects.create(
            name="test-registrar",
            display_name="Test Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )

    def test_secrets_not_prefilled_and_encrypted_on_save(self) -> None:
        form = RegistrarForm(instance=self.registrar)
        # Form fields for secrets should not have initial values
        self.assertEqual(form.fields["api_key"].initial, "")
        self.assertEqual(form.fields["api_secret"].initial, "")
        self.assertEqual(form.fields["webhook_secret"].initial, "")

        data = {
            "display_name": "Test Registrar",
            "name": "test-registrar",
            "website_url": "https://example.com",
            "api_endpoint": "https://api.example.com",
            "api_username": "apiuser",
            "api_key": "PLAINTEXT_KEY",
            "api_secret": "PLAINTEXT_SECRET",
            "webhook_secret": "whsec_123",
            "webhook_endpoint": "https://example.com/webhook",
            "status": "active",
            "default_nameservers": json.dumps(["ns1.example.com", "ns2.example.com"]),
            "currency": "USD",
            "monthly_fee_cents": 0,
        }

        form = RegistrarForm(data=data, instance=self.registrar)
        self.assertTrue(form.is_valid(), form.errors)
        instance = form.save()

        # Secrets should be stored encrypted for api key/secret (not equal to plaintext)
        self.assertNotEqual(instance.api_key, "PLAINTEXT_KEY")
        self.assertNotEqual(instance.api_secret, "PLAINTEXT_SECRET")
        # webhook_secret is write-only but currently not encrypted in model; value should be set
        self.assertEqual(instance.webhook_secret, "whsec_123")

    def test_nameservers_validation(self) -> None:
        bad = RegistrarForm(
            data={
                "display_name": "Bad",
                "name": "bad",
                "website_url": "https://example.com",
                "api_endpoint": "https://api.example.com",
                "status": "active",
                "default_nameservers": json.dumps(["localhost", "256.1.1.1"]),
                "currency": "USD",
                "monthly_fee_cents": 0,
            }
        )
        self.assertFalse(bad.is_valid())


class DomainRegistrationRaceConditionTests(TestCase):
    def setUp(self) -> None:
        self.tld = TLD.objects.create(
            extension="com",
            description=".com",
            registration_price_cents=1000,
            renewal_price_cents=1000,
            transfer_price_cents=1000,
            registrar_cost_cents=500,
            min_registration_period=1,
            max_registration_period=10,
        )
        self.registrar = Registrar.objects.create(
            name="test-registrar",
            display_name="Test Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )
        # Associate registrar as primary for the TLD
        from apps.domains.models import TLDRegistrarAssignment
        TLDRegistrarAssignment.objects.create(
            tld=self.tld,
            registrar=self.registrar,
            is_primary=True,
            is_active=True,
            priority=1,
        )

        # Minimal user/customer – import lazily to avoid cross-app heavy setup
        from apps.customers.models import Customer

        self.customer = Customer.objects.create(
            name="John Doe",
            primary_email="cust@example.com",
            company_name="ACME",
            customer_type="individual",
        )

    def test_duplicate_registration_returns_already_registered(self) -> None:
        ok, res = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="example.com",
            years=1,
        )
        self.assertTrue(ok, res)

        ok2, res2 = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="example.com",
            years=1,
        )
        self.assertFalse(ok2)
        self.assertIn("already registered", str(res2).lower())

    def test_years_out_of_range_rejected(self) -> None:
        ok, res = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="too.com",
            years=20,
        )
        self.assertFalse(ok)
        self.assertIn("period", str(res).lower())


class RegistrarAdminAuthorizationTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = User.objects.create_user(
            email="admin@example.com", password="testpass123", is_superuser=True, is_staff=True
        )
        self.staff = User.objects.create_user(
            email="staff@example.com", password="testpass123", is_staff=True
        )

    def test_staff_cannot_access_registrar_create(self) -> None:
        self.client.login(email="staff@example.com", password="testpass123")
        resp = self.client.get(reverse("domains:registrar_create"))
        # Expect 403 due to admin_required
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_registrar_create(self) -> None:
        self.client.login(email="admin@example.com", password="testpass123")
        resp = self.client.get(reverse("domains:registrar_create"))
        self.assertEqual(resp.status_code, 200)
