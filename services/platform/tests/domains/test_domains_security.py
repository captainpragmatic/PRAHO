from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.common.encryption import decrypt_sensitive_data, is_encrypted
from apps.customers.models import Customer
from apps.domains.forms import RegistrarForm
from apps.domains.models import TLD, Registrar, TLDRegistrarAssignment
from apps.domains.services import DomainLifecycleService, DomainValidationService

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

        # All secrets should be stored encrypted (AES-256-GCM with "aes:" prefix)
        self.assertTrue(is_encrypted(instance.api_key), "api_key should be AES-encrypted")
        self.assertTrue(is_encrypted(instance.api_secret), "api_secret should be AES-encrypted")
        self.assertTrue(is_encrypted(instance.webhook_secret), "webhook_secret should be AES-encrypted")

        # Verify round-trip: decrypt should return original plaintext
        self.assertEqual(decrypt_sensitive_data(instance.api_key), "PLAINTEXT_KEY")
        self.assertEqual(decrypt_sensitive_data(instance.api_secret), "PLAINTEXT_SECRET")
        self.assertEqual(decrypt_sensitive_data(instance.webhook_secret), "whsec_123")

        # Verify model accessor methods also decrypt correctly
        username, key = instance.get_api_credentials()
        self.assertEqual(username, "apiuser")
        self.assertEqual(key, "PLAINTEXT_KEY")
        self.assertEqual(instance.get_decrypted_api_secret(), "PLAINTEXT_SECRET")
        self.assertEqual(instance.get_decrypted_webhook_secret(), "whsec_123")

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
        TLDRegistrarAssignment.objects.create(
            tld=self.tld,
            registrar=self.registrar,
            is_primary=True,
            is_active=True,
            priority=1,
        )

        self.customer = Customer.objects.create(
            name="John Doe",
            primary_email="cust@example.com",
            company_name="ACME",
            customer_type="individual",
        )

    def test_duplicate_registration_returns_already_registered(self) -> None:
        # First registration must be registrar-confirmed to leave an active row —
        # the uniqueness precondition then blocks the duplicate.
        confirmed_payload = (
            True,
            {
                "registrar_domain_id": "REG-1",
                "expires_at": datetime(2027, 1, 1, tzinfo=UTC),
                "nameservers": [],
                "epp_code": "",
            },
        )
        with patch(
            "apps.domains.services.DomainRegistrarGateway.register_domain",
            return_value=confirmed_payload,
        ):
            result = DomainLifecycleService.create_domain_registration(
                customer=self.customer,
                domain_name="example.com",
                years=1,
            )
        self.assertTrue(result.is_ok(), result)

        result2 = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="example.com",
            years=1,
        )
        self.assertTrue(result2.is_err())
        self.assertIn("already registered", str(result2.unwrap_err()).lower())

    def test_years_out_of_range_rejected(self) -> None:
        result = DomainLifecycleService.create_domain_registration(
            customer=self.customer,
            domain_name="too.com",
            years=20,
        )
        self.assertTrue(result.is_err())
        self.assertIn("period", str(result.unwrap_err()).lower())


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


class DomainNameHomographValidationTests(TestCase):
    """validate_domain_name rejects non-ASCII homographs (PR #169 review M1)."""

    def test_non_ascii_homograph_rejected(self) -> None:
        # "example.com" with the ASCII 'a' replaced by Cyrillic small a (U+0430).
        homograph = "ex\u0430mple.com"
        is_valid, msg = DomainValidationService.validate_domain_name(homograph)
        self.assertFalse(is_valid)
        self.assertIn("ASCII", str(msg))

    def test_ascii_domain_accepted(self) -> None:
        is_valid, _msg = DomainValidationService.validate_domain_name("example.com")
        self.assertTrue(is_valid)
