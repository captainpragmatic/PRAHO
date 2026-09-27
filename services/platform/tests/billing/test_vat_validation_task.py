"""Tests for validate_vat_number task (apps.billing.tasks)."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.gateways.vies_gateway import VIESResponse
from apps.billing.tasks import validate_vat_number
from apps.billing.tax_models import VATValidation
from apps.common.eu_vat_validator import VATFormatResult
from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer, CustomerTaxProfile

User = get_user_model()


@pytest.fixture
def _tax_profile(db):
    """Create a minimal customer with tax profile for VAT tests."""
    user = User.objects.create_user(email="vat-test@example.com", password="testpass123")
    customer = Customer.objects.create(
        name="VAT Test SRL",
        customer_type="company",
        company_name="VAT Test SRL",
        primary_email="vat-test@example.com",
        data_processing_consent=True,
        created_by=user,
    )
    return CustomerTaxProfile.objects.create(
        customer=customer,
        vat_number="RO12345678",
        is_vat_payer=True,
        vat_rate=Decimal("21.00"),
    )


# Patch targets are the source modules (deferred imports resolve there at runtime)
_PARSE = "apps.common.eu_vat_validator.parse_vat_number"
_FORMAT = "apps.common.eu_vat_validator.validate_vat_format"
_IS_EU = "apps.common.eu_vat_validator.is_eu_country"
_GATEWAY = "apps.billing.gateways.vies_gateway.VIESGateway.check_vat"
_AUDIT = "apps.audit.services.AuditService.log_simple_event"


@override_settings(COMPANY_CUI="RO1234567", VIES_OUTAGE_GRACE_DAYS=14)
class VATValidationEvidencePersistenceTests(TestCase):
    def setUp(self) -> None:
        customer = Customer.objects.create(name="VIES Persistence", primary_email="vies-persistence@example.test")
        self.verified_at = timezone.now() - timedelta(days=1)
        self.profile = CustomerTaxProfile.objects.create(
            customer=customer, vat_number="DE136695976", is_vat_payer=True,
            vies_verification_status="valid", reverse_charge_eligible=True,
            vies_verified_at=self.verified_at, vies_verified_name="Original GmbH",
        )

    def test_number_is_resolved_against_the_billing_country(self) -> None:
        for country, number, expected in (
            ("DE", "136695976", ("DE", "136695976")),
            ("GR", "GR094259216", ("EL", "094259216")),
        ):
            with self.subTest(country=country, number=number):
                CustomerAddress.objects.filter(customer=self.profile.customer).delete()
                CustomerAddress.objects.create(
                    customer=self.profile.customer, is_billing=True, is_current=True,
                    address_line1="Teststrasse 1", city="Somewhere", country=country,
                )
                CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
                    vat_number=number, vies_verification_status="pending"
                )
                response = VIESResponse(
                    is_valid=True, country_code=expected[0], vat_number=expected[1], api_available=True,
                )
                with patch(_GATEWAY, return_value=response) as gateway:
                    validate_vat_number(str(self.profile.pk))
                gateway.assert_called_once()
                passed = tuple(gateway.call_args.args) + tuple(gateway.call_args.kwargs.values())
                self.assertEqual(passed[:2], expected)
                self.profile.refresh_from_db()
                self.assertEqual(self.profile.vies_verification_status, "valid")

    def test_vies_outage_keeps_recent_valid_profile(self) -> None:
        validation = VATValidation.objects.create(
            country_code="DE", vat_number="136695976", full_vat_number="DE136695976",
            is_valid=True, is_active=True, validation_source="vies",
            expires_at=timezone.now() - timedelta(hours=1), consultation_reference="original-reference",
        )
        with patch(_GATEWAY, return_value=VIESResponse(
            is_valid=False, country_code="DE", vat_number="136695976", api_available=False,
        )):
            result = validate_vat_number(str(self.profile.pk))
        self.assertEqual(result, {"success": True, "status": "vies_unavailable_grace"})
        self.profile.refresh_from_db()
        validation.refresh_from_db()
        self.assertEqual(self.profile.vies_verification_status, "valid")
        self.assertTrue(self.profile.reverse_charge_eligible)
        self.assertEqual(self.profile.vies_verified_at, self.verified_at)
        self.assertEqual(self.profile.vies_verified_name, "Original GmbH")
        self.assertTrue(validation.is_valid)
        self.assertTrue(validation.is_active)
        self.assertEqual(validation.consultation_reference, "original-reference")
        self.assertGreater(validation.expires_at, timezone.now() + timedelta(hours=23))

    def test_vies_outage_preserves_evidence_with_small_clock_skew(self) -> None:
        verified_at = timezone.now() + timedelta(seconds=30)
        self.profile.vies_verified_at = verified_at
        self.profile.save(update_fields=["vies_verified_at"])
        with patch(
            _GATEWAY,
            return_value=VIESResponse(
                is_valid=False, country_code="DE", vat_number="136695976", api_available=False,
            ),
        ):
            result = validate_vat_number(str(self.profile.pk))
        self.assertEqual(result, {"success": True, "status": "vies_unavailable_grace"})
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.vies_verification_status, "valid")
        self.assertTrue(self.profile.reverse_charge_eligible)
        self.assertEqual(self.profile.vies_verified_at, verified_at)
        self.assertEqual(self.profile.vies_verified_name, "Original GmbH")

    def test_result_for_a_changed_number_is_not_persisted(self) -> None:
        def change_number(*args: object, **kwargs: object) -> VIESResponse:
            self.profile.vat_number = "FR40303265045"
            self.profile.save(update_fields=["vat_number"])
            return VIESResponse(is_valid=True, country_code="DE", vat_number="136695976", api_available=True)

        with patch(_GATEWAY, side_effect=change_number):
            result = validate_vat_number(str(self.profile.pk))
        self.assertEqual(result, {"success": True, "skipped": "vat_number_changed"})
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.vat_number, "FR40303265045")
        self.assertEqual(self.profile.vies_verification_status, "pending")
        self.assertFalse(self.profile.reverse_charge_eligible)
        self.assertIsNone(self.profile.vies_verified_at)
        self.assertFalse(VATValidation.objects.filter(country_code="DE", vat_number="136695976").exists())


@pytest.mark.django_db
class TestValidateVatNumberTask:

    """Test the rewritten validate_vat_number task."""

    def test_no_vat_number_skips(self, _tax_profile):
        _tax_profile.vat_number = ""
        _tax_profile.save(update_fields=["vat_number"])

        result = validate_vat_number(str(_tax_profile.id))

        assert result["success"] is True
        assert "No VAT number" in result["message"]

    @patch(_AUDIT)
    @patch(_GATEWAY)
    @patch(_FORMAT)
    @patch(_PARSE)
    def test_valid_ro_vat_with_vies(
        self, mock_parse, mock_format, mock_gateway, mock_audit, _tax_profile
    ):
        mock_parse.return_value = ("RO", "12345678")
        mock_format.return_value = VATFormatResult(
            is_valid=True, country_code="RO", vat_digits="12345678",
            full_vat_number="RO12345678",
        )
        mock_gateway.return_value = VIESResponse(
            is_valid=True, country_code="RO", vat_number="12345678",
            company_name="SC Test SRL", api_available=True,
        )

        result = validate_vat_number(str(_tax_profile.id))

        assert result["success"] is True
        assert result["is_valid"] is True
        assert result["vies_status"] == "valid"

        _tax_profile.refresh_from_db()
        assert _tax_profile.vies_verification_status == "valid"
        assert _tax_profile.vies_verified_name == "SC Test SRL"
        assert _tax_profile.reverse_charge_eligible is True

    @patch(_AUDIT)
    @patch(_GATEWAY)
    @patch(_FORMAT)
    @patch(_PARSE)
    def test_format_invalid_skips_vies(
        self, mock_parse, mock_format, mock_gateway, mock_audit, _tax_profile
    ):
        _tax_profile.vat_number = "RO999"
        _tax_profile.save(update_fields=["vat_number"])

        mock_parse.return_value = ("RO", "999")
        mock_format.return_value = VATFormatResult(
            is_valid=False, country_code="RO", vat_digits="999",
            full_vat_number="RO999", error_message="CUI must have 2-10 digits",
        )

        result = validate_vat_number(str(_tax_profile.id))

        assert result["success"] is True
        assert result["is_valid"] is False
        mock_gateway.assert_not_called()

        _tax_profile.refresh_from_db()
        assert _tax_profile.vies_verification_status == "invalid"

    @patch(_AUDIT)
    @patch(_GATEWAY)
    @patch(_FORMAT)
    @patch(_PARSE)
    def test_vies_unavailable_falls_back_to_format_only(
        self, mock_parse, mock_format, mock_gateway, mock_audit, _tax_profile
    ):
        _tax_profile.vat_number = "DE123456789"
        _tax_profile.save(update_fields=["vat_number"])

        mock_parse.return_value = ("DE", "123456789")
        mock_format.return_value = VATFormatResult(
            is_valid=True, country_code="DE", vat_digits="123456789",
            full_vat_number="DE123456789",
        )
        mock_gateway.return_value = VIESResponse(
            is_valid=False, country_code="DE", vat_number="123456789",
            api_available=False, error_message="Connection timeout",
        )

        result = validate_vat_number(str(_tax_profile.id))

        assert result["success"] is True
        assert result["is_valid"] is False
        assert result["vies_status"] == "format_only"

        _tax_profile.refresh_from_db()
        assert _tax_profile.vies_verification_status == "format_only"

    @patch(_IS_EU)
    @patch(_PARSE)
    def test_non_eu_country_returns_not_applicable(
        self, mock_parse, mock_is_eu, _tax_profile
    ):
        _tax_profile.vat_number = "GB123456789"
        _tax_profile.save(update_fields=["vat_number"])

        mock_parse.return_value = ("GB", "123456789")
        mock_is_eu.return_value = False

        result = validate_vat_number(str(_tax_profile.id))

        assert result["success"] is True
        assert "not applicable" in result["message"].lower()

        _tax_profile.refresh_from_db()
        assert _tax_profile.vies_verification_status == "not_applicable"

    def test_nonexistent_profile_returns_error(self):
        result = validate_vat_number("00000000-0000-0000-0000-000000000000")

        assert result["success"] is False
        assert "error" in result
