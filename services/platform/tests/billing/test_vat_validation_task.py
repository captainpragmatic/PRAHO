"""Tests for validate_vat_number task (apps.billing.tasks)."""

from decimal import Decimal
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from apps.billing.gateways.vies_gateway import VIESResponse
from apps.billing.tasks import validate_vat_number
from apps.common.eu_vat_validator import VATFormatResult
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
