"""Tests for Proforma dataclass and serializer — bill_to field extraction."""

from django.test import SimpleTestCase

from apps.billing.serializers import create_proforma_from_api


class ProformaBillToFieldsTests(SimpleTestCase):
    """Verify bill_to fields are extracted from API response into Proforma dataclass."""

    def _make_api_data(self, **overrides):
        base = {
            "id": 1,
            "number": "PRO-000001",
            "status": "draft",
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "currency": {"id": 1, "code": "RON", "symbol": "lei", "decimal_places": 2, "name": "Romanian Leu"},
            "valid_until": "2026-04-01T00:00:00Z",
            "created_at": "2026-03-23T22:00:00Z",
        }
        base.update(overrides)
        return base

    def test_bill_to_nested_dict_extracted(self):
        """bill_to nested dict from API response is extracted to dataclass fields."""
        data = self._make_api_data(
            bill_to={
                "name": "Test SRL",
                "email": "test@test.ro",
                "tax_id": "RO12345678",
                "address": "Str. Test 1, București",
            }
        )
        proforma = create_proforma_from_api(data)
        self.assertEqual(proforma.bill_to_name, "Test SRL")
        self.assertEqual(proforma.bill_to_email, "test@test.ro")
        self.assertEqual(proforma.bill_to_tax_id, "RO12345678")
        self.assertEqual(proforma.bill_to_address1, "Str. Test 1, București")

    def test_bill_to_flat_fields_extracted(self):
        """Flat bill_to_* fields from API response are extracted."""
        data = self._make_api_data(
            bill_to_name="Flat SRL",
            bill_to_email="flat@test.ro",
            bill_to_tax_id="RO99999999",
        )
        proforma = create_proforma_from_api(data)
        self.assertEqual(proforma.bill_to_name, "Flat SRL")
        self.assertEqual(proforma.bill_to_email, "flat@test.ro")
        self.assertEqual(proforma.bill_to_tax_id, "RO99999999")

    def test_bill_to_empty_when_not_provided(self):
        """bill_to fields default to empty string when not in API response."""
        data = self._make_api_data()
        proforma = create_proforma_from_api(data)
        self.assertEqual(proforma.bill_to_name, "")
        self.assertEqual(proforma.bill_to_email, "")
