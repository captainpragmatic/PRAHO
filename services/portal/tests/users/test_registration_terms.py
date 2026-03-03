"""
Customer Registration Form — terms_accepted Field Tests

Verifies that the CustomerRegistrationForm enforces the terms_accepted field
correctly and that register_customer() includes it in the API payload.
No database access — pure form validation logic.
"""

import unittest
from unittest.mock import patch, MagicMock

from apps.users.forms import CustomerRegistrationForm


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_BASE_DATA = {
    'email': 'test@example.com',
    'first_name': 'Ion',
    'last_name': 'Popescu',
    'password1': 'SecurePassword123!',
    'password2': 'SecurePassword123!',
    'customer_type': 'srl',
    'company_name': 'Test Company SRL',
    'vat_number': 'RO12345678',
    'address_line1': 'Str. Test Nr. 1',
    'city': 'București',
    'county': 'București',
    'postal_code': '010001',
    'data_processing_consent': True,
    'marketing_consent': False,
}


def _form_data(**overrides: object) -> dict:
    data = dict(_BASE_DATA)
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# Form validation tests
# ---------------------------------------------------------------------------

class RegistrationTermsValidationTestCase(unittest.TestCase):
    """Tests for terms_accepted field validation on CustomerRegistrationForm."""

    def test_form_invalid_when_terms_not_accepted(self):
        """Form is invalid when terms_accepted is absent (not submitted)."""
        data = _form_data()  # terms_accepted not included
        form = CustomerRegistrationForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn('terms_accepted', form.errors)

    def test_form_invalid_when_terms_explicitly_false(self):
        """Form is invalid when terms_accepted is explicitly False."""
        data = _form_data(terms_accepted=False)
        form = CustomerRegistrationForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn('terms_accepted', form.errors)

    def test_form_valid_when_terms_accepted(self):
        """Form is valid when all required fields are present and terms_accepted is True."""
        data = _form_data(terms_accepted=True)
        form = CustomerRegistrationForm(data)
        self.assertTrue(
            form.is_valid(),
            f"Form should be valid but got errors: {form.errors.as_json()}",
        )

    def test_terms_accepted_field_is_required(self):
        """Confirm terms_accepted field carries required=True (BooleanField default)."""
        field = CustomerRegistrationForm().fields['terms_accepted']
        self.assertTrue(field.required)

    def test_form_cleaned_data_contains_terms_accepted_true(self):
        """After successful validation, cleaned_data['terms_accepted'] is True."""
        data = _form_data(terms_accepted=True)
        form = CustomerRegistrationForm(data)
        form.is_valid()
        self.assertTrue(form.cleaned_data.get('terms_accepted'))


# ---------------------------------------------------------------------------
# register_customer() payload tests
# ---------------------------------------------------------------------------

class RegistrationPayloadTermsTestCase(unittest.TestCase):
    """Tests that register_customer() sends terms_accepted in the API payload."""

    def _get_validated_form(self) -> CustomerRegistrationForm:
        data = _form_data(terms_accepted=True)
        form = CustomerRegistrationForm(data)
        assert form.is_valid(), f"Test setup failed: {form.errors.as_json()}"
        return form

    @patch('apps.users.forms.api_client')
    def test_register_customer_payload_includes_terms_accepted_true(self, mock_api: MagicMock) -> None:
        """register_customer() passes terms_accepted=True in the customer_data payload."""
        mock_api._make_request.return_value = {'success': True, 'customer_id': 42}

        form = self._get_validated_form()
        form.register_customer()

        mock_api._make_request.assert_called_once()
        call_kwargs = mock_api._make_request.call_args
        # _make_request is called as: _make_request("POST", path, data=payload)
        payload = call_kwargs.kwargs.get('data') or call_kwargs[1].get('data') or call_kwargs[0][2]
        customer_data = payload.get('customer_data', {})
        self.assertIn('terms_accepted', customer_data)
        self.assertTrue(customer_data['terms_accepted'])

    @patch('apps.users.forms.api_client')
    def test_register_customer_payload_includes_terms_accepted_false(self, mock_api: MagicMock) -> None:
        """Even when terms_accepted=False slips through (hypothetical), the value is forwarded."""
        # Directly set cleaned_data to bypass form validation for this low-level test
        mock_api._make_request.return_value = {'success': True}

        form = self._get_validated_form()
        # Override cleaned_data to simulate a False value being passed
        form.cleaned_data['terms_accepted'] = False
        form.register_customer()

        call_kwargs = mock_api._make_request.call_args
        payload = call_kwargs.kwargs.get('data') or call_kwargs[1].get('data') or call_kwargs[0][2]
        customer_data = payload.get('customer_data', {})
        self.assertFalse(customer_data.get('terms_accepted', True))

    @patch('apps.users.forms.api_client')
    def test_register_customer_returns_none_on_api_error(self, mock_api: MagicMock) -> None:
        """register_customer() returns None when the API call raises an exception."""
        from apps.api_client.services import PlatformAPIError

        mock_api._make_request.side_effect = PlatformAPIError('server error')

        form = self._get_validated_form()
        result = form.register_customer()

        self.assertIsNone(result)
