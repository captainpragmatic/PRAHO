"""
Portal CNP form validation tests — no database access.

Tests the basic format check in CustomerRegistrationForm.clean_cnp().
Platform does authoritative semantic validation; Portal only rejects
obviously invalid formats.
"""

from django.test import SimpleTestCase

from apps.users.forms import CustomerRegistrationForm


class TestPortalCNPFormValidation(SimpleTestCase):
    """CustomerRegistrationForm.clean_cnp() — basic format checks."""

    def _make_form_with_cnp(self, cnp: str) -> CustomerRegistrationForm:
        """Create a form with only the CNP field populated for isolated testing."""
        # Minimal data to avoid unrelated validation errors
        data = {
            "email": "test@example.com",
            "first_name": "Ion",
            "last_name": "Popescu",
            "password1": "securepass123!",
            "password2": "securepass123!",
            "customer_type": "srl",
            "company_name": "Test SRL",
            "address_line1": "Str. Test 1",
            "city": "Bucuresti",
            "county": "Bucuresti",
            "postal_code": "010001",
            "data_processing_consent": True,
            "terms_accepted": True,
            "cnp": cnp,
        }
        return CustomerRegistrationForm(data=data)

    def test_cnp_starting_with_0_rejected(self) -> None:
        """Century marker 0 is invalid per Romanian CNP spec."""
        form = self._make_form_with_cnp("0850101123456")
        form.is_valid()
        self.assertIn("cnp", form.errors)

    def test_cnp_starting_with_1_passes_format(self) -> None:
        """13-digit CNP starting with valid century marker passes basic check."""
        form = self._make_form_with_cnp("1850101123451")
        form.is_valid()
        # CNP field itself should not have errors (cross-field validation
        # may add errors for non-individual types, but clean_cnp passes)
        cnp_errors = form.errors.get("cnp", [])
        format_errors = [e for e in cnp_errors if "13 digits" in str(e) or "format" in str(e).lower()]
        self.assertEqual(format_errors, [])

    def test_non_13_digit_rejected(self) -> None:
        form = self._make_form_with_cnp("12345")
        form.is_valid()
        self.assertIn("cnp", form.errors)

    def test_non_numeric_rejected(self) -> None:
        form = self._make_form_with_cnp("185010112345a")
        form.is_valid()
        self.assertIn("cnp", form.errors)

    def test_empty_cnp_returns_empty(self) -> None:
        """Empty CNP is allowed (CNP is optional for non-individuals)."""
        form = self._make_form_with_cnp("")
        form.is_valid()
        cnp_errors = form.errors.get("cnp", [])
        # No CNP-specific errors (cross-field may add "required for individuals")
        format_errors = [e for e in cnp_errors if "13 digits" in str(e)]
        self.assertEqual(format_errors, [])
