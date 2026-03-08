"""
Tests for ProfileService — field allowlists and validate-before-mutate.

Regression guard: these tests capture chaos-monkey findings around:
- Unsafe field updates (id, customer_id) not being blocked by allowlist
- CUI validated against the OLD value instead of the NEW value,
  allowing invalid CUIs to be persisted when the old value happened to be valid
- CUI changed_fields tracking: cui must appear in update_fields when updated
"""

import contextlib
import time
from unittest.mock import patch

from django.test import TestCase

from apps.customers.profile_service import ProfileService
from tests.factories.core_factories import CustomerCreationRequest, create_admin_user, create_full_customer


def _create_customer() -> object:
    req = CustomerCreationRequest(
        name="Profile Test SRL",
        company_name="Profile Test SRL",
        primary_email=f"profile_{int(time.time() * 1000)}@test.ro",
        with_tax_profile=False,
        with_billing_profile=False,
        with_address=False,
    )
    return create_full_customer(req)


def _create_user() -> object:
    return create_admin_user(username=f"admin_{int(time.time() * 1000)}")


class TestProfileServiceTaxProfileAllowlist(TestCase):
    """update_tax_profile() only mutates fields in TAX_PROFILE_UPDATABLE_FIELDS."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()
        # Create the tax profile via the service (uses update_or_create)
        self.tax_profile = ProfileService.create_tax_profile(
            self.customer,
            self.user,
            cui="RO18189442",
        )

    def test_allowed_field_vat_number_is_updated(self) -> None:
        """vat_number is in TAX_PROFILE_UPDATABLE_FIELDS — must be saved."""
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, vat_number="RO99887766"
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.vat_number, "RO99887766")

    def test_allowed_field_is_vat_payer_is_updated(self) -> None:
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, is_vat_payer=False
        )
        self.tax_profile.refresh_from_db()
        self.assertFalse(self.tax_profile.is_vat_payer)

    def test_allowed_field_registration_number_is_updated(self) -> None:
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, registration_number="J40/9999/2025"
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.registration_number, "J40/9999/2025")

    def test_unsafe_field_id_is_silently_dropped(self) -> None:
        """id is NOT in TAX_PROFILE_UPDATABLE_FIELDS — must be silently ignored.

        Regression: if the allowlist filter were missing, this would attempt to
        overwrite the primary key with an arbitrary integer.
        """
        original_id = self.tax_profile.id
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, id=99999
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.id, original_id)

    def test_unsafe_field_customer_id_is_silently_dropped(self) -> None:
        """customer_id is NOT allowed — reassigning the owning customer must be blocked."""
        original_customer_id = self.tax_profile.customer_id
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, customer_id=99999
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.customer_id, original_customer_id)

    def test_updatable_fields_constant_does_not_contain_id(self) -> None:
        """Class-level constant must not accidentally include 'id'."""
        self.assertNotIn("id", ProfileService.TAX_PROFILE_UPDATABLE_FIELDS)

    def test_updatable_fields_constant_does_not_contain_customer_id(self) -> None:
        self.assertNotIn("customer_id", ProfileService.TAX_PROFILE_UPDATABLE_FIELDS)


class TestProfileServiceBillingProfileAllowlist(TestCase):
    """update_billing_profile() only mutates fields in BILLING_PROFILE_UPDATABLE_FIELDS."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()
        self.billing_profile = ProfileService.create_billing_profile(
            self.customer, self.user
        )

    def test_allowed_field_payment_terms_is_updated(self) -> None:
        ProfileService.update_billing_profile(
            self.billing_profile, self.user, payment_terms=45
        )
        self.billing_profile.refresh_from_db()
        self.assertEqual(self.billing_profile.payment_terms, 45)

    def test_allowed_field_preferred_currency_is_updated(self) -> None:
        ProfileService.update_billing_profile(
            self.billing_profile, self.user, preferred_currency="EUR"
        )
        self.billing_profile.refresh_from_db()
        self.assertEqual(self.billing_profile.preferred_currency, "EUR")

    def test_unsafe_field_id_is_silently_dropped(self) -> None:
        original_id = self.billing_profile.id
        ProfileService.update_billing_profile(
            self.billing_profile, self.user, id=99999
        )
        self.billing_profile.refresh_from_db()
        self.assertEqual(self.billing_profile.id, original_id)

    def test_unsafe_field_customer_id_is_silently_dropped(self) -> None:
        original_customer_id = self.billing_profile.customer_id
        ProfileService.update_billing_profile(
            self.billing_profile, self.user, customer_id=99999
        )
        self.billing_profile.refresh_from_db()
        self.assertEqual(self.billing_profile.customer_id, original_customer_id)

    def test_billing_updatable_fields_does_not_contain_id(self) -> None:
        self.assertNotIn("id", ProfileService.BILLING_PROFILE_UPDATABLE_FIELDS)

    def test_billing_updatable_fields_does_not_contain_customer_id(self) -> None:
        self.assertNotIn("customer_id", ProfileService.BILLING_PROFILE_UPDATABLE_FIELDS)


class TestProfileServiceCUIValidation(TestCase):
    """update_tax_profile() validates the NEW CUI value before persisting.

    Regression: the original code validated tax_profile.cui (the OLD stored value)
    rather than the incoming new value — any valid old CUI would allow an invalid
    new CUI to slip through.
    """

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()
        self.tax_profile = ProfileService.create_tax_profile(
            self.customer,
            self.user,
            cui="RO18189442",
        )

    def test_invalid_cui_raises_value_error(self) -> None:
        """Invalid CUI format must raise ValueError before any DB write."""
        with self.assertRaises(ValueError):
            ProfileService.update_tax_profile(
                self.tax_profile, self.user, cui="INVALID"
            )

    def test_invalid_cui_does_not_mutate_stored_value(self) -> None:
        """After a failed update, the DB row must retain the original CUI.

        Regression: if the old value were validated instead of the new one,
        the invalid value would be written to the DB before validation ran.
        """
        original_cui = self.tax_profile.cui
        with contextlib.suppress(ValueError):
            ProfileService.update_tax_profile(
                self.tax_profile, self.user, cui="INVALID"
            )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.cui, original_cui)

    def test_valid_cui_is_accepted(self) -> None:
        """A correctly formatted CUI must be saved without raising."""
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, cui="RO14399840"
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.cui, "RO14399840")

    def test_valid_cui_without_ro_prefix_is_accepted(self) -> None:
        """CUI without RO prefix is also a valid format."""
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, cui="14399840"
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.cui, "14399840")


class TestProfileServiceCreateTaxProfile(TestCase):
    """ProfileService.create_tax_profile() — basic creation and idempotency."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()

    def test_create_tax_profile_persisted(self) -> None:
        tp = ProfileService.create_tax_profile(self.customer, self.user, cui="RO18189442")
        self.assertIsNotNone(tp.pk)

    def test_create_tax_profile_linked_to_customer(self) -> None:
        tp = ProfileService.create_tax_profile(self.customer, self.user, cui="RO18189442")
        self.assertEqual(tp.customer_id, self.customer.id)

    def test_create_tax_profile_is_idempotent(self) -> None:
        """Calling create_tax_profile twice on the same customer uses update_or_create."""
        tp1 = ProfileService.create_tax_profile(self.customer, self.user, cui="RO18189442")
        tp2 = ProfileService.create_tax_profile(self.customer, self.user, cui="RO18189442")
        self.assertEqual(tp1.pk, tp2.pk)


class TestProfileServiceCreateBillingProfile(TestCase):
    """ProfileService.create_billing_profile() — basic creation."""

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()

    def test_create_billing_profile_persisted(self) -> None:
        bp = ProfileService.create_billing_profile(self.customer, self.user)
        self.assertIsNotNone(bp.pk)

    def test_create_billing_profile_linked_to_customer(self) -> None:
        bp = ProfileService.create_billing_profile(self.customer, self.user)
        self.assertEqual(bp.customer_id, self.customer.id)


class TestProfileServiceCUIChangedFieldsTracking(TestCase):
    """update_tax_profile() must include 'cui' in update_fields when CUI is updated.

    Regression guard for F06: the original code checked ``updates`` (raw kwargs)
    instead of tracking whether CUI was processed through the allowlist and
    validation path.  A non-updatable field passed alongside cui could
    previously cause cui to be silently omitted from update_fields.
    """

    def setUp(self) -> None:
        self.user = _create_user()
        self.customer = _create_customer()
        self.tax_profile = ProfileService.create_tax_profile(
            self.customer,
            self.user,
            cui="RO18189442",
        )

    def test_cui_appears_in_update_fields_when_updated(self) -> None:
        """save() must be called with update_fields that includes 'cui'."""
        with patch.object(self.tax_profile.__class__, "save") as mock_save:
            ProfileService.update_tax_profile(
                self.tax_profile, self.user, cui="RO14399840"
            )
        mock_save.assert_called_once()
        _, call_kwargs = mock_save.call_args
        update_fields: list[str] = list(call_kwargs.get("update_fields", []))
        self.assertIn("cui", update_fields)

    def test_non_updatable_field_customer_is_silently_rejected(self) -> None:
        """A field not in TAX_PROFILE_UPDATABLE_FIELDS must not reach save()."""
        original_customer_id = self.tax_profile.customer_id
        ProfileService.update_tax_profile(
            self.tax_profile, self.user, customer=object()
        )
        self.tax_profile.refresh_from_db()
        self.assertEqual(self.tax_profile.customer_id, original_customer_id)
